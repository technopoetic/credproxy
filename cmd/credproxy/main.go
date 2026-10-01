package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/technopoetic/credproxy/internal/ca"
	"github.com/technopoetic/credproxy/internal/config"
	"github.com/technopoetic/credproxy/internal/mitm"
	"github.com/technopoetic/credproxy/internal/pooler"
	"github.com/technopoetic/credproxy/internal/providers"
	"github.com/technopoetic/credproxy/internal/resolver"
)

func main() {
	configPath := flag.String("config", config.DefaultConfigPath(), "path to global config")
	profile := flag.String("profile", "", "config profile to activate")
	sentinel := flag.String("sentinel", "CREDPROXY_TOKEN", "sentinel string to substitute")
	openProxy := flag.Bool("open-proxy", false, "allow all hosts (not recommended)")
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "usage: credproxy <command> [args...]\n")
		os.Exit(1)
	}

	if err := config.EnsureDirs(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create config directory: %v\n", err)
		os.Exit(1)
	}

	created, err := config.MaybeWriteDefaultConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not write default config: %v\n", err)
	}
	if created {
		fmt.Fprintf(os.Stderr, "Created default config at %s — edit to add your hosts.\n", config.DefaultConfigPath())
	}

	logPath := filepath.Join(config.DefaultCADir(), "credproxy.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open log file %s: %v\n", logPath, err)
		os.Exit(1)
	}
	defer logFile.Close()

	logger := slog.New(slog.NewTextHandler(logFile, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := loadMergedConfig(*configPath, *profile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	if *openProxy {
		cfg.AllowAll()
	}

	if err := cfg.ValidateDatabases(); err != nil {
		fmt.Fprintf(os.Stderr, "invalid database config: %v\n", err)
		os.Exit(1)
	}

	caProvider, err := ca.LoadOrGenerate(config.DefaultCADir())
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to init CA: %v\n", err)
		os.Exit(1)
	}

	reg := providers.NewRegistry()
	reg.Register(providers.NewOnePasswordProvider())

	res := resolver.New(cfg, reg)
	res.SetSentinel(*sentinel)

	if err := cfg.ResolveEnv(context.Background(), res); err != nil {
		fmt.Fprintf(os.Stderr, "failed to resolve env credentials: %v\n", err)
		os.Exit(1)
	}

	if err := cfg.ResolveDatabasePasswords(context.Background(), res); err != nil {
		fmt.Fprintf(os.Stderr, "failed to resolve database credentials: %v\n", err)
		os.Exit(1)
	}

	// runWrap returns the child's exit code rather than exiting itself: the
	// poolers and shim dir are cleaned up by its defers, and os.Exit would
	// skip them — leaking the 0600 temp dir with the real password on every
	// non-zero child exit.
	os.Exit(runWrap(cfg, caProvider, res, logger, logFile, args))
}

func loadMergedConfig(globalPath string, profileName string) (*config.Config, error) {
	global, err := config.Load(globalPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		global = &config.Config{
			Hosts:    make(map[string]config.HostConfig),
			Env:      make(map[string]string),
			Profiles: make(map[string]config.ProfileConfig),
		}
		global.SetDefaults()
	}

	stopAt, _ := os.UserHomeDir()

	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}

	projectPath, err := config.WalkProjectConfig(cwd, stopAt)
	if err != nil {
		return nil, fmt.Errorf("walking for project config: %w", err)
	}

	if projectPath == "" {
		return global.ApplyProfile(profileName)
	}

	project, err := config.Load(projectPath)
	if err != nil {
		return nil, fmt.Errorf("loading project config %s: %w", projectPath, err)
	}

	merged := global.Merge(project)
	return merged.ApplyProfile(profileName)
}

func runWrap(cfg *config.Config, caProvider *ca.Provider, res *resolver.Resolver, logger *slog.Logger, logFile *os.File, command []string) int {
	addr := ":0"
	srv := mitm.New(addr, caProvider, res, logger)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to start proxy: %v\n", err)
		return 1
	}
	defer ln.Close()

	go srv.Serve(ln)

	// Poolers start before the child exists so the injected URLs are known.
	// Start is a no-op when no [databases.*] are configured.
	mgr := pooler.NewManager(cfg, logger, logFile)
	if err := mgr.Start(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start database poolers: %v\n", err)
		return 1
	}
	defer mgr.Stop()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())

	childPath, shimDir, cleanupShims := stripSecretStoreCLIs(os.Getenv("PATH"))
	defer cleanupShims()
	caCertPath, err := caProvider.WriteTrustBundle(config.DefaultCADir())
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to write CA trust bundle: %v\n", err)
		return 1
	}
	childEnv := buildChildEnv(cfg, portStr, childPath, caCertPath, shimDir, mgr.Env, mgr.Strip)

	childBin, err := exec.LookPath(command[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "command not found: %s\n", command[0])
		return 1
	}

	child := exec.Command(childBin, command[1:]...)
	child.Env = childEnv
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr

	if err := child.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "exec failed: %v\n", err)
		return 1
	}

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		for range sig {
			child.Process.Signal(syscall.SIGINT)
		}
	}()

	if err := child.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode()
		}
		fmt.Fprintf(os.Stderr, "exec failed: %v\n", err)
		return 1
	}
	return 0
}

func buildChildEnv(cfg *config.Config, proxyPort string, childPath string, caCertPath string, shimDir string, poolerEnv map[string]string, poolerStrip []string) []string {
	strip := make(map[string]bool, len(poolerStrip))
	for _, k := range poolerStrip {
		strip[k] = true
	}
	env := os.Environ()
	configEnv := cfg.EnvVars()
	filtered := make([]string, 0, len(env)+len(configEnv)+len(poolerEnv))
	prevBashEnv := os.Getenv("BASH_ENV")
	for _, e := range env {
		key := strings.SplitN(e, "=", 2)[0]
		if strings.HasPrefix(e, "OP_SERVICE_ACCOUNT_TOKEN=") || strings.HasPrefix(e, "BW_SESSION=") {
			continue
		}
		if strings.HasPrefix(e, "HTTPS_PROXY=") || strings.HasPrefix(e, "HTTP_PROXY=") ||
			strings.HasPrefix(e, "https_proxy=") || strings.HasPrefix(e, "http_proxy=") {
			continue
		}
		if strings.HasPrefix(e, "NO_PROXY=") || strings.HasPrefix(e, "no_proxy=") {
			continue
		}
		if strings.HasPrefix(e, "PATH=") {
			continue
		}
		if strings.HasPrefix(e, "SSL_CERT_FILE=") || strings.HasPrefix(e, "REQUESTS_CA_BUNDLE=") ||
			strings.HasPrefix(e, "NODE_EXTRA_CA_CERTS=") || strings.HasPrefix(e, "CURL_CA_BUNDLE=") {
			continue
		}
		// When shims exist we redirect BASH_ENV to credproxy's own script (see
		// below); the inherited value, if any, is preserved separately.
		if shimDir != "" && strings.HasPrefix(e, "BASH_ENV=") {
			continue
		}
		// An inherited DB credential would defeat pooler isolation — the
		// whole point of [databases.*] is that the child never holds the
		// real secret.
		if strip[key] {
			continue
		}
		if _, ok := configEnv[key]; ok {
			continue
		}
		filtered = append(filtered, e)
	}
	for k, v := range configEnv {
		filtered = append(filtered, k+"="+v)
	}
	// Pooler URLs go last: os/exec keeps the last value for duplicate keys,
	// so they win over both inherited values and [env] config values.
	for k, v := range poolerEnv {
		filtered = append(filtered, k+"="+v)
	}
	filtered = append(filtered,
		"PATH="+childPath,
		"HTTPS_PROXY=http://localhost:"+proxyPort,
		"https_proxy=http://localhost:"+proxyPort,
		"NO_PROXY=localhost,127.0.0.1",
		"no_proxy=localhost,127.0.0.1",
		"SSL_CERT_FILE="+caCertPath,
		"REQUESTS_CA_BUNDLE="+caCertPath,
		"NODE_EXTRA_CA_CERTS="+caCertPath,
		"CURL_CA_BUNDLE="+caCertPath,
		"CREDPROXY_TOKEN=CREDPROXY_TOKEN",
	)
	if shimDir != "" {
		// Non-interactive bash sources BASH_ENV at startup. macOS path_helper
		// (run by /etc/profile in login shells) rebuilds PATH with its own dirs
		// first, demoting the shim dir behind /usr/local/bin where the real op
		// lives. Sourcing path.sh re-asserts the shim dir, so nested agent
		// shells (bash -c under a login parent) still resolve the shims.
		filtered = append(filtered, "BASH_ENV="+filepath.Join(shimDir, "path.sh"))
		if prevBashEnv != "" {
			filtered = append(filtered, "CREDPROXY_PREV_BASH_ENV="+prevBashEnv)
		}
	}
	return filtered
}

func stripSecretStoreCLIs(pathEnv string) (string, string, func()) {
	dirs := filepath.SplitList(pathEnv)
	blockedCLIs := []string{"op", "bw"}
	var shimDir string
	for _, dir := range dirs {
		needsShim := false
		for _, cli := range blockedCLIs {
			if _, err := os.Stat(filepath.Join(dir, cli)); err == nil {
				needsShim = true
				break
			}
		}
		if needsShim {
			if shimDir == "" {
				tmp, err := os.MkdirTemp("", "credproxy-shims-*")
				if err != nil {
					fmt.Fprintf(os.Stderr, "failed to create shim dir: %v\n", err)
					os.Exit(1)
				}
				shimDir = tmp
			}
			for _, cli := range blockedCLIs {
				shimPath := filepath.Join(shimDir, cli)
				if err := os.WriteFile(shimPath, []byte("#!/bin/sh\nexit 1\n"), 0755); err != nil {
					fmt.Fprintf(os.Stderr, "failed to write shim for %s: %v\n", cli, err)
					os.Exit(1)
				}
			}
		}
	}

	// path.sh is sourced via BASH_ENV by every non-interactive bash in the
	// child tree. PATH prepending alone is not enough on macOS: path_helper
	// (login shells) rebuilds PATH with system dirs first, leaving the shim
	// dir present but behind /usr/local/bin — which is exactly the state that
	// resolves the real op/bw. So the shim dir is unconditionally prepended
	// here ("already in PATH" is the wrong predicate; FIRST is what matters).
	// See the BASH_ENV handling in buildChildEnv.
	if shimDir != "" {
		pathShim := "# credproxy: put shim dir FIRST over path_helper's rebuilt PATH\n" +
			"PATH=\"" + shimDir + ":$PATH\"\n" +
			"export PATH\n" +
			"if [ -n \"$CREDPROXY_PREV_BASH_ENV\" ] && [ -f \"$CREDPROXY_PREV_BASH_ENV\" ]; then\n" +
			"  . \"$CREDPROXY_PREV_BASH_ENV\"\n" +
			"fi\n"
		if err := os.WriteFile(filepath.Join(shimDir, "path.sh"), []byte(pathShim), 0755); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write path.sh shim: %v\n", err)
			os.Exit(1)
		}
	}

	cleanup := func() {
		if shimDir != "" {
			os.RemoveAll(shimDir)
		}
	}

	if shimDir != "" {
		dirs = append([]string{shimDir}, dirs...)
	}

	return strings.Join(dirs, string(filepath.ListSeparator)), shimDir, cleanup
}
