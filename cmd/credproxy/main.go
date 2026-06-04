package main

import (
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

	"github.com/rhibbitts/credproxy/internal/ca"
	"github.com/rhibbitts/credproxy/internal/config"
	"github.com/rhibbitts/credproxy/internal/mitm"
	"github.com/rhibbitts/credproxy/internal/providers"
	"github.com/rhibbitts/credproxy/internal/resolver"
)

func main() {
	port := flag.Int("port", 0, "proxy listen port (0 = random in wrap mode, default 8042 in daemon mode)")
	configPath := flag.String("config", config.DefaultConfigPath(), "path to global config")
	sentinel := flag.String("sentinel", "CREDPROXY_TOKEN", "sentinel string to substitute")
	openProxy := flag.Bool("open-proxy", false, "allow all hosts (not recommended)")
	flag.Parse()

	args := flag.Args()

	logPath := filepath.Join(config.DefaultCADir(), "credproxy.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open log file %s: %v\n", logPath, err)
		os.Exit(1)
	}
	defer logFile.Close()

	logger := slog.New(slog.NewTextHandler(logFile, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := loadMergedConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	if *openProxy {
		cfg.AllowAll()
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

	if len(args) > 0 {
		runWrap(cfg, caProvider, res, logger, args)
	} else {
		daemonPort := *port
		if daemonPort == 0 {
			daemonPort = 8042
		}
		runDaemon(cfg, caProvider, res, logger, daemonPort)
	}
}

func loadMergedConfig(globalPath string) (*config.Config, error) {
	global, err := config.Load(globalPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		global = &config.Config{
			Hosts:       make(map[string]config.HostConfig),
			ProjectsDir: config.DefaultProjectsDir(),
		}
		global.SetDefaults()
	}

	stopAt := global.ProjectsDir
	if stopAt == "" {
		home, _ := os.UserHomeDir()
		stopAt = home
	}

	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}

	projectPath, err := config.WalkProjectConfig(cwd, stopAt)
	if err != nil {
		return nil, fmt.Errorf("walking for project config: %w", err)
	}

	if projectPath == "" {
		return global, nil
	}

	project, err := config.Load(projectPath)
	if err != nil {
		return nil, fmt.Errorf("loading project config %s: %w", projectPath, err)
	}

	return global.Merge(project), nil
}

func runWrap(cfg *config.Config, caProvider *ca.Provider, res *resolver.Resolver, logger *slog.Logger, command []string) {
	addr := ":0"
	srv := mitm.New(addr, caProvider, res, logger)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to start proxy: %v\n", err)
		os.Exit(1)
	}
	defer ln.Close()

	go srv.Serve(ln)

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())

	childPath := stripSecretStoreCLIs(os.Getenv("PATH"))
	childEnv := buildChildEnv(cfg, portStr, childPath)

	childBin, err := exec.LookPath(command[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "command not found: %s\n", command[0])
		os.Exit(1)
	}

	child := exec.Command(childBin, command[1:]...)
	child.Env = childEnv
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		for range sig {
			child.Process.Signal(syscall.SIGINT)
		}
	}()

	if err := child.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "exec failed: %v\n", err)
		os.Exit(1)
	}
}

func runDaemon(cfg *config.Config, caProvider *ca.Provider, res *resolver.Resolver, logger *slog.Logger, port int) {
	addr := fmt.Sprintf(":%d", port)
	srv := mitm.New(addr, caProvider, res, logger)

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		fmt.Println("\nshutting down")
		os.Exit(0)
	}()

	caPath := config.DefaultCADir() + "/ca.pem"
	fmt.Printf("credproxy listening on %s\n", addr)
	fmt.Printf("CA cert: %s\n", caPath)
	fmt.Println()
	fmt.Println("Trust the CA cert to use HTTPS proxying:")
	fmt.Println("  macOS:   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain " + caPath)
	fmt.Println("  Linux:   sudo cp " + caPath + " /usr/local/share/ca-certificates/credproxy.crt && sudo update-ca-certificates")
	fmt.Println()
	fmt.Println("Wrap mode (recommended):")
	fmt.Println("  credproxy opencode")
	fmt.Println("  credproxy -- claude-code")
	fmt.Println()
	fmt.Println("Agent instructions — add to AGENTS.md:")
	fmt.Println("  When making authenticated API calls, use CREDPROXY_TOKEN as the credential value.")
	fmt.Println()
	fmt.Println("press Ctrl-C to exit")

	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

func buildChildEnv(cfg *config.Config, proxyPort string, childPath string) []string {
	env := os.Environ()
	filtered := make([]string, 0, len(env))
	for _, e := range env {
		if strings.HasPrefix(e, "OP_SERVICE_ACCOUNT_TOKEN=") {
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
		filtered = append(filtered, e)
	}
	filtered = append(filtered,
		"PATH="+childPath,
		"HTTPS_PROXY=http://localhost:"+proxyPort,
		"https_proxy=http://localhost:"+proxyPort,
		"NO_PROXY=localhost,127.0.0.1",
		"no_proxy=localhost,127.0.0.1",
	)
	return filtered
}

func stripSecretStoreCLIs(pathEnv string) string {
	dirs := filepath.SplitList(pathEnv)
	strippedCLIs := []string{"op", "bw"}
	filtered := make([]string, 0, len(dirs))
	for _, dir := range dirs {
		skip := false
		for _, cli := range strippedCLIs {
			if _, err := os.Stat(filepath.Join(dir, cli)); err == nil {
				skip = true
				break
			}
		}
		if !skip {
			filtered = append(filtered, dir)
		}
	}
	return strings.Join(filtered, string(filepath.ListSeparator))
}
