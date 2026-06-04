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

	"github.com/technopoetic/credproxy/internal/ca"
	"github.com/technopoetic/credproxy/internal/config"
	"github.com/technopoetic/credproxy/internal/mitm"
	"github.com/technopoetic/credproxy/internal/providers"
	"github.com/technopoetic/credproxy/internal/resolver"
)

func main() {
	configPath := flag.String("config", config.DefaultConfigPath(), "path to global config")
	sentinel := flag.String("sentinel", "CREDPROXY_TOKEN", "sentinel string to substitute")
	openProxy := flag.Bool("open-proxy", false, "allow all hosts (not recommended)")
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "usage: credproxy <command> [args...]\n")
		os.Exit(1)
	}

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

	runWrap(cfg, caProvider, res, logger, args)
}

func loadMergedConfig(globalPath string) (*config.Config, error) {
	global, err := config.Load(globalPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		global = &config.Config{
			Hosts: make(map[string]config.HostConfig),
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

	childPath, cleanupShims := stripSecretStoreCLIs(os.Getenv("PATH"))
	defer cleanupShims()
	caCertPath := filepath.Join(config.DefaultCADir(), "ca.pem")
	childEnv := buildChildEnv(cfg, portStr, childPath, caCertPath)

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

	if err := child.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "exec failed: %v\n", err)
		os.Exit(1)
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
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "exec failed: %v\n", err)
		os.Exit(1)
	}
}

func buildChildEnv(cfg *config.Config, proxyPort string, childPath string, caCertPath string) []string {
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
		if strings.HasPrefix(e, "SSL_CERT_FILE=") || strings.HasPrefix(e, "REQUESTS_CA_BUNDLE=") ||
			strings.HasPrefix(e, "NODE_EXTRA_CA_CERTS=") || strings.HasPrefix(e, "CURL_CA_BUNDLE=") {
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
		"SSL_CERT_FILE="+caCertPath,
		"REQUESTS_CA_BUNDLE="+caCertPath,
		"NODE_EXTRA_CA_CERTS="+caCertPath,
		"CURL_CA_BUNDLE="+caCertPath,
		"CREDPROXY_TOKEN=CREDPROXY_TOKEN",
	)
	return filtered
}

func stripSecretStoreCLIs(pathEnv string) (string, func()) {
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

	cleanup := func() {
		if shimDir != "" {
			os.RemoveAll(shimDir)
		}
	}

	if shimDir != "" {
		dirs = append([]string{shimDir}, dirs...)
	}

	return strings.Join(dirs, string(filepath.ListSeparator)), cleanup
}
