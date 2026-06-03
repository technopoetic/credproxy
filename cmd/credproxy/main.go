package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/rhibbitts/credproxy/internal/ca"
	"github.com/rhibbitts/credproxy/internal/config"
	"github.com/rhibbitts/credproxy/internal/mitm"
	"github.com/rhibbitts/credproxy/internal/providers"
	"github.com/rhibbitts/credproxy/internal/resolver"
)

func main() {
	port := flag.Int("port", 8042, "proxy listen port")
	configPath := flag.String("config", config.DefaultConfigPath(), "path to credentials config")
	openProxy := flag.Bool("open-proxy", false, "allow all hosts (not recommended)")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load(*configPath)
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

	addr := fmt.Sprintf(":%d", *port)
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
	fmt.Printf("config: %s\n", *configPath)
	fmt.Printf("CA cert: %s\n", caPath)
	fmt.Println()
	fmt.Println("Trust the CA cert to use HTTPS proxying:")
	fmt.Println("  macOS:   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain " + caPath)
	fmt.Println("  Linux:   sudo cp " + caPath + " /usr/local/share/ca-certificates/credproxy.crt && sudo update-ca-certificates")
	fmt.Println()
	fmt.Println("Then set env vars before starting your agent:")
	fmt.Println("  export HTTPS_PROXY=http://localhost:" + fmt.Sprintf("%d", *port))
	fmt.Println("  export NO_PROXY=localhost,127.0.0.1")
	fmt.Println("  export ANTHROPIC_API_KEY=__anthropic_key__")
	fmt.Println()
	fmt.Println("press Ctrl-C to exit")

	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}
