package main

import (
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

// poolersim impersonates a pooler binary for integration tests: it drops a
// marker file, opens the listen_port found in the ini-style config argument,
// and removes the marker when SIGTERM arrives — so tests can assert whether
// credproxy actually stopped it. The marker is written before the port opens
// so a successful waitForListen guarantees the marker exists.
func main() {
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	marker := os.Getenv("POOLER_SIM_MARKER")
	if marker == "" {
		os.Exit(2)
	}
	if err := os.WriteFile(marker, []byte("running"), 0600); err != nil {
		os.Exit(2)
	}
	var port string
	if data, err := os.ReadFile(os.Args[1]); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "listen_port") {
				port = strings.TrimSpace(strings.SplitN(line, "=", 2)[1])
			}
		}
	}
	if port != "" {
		if _, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", port)); err == nil {
			// held open for the process lifetime
		} else {
			os.Exit(2)
		}
	} else {
		os.Exit(2)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM)
	<-sig
	os.Remove(marker)
}
