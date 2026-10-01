package pooler

import (
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// proc is one running pooler process plus the ports it must open before the
// manager considers it ready.
type proc struct {
	name    string
	cmd     *exec.Cmd
	sqlPort int   // the port used in injected connection URLs
	ports   []int // every port that must accept connections
	waitCh  chan struct{}
	mu      sync.Mutex
	exitErr error
	stopped bool
}

// startProc starts the process and launches its watch goroutine. Both live
// here because the goroutine must exist before waitForListen runs, yet
// Wait() must not be called before Start() succeeds.
func startProc(name string, cmd *exec.Cmd, ports []int, sqlPort int, logger *slog.Logger) (*proc, error) {
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := &proc{name: name, cmd: cmd, ports: ports, sqlPort: sqlPort, waitCh: make(chan struct{})}
	go func() {
		err := cmd.Wait()
		p.mu.Lock()
		p.exitErr = err
		stopped := p.stopped
		p.mu.Unlock()
		close(p.waitCh)
		if !stopped {
			// A pooler that dies mid-session leaves the child's DB calls
			// failing visibly; surface it in the log like the MITM proxy dying.
			logger.Warn("pooler process exited unexpectedly; database connections through it will fail",
				"pooler", name, "err", err)
		}
	}()
	return p, nil
}

func (p *proc) exitError() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.exitErr
}

func (p *proc) stop() {
	p.mu.Lock()
	p.stopped = true
	p.mu.Unlock()
	if p.cmd.Process == nil {
		return
	}
	// Polite first: SIGTERM lets pgbouncer finish pooled sessions. Escalate
	// if the process ignores it.
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.waitCh:
	case <-time.After(3 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.waitCh
	}
}

// waitForListen polls every port until all accept TCP connections, the
// process exits (failure), or the timeout elapses (failure).
func waitForListen(p *proc, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		if err := p.exitError(); err != nil {
			return fmt.Errorf("%s exited during startup: %v", p.name, err)
		}
		allOpen := true
		for _, port := range p.ports {
			conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 250*time.Millisecond)
			if err != nil {
				allOpen = false
				lastErr = err
				break
			}
			conn.Close()
		}
		if allOpen {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s did not open ports %v within %s: %v", p.name, p.ports, timeout, lastErr)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// startupTimeout bounds how long a pooler binary has to open its listening
// ports after launch before start fails.
const startupTimeout = 15 * time.Second
