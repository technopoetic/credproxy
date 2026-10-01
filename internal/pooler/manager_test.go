package pooler

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fakeListenerMain is the body of the subprocess used by lifecycle tests:
// when invoked with "--fake-listen", it opens the requested ports and blocks.
// The subprocess re-exec pattern avoids netcat's BSD/GNU flag differences.
// Blocking happens on a signal receive, not `select {}` — an empty select
// with no other goroutines trips Go's deadlock detector and the child would
// exit 2 immediately.
func fakeListenerMain(ports []int) {
	listeners := make([]net.Listener, 0, len(ports))
	for _, p := range ports {
		l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		listeners = append(listeners, l)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM)
	<-sig
	os.Exit(0)
}

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "--fake-listen" {
		ports := make([]int, 0, len(os.Args)-2)
		for _, a := range os.Args[2:] {
			p, _ := strconv.Atoi(a)
			ports = append(ports, p)
		}
		fakeListenerMain(ports)
		return
	}
	os.Exit(m.Run())
}

func intStrings(xs []int) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = strconv.Itoa(x)
	}
	return out
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func startFakeListener(t *testing.T, ports []int) *proc {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, append([]string{"--fake-listen"}, intStrings(ports)...)...)
	p, err := startProc("fake", cmd, ports, ports[len(ports)-1], testLogger())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestWaitForListenSuccess(t *testing.T) {
	port1, err := pickPort()
	if err != nil {
		t.Fatal(err)
	}
	port2, err := pickPort()
	if err != nil {
		t.Fatal(err)
	}
	p := startFakeListener(t, []int{port1, port2})
	defer p.stop()
	if err := waitForListen(p, 5*time.Second); err != nil {
		t.Fatalf("expected listen: %v", err)
	}
}

func TestWaitForListenProcessExits(t *testing.T) {
	port, err := pickPort()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("false") // exits 1 immediately
	p, err := startProc("exiter", cmd, []int{port}, port, testLogger())
	if err != nil {
		t.Fatal(err) // start succeeds; the exit happens after
	}
	err = waitForListen(p, 5*time.Second)
	if err == nil {
		t.Fatal("expected error when process exits during startup")
	}
	if !strings.Contains(err.Error(), "exited during startup") {
		t.Fatalf("wrong error: %v", err)
	}
}

func TestWaitForListenTimeout(t *testing.T) {
	port, err := pickPort() // reserved above, nothing listening
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sleep", "30")
	p, err := startProc("silent", cmd, []int{port}, port, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer p.stop()
	start := time.Now()
	err = waitForListen(p, 300*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("timeout not respected")
	}
}

func TestStopKillsProcess(t *testing.T) {
	port, err := pickPort()
	if err != nil {
		t.Fatal(err)
	}
	p := startFakeListener(t, []int{port})
	if err := waitForListen(p, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	p.stop()
	select {
	case <-p.waitCh:
	case <-time.After(3 * time.Second):
		t.Fatal("process not reaped after stop")
	}
	p.mu.Lock()
	stopped := p.stopped
	p.mu.Unlock()
	if !stopped {
		t.Fatal("stop must set the stopped flag so unexpected-exit logging is suppressed")
	}
}
