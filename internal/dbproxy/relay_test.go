package dbproxy

import (
	"io"
	"net"
	"testing"
	"time"
)

// TestRelayBidirectional pins the core contract: after Relay(a, b) starts,
// bytes flow both ways, and the relay keeps both sides connected until one
// side closes — at which point both are closed.
func TestRelayBidirectional(t *testing.T) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	defer b2.Close()

	go Relay(a1, b1)

	// client (a2) writes toward backend (b2)
	go func() {
		a2.Write([]byte("ping"))
	}()
	buf := make([]byte, 4)
	b2.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(b2, buf); err != nil {
		t.Fatalf("backend did not receive client bytes: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("backend got %q", buf)
	}

	// backend writes toward client
	go func() {
		b2.Write([]byte("pong"))
	}()
	a2.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(a2, buf); err != nil {
		t.Fatalf("client did not receive backend bytes: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("client got %q", buf)
	}
}

func TestRelayClosesBothOnBackendClose(t *testing.T) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	defer a2.Close()
	defer b2.Close()

	go Relay(a1, b1)

	b2.Close() // backend side vanishes

	// The client side must observe closure (read returns error), not hang.
	a2.SetReadDeadline(time.Now().Add(2 * time.Second))
	one := make([]byte, 1)
	if _, err := a2.Read(one); err == nil {
		t.Fatal("client still readable after backend closed — relay did not propagate closure")
	}
}
