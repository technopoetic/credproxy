// Package dbproxy provides the shared byte relay used by the per-engine
// database relays: after authentication completes on both legs, traffic is
// copied verbatim — the relay never interprets post-auth bytes.
package dbproxy

import (
	"io"
	"net"
	"time"
)

// Relay copies bytes between a and b in both directions until either side
// closes or errors; both connections are then closed (which unblocks the
// second copy). It returns when both directions have finished.
func Relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(a, b)
		a.SetDeadline(pastDeadline())
		done <- struct{}{}
	}()
	go func() {
		io.Copy(b, a)
		b.SetDeadline(pastDeadline())
		done <- struct{}{}
	}()
	<-done
	<-done
}

// pastDeadline is an already-elapsed deadline used to unblock the opposite
// io.Copy when one side finishes; Close alone is sufficient for most
// transports, but pipes and some conns only honor deadlines.
func pastDeadline() time.Time {
	return time.Unix(1, 0)
}
