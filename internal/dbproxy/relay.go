// Package dbproxy provides the shared byte relay used by the per-engine
// database relays: after authentication completes on both legs, traffic is
// copied verbatim — the relay never interprets post-auth bytes.
package dbproxy

import (
	"errors"
	"io"
	"net"
	"time"
)

// AuthRejection reports an upstream database rejecting the configured
// credential. Detail holds server context (error codes, host/user/IP that
// the server embedded in its denial) intended for credproxy's log only;
// callers must never forward it to the isolated child.
type AuthRejection struct {
	Detail string
}

func (e *AuthRejection) Error() string { return e.Detail }

// ChildFacingBackendError renders the message the isolated child may see
// for a backend failure: a coarse category with no server internals. The
// relay exists to hide the real host, port, credentials, and server error
// text from the child, so dial errors and server rejections — which embed
// exactly those details — must never cross the egress boundary verbatim.
// Full detail stays in credproxy.log.
func ChildFacingBackendError(err error) string {
	var ar *AuthRejection
	if errors.As(err, &ar) {
		return "upstream authentication failed"
	}
	return "upstream connection failed"
}

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
