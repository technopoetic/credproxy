// Package pg implements credproxy's side of the Postgres wire protocol for
// the auth-split relay: it authenticates the local child with the session
// password, dials the real database with the real credential, and relays
// bytes. Post-auth traffic is never interpreted — the only protocol logic
// here is the connection handshake and auth negotiation.
package pg

import (
	"errors"
	"fmt"
	"net"
)

// ErrCancelRequest is returned by FrontendAuth when the incoming connection
// is a Postgres cancel request, not a startup. Cancel requests carry no
// authentication and cannot be routed 1:1; the caller closes the connection.
var ErrCancelRequest = errors.New("postgres cancel request")

// The protocol's special 8-byte startup probes (Postgres docs: 55.1,
// "special" codes). SSLRequest asks for TLS; GSSENCRequest for GSSAPI
// encryption — both are answered 'N' on the loopback leg and the client
// falls back to the next thing (SSLRequest, then plaintext startup), which
// is exactly the sequence psql performs.
const (
	sslRequestCode    = 80877103
	gssEncRequestCode = 80877104
	cancelRequestCode = 80877102
	protocolVersion3  = 196608
)

// maxMessageSize caps pre-auth message allocation. Real auth-phase messages
// are tiny; a forged header claiming gigabytes must be rejected, not
// allocated (a local unauthenticated process could otherwise OOM credproxy).
const maxMessageSize = 1 << 20

// readMessage reads one typed message: 1-byte type, int32 length (inclusive
// of itself, exclusive of the type byte), body. It returns the type, body,
// and the complete raw frame (for lossless forwarding).
func readMessage(conn net.Conn) (typ byte, body []byte, raw []byte, err error) {
	var head [5]byte
	if _, err = readFull(conn, head[:]); err != nil {
		return 0, nil, nil, err
	}
	n := int(head[1])<<24 | int(head[2])<<16 | int(head[3])<<8 | int(head[4])
	if n < 4 {
		return 0, nil, nil, fmt.Errorf("absurd message length %d", n)
	}
	if n > maxMessageSize {
		return 0, nil, nil, fmt.Errorf("message length %d exceeds %d", n, maxMessageSize)
	}
	body = make([]byte, n-4)
	if _, err = readFull(conn, body); err != nil {
		return 0, nil, nil, err
	}
	raw = make([]byte, 0, n+1)
	raw = append(raw, head[0])
	raw = append(raw, head[1:]...)
	raw = append(raw, body...)
	return head[0], body, raw, nil
}

func writeMessage(conn net.Conn, typ byte, body []byte) error {
	buf := make([]byte, 5, 5+len(body))
	buf[0] = typ
	n := len(body) + 4
	buf[1] = byte(n >> 24)
	buf[2] = byte(n >> 16)
	buf[3] = byte(n >> 8)
	buf[4] = byte(n)
	buf = append(buf, body...)
	_, err := conn.Write(buf)
	return err
}

// readStartup reads the pre-authentication startup exchange: SSLRequest
// probes (answered 'N' — the loopback leg does no TLS), cancel requests, and
// finally the protocol-3 StartupMessage. It returns the startup parameters
// (including user and database, which the caller ignores in favor of the
// configured entry).
func readStartup(conn net.Conn) (map[string]string, error) {
	for {
		var lenBuf [4]byte
		if _, err := readFull(conn, lenBuf[:]); err != nil {
			return nil, err
		}
		l := int(lenBuf[0])<<24 | int(lenBuf[1])<<16 | int(lenBuf[2])<<8 | int(lenBuf[3])
		if l == 8 {
			var codeBuf [4]byte
			if _, err := readFull(conn, codeBuf[:]); err != nil {
				return nil, err
			}
			code := int(codeBuf[0])<<24 | int(codeBuf[1])<<16 | int(codeBuf[2])<<8 | int(codeBuf[3])
			switch code {
			case sslRequestCode, gssEncRequestCode:
				if _, err := conn.Write([]byte{'N'}); err != nil {
					return nil, err
				}
				continue
			default:
				return nil, fmt.Errorf("unexpected 8-byte startup request code %d", code)
			}
		}
		if l < 12 || l > 65535 {
			return nil, fmt.Errorf("absurd startup length %d", l)
		}
		payload := make([]byte, l-4)
		if _, err := readFull(conn, payload); err != nil {
			return nil, err
		}
		if len(payload) < 8 {
			return nil, errors.New("short startup payload")
		}
		first := int(payload[0])<<24 | int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
		// CancelRequest is a length-16 message carrying the cancel code where
		// a startup message would carry the protocol version. It cannot be
		// routed (no auth, new connection), so it surfaces as a sentinel.
		if first == cancelRequestCode {
			return nil, ErrCancelRequest
		}
		if first != protocolVersion3 {
			return nil, fmt.Errorf("unsupported protocol version %d", first)
		}
		return parseKVPairs(payload[4:]), nil
	}
}

// parseKVPairs parses NUL-separated key/value pairs terminated by an empty
// key (the StartupMessage's trailing NUL).
func parseKVPairs(b []byte) map[string]string {
	params := make(map[string]string)
	for {
		end := indexOf(b, 0)
		if end < 0 {
			return params
		}
		key := string(b[:end])
		b = b[end+1:]
		if len(b) == 0 {
			return params
		}
		if key == "" {
			return params
		}
		vEnd := indexOf(b, 0)
		if vEnd < 0 {
			return params
		}
		params[key] = string(b[:vEnd])
		b = b[vEnd+1:]
	}
}

func indexOf(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// errorResponse builds an ErrorResponse message body in the wire format:
// fields are single-char codes followed by cstrings, terminated by an empty
// field.
func errorResponse(code, message string) []byte {
	var b []byte
	b = append(b, 'S', 'F', 'A', 'T', 'A', 'L', 0)
	b = append(b, 'V', 'F', 'A', 'T', 'A', 'L', 0)
	b = append(b, 'C')
	b = append(b, code...)
	b = append(b, 0)
	b = append(b, 'M')
	b = append(b, message...)
	b = append(b, 0)
	b = append(b, 0)
	return b
}
