package mysql

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec — mysql_native_password is SHA-1 by protocol definition
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/technopoetic/credproxy/internal/config"
	"github.com/technopoetic/credproxy/internal/dbproxy"
)

// ListenAndServe accepts connections on ln until the listener is closed,
// running the auth-split relay per connection. Individual connection errors
// are logged and never kill the loop.
func ListenAndServe(ln net.Listener, cfg config.DatabaseConfig, realPassword, sessionPassword string, logf func(format string, args ...any)) error {
	for {
		client, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer client.Close()
			client.SetDeadline(time.Now().Add(30 * time.Second))
			if err := FrontendAuth(client, sessionPassword); err != nil {
				if !isExpectedClose(err) {
					logf("mysql relay: frontend auth: %v", err)
				}
				return
			}
			client.SetDeadline(time.Time{})
			backend, err := DialBackend(ctx(), cfg)
			if err != nil {
				logf("mysql relay: backend dial: %v", err)
				_ = writeErrorPacket(client, 1045, fmt.Sprintf("backend: %v", err))
				return
			}
			defer backend.Close()
			dbproxy.Relay(client, backend)
		}()
	}
}

func ctx() context.Context { return context.Background() }

// isExpectedClose reports whether an error is the routine end of a
// connection rather than a fault worth logging.
func isExpectedClose(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	return errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled)
}

// FrontendAuth serves the Initial Handshake to the child, offers
// mysql_native_password (implemented here in Go — server-side plugin support
// is irrelevant), verifies the session-password token, and sends OK. On
// success the child is fully authenticated and expects to speak protocol.
func FrontendAuth(conn net.Conn, sessionPassword string) error {
	scramble, err := randomScramble()
	if err != nil {
		return err
	}
	r := &packetReader{conn: conn}
	w := &packetWriter{conn: conn}

	// Initial Handshake V10
	hs := []byte{initialHandshakeProto}
	hs = append(hs, "8.0.36-credproxy-relay\x00"...)
	hs = append(hs, 1, 2, 3, 4) // connection id (cosmetic)
	hs = append(hs, scramble[:8]...)
	hs = append(hs, 0) // filler
	caps := uint32(capClientProtocol41 | capClientSecureConnection | capClientPluginAuth |
		capClientLongPassword | capClientTransactions)
	hs = append(hs, byte(caps), byte(caps>>8)) // caps low
	hs = append(hs, 45)                        // charset utf8mb4
	hs = append(hs, 2, 0)                      // status flags
	hs = append(hs, byte(caps>>16), byte(caps>>24))
	hs = append(hs, 21) // auth-plugin-data length (12 bytes part-2 + NUL)
	hs = append(hs, scramble[8:20]...)
	hs = append(hs, 0) // part-2 NUL terminator — the field is 13 bytes
	hs = append(hs, pluginNativePassword...)
	hs = append(hs, 0)
	if err := w.write(hs); err != nil {
		return err
	}

	payload, err := r.next()
	if err != nil {
		return err
	}
	if len(payload) < 32 {
		return fmt.Errorf("short handshake response (%d bytes)", len(payload))
	}
	clientCaps := binary.LittleEndian.Uint32(payload[0:4])
	if clientCaps&capClientProtocol41 == 0 {
		return fmt.Errorf("client without CLIENT_PROTOCOL_41 unsupported")
	}
	rest := payload[32:]
	user, rest, err := readCString(rest)
	if err != nil {
		return fmt.Errorf("username: %w", err)
	}
	_ = user // the session password is the credential; username is cosmetic
	authResp, rest, err := readAuthResponse(clientCaps, rest)
	if err != nil {
		return err
	}
	plugin := pluginNativePassword
	if clientCaps&capClientConnectWithDB != 0 {
		// database cstring sits between the auth response and the plugin
		// name; the relay ignores it (each listener serves one entry).
		if _, rest, err = readCString(rest); err != nil {
			return fmt.Errorf("database: %w", err)
		}
	}
	if clientCaps&capClientPluginAuth != 0 {
		plugin, _, err = readCString(rest)
		if err != nil {
			return fmt.Errorf("auth plugin: %w", err)
		}
	}
	if plugin != pluginNativePassword {
		// The client proposed a plugin we don't implement toward the child;
		// every MySQL client honors AuthSwitchRequest, so switch it to
		// native. (caching_sha2 frontend auth is unnecessary: the session
		// password is worthless off-box.)
		sw := append([]byte{0xfe}, []byte(pluginNativePassword)...)
		sw = append(sw, 0)
		sw = append(sw, scramble...)
		sw = append(sw, 0)
		if err := w.write(sw); err != nil {
			return err
		}
		if payload, err = r.next(); err != nil {
			return err
		}
		authResp = payload
	}
	expected := nativeToken(sessionPassword, scramble)
	if len(authResp) != len(expected) ||
		subtle.ConstantTimeCompare(authResp, expected) != 1 {
		_ = writeErrorPacket(conn, 1045, "Access denied: invalid session password")
		return fmt.Errorf("client sent invalid session password")
	}
	// OK packet: header + lenenc(0) affected rows + lenenc(0) insert id +
	// status flags + warnings.
	return w.write([]byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00})
}

func readCString(b []byte) (string, []byte, error) {
	i := bytes.IndexByte(b, 0)
	if i < 0 {
		return "", nil, errors.New("unterminated cstring")
	}
	return string(b[:i]), b[i+1:], nil
}

// readAuthResponse parses the handshake response's auth data per the
// client's capability flags.
func readAuthResponse(caps uint32, b []byte) ([]byte, []byte, error) {
	switch {
	case caps&capClientPluginAuthLenenc != 0:
		if len(b) < 1 {
			return nil, nil, errors.New("short lenenc auth response")
		}
		switch b[0] {
		case 0xfc:
			if len(b) < 3 {
				return nil, nil, errors.New("short lenenc 0xfc")
			}
			n := int(b[1]) | int(b[2])<<8
			if len(b) < 3+n {
				return nil, nil, errors.New("short lenenc payload")
			}
			return b[3 : 3+n], b[3+n:], nil
		default:
			n := int(b[0])
			if len(b) < 1+n {
				return nil, nil, errors.New("short lenenc payload")
			}
			return b[1 : 1+n], b[1+n:], nil
		}
	case caps&capClientSecureConnection != 0:
		if len(b) < 1 {
			return nil, nil, errors.New("short auth response length")
		}
		n := int(b[0])
		if len(b) < 1+n {
			return nil, nil, errors.New("short auth response payload")
		}
		return b[1 : 1+n], b[1+n:], nil
	default:
		i := bytes.IndexByte(b, 0)
		if i < 0 {
			return nil, nil, errors.New("unterminated auth response")
		}
		return b[:i], b[i+1:], nil
	}
}

// nativeToken implements mysql_native_password:
// SHA1(pw) XOR SHA1(scramble || SHA1(SHA1(pw))).
func nativeToken(password string, scramble []byte) []byte {
	s1 := sha1.Sum([]byte(password))
	s2 := sha1.Sum(s1[:])
	h := sha1.New()
	h.Write(scramble)
	h.Write(s2[:])
	s3 := h.Sum(nil)
	out := make([]byte, len(s1))
	for i := range s1 {
		out[i] = s1[i] ^ s3[i]
	}
	return out
}

// fastToken implements the caching_sha2_password fast-auth token:
// SHA256(pw) XOR SHA256(SHA256(SHA256(pw)) || scramble).
func fastToken(password string, scramble []byte) []byte {
	h1 := sha256.Sum256([]byte(password))
	h2 := sha256.Sum256(h1[:])
	h := sha256.New()
	h.Write(h2[:])
	h.Write(scramble)
	h3 := h.Sum(nil)
	out := make([]byte, len(h1))
	for i := range h1 {
		out[i] = h1[i] ^ h3[i]
	}
	return out
}

// xorPassword masks the (NUL-terminated) password with the scramble
// cyclically, for caching_sha2 full auth.
func xorPassword(pw []byte, scramble []byte) []byte {
	out := make([]byte, len(pw))
	for i := range pw {
		out[i] = pw[i] ^ scramble[i%len(scramble)]
	}
	return out
}

func writeErrorPacket(conn net.Conn, code uint16, message string) error {
	p := []byte{0xff, byte(code), byte(code >> 8), '#', 'H', 'Y', '0', '0', '0'}
	p = append(p, message...)
	w := &packetWriter{conn: conn, seq: 1}
	return w.write(p)
}
