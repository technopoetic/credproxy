package pg

import (
	"context"
	"crypto/md5" //nolint:gosec — MD5 is the legacy Postgres auth scheme, not a security choice
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/xdg-go/scram"

	"github.com/technopoetic/credproxy/internal/config"
	"github.com/technopoetic/credproxy/internal/dbproxy"
)

// ListenAndServe accepts connections on ln until the listener is closed,
// running the auth-split relay for each: authenticate the child with the
// session password, dial the real database with the real password, relay.
// Errors on individual connections are logged and never kill the loop; the
// only returned error is the Accept error that ends the session (listener
// closed by the manager).
func ListenAndServe(ln net.Listener, cfg config.DatabaseConfig, realPassword, sessionPassword string, logf func(format string, args ...any)) error {
	for {
		client, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer client.Close()
			client.SetDeadline(time.Now().Add(30 * time.Second))
			params, err := FrontendAuth(client, sessionPassword)
			if err != nil {
				if !isExpectedClose(err) {
					logf("pg relay: frontend auth: %v", err)
				}
				return
			}
			client.SetDeadline(time.Time{})
			backend, preamble, err := DialBackend(context.Background(), cfg, realPassword, params)
			if err != nil {
				logf("pg relay: backend dial: %v", err)
				_ = writeMessage(client, 'E', errorResponse("08006", err.Error()))
				return
			}
			defer backend.Close()
			if len(preamble) > 0 {
				if _, err := client.Write(preamble); err != nil {
					return
				}
			}
			dbproxy.Relay(client, backend)
		}()
	}
}

// FrontendAuth performs the relay-side startup handshake. On success the
// client has authenticated with the session password and expects the
// backend's post-auth stream next; nothing else has been consumed.
// extraParams are the client's startup parameters minus user/database, to be
// forwarded to the backend so driver-requested settings survive the relay.
func FrontendAuth(conn net.Conn, sessionPassword string) (extraParams map[string]string, err error) {
	params, err := readStartup(conn)
	if err != nil {
		return nil, err
	}
	if err := writeMessage(conn, 'R', []byte{0, 0, 0, 3}); err != nil { // AuthenticationCleartextPassword
		return nil, err
	}
	typ, body, _, err := readMessage(conn)
	if err != nil {
		return nil, err
	}
	if typ != 'p' {
		return nil, fmt.Errorf("expected PasswordMessage, got %c", typ)
	}
	got := body
	if n := len(got); n > 0 && got[n-1] == 0 {
		got = got[:n-1]
	}
	if subtle.ConstantTimeCompare(got, []byte(sessionPassword)) != 1 {
		if err := writeMessage(conn, 'E', errorResponse("28P01", "password authentication failed")); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("client sent invalid session password")
	}
	extra := make(map[string]string, len(params))
	for k, v := range params {
		if k == "user" || k == "database" {
			continue
		}
		extra[k] = v
	}
	return extra, nil
}

// DialBackend connects to the configured database, negotiates TLS per the
// sslmode param, authenticates with the real credential, and returns the
// connection plus the raw post-auth bytes (AuthenticationOk through
// ReadyForQuery) that must be forwarded to the client before relaying.
func DialBackend(ctx context.Context, cfg config.DatabaseConfig, realPassword string, extraParams map[string]string) (net.Conn, []byte, error) {
	sslmode := "prefer"
	for _, kv := range strings.Split(cfg.Params, ",") {
		parts := strings.SplitN(strings.TrimSpace(kv), "=", 2)
		if len(parts) == 2 && parts[0] == "sslmode" && parts[1] != "" {
			sslmode = parts[1]
		}
	}

	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, nil, err
	}

	tlsConn, err := negotiateTLS(conn, cfg.Host, sslmode)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	if tlsConn != nil {
		conn = tlsConn
	}

	if err := sendStartup(conn, cfg.User, cfg.Database, extraParams); err != nil {
		conn.Close()
		return nil, nil, err
	}

	backendErr := func(format string, args ...any) (net.Conn, []byte, error) {
		conn.Close()
		return nil, nil, fmt.Errorf(format, args...)
	}

	var preamble []byte
	for {
		typ, body, raw, err := readMessage(conn)
		if err != nil {
			return backendErr("backend read: %v", err)
		}
		switch typ {
		case 'R':
			if len(body) < 4 {
				return backendErr("short Authentication message")
			}
			code := binary.BigEndian.Uint32(body)
			switch code {
			case 0: // AuthenticationOk
				preamble = append(preamble, raw...)
			case 3: // cleartext password — real password may cross only on TLS
				if _, isTLS := conn.(*tls.Conn); !isTLS {
					return backendErr("server requested cleartext password without TLS; set sslmode=require (or higher)")
				}
				if err := sendPassword(conn, realPassword); err != nil {
					return backendErr("sending password: %v", err)
				}
			case 5: // md5
				if len(body) != 8 {
					return backendErr("short md5 challenge")
				}
				resp := md5Response(realPassword, cfg.User, body[4:])
				if err := sendPassword(conn, resp); err != nil {
					return backendErr("sending md5 response: %v", err)
				}
			case 10: // SASL
				if err := saslExchange(conn, cfg.User, realPassword, body[4:]); err != nil {
					return backendErr("sasl: %v", err)
				}
			case 11, 12: // SASL continue/final arrive inside saslExchange
				return backendErr("unexpected SASL message code %d", code)
			default:
				return backendErr("unsupported backend auth method %d", code)
			}
		case 'E':
			return backendErr("backend rejected connection: %s", errorBodyMessage(body))
		case 'Z': // ReadyForQuery — auth complete, everything consumed
			preamble = append(preamble, raw...)
			return conn, preamble, nil
		case 'N', 'S', 'K':
			preamble = append(preamble, raw...)
		default:
			preamble = append(preamble, raw...)
		}
	}
}

// negotiateTLS runs the SSLRequest dance. It returns a TLS-wrapped conn, or
// nil for plaintext. sslmode=prefer allows falling back to plaintext;
// require/verify-full do not.
func negotiateTLS(conn net.Conn, host, sslmode string) (net.Conn, error) {
	if sslmode == "disable" {
		return nil, nil
	}
	// SSLRequest is an 8-byte header-only message (no type byte).
	req := make([]byte, 8)
	binary.BigEndian.PutUint32(req[0:], 8)
	binary.BigEndian.PutUint32(req[4:], sslRequestCode)
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}
	var reply [1]byte
	if _, err := readFull(conn, reply[:]); err != nil {
		return nil, err
	}
	if reply[0] != 'S' {
		if sslmode == "prefer" {
			return nil, nil
		}
		return nil, fmt.Errorf("server does not support TLS (sslmode=%s)", sslmode)
	}
	tlsCfg := &tls.Config{ServerName: host}
	if sslmode == "require" || sslmode == "prefer" {
		// libpq semantics: require encrypts without verifying the chain.
		tlsCfg.InsecureSkipVerify = true //nolint:gosec — matches libpq sslmode=require
	}
	tc := tls.Client(conn, tlsCfg)
	if err := tc.Handshake(); err != nil {
		return nil, fmt.Errorf("tls handshake: %w", err)
	}
	return tc, nil
}

func sendStartup(conn net.Conn, user, database string, extraParams map[string]string) error {
	var kv []byte
	kv = append(kv, "user\x00"...)
	kv = append(kv, user...)
	kv = append(kv, 0)
	kv = append(kv, "database\x00"...)
	kv = append(kv, database...)
	kv = append(kv, 0)
	for k, v := range extraParams {
		// user/database come from config; a hostile client could have set
		// anything else, but startup keys are plain strings — forward as-is.
		kv = append(kv, k...)
		kv = append(kv, 0)
		kv = append(kv, v...)
		kv = append(kv, 0)
	}
	kv = append(kv, 0)
	body := make([]byte, 4, 4+len(kv))
	binary.BigEndian.PutUint32(body, protocolVersion3)
	body = append(body, kv...)
	n := len(body) + 4
	buf := make([]byte, 4, n)
	buf[0] = byte(n >> 24)
	buf[1] = byte(n >> 16)
	buf[2] = byte(n >> 8)
	buf[3] = byte(n)
	buf = append(buf, body...)
	_, err := conn.Write(buf)
	return err
}

func sendPassword(conn net.Conn, password string) error {
	return writeMessage(conn, 'p', append([]byte(password), 0))
}

// md5Response implements Postgres's md5 scheme:
// "md5" + hex(md5(hex(md5(password+user)) + salt)).
func md5Response(password, user string, salt []byte) string {
	inner := md5.Sum([]byte(password + user))
	innerHex := []byte(hex.EncodeToString(inner[:]))
	outer := md5.Sum(append(innerHex, salt...))
	return "md5" + hex.EncodeToString(outer[:])
}

// saslExchange performs the SCRAM-SHA-256 client exchange. The backend
// legitimately offers other SASL mechanisms only in exotic configurations;
// SCRAM-SHA-256 is what modern Postgres negotiates (pg_hba scram-sha-256).
func saslExchange(conn net.Conn, user, realPassword string, body []byte) error {
	mechs := strings.Split(strings.TrimRight(string(body), "\x00"), "\x00")
	hasScram := false
	for _, m := range mechs {
		if m == "SCRAM-SHA-256" {
			hasScram = true
		}
	}
	if !hasScram {
		return fmt.Errorf("server offered unsupported SASL mechanisms: %v", mechs)
	}

	client, err := scram.SHA256.NewClient(user, realPassword, "")
	if err != nil {
		return fmt.Errorf("scram client: %w", err)
	}
	conv := client.NewConversation()
	// Step("") produces the client-first message (gs2 header "n,," — no
	// channel binding; Postgres accepts it over non-TLS and TLS alike).
	clientFirst, err := conv.Step("")
	if err != nil {
		return err
	}
	saslInit := append([]byte("SCRAM-SHA-256\x00"), 0, 0, 0, 0)
	binary.BigEndian.PutUint32(saslInit[len(saslInit)-4:], uint32(len(clientFirst)))
	saslInit = append(saslInit, clientFirst...)
	if err := writeMessage(conn, 'p', saslInit); err != nil {
		return err
	}

	typ, sbody, _, err := readMessage(conn)
	if err != nil {
		return err
	}
	if typ != 'R' || len(sbody) < 4 || binary.BigEndian.Uint32(sbody) != 11 {
		return fmt.Errorf("expected AuthenticationSASLContinue, got %c", typ)
	}
	clientFinal, err := conv.Step(string(sbody[4:]))
	if err != nil {
		return fmt.Errorf("scram server-first rejected: %w", err)
	}
	if err := writeMessage(conn, 'p', []byte(clientFinal)); err != nil {
		return err
	}

	typ, sbody, _, err = readMessage(conn)
	if err != nil {
		return err
	}
	if typ != 'R' || len(sbody) < 4 || binary.BigEndian.Uint32(sbody) != 12 {
		return fmt.Errorf("expected AuthenticationSASLFinal, got %c", typ)
	}
	if _, err := conv.Step(string(sbody[4:])); err != nil {
		return fmt.Errorf("scram server-final rejected: %w", err)
	}
	return nil
}

// errorBodyMessage extracts the 'M' (message) field from an ErrorResponse
// body for surfacing in errors.
func errorBodyMessage(body []byte) string {
	for i := 0; i < len(body); {
		end := indexOf(body[i:], 0)
		if end < 0 {
			break
		}
		field := body[i : i+end]
		i += end + 1
		if len(field) >= 1 && field[0] == 'M' {
			return string(field[1:])
		}
	}
	return string(body)
}

// isExpectedClose reports whether an error is the routine end of a
// connection (client went away, cancel request) rather than a fault worth
// logging.
func isExpectedClose(err error) bool {
	if errors.Is(err, ErrCancelRequest) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true // timeouts/ECONNRESET on abandoned connections are routine
	}
	return strings.Contains(err.Error(), "closed")
}
