package pg

import (
	"context"
	"crypto/hmac"
	"crypto/md5" //nolint:gosec — MD5 is the legacy Postgres auth scheme, not a security choice
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/xdg-go/scram"

	"github.com/technopoetic/credproxy/internal/config"
)

// ---- framing helpers ----

func pgWriteMsg(t *testing.T, conn net.Conn, typ byte, body []byte) {
	t.Helper()
	head := make([]byte, 5)
	head[0] = typ
	binary.BigEndian.PutUint32(head[1:], uint32(len(body)+4))
	if _, err := conn.Write(append(head, body...)); err != nil {
		t.Fatalf("write %c: %v", typ, err)
	}
}

// pgWriteMsgErr is the goroutine-safe variant: returns the error instead of
// calling t.Fatalf (t is not safe from other goroutines).
func pgWriteMsgErr(conn net.Conn, typ byte, body []byte) error {
	head := make([]byte, 5)
	head[0] = typ
	binary.BigEndian.PutUint32(head[1:], uint32(len(body)+4))
	_, err := conn.Write(append(head, body...))
	return err
}

func pgReadMsg(t *testing.T, conn net.Conn) (byte, []byte) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var head [5]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		t.Fatalf("read header: %v", err)
	}
	n := binary.BigEndian.Uint32(head[1:5])
	if n < 4 {
		t.Fatalf("absurd message length %d", n)
	}
	body := make([]byte, n-4)
	if _, err := io.ReadFull(conn, body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	return head[0], body
}

func pgSendStartup(t *testing.T, conn net.Conn, user, db string, extra map[string]string) {
	t.Helper()
	var kv []byte
	kv = append(kv, "user\x00"...)
	kv = append(kv, user...)
	kv = append(kv, 0)
	kv = append(kv, "database\x00"...)
	kv = append(kv, db...)
	kv = append(kv, 0)
	for k, v := range extra {
		kv = append(kv, k...)
		kv = append(kv, 0)
		kv = append(kv, v...)
		kv = append(kv, 0)
	}
	kv = append(kv, 0)
	body := make([]byte, 4, 4+len(kv))
	binary.BigEndian.PutUint32(body, 196608)
	body = append(body, kv...)
	total := make([]byte, 4, 4+len(body))
	binary.BigEndian.PutUint32(total, uint32(len(body)+4))
	if _, err := conn.Write(append(total, body...)); err != nil {
		t.Fatalf("write startup: %v", err)
	}
}

func pgSendSSLRequest(t *testing.T, conn net.Conn) {
	t.Helper()
	probe := make([]byte, 8)
	binary.BigEndian.PutUint32(probe[0:], 8)
	binary.BigEndian.PutUint32(probe[4:], 80877103)
	if _, err := conn.Write(probe); err != nil {
		t.Fatalf("write SSLRequest: %v", err)
	}
}

func hexMD5(b []byte) string {
	sum := md5.Sum(b)
	return hex.EncodeToString(sum[:])
}

func testDB(sslmode string) config.DatabaseConfig {
	return config.DatabaseConfig{
		Engine: "postgres", Host: "127.0.0.1", Port: 5432,
		User: "app_user", Password: "REALPW", Database: "appdb", Params: sslmode,
	}
}

// ---- FrontendAuth (relay as server toward the child) ----

func TestFrontendAuthSuccess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type result struct {
		params map[string]string
		err    error
	}
	done := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- result{err: err}
			return
		}
		params, err := FrontendAuth(conn, "sesspw")
		conn.Close()
		done <- result{params: params, err: err}
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(5 * time.Second))

	pgSendSSLRequest(t, client)
	one := make([]byte, 1)
	if _, err := io.ReadFull(client, one); err != nil {
		t.Fatalf("no SSLRequest reply: %v", err)
	}
	if one[0] != 'N' {
		t.Fatalf("SSLRequest reply = %c, want N", one[0])
	}

	pgSendStartup(t, client, "app_user", "mydb", map[string]string{"application_name": "agent"})
	typ, body := pgReadMsg(t, client)
	if typ != 'R' || binary.BigEndian.Uint32(body) != 3 {
		t.Fatalf("expected AuthenticationCleartextPassword, got %c %v", typ, body)
	}
	pgWriteMsg(t, client, 'p', append([]byte("sesspw"), 0))

	res := <-done
	if res.err != nil {
		t.Fatalf("FrontendAuth: %v", res.err)
	}
	if res.params["application_name"] != "agent" {
		t.Fatalf("extra params not surfaced: %v", res.params)
	}
}

func TestFrontendAuthWrongPassword(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	errCh := make(chan error, 1)
	go func() {
		server.SetDeadline(time.Now().Add(5 * time.Second))
		_, err := FrontendAuth(server, "sesspw")
		errCh <- err
	}()

	pgSendStartup(t, client, "app_user", "mydb", nil)
	typ, body := pgReadMsg(t, client)
	if typ != 'R' || binary.BigEndian.Uint32(body) != 3 {
		t.Fatalf("expected cleartext auth request, got %c", typ)
	}
	pgWriteMsg(t, client, 'p', append([]byte("WRONG"), 0))
	typ, body = pgReadMsg(t, client)
	if typ != 'E' {
		t.Fatalf("expected ErrorResponse, got %c", typ)
	}
	if !strings.Contains(string(body), "28P01") {
		t.Fatalf("expected invalid-password error code, got: %s", body)
	}
	if err := <-errCh; err == nil {
		t.Fatal("FrontendAuth must fail on wrong password")
	}
}

func TestFrontendAuthCancelRequest(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	errCh := make(chan error, 1)
	go func() {
		server.SetDeadline(time.Now().Add(5 * time.Second))
		_, err := FrontendAuth(server, "sesspw")
		errCh <- err
	}()
	// Real CancelRequest: length 16, code 80877102, pid, secret key.
	cancel := make([]byte, 16)
	binary.BigEndian.PutUint32(cancel[0:], 16)
	binary.BigEndian.PutUint32(cancel[4:], 80877102)
	binary.BigEndian.PutUint32(cancel[8:], 42)
	binary.BigEndian.PutUint32(cancel[12:], 99)
	if _, err := client.Write(cancel); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; !errors.Is(err, ErrCancelRequest) {
		t.Fatalf("expected ErrCancelRequest, got %v", err)
	}
}

// ---- DialBackend (relay as client toward the real server) ----

func TestDialBackendMD5AndPreamble(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cfg := testDB("prefer") // exercises the SSLRequest probe + plaintext fallback
	if p, ok := ln.Addr().(*net.TCPAddr); ok {
		cfg.Port = p.Port
	}
	backendErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		var head [8]byte
		if _, err := io.ReadFull(conn, head[:]); err != nil {
			backendErr <- err
			return
		}
		if _, err := conn.Write([]byte{'N'}); err != nil {
			backendErr <- err
			return
		}
		var slen [4]byte
		if _, err := io.ReadFull(conn, slen[:]); err != nil {
			backendErr <- err
			return
		}
		startup := make([]byte, binary.BigEndian.Uint32(slen[:])-4)
		if _, err := io.ReadFull(conn, startup); err != nil {
			backendErr <- err
			return
		}
		s := string(startup)
		if !strings.Contains(s, "user\x00app_user\x00") || !strings.Contains(s, "database\x00appdb\x00") {
			backendErr <- errors.New("startup missing user/database: " + s)
			return
		}
		salt := []byte{0x11, 0x22, 0x33, 0x44}
		if err := pgWriteMsgErr(conn, 'R', append([]byte{0, 0, 0, 5}, salt...)); err != nil {
			backendErr <- err
			return
		}
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		var phead [5]byte
		if _, err := io.ReadFull(conn, phead[:]); err != nil {
			backendErr <- err
			return
		}
		if phead[0] != 'p' {
			backendErr <- errors.New("expected PasswordMessage, got " + string(phead[0]))
			return
		}
		body := make([]byte, binary.BigEndian.Uint32(phead[1:])-4)
		io.ReadFull(conn, body)
		inner := hexMD5([]byte("REALPWapp_user"))
		outer := hexMD5(append([]byte(inner), salt...))
		want := append([]byte("md5"), []byte(outer)...)
		if string(body[:len(body)-1]) != string(want) {
			backendErr <- errors.New("md5 response mismatch")
			return
		}
		_ = pgWriteMsgErr(conn, 'R', []byte{0, 0, 0, 0})
		_ = pgWriteMsgErr(conn, 'K', make([]byte, 8))
		_ = pgWriteMsgErr(conn, 'Z', []byte{'I'})
		// signal success before waiting for the echo, or the test (waiting
		// on backendErr before writing) and this goroutine deadlock
		backendErr <- nil
		buf := make([]byte, 1)
		if n, err := conn.Read(buf); err == nil && n == 1 {
			_, _ = conn.Write(buf)
		}
	}()

	conn, preamble, err := DialBackend(context.Background(), cfg, "REALPW", nil)
	if err != nil {
		t.Fatalf("DialBackend: %v", err)
	}
	defer conn.Close()
	if len(preamble) == 0 {
		t.Fatal("expected post-auth preamble bytes")
	}
	if be := <-backendErr; be != nil {
		t.Fatalf("fake backend: %v", be)
	}
	conn.Write([]byte{'Q'})
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	one := make([]byte, 1)
	if _, err := io.ReadFull(conn, one); err != nil || one[0] != 'Q' {
		t.Fatalf("relay round-trip failed: %v %v", one, err)
	}
}

func TestDialBackendCleartextRefusedWithoutTLS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		var head [8]byte
		io.ReadFull(conn, head[:])
		conn.Write([]byte{'N'})
		var slen [4]byte
		io.ReadFull(conn, slen[:])
		startup := make([]byte, binary.BigEndian.Uint32(slen[:])-4)
		io.ReadFull(conn, startup)
		_ = pgWriteMsgErr(conn, 'R', []byte{0, 0, 0, 3}) // demand cleartext over non-TLS
		time.Sleep(100 * time.Millisecond)
	}()

	if _, _, err := DialBackend(context.Background(), testDB("prefer"), "REALPW", nil); err == nil {
		t.Fatal("cleartext password over non-TLS must be refused")
	}
}

// ---- SCRAM end-to-end: our client side vs a fake server driven by
// xdg-go/scram's server conversation — an independent implementation
// cross-checking ours. ----

// pbkdf2SHA256 is a minimal stdlib-only PBKDF2 (test-only; used to build the
// SCRAM stored credentials a real server would hold in pg_authid).
func pbkdf2SHA256(password, salt []byte, iters, keyLen int) []byte {
	h := func(data []byte) []byte {
		m := hmac.New(sha256.New, password)
		m.Write(data)
		return m.Sum(nil)
	}
	var out []byte
	for block := 1; len(out) < keyLen; block++ {
		var ib [4]byte
		binary.BigEndian.PutUint32(ib[:], uint32(block))
		u := h(append(append([]byte{}, salt...), ib[:]...))
		t := append([]byte{}, u...)
		for i := 1; i < iters; i++ {
			u = h(u)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

func TestDialBackendSCRAM(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cfg := testDB("prefer")
	if p, ok := ln.Addr().(*net.TCPAddr); ok {
		cfg.Port = p.Port
	}
	backendErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		var head [8]byte
		if _, err := io.ReadFull(conn, head[:]); err != nil {
			backendErr <- err
			return
		}
		conn.Write([]byte{'N'})
		var slen [4]byte
		io.ReadFull(conn, slen[:])
		startup := make([]byte, binary.BigEndian.Uint32(slen[:])-4)
		io.ReadFull(conn, startup)

		// Build the stored credentials a real server would hold.
		salt := []byte("0123456789abcdef")
		salted := pbkdf2SHA256([]byte("REALPW"), salt, 4096, 32)
		clientKey := hmacSHA256(salted, []byte("Client Key"))
		storedKey := sha256Sum(clientKey)
		serverKey := hmacSHA256(salted, []byte("Server Key"))
		srv, err := scram.SHA256.NewServer(func(user string) (scram.StoredCredentials, error) {
			return scram.StoredCredentials{
				KeyFactors: scram.KeyFactors{Salt: string(salt), Iters: 4096},
				StoredKey:  storedKey,
				ServerKey:  serverKey,
			}, nil
		})
		if err != nil {
			backendErr <- err
			return
		}
		conv := srv.NewConversation()

		// offer SCRAM-SHA-256
		if err := pgWriteMsgErr(conn, 'R', append([]byte{0, 0, 0, 10}, []byte("SCRAM-SHA-256\x00\x00")...)); err != nil {
			backendErr <- err
			return
		}
		typ, body := pgReadMsg(t, conn)
		if typ != 'p' {
			backendErr <- errors.New("expected SASLInitialResponse, got " + string(typ))
			return
		}
		parts := strings.SplitN(string(body), "\x00", 2)
		if parts[0] != "SCRAM-SHA-256" {
			backendErr <- errors.New("mechanism = " + parts[0])
			return
		}
		rest := []byte(parts[1])
		n := binary.BigEndian.Uint32(rest[0:4])
		clientFirst := string(rest[4 : 4+n])

		serverFirst, err := conv.Step(clientFirst)
		if err != nil {
			backendErr <- fmt.Errorf("server step1: %w", err)
			return
		}
		_ = pgWriteMsgErr(conn, 'R', append([]byte{0, 0, 0, 11}, []byte(serverFirst)...))

		typ, body = pgReadMsg(t, conn)
		if typ != 'p' {
			backendErr <- errors.New("expected SASLResponse, got " + string(typ))
			return
		}
		serverFinal, err := conv.Step(string(body))
		if err != nil {
			backendErr <- fmt.Errorf("server step2: %w", err)
			return
		}
		_ = pgWriteMsgErr(conn, 'R', append([]byte{0, 0, 0, 12}, []byte(serverFinal)...))
		_ = pgWriteMsgErr(conn, 'R', []byte{0, 0, 0, 0})
		_ = pgWriteMsgErr(conn, 'Z', []byte{'I'})
		backendErr <- nil
	}()

	conn, preamble, err := DialBackend(context.Background(), cfg, "REALPW", nil)
	if err != nil {
		t.Fatalf("DialBackend SCRAM: %v", err)
	}
	defer conn.Close()
	if be := <-backendErr; be != nil {
		t.Fatalf("fake backend: %v", be)
	}
	if !strings.Contains(string(preamble), string([]byte{'R', 0, 0, 0, 8, 0, 0, 0, 0})) &&
		len(preamble) == 0 {
		t.Fatal("expected preamble")
	}
}

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

// TestFrontendAuthHugeLengthRejected pins pre-auth bounds safety: a forged
// header claiming a ~2GB message must be rejected immediately, not
// allocated (a local unauthenticated process could otherwise OOM credproxy).
func TestFrontendAuthHugeLengthRejected(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	errCh := make(chan error, 1)
	go func() {
		server.SetDeadline(time.Now().Add(5 * time.Second))
		_, err := FrontendAuth(server, "sesspw")
		errCh <- err
	}()
	pgSendStartup(t, client, "app_user", "mydb", nil)
	// wait for the cleartext auth request, then forge a huge PasswordMessage
	typ, body := pgReadMsg(t, client)
	if typ != 'R' || binary.BigEndian.Uint32(body) != 3 {
		t.Fatalf("expected cleartext auth request, got %c", typ)
	}
	huge := make([]byte, 5)
	huge[0] = 'p'                               // PasswordMessage type
	binary.BigEndian.PutUint32(huge[1:], 2<<30) // ~2GB claimed length
	if _, err := client.Write(huge); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected error on absurd length")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("FrontendAuth still allocating/blocked on absurd length")
	}
}
