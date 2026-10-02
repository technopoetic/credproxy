package mysql

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec — mysql_native_password is SHA-1 by protocol definition
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/technopoetic/credproxy/internal/config"
)

// Independently computed vectors (python3 hashlib, plan Review Focus):
// scramble = 0102030405060708090a0b0c0d0e0f1011121314, password = "REALPW"
var (
	fixedScramble = mustHex("0102030405060708090a0b0c0d0e0f1011121314")
	nativeVector  = mustHex("3bb62fe23c69faa7bbe9b118594fcc6061dfe5c7")
	fastVector    = mustHex("bf445376c4722b8c0ebd3e15b5569391760ceec6c426a74828dfade197f39096")
)

func mustHex(s string) []byte {
	b := make([]byte, len(s)/2)
	for i := 0; i < len(b); i++ {
		b[i] = hexVal(s[i*2])<<4 | hexVal(s[i*2+1])
	}
	return b
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		panic("bad hex")
	}
}

func writePacket(conn net.Conn, seq *byte, payload []byte) error {
	head := []byte{byte(len(payload)), byte(len(payload) >> 8), byte(len(payload) >> 16), *seq}
	*seq++
	_, err := conn.Write(append(head, payload...))
	return err
}

func readPacket(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var head [4]byte
	if _, err := ioReadFull(conn, head[:]); err != nil {
		t.Fatalf("read packet header: %v", err)
	}
	n := int(head[0]) | int(head[1])<<8 | int(head[2])<<16
	payload := make([]byte, n)
	if _, err := ioReadFull(conn, payload); err != nil {
		t.Fatalf("read packet body: %v", err)
	}
	return payload
}

func readPacketErr(conn net.Conn) ([]byte, error) {
	var head [4]byte
	if _, err := ioReadFull(conn, head[:]); err != nil {
		return nil, err
	}
	n := int(head[0]) | int(head[1])<<8 | int(head[2])<<16
	payload := make([]byte, n)
	if _, err := ioReadFull(conn, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func ioReadFull(conn net.Conn, buf []byte) (int, error) {
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

func buildHandshakeResponse(authResp []byte, plugin, db string) []byte {
	caps := uint32(capClientProtocol41 | capClientSecureConnection | capClientPluginAuth |
		capClientLongPassword | capClientTransactions | capClientPluginAuthLenenc)
	if db != "" {
		caps |= capClientConnectWithDB
	}
	var p []byte
	var c4 [4]byte
	binary.LittleEndian.PutUint32(c4[:], caps)
	p = append(p, c4[:]...)
	binary.LittleEndian.PutUint32(c4[:], 1<<24)
	p = append(p, c4[:]...)
	p = append(p, 45) // utf8mb4
	p = append(p, make([]byte, 23)...)
	p = append(p, "app_user\x00"...)
	switch {
	case len(authResp) < 251:
		p = append(p, byte(len(authResp)))
	default:
		p = append(p, 0xfc, byte(len(authResp)), byte(len(authResp)>>8))
	}
	p = append(p, authResp...)
	if db != "" {
		p = append(p, db...)
		p = append(p, 0)
	}
	p = append(p, plugin...)
	p = append(p, 0)
	return p
}

// buildInitialHandshake renders a server Initial Handshake V10 as a real
// MySQL server would.
func buildInitialHandshake(scramble []byte, plugin string, caps uint32) []byte {
	p := []byte{0x0a}
	p = append(p, "8.0.36\x00"...)
	p = append(p, 1, 2, 3, 4) // connection id
	p = append(p, scramble[:8]...)
	p = append(p, 0)
	p = append(p, byte(caps), byte(caps>>8))
	p = append(p, 45)   // charset
	p = append(p, 2, 0) // status
	p = append(p, byte(caps>>16), byte(caps>>24))
	p = append(p, 21)                  // auth-plugin-data len (12 bytes part-2 + NUL)
	p = append(p, make([]byte, 10)...) // reserved (all zeros)
	p = append(p, scramble[8:20]...)
	p = append(p, 0) // part-2 NUL terminator — the field is 13 bytes
	p = append(p, plugin...)
	p = append(p, 0)
	return p
}

func testDBConfig() config.DatabaseConfig {
	return config.DatabaseConfig{
		Engine: "mysql", Host: "127.0.0.1", Port: 3306,
		User: "app_user", Password: "REALPW", Database: "appdb",
	}
}

const serverCaps = capClientProtocol41 | capClientSecureConnection | capClientPluginAuth |
	capClientConnectWithDB | capClientLongPassword | capClientTransactions

// ---- token math (protocol vectors) ----

func TestNativeTokenVector(t *testing.T) {
	got := nativeToken("REALPW", fixedScramble)
	if !bytes.Equal(got, nativeVector) {
		t.Fatalf("native token mismatch:\n got %x\nwant %x", got, nativeVector)
	}
}

func TestFastTokenVector(t *testing.T) {
	got := fastToken("REALPW", fixedScramble)
	if !bytes.Equal(got, fastVector) {
		t.Fatalf("fast token mismatch:\n got %x\nwant %x", got, fastVector)
	}
}

// ---- FrontendAuth (relay as server toward the child) ----

func TestFrontendAuthNativeSuccess(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	errCh := make(chan error, 1)
	go func() {
		server.SetDeadline(time.Now().Add(5 * time.Second))
		errCh <- FrontendAuth(server, "sesspw")
	}()

	// Fake child: parse the server's scramble, answer native with the
	// session password.
	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	var head [4]byte
	if _, err := ioReadFull(client, head[:]); err != nil {
		t.Fatal(err)
	}
	n := int(head[0]) | int(head[1])<<8 | int(head[2])<<16
	hs := make([]byte, n)
	if _, err := ioReadFull(client, hs); err != nil {
		t.Fatal(err)
	}
	scramble := parseScrambleFromHandshake(t, hs)
	seq := byte(1)
	if err := writePacket(client, &seq, buildHandshakeResponse(nativeToken("sesspw", scramble), "mysql_native_password", "mydb")); err != nil {
		t.Fatal(err)
	}
	ok := readPacket(t, client)
	if ok[0] != 0x00 {
		t.Fatalf("expected OK, got %x", ok[0])
	}
	if err := <-errCh; err != nil {
		t.Fatalf("FrontendAuth: %v", err)
	}
}

func TestFrontendAuthWrongToken(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	errCh := make(chan error, 1)
	go func() {
		server.SetDeadline(time.Now().Add(5 * time.Second))
		errCh <- FrontendAuth(server, "sesspw")
	}()

	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	var head [4]byte
	ioReadFull(client, head[:])
	n := int(head[0]) | int(head[1])<<8 | int(head[2])<<16
	hs := make([]byte, n)
	ioReadFull(client, hs)
	scramble := parseScrambleFromHandshake(t, hs)
	seq := byte(1)
	_ = writePacket(client, &seq, buildHandshakeResponse(nativeToken("WRONG", scramble), "mysql_native_password", "mydb"))
	errPkt := readPacket(t, client)
	if errPkt[0] != 0xff {
		t.Fatalf("expected ERR, got %x", errPkt[0])
	}
	if code := int(errPkt[1]) | int(errPkt[2])<<8; code != 1045 {
		t.Fatalf("expected access-denied 1045, got %d", code)
	}
	if err := <-errCh; err == nil {
		t.Fatal("FrontendAuth must fail on wrong token")
	}
}

// TestFrontendAuthPymysqlOmitsDatabase pins compatibility with pymysql's
// handshake response: pymysql sets CLIENT_CONNECT_WITH_DB but omits the
// database field entirely — the packet runs user -> auth response -> plugin
// name with nothing in between (captured byte-for-byte in the repro behind
// docs/connection-test-2.md; mycli/pymysql failed with
// "auth plugin: unterminated cstring"). Real servers treat the missing
// optional field as absent; the relay must too.
func TestFrontendAuthPymysqlOmitsDatabase(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	errCh := make(chan error, 1)
	go func() {
		server.SetDeadline(time.Now().Add(5 * time.Second))
		errCh <- FrontendAuth(server, "sesspw")
	}()

	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	var head [4]byte
	if _, err := ioReadFull(client, head[:]); err != nil {
		t.Fatal(err)
	}
	n := int(head[0]) | int(head[1])<<8 | int(head[2])<<16
	hs := make([]byte, n)
	if _, err := ioReadFull(client, hs); err != nil {
		t.Fatal(err)
	}
	scramble := parseScrambleFromHandshake(t, hs)

	caps := uint32(capClientProtocol41 | capClientSecureConnection | capClientPluginAuth |
		capClientPluginAuthLenenc | capClientConnectWithDB)
	token := nativeToken("sesspw", scramble)
	body := make([]byte, 0, 64)
	body = append(body, byte(caps), byte(caps>>8), byte(caps>>16), byte(caps>>24))
	var max4 [4]byte
	binary.LittleEndian.PutUint32(max4[:], 1<<24)
	body = append(body, max4[:]...)
	body = append(body, 45) // charset utf8mb4
	body = append(body, make([]byte, 23)...)
	body = append(body, []byte("repro-user\x00")...)
	body = append(body, byte(len(token))) // auth response, lenenc single-byte form (<251)
	body = append(body, token...)
	// NOTE: no database field, despite CLIENT_CONNECT_WITH_DB — this is the
	// pymysql layout under test.
	body = append(body, []byte("mysql_native_password\x00")...)
	seq := byte(1)
	if err := writePacket(client, &seq, body); err != nil {
		t.Fatal(err)
	}
	ok := readPacket(t, client)
	if ok[0] != 0x00 {
		t.Fatalf("expected OK, got ERR packet %q", ok)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("FrontendAuth: %v", err)
	}
}

func TestFrontendAuthAuthSwitch(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	errCh := make(chan error, 1)
	go func() {
		server.SetDeadline(time.Now().Add(5 * time.Second))
		errCh <- FrontendAuth(server, "sesspw")
	}()

	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	var head [4]byte
	ioReadFull(client, head[:])
	n := int(head[0]) | int(head[1])<<8 | int(head[2])<<16
	hs := make([]byte, n)
	ioReadFull(client, hs)
	scramble := parseScrambleFromHandshake(t, hs)
	seq := byte(1)
	// Client insists on caching_sha2 — the relay must switch it to native.
	_ = writePacket(client, &seq, buildHandshakeResponse(make([]byte, 32), "caching_sha2_password", "mydb"))
	switchPkt := readPacket(t, client)
	if switchPkt[0] != 0xfe {
		t.Fatalf("expected AuthSwitchRequest, got %x", switchPkt[0])
	}
	if !bytes.Contains(switchPkt, []byte("mysql_native_password")) {
		t.Fatalf("switch must request mysql_native_password: %q", switchPkt)
	}
	_ = writePacket(client, &seq, nativeToken("sesspw", scramble))
	ok := readPacket(t, client)
	if ok[0] != 0x00 {
		t.Fatalf("expected OK after switch, got %x", ok[0])
	}
	if err := <-errCh; err != nil {
		t.Fatalf("FrontendAuth: %v", err)
	}
}

// parseScrambleFromHandshake extracts the 20-byte scramble from a server
// Initial Handshake (client side of the fake child).
func parseScrambleFromHandshake(t *testing.T, hs []byte) []byte {
	t.Helper()
	if hs[0] != 0x0a {
		t.Fatalf("protocol version %d", hs[0])
	}
	rest := hs[1:]
	i := bytes.IndexByte(rest, 0)
	if i < 0 {
		t.Fatal("no server version terminator")
	}
	rest = rest[i+1:]
	if len(rest) < 4+8+1+2+1+2+2+1 {
		t.Fatal("handshake too short")
	}
	scramble := append([]byte{}, rest[4:12]...)
	// connid(4) part1(8) filler(1) capsLo(2) charset(1) status(2) capsHi(2)
	authLen := int(rest[4+8+1+2+1+2+2])
	rest = rest[4+8+1+2+1+2+2+1:]
	// 10 reserved (all-zero) bytes sit between the auth-plugin-data length
	// and part-2.
	rest = rest[10:]
	// part-2 is authLen-8 bytes including its NUL terminator; the scramble
	// itself is the 12 bytes before that NUL.
	part2 := authLen - 8
	if part2 < 12 {
		part2 = 12
	}
	if len(rest) < part2 {
		t.Fatal("handshake missing scramble part 2")
	}
	return append(scramble, rest[:part2-1]...)
}

// ---- DialBackend (relay as client toward the real server) ----

func TestBackendNative(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cfg := testDBConfig()
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
		var seq byte
		if err := writePacket(conn, &seq, buildInitialHandshake(fixedScramble, "mysql_native_password", serverCaps)); err != nil {
			backendErr <- err
			return
		}
		resp, err := readPacketErr(conn)
		if err != nil {
			backendErr <- err
			return
		}
		// caps(4) max(4) charset(1) filler(23) user\0 lenenc token db\0 plugin\0
		if !bytes.Contains(resp, []byte("app_user\x00")) {
			backendErr <- errors.New("response missing username")
			return
		}
		// locate the lenenc token after the username
		ui := bytes.Index(resp, []byte("app_user\x00")) + len("app_user\x00")
		tokLen := int(resp[ui])
		tok := resp[ui+1 : ui+1+tokLen]
		if !bytes.Equal(tok, nativeVector) {
			backendErr <- errors.New("native token mismatch against independent vector")
			return
		}
		if !bytes.Contains(resp, []byte("appdb")) {
			backendErr <- errors.New("response missing database")
			return
		}
		if err := writePacket(conn, &seq, []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}); err != nil {
			backendErr <- err
			return
		}
		backendErr <- nil
	}()

	conn, dialErr := DialBackend(context.Background(), cfg)
	be := <-backendErr
	if dialErr != nil {
		t.Fatalf("DialBackend: %v; fake backend: %v", dialErr, be)
	}
	if be != nil {
		t.Fatalf("fake backend: %v", be)
	}
	conn.Close()
}

func TestBackendCachingSha2FastAuth(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cfg := testDBConfig()
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
		var seq byte
		_ = writePacket(conn, &seq, buildInitialHandshake(fixedScramble, "caching_sha2_password", serverCaps))
		resp, err := readPacketErr(conn)
		if err != nil {
			backendErr <- err
			return
		}
		ui := bytes.Index(resp, []byte("app_user\x00")) + len("app_user\x00")
		tokLen := int(resp[ui])
		tok := resp[ui+1 : ui+1+tokLen]
		if !bytes.Equal(tok, fastVector) {
			backendErr <- errors.New("fast token mismatch against independent vector")
			return
		}
		// fast auth success: AuthMoreData 0x01 0x03, then OK
		_ = writePacket(conn, &seq, []byte{0x01, 0x03})
		_ = writePacket(conn, &seq, []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00})
		backendErr <- nil
	}()

	conn, dialErr := DialBackend(context.Background(), cfg)
	be := <-backendErr
	if dialErr != nil {
		t.Fatalf("DialBackend: %v; fake backend: %v", dialErr, be)
	}
	if be != nil {
		t.Fatalf("fake backend: %v", be)
	}
	conn.Close()
}

func TestBackendCachingSha2FullAuthRSA(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cfg := testDBConfig()
	if p, ok := ln.Addr().(*net.TCPAddr); ok {
		cfg.Port = p.Port
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	backendErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		var seq byte
		_ = writePacket(conn, &seq, buildInitialHandshake(fixedScramble, "caching_sha2_password", serverCaps))
		_, err = readPacketErr(conn) // fast token response
		if err != nil {
			backendErr <- err
			return
		}
		// full auth required
		_ = writePacket(conn, &seq, []byte{0x01, 0x04})
		// the relay must request the public key (payload 0x02) before we
		// send it — real MySQL servers require this step
		if req, err := readPacketErr(conn); err != nil {
			backendErr <- err
			return
		} else if len(req) != 1 || req[0] != 0x02 {
			backendErr <- errors.New("expected public-key request packet 0x02")
			return
		}
		_ = writePacket(conn, &seq, pubPEM)
		// relay responds with RSA-OAEP-encrypted XOR(password∥NUL, scramble)
		ct, err := readPacketErr(conn)
		if err != nil {
			backendErr <- err
			return
		}
		plain, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, key, ct, nil)
		if err != nil {
			backendErr <- errors.New("ciphertext does not decrypt with our key: " + err.Error())
			return
		}
		want := xorPassword(append([]byte("REALPW"), 0), fixedScramble)
		if !bytes.Equal(plain, want) {
			backendErr <- errors.New("recovered plaintext mismatch")
			return
		}
		_ = writePacket(conn, &seq, []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00})
		backendErr <- nil
	}()

	conn, dialErr := DialBackend(context.Background(), cfg)
	be := <-backendErr
	if dialErr != nil {
		t.Fatalf("DialBackend: %v; fake backend: %v", dialErr, be)
	}
	if be != nil {
		t.Fatalf("fake backend: %v", be)
	}
	conn.Close()
}

func TestBackendServerSendsERR(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cfg := testDBConfig()
	if p, ok := ln.Addr().(*net.TCPAddr); ok {
		cfg.Port = p.Port
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var seq byte
		_ = writePacket(conn, &seq, buildInitialHandshake(fixedScramble, "mysql_native_password", serverCaps))
		_, _ = readPacketErr(conn)
		_ = writePacket(conn, &seq, []byte{0xff, 0x15, 0x04, '#', '2', '8', '0', '0', '0'})
	}()

	if _, err := DialBackend(context.Background(), cfg); err == nil {
		t.Fatal("expected error on backend ERR packet")
	}
}

// TestBackendCachingSha2FullAuthOverTLS pins the use_ssl=1 + caching_sha2
// full-auth path: the relay must send the masked password directly over the
// TLS channel (no public-key request — the server sends nothing until it
// gets the password, so reading one deadlocks both sides).
func TestBackendCachingSha2FullAuthOverTLS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cfg := testDBConfig()
	cfg.Params = "use_ssl=1"
	if p, ok := ln.Addr().(*net.TCPAddr); ok {
		cfg.Port = p.Port
	}
	cert := selfSignedTLSCert(t)
	backendErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		var seq byte
		_ = writePacket(conn, &seq, buildInitialHandshake(fixedScramble, "caching_sha2_password", serverCaps|capClientSSL))
		// relay's SSL request
		if _, err := readPacketErr(conn); err != nil {
			backendErr <- err
			return
		}
		tc := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err := tc.Handshake(); err != nil {
			backendErr <- err
			return
		}
		// handshake response inside TLS
		if _, err := readPacketErr(tc); err != nil {
			backendErr <- err
			return
		}
		// full auth demanded — over TLS the relay must send the cleartext
		// password NUL-terminated, WITHOUT requesting a public key
		// (requesting one deadlocks: the server sends nothing until it has
		// the password). XOR-masking is only for the RSA path; the server
		// hashes whatever bytes it receives, so masked bytes fail auth
		// with 1045.
		_ = writePacket(tc, &seq, []byte{0x01, 0x04})
		got, err := readPacketErr(tc)
		if err != nil {
			backendErr <- errors.New("no password received over TLS (deadlock): " + err.Error())
			return
		}
		want := append([]byte("REALPW"), 0)
		if !bytes.Equal(got, want) {
			backendErr <- fmt.Errorf("full-auth payload over TLS: got %x, want cleartext password+NUL", got)
			return
		}
		_ = writePacket(tc, &seq, []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00})
		backendErr <- nil
	}()

	conn, err := DialBackend(context.Background(), cfg)
	if err != nil {
		t.Fatalf("DialBackend: %v", err)
	}
	if be := <-backendErr; be != nil {
		t.Fatalf("fake backend: %v", be)
	}
	conn.Close()
}

func selfSignedTLSCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"}}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestBackendEmptyPacketDoesNotPanic pins bounds safety: a zero-length
// packet from a misbehaving backend must fail the connection, not crash
// credproxy with an index-out-of-range.
func TestBackendEmptyPacketDoesNotPanic(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cfg := testDBConfig()
	if p, ok := ln.Addr().(*net.TCPAddr); ok {
		cfg.Port = p.Port
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		var seq byte
		_ = writePacket(conn, &seq, buildInitialHandshake(fixedScramble, "mysql_native_password", serverCaps))
		_, _ = readPacketErr(conn)
		_ = writePacket(conn, &seq, []byte{}) // empty packet — must not panic
		time.Sleep(200 * time.Millisecond)
	}()

	if _, err := DialBackend(context.Background(), cfg); err == nil {
		t.Fatal("expected error on empty backend packet")
	}
}
