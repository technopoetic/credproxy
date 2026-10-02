// Package mysql implements credproxy's side of the MySQL wire protocol for
// the auth-split relay: authenticate the local child with the session
// password, dial the real database with the real credential, relay bytes.
// Only the handshake and auth negotiation are parsed; post-auth traffic is a
// transparent byte stream.
package mysql

import (
	"crypto/rand"
	"net"
)

// Client capability flags (MySQL protocol 4.1+). Only the ones the relay
// actually negotiates are named.
const (
	capClientLongPassword     = 0x00000001
	capClientFoundRows        = 0x00000002
	capClientLongFlag         = 0x00000004
	capClientConnectWithDB    = 0x00000008
	capClientProtocol41       = 0x00000200
	capClientSSL              = 0x00000800
	capClientTransactions     = 0x00002000
	capClientSecureConnection = 0x00008000
	capClientPluginAuth       = 0x00080000
	capClientPluginAuthLenenc = 0x00200000
)

const (
	pluginNativePassword  = "mysql_native_password"
	pluginCachingSha2     = "caching_sha2_password"
	initialHandshakeProto = 0x0a
)

// packetReader reads MySQL protocol packets: 3-byte little-endian length +
// 1-byte sequence + payload. It records the peer's sequence number so
// writes can answer with r.seq + 1; no strict validation is done —
// AuthSwitchRequest flows and caching_sha2 round-trips produce legal
// sequences a strict counter would false-reject.
type packetReader struct {
	conn net.Conn
	seq  byte
}

func (r *packetReader) next() ([]byte, error) {
	var head [4]byte
	if _, err := readFull(r.conn, head[:]); err != nil {
		return nil, err
	}
	n := int(head[0]) | int(head[1])<<8 | int(head[2])<<16
	r.seq = head[3]
	payload := make([]byte, n)
	if _, err := readFull(r.conn, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// packetWriter writes packets with an incrementing sequence counter. For the
// relay-as-server the sequence answers the client's; for the relay-as-client
// it continues the server's.
type packetWriter struct {
	conn net.Conn
	seq  byte
}

func (w *packetWriter) write(payload []byte) error {
	head := []byte{byte(len(payload)), byte(len(payload) >> 8), byte(len(payload) >> 16), w.seq}
	w.seq++
	_, err := w.conn.Write(append(head, payload...))
	return err
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

// randomScramble returns 20 random bytes with no NUL (a NUL would terminate
// the cstring fields in the handshake packet).
func randomScramble() ([]byte, error) {
	s := make([]byte, 20)
	if _, err := rand.Read(s); err != nil {
		return nil, err
	}
	for i := range s {
		if s[i] == 0 {
			s[i] = 1
		}
	}
	return s, nil
}
