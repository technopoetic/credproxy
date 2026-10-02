package mysql

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec — MySQL's RSA full-auth padding is OAEP-SHA1 by protocol definition
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/technopoetic/credproxy/internal/config"
)

// useSSLFromParams decides backend TLS from the entry's params. Validation
// has already constrained the vocabulary: use_ssl=0/1, or sslmode where
// disabled→no TLS and required/verify_*→TLS.
func useSSLFromParams(params string) bool {
	for _, kv := range strings.Split(params, ",") {
		parts := strings.SplitN(strings.TrimSpace(kv), "=", 2)
		if len(parts) != 2 {
			continue
		}
		switch strings.ToLower(parts[0]) {
		case "use_ssl":
			return parts[1] == "1"
		case "sslmode":
			return strings.ToLower(parts[1]) != "disabled"
		}
	}
	return false
}

// DialBackend connects to the configured MySQL server and authenticates with
// the real credential. The returned connection is positioned right after the
// handshake's OK packet, ready for raw relaying. The real password never
// crosses a non-TLS socket in plaintext: native and caching_sha2 fast-auth
// are nonce-bound tokens; caching_sha2 full auth is RSA-OAEP encrypted.
func DialBackend(ctx context.Context, cfg config.DatabaseConfig) (net.Conn, error) {
	useSSL := useSSLFromParams(cfg.Params)

	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	backendErr := func(format string, args ...any) (net.Conn, error) {
		conn.Close()
		return nil, fmt.Errorf(format, args...)
	}

	r := &packetReader{conn: conn}
	w := &packetWriter{conn: conn, seq: 0}

	hs, err := r.next()
	if err != nil {
		return backendErr("reading server handshake: %v", err)
	}
	if len(hs) < 1 || hs[0] != initialHandshakeProto {
		return backendErr("not an Initial Handshake packet")
	}
	serverCaps, scramble, plugin, err := parseServerHandshake(hs)
	if err != nil {
		return backendErr("%v", err)
	}
	// Sequence numbers alternate across both directions: our handshake
	// response answers the server's packet.
	w.seq = r.seq + 1

	isTLS := false
	if useSSL && serverCaps&capClientSSL != 0 {
		// SSL Request: short handshake response with CLIENT_SSL set.
		sslCaps := uint32(capClientProtocol41 | capClientSecureConnection | capClientSSL |
			capClientLongPassword | capClientTransactions | capClientPluginAuth)
		req := make([]byte, 32)
		binary.LittleEndian.PutUint32(req[0:], sslCaps)
		binary.LittleEndian.PutUint32(req[4:], 1<<24)
		req[8] = 45
		// bytes 9..31 are the zero filler
		w.seq = 1
		if err := w.write(req); err != nil {
			return backendErr("ssl request: %v", err)
		}
		tc := tls.Client(conn, &tls.Config{
			ServerName: cfg.Host,
			// use_ssl=1 matches go-sql-driver's tls=true semantics: encrypt
			// without chain verification (MySQL deployments commonly use
			// self-signed server certs). Verified-TLS needs a CA config — future work.
			InsecureSkipVerify: true, //nolint:gosec — documented use_ssl semantics
		})
		if err := tc.Handshake(); err != nil {
			return backendErr("backend tls handshake: %v", err)
		}
		r = &packetReader{conn: tc, seq: 2}
		w = &packetWriter{conn: tc, seq: 2}
		conn = tc
		isTLS = true
	}

	respCaps := uint32(capClientProtocol41 | capClientSecureConnection | capClientPluginAuth |
		capClientLongPassword | capClientTransactions | capClientPluginAuthLenenc)
	if cfg.Database != "" {
		respCaps |= capClientConnectWithDB
	}
	resp := make([]byte, 0, 128)
	var c4 [4]byte
	binary.LittleEndian.PutUint32(c4[:], respCaps)
	resp = append(resp, c4[:]...)
	binary.LittleEndian.PutUint32(c4[:], 1<<24)
	resp = append(resp, c4[:]...)
	resp = append(resp, 45)
	resp = append(resp, make([]byte, 23)...)
	resp = append(resp, cfg.User...)
	resp = append(resp, 0)
	// auth response is length-encoded (CLIENT_PLUGIN_AUTH_LENENC)
	token := tokenFor(plugin, cfg.Password, scramble)
	switch {
	case len(token) < 251:
		resp = append(resp, byte(len(token)))
	default:
		resp = append(resp, 0xfc, byte(len(token)), byte(len(token)>>8))
	}
	resp = append(resp, token...)
	if cfg.Database != "" {
		resp = append(resp, cfg.Database...)
		resp = append(resp, 0)
	}
	resp = append(resp, plugin...)
	resp = append(resp, 0)
	if err := w.write(resp); err != nil {
		return backendErr("handshake response: %v", err)
	}

	for {
		payload, err := r.next()
		if err != nil {
			return backendErr("backend read: %v", err)
		}
		w.seq = r.seq + 1 // MySQL sequences alternate across both directions
		if len(payload) == 0 {
			return backendErr("empty packet from backend")
		}
		switch payload[0] {
		case 0x00: // OK — handshake complete
			return conn, nil
		case 0xff: // ERR
			return backendErr("backend auth failed: %s", errPacketMessage(payload))
		case 0xfe: // AuthSwitchRequest
			if len(payload) < 2 {
				return backendErr("short auth switch")
			}
			newPlugin, rest, err := readCString(payload[1:])
			if err != nil {
				return backendErr("auth switch plugin: %v", err)
			}
			newScramble := rest
			if n := len(newScramble); n > 0 && newScramble[n-1] == 0 {
				newScramble = newScramble[:n-1]
			}
			if err := w.write(tokenFor(newPlugin, cfg.Password, newScramble)); err != nil {
				return backendErr("auth switch response: %v", err)
			}
		case 0x01: // AuthMoreData — caching_sha2 flow
			if len(payload) < 2 {
				return backendErr("short auth more-data")
			}
			switch payload[1] {
			case 0x03: // fast auth success; next packet is OK
				continue
			case 0x04: // full auth required
				var toSend []byte
				masked := xorPassword(append([]byte(cfg.Password), 0), scramble)
				if isTLS {
					// The password is protected by the TLS channel — send
					// it directly. The server sends nothing until it has
					// the password, so a public-key request here would
					// deadlock both sides.
					toSend = masked
				} else {
					// Insecure channel: request the server's RSA public
					// key (packet payload 0x02), then read the key packet.
					if err := w.write([]byte{0x02}); err != nil {
						return backendErr("requesting rsa key: %v", err)
					}
					pubPkt, err := r.next()
					if err != nil {
						return backendErr("reading server rsa key: %v", err)
					}
					w.seq = r.seq + 1 // answer the key packet with the ciphertext
					if len(pubPkt) > 1 && pubPkt[0] == 0x01 {
						// AuthMoreData prefix on the key packet
						pubPkt = pubPkt[1:]
					}
					block, _ := pem.Decode(pubPkt)
					if block == nil {
						return backendErr("server rsa key is not PEM")
					}
					pub, err := x509.ParsePKIXPublicKey(block.Bytes)
					if err != nil {
						return backendErr("parsing server rsa key: %v", err)
					}
					rsaPub, ok := pub.(*rsa.PublicKey)
					if !ok {
						return backendErr("server key is not RSA")
					}
					ct, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, rsaPub, masked, nil)
					if err != nil {
						return backendErr("rsa encryption: %v", err)
					}
					toSend = ct
				}
				if err := w.write(toSend); err != nil {
					return backendErr("sending full-auth response: %v", err)
				}
			default:
				return backendErr("unexpected caching_sha2 auth-more-data byte %#x", payload[1])
			}
		default:
			return backendErr("unexpected packet type %#x during auth", payload[0])
		}
	}
}

// parseServerHandshake extracts capability flags, the 20-byte scramble, and
// the auth plugin name from a server Initial Handshake V10.
func parseServerHandshake(hs []byte) (uint32, []byte, string, error) {
	if len(hs) < 1 || hs[0] != initialHandshakeProto {
		return 0, nil, "", fmt.Errorf("not an Initial Handshake")
	}
	rest := hs[1:]
	i := indexOfByte(rest, 0)
	if i < 0 {
		return 0, nil, "", errors.New("unterminated server version")
	}
	rest = rest[i+1:]
	// connection id (4) + part1 (8) + filler (1) + capsLo (2)
	if len(rest) < 4+8+1+2 {
		return 0, nil, "", errors.New("short server handshake")
	}
	scramble := append([]byte{}, rest[4:12]...)
	rest = rest[4+8+1:] // hs[21:]: capsLo(2) charset(1) status(2) capsHi(2) authLen(1) part2...
	if len(rest) < 7 {
		return 0, nil, "", errors.New("short server handshake header")
	}
	capsLo := uint16(rest[0]) | uint16(rest[1])<<8
	capsHi := uint32(rest[5])<<16 | uint32(rest[6])<<24
	caps := uint32(capsLo) | capsHi
	rest = rest[7:]

	var authLen int
	if caps&capClientPluginAuth != 0 {
		if len(rest) < 1 {
			return 0, nil, "", errors.New("missing auth-plugin-data length")
		}
		authLen = int(rest[0])
		rest = rest[1:]
	} else {
		if len(rest) < 1 {
			return 0, nil, "", errors.New("missing scramble terminator")
		}
		rest = rest[1:] // NUL terminator of part-1 when no PLUGIN_AUTH
	}
	// 10 reserved (all-zero) bytes sit between the auth-plugin-data length
	// and part-2 in the Initial Handshake.
	if len(rest) < 10 {
		return 0, nil, "", errors.New("short reserved field")
	}
	rest = rest[10:]
	plugin := pluginNativePassword
	var part2 []byte
	if caps&capClientSecureConnection != 0 {
		part2Len := 13
		if caps&capClientPluginAuth != 0 {
			if authLen < 13 {
				return 0, nil, "", errors.New("absurd auth-plugin-data length")
			}
			part2Len = authLen - 8
		} else {
			// terminator byte then 12 bytes
		}
		if len(rest) < part2Len {
			return 0, nil, "", errors.New("short scramble part 2")
		}
		part2 = rest[:part2Len]
		rest = rest[part2Len:]
	}
	if caps&capClientPluginAuth != 0 {
		p, _, err := readCString(rest)
		if err != nil {
			return 0, nil, "", err
		}
		plugin = p
	}
	if len(part2) > 12 {
		part2 = part2[:12]
	}
	scramble = append(scramble, part2...)
	if len(scramble) < 20 {
		return 0, nil, "", errors.New("scramble shorter than 20 bytes")
	}
	return caps, scramble[:20], plugin, nil
}

// tokenFor computes the auth token for the named plugin.
func tokenFor(plugin, password string, scramble []byte) []byte {
	switch plugin {
	case pluginCachingSha2:
		return fastToken(password, scramble)
	default:
		return nativeToken(password, scramble)
	}
}

func errPacketMessage(payload []byte) string {
	if len(payload) < 3 {
		return "short ERR packet"
	}
	code := uint16(payload[1]) | uint16(payload[2])<<8
	msg := payload[3:]
	if len(msg) > 0 && msg[0] == '#' && len(msg) >= 6 {
		msg = msg[6:]
	}
	return fmt.Sprintf("%d: %s", code, msg)
}

func indexOfByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}
