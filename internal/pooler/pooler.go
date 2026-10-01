package pooler

import (
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/url"
	"sort"
	"strconv"

	"github.com/technopoetic/credproxy/internal/config"
)

// sessionPassword returns a 32-byte random password, base64url-encoded. The
// alphabet needs no escaping in URLs, ini files, or SQL strings.
func sessionPassword() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// pickPort grabs a free loopback port and releases it. The bind-close-reuse
// race is accepted for local dev; ProxySQL has no port-0 support, so both
// engines use this.
func pickPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// buildURL constructs the injected connection string with net/url so special
// characters in user/password are percent-encoded exactly as drivers expect.
func buildURL(engine, user, password string, port int, alias string) string {
	scheme := engine // "postgres" and "mysql" are already the URL schemes
	u := url.URL{
		Scheme: scheme,
		User:   url.UserPassword(user, password),
		Host:   net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		Path:   "/" + alias,
	}
	return u.String()
}

func sortedNames(dbs map[string]config.DatabaseConfig) []string {
	names := make([]string, 0, len(dbs))
	for name := range dbs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
