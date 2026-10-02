package dbrelay

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/technopoetic/credproxy/internal/config"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// urlPassword extracts the password component from a relay URL.
func urlPassword(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	pw, _ := u.User.Password()
	return pw
}

// TestManagerDistinctSessionPasswords pins per-relay credential isolation:
// each relay gets its own random session password, so a child that learns the
// staging relay URL cannot authenticate to the prod relay by port-scanning
// loopback. It also pins that the real configured password never appears in
// the child-visible URL.
func TestManagerDistinctSessionPasswords(t *testing.T) {
	cfg := &config.Config{
		Databases: map[string]config.DatabaseConfig{
			"a": {Engine: "mysql", Host: "127.0.0.1", Port: 59997, User: "u1", Password: "REAL1", Database: "dba", Env: "A_URL"},
			"b": {Engine: "mysql", Host: "127.0.0.1", Port: 59996, User: "u2", Password: "REAL2", Database: "dbb", Env: "B_URL"},
		},
	}
	m := NewManager(cfg, testLogger())
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	pwA := urlPassword(m.Env["A_URL"])
	pwB := urlPassword(m.Env["B_URL"])
	if pwA == "" || pwB == "" {
		t.Fatalf("empty session password(s): A=%q B=%q", pwA, pwB)
	}
	if pwA == pwB {
		t.Fatalf("relays share one session password (%q); per-relay isolation broken", pwA)
	}
	if pwA == "REAL1" || pwB == "REAL2" {
		t.Fatal("real backend password leaked into the child-visible URL")
	}
}


func TestManagerNoDatabasesIsNoop(t *testing.T) {
	m := NewManager(&config.Config{}, testLogger())
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m.Env != nil || len(m.Strip) != 0 {
		t.Fatalf("no-op manager must not set env/strip: env=%v strip=%v", m.Env, m.Strip)
	}
	m.Stop() // must be safe with nothing running
}

// TestManagerListenersServeAndClose pins the embedded lifecycle: Start opens
// a loopback listener per entry and computes the injected URLs; Stop closes
// the listeners so further dials are refused.
func TestManagerListenersServeAndClose(t *testing.T) {
	cfg := &config.Config{
		Databases: map[string]config.DatabaseConfig{
			// Alias and Database deliberately differ: the URL must advertise
			// the database the backend actually pins (Database), not the
			// config alias — a mismatch here makes the prod relay silently
			// land on staging (docs/connection_test.md observation 2).
			"mydb": {Engine: "postgres", Host: "127.0.0.1", Port: 59999, User: "app_user", Password: "REAL", Database: "pgdb", Env: "DATABASE_URL"},
			"mdb":  {Engine: "mysql", Host: "127.0.0.1", Port: 59998, User: "mu", Password: "REAL", Database: "mydb_real", Env: "MYSQL_URL"},
		},
	}
	m := NewManager(cfg, testLogger())
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(m.Env["DATABASE_URL"], "postgres://app_user:") ||
		!strings.Contains(m.Env["DATABASE_URL"], "@127.0.0.1:") ||
		!strings.Contains(m.Env["DATABASE_URL"], "/pgdb") ||
		strings.Contains(m.Env["DATABASE_URL"], "/mydb") ||
		!strings.Contains(m.Env["DATABASE_URL"], "sslmode=disable") {
		t.Fatalf("postgres URL wrong: %s", m.Env["DATABASE_URL"])
	}
	if !strings.HasPrefix(m.Env["MYSQL_URL"], "mysql://mu:") ||
		!strings.Contains(m.Env["MYSQL_URL"], "/mydb_real") ||
		strings.Contains(m.Env["MYSQL_URL"], "/mdb") {
		t.Fatalf("mysql URL wrong: %s", m.Env["MYSQL_URL"])
	}
	strip := strings.Join(m.Strip, ",")
	if !strings.Contains(strip, "DATABASE_URL") || !strings.Contains(strip, "PGPASSWORD") ||
		!strings.Contains(strip, "MYSQL_URL") || !strings.Contains(strip, "MYSQL_PWD") {
		t.Fatalf("strip list wrong: %v", m.Strip)
	}

	// Listeners accept connections (the relay handshake will fail against
	// the unreachable backends, but the TCP layer must be up).
	for _, envName := range []string{"DATABASE_URL", "MYSQL_URL"} {
		conn, err := net.DialTimeout("tcp", dialAddr(m.Env[envName]), time.Second)
		if err != nil {
			t.Fatalf("relay listener not reachable for %s: %v", envName, err)
		}
		conn.Close()
	}

	m.Stop()

	for _, envName := range []string{"DATABASE_URL", "MYSQL_URL"} {
		conn, err := net.DialTimeout("tcp", dialAddr(m.Env[envName]), time.Second)
		if err == nil {
			conn.Close()
			t.Fatalf("listener still accepting after Stop for %s", envName)
		}
	}
}

// dialAddr extracts host:port from a URL string without pulling net/url
// plumbing into every assertion.
func dialAddr(u string) string {
	// scheme://user:pass@host:port/db?...
	rest := u
	if i := strings.Index(rest, "//"); i >= 0 {
		rest = rest[i+2:]
	}
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		rest = rest[i+1:]
	}
	if i := strings.IndexAny(rest, "/?"); i >= 0 {
		rest = rest[:i]
	}
	return rest
}

func TestManagerStopIdempotent(t *testing.T) {
	cfg := &config.Config{
		Databases: map[string]config.DatabaseConfig{
			"mydb": {Engine: "postgres", Host: "127.0.0.1", Port: 5432, User: "u", Password: "p", Database: "d", Env: "DATABASE_URL"},
		},
	}
	m := NewManager(cfg, testLogger())
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	m.Stop()
	m.Stop() // must not panic or double-close
}
