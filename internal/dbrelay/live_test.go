//go:build live

// Live verification against real servers. Guarded by the `live` build tag so
// normal `go test ./...` never touches the network:
//
//	go test -tags live -run TestLive ./internal/dbrelay/ -v
//
// Env vars: CREDPROXY_LIVE_PG_HOST/PORT/USER/PASSWORD/DATABASE and
// CREDPROXY_LIVE_MYSQL_HOST/PORT/USER/PASSWORD/DATABASE.
// See docs/live-testing-db-poolers.md for the full procedure.
package dbrelay

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	_ "github.com/go-sql-driver/mysql" // live MySQL client
	_ "github.com/lib/pq"              // live Postgres client

	"github.com/technopoetic/credproxy/internal/config"
)

func TestLivePostgres(t *testing.T) {
	cfg := &config.Config{
		Databases: map[string]config.DatabaseConfig{
			"mydb": {
				Engine:   "postgres",
				Host:     requireEnv(t, "CREDPROXY_LIVE_PG_HOST"),
				Port:     requireEnvInt(t, "CREDPROXY_LIVE_PG_PORT"),
				User:     requireEnv(t, "CREDPROXY_LIVE_PG_USER"),
				Password: requireEnv(t, "CREDPROXY_LIVE_PG_PASSWORD"),
				Database: requireEnv(t, "CREDPROXY_LIVE_PG_DATABASE"),
				Params:   "sslmode=prefer",
				Env:      "DATABASE_URL",
			},
		},
	}
	runLiveTest(t, cfg, "postgres", true)
}

func TestLiveMySQLNative(t *testing.T) {
	cfg := &config.Config{
		Databases: map[string]config.DatabaseConfig{
			"mdb": {
				Engine:   "mysql",
				Host:     requireEnv(t, "CREDPROXY_LIVE_MYSQL_HOST"),
				Port:     requireEnvInt(t, "CREDPROXY_LIVE_MYSQL_PORT"),
				User:     requireEnv(t, "CREDPROXY_LIVE_MYSQL_NATIVE_USER"),
				Password: requireEnv(t, "CREDPROXY_LIVE_MYSQL_PASSWORD"),
				Database: requireEnv(t, "CREDPROXY_LIVE_MYSQL_DATABASE"),
				Env:      "DATABASE_URL",
			},
		},
	}
	runLiveTest(t, cfg, "mysql", false)
}

func TestLiveMySQLCachingSha2(t *testing.T) {
	cfg := &config.Config{
		Databases: map[string]config.DatabaseConfig{
			"mdb": {
				Engine:   "mysql",
				Host:     requireEnv(t, "CREDPROXY_LIVE_MYSQL_HOST"),
				Port:     requireEnvInt(t, "CREDPROXY_LIVE_MYSQL_PORT"),
				User:     requireEnv(t, "CREDPROXY_LIVE_MYSQL_USER"),
				Password: requireEnv(t, "CREDPROXY_LIVE_MYSQL_PASSWORD"),
				Database: requireEnv(t, "CREDPROXY_LIVE_MYSQL_DATABASE"),
				Env:      "DATABASE_URL",
			},
		},
	}
	runLiveTest(t, cfg, "mysql", false)
}

// runLiveTest starts the manager against the real target, connects through
// the injected URL with the named driver, and asserts the isolation
// contract: loopback URL, real password absent, prepared statements work
// (postgres), and nothing written to disk.
func runLiveTest(t *testing.T, cfg *config.Config, driver string, prepared bool) {
	t.Helper()
	// Snapshot the temp dir before, so we can assert credproxy created
	// nothing in it (the old pooler design wrote real passwords to disk).
	tmpBefore, err := filepath.Glob(filepath.Join(os.TempDir(), "credproxy-*"))
	if err != nil {
		t.Fatal(err)
	}

	m := NewManager(cfg, testLogger())
	defer m.Stop()
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("manager start: %v", err)
	}

	dsn := m.Env["DATABASE_URL"]
	if !strings.Contains(dsn, "@127.0.0.1:") {
		t.Fatalf("URL must point at loopback: %s", dsn)
	}
	for _, db := range cfg.Databases {
		if db.Password != "" && strings.Contains(dsn, db.Password) {
			t.Fatal("real password leaked into injected URL")
		}
	}

	db, err := sql.Open(driver, liveDSN(driver, dsn))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		t.Fatalf("ping through relay: %v", err)
	}
	var one int
	if err := db.QueryRow("SELECT 1").Scan(&one); err != nil {
		t.Fatalf("query through relay: %v", err)
	}
	if one != 1 {
		t.Fatalf("expected 1, got %d", one)
	}
	if prepared {
		// Parameterized query — pins the extended query protocol passing
		// through the relay untouched (lib/pq uses prepared statements here).
		var two int
		if err := db.QueryRow("SELECT $1::int", 2).Scan(&two); err != nil {
			t.Fatalf("parameterized query through relay: %v", err)
		}
		if two != 2 {
			t.Fatalf("expected 2, got %d", two)
		}
	}

	tmpAfter, err := filepath.Glob(filepath.Join(os.TempDir(), "credproxy-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(tmpAfter) > len(tmpBefore) {
		t.Fatalf("relay wrote files to the temp dir: %v", tmpAfter[len(tmpBefore):])
	}
}

func requireEnv(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Skipf("%s not set; skipping live test", name)
	}
	return v
}

func requireEnvInt(t *testing.T, name string) int {
	t.Helper()
	v := requireEnv(t, name)
	n, err := strconv.Atoi(v)
	if err != nil {
		t.Fatalf("%s must be an integer: %v", name, err)
	}
	return n
}

// liveDSN converts the injected mysql:// URL into go-sql-driver's DSN
// format (the driver does not parse URLs; URL-consuming tools are the
// production target of MYSQL_URL).
func liveDSN(driver, dsn string) string {
	if driver != "mysql" {
		return dsn
	}
	rest := strings.TrimPrefix(dsn, "mysql://")
	at := strings.LastIndex(rest, "@")
	if at < 0 {
		return dsn
	}
	userpass := rest[:at]
	hostport := rest[at+1:]
	if slash := strings.Index(hostport, "/"); slash >= 0 {
		hostport = "(" + hostport[:slash] + ")" + hostport[slash:]
	}
	return userpass + "@tcp" + hostport
}
