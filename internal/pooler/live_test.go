//go:build live

// Live verification against real servers. Guarded by the `live` build tag so
// normal `go test ./...` never touches the network or needs pooler binaries:
//
//	go test -tags live -run TestLive ./internal/pooler/ -v
//
// Env vars: CREDPROXY_LIVE_PG_HOST/PORT/USER/PASSWORD/DATABASE and
// CREDPROXY_LIVE_MYSQL_HOST/PORT/USER/PASSWORD/DATABASE, plus optional
// PGBOUNCER_PATH / PROXYSQL_PATH binary overrides. See
// docs/live-testing-db-poolers.md for the full procedure.
package pooler

import (
	"context"
	"database/sql"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"

	_ "github.com/lib/pq" // live Postgres client

	"github.com/technopoetic/credproxy/internal/config"
)

func TestLivePostgres(t *testing.T) {
	cfg := &config.Config{
		PgbouncerPath: os.Getenv("PGBOUNCER_PATH"),
		Databases: map[string]config.DatabaseConfig{
			"mydb": {
				Engine: "postgres",
				Host:   requireEnv(t, "CREDPROXY_LIVE_PG_HOST"),
				Port:   requireEnvInt(t, "CREDPROXY_LIVE_PG_PORT"),
				User:   requireEnv(t, "CREDPROXY_LIVE_PG_USER"),
				// The manager must resolve op:// before Start; live tests pass
				// literals and call Start directly.
				Password: requireEnv(t, "CREDPROXY_LIVE_PG_PASSWORD"),
				Database: requireEnv(t, "CREDPROXY_LIVE_PG_DATABASE"),
				Env:      "DATABASE_URL",
			},
		},
	}
	runLiveTest(t, cfg, "postgres")
}

func TestLiveMySQL(t *testing.T) {
	cfg := &config.Config{
		ProxySQLPath: os.Getenv("PROXYSQL_PATH"),
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
	runLiveTest(t, cfg, "mysql")
}

func runLiveTest(t *testing.T, cfg *config.Config, driver string) {
	t.Helper()
	m := NewManager(cfg, testLogger(), io.Discard)
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
	db, err := sql.Open(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var one int
	if err := db.QueryRow("SELECT 1").Scan(&one); err != nil {
		t.Fatalf("query through pooler: %v", err)
	}
	if one != 1 {
		t.Fatalf("expected 1, got %d", one)
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
