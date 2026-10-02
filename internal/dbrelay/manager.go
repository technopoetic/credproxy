// Package dbrelay owns the session's database relays: for each configured
// [databases.*] entry it listens on a loopback port, authenticates the child
// with a random per-session password, and relays to the real database with
// the real credential. No external processes, no temp files — the real
// password lives only in credproxy's memory for the life of the session.
package dbrelay

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/technopoetic/credproxy/internal/config"
	"github.com/technopoetic/credproxy/internal/dbproxy/mysql"
	"github.com/technopoetic/credproxy/internal/dbproxy/pg"
)

// Manager computes the child env vars and owns one listener per database
// entry for the duration of the session.
type Manager struct {
	cfg      *config.Config
	logger   *slog.Logger
	listens  map[string]net.Listener // entry name -> listener
	ports    map[string]int          // entry name -> port
	Env      map[string]string
	Strip    []string
	stopOnce sync.Once
}

func NewManager(cfg *config.Config, logger *slog.Logger) *Manager {
	return &Manager{cfg: cfg, logger: logger, listens: make(map[string]net.Listener), ports: make(map[string]int)}
}

// Start opens one relay listener per configured database entry. It is a
// no-op when none are configured. Backend connections are dialed lazily per
// child connection, so an unreachable database fails the child's queries
// visibly instead of failing session startup.
func (m *Manager) Start(ctx context.Context) error {
	if len(m.cfg.Databases) == 0 {
		return nil
	}

	m.Env = make(map[string]string, len(m.cfg.Databases))

	for _, name := range sortedNames(m.cfg.Databases) {
		db := m.cfg.Databases[name]
		// Per-relay password: a child that learns one relay's URL (and
		// port-scans loopback for the others) must not be able to
		// authenticate to a different relay.
		password, err := sessionPassword()
		if err != nil {
			m.Stop()
			return fmt.Errorf("generating session password for database %q: %w", name, err)
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			m.Stop()
			return fmt.Errorf("listening for database %q: %w", name, err)
		}
		m.listens[name] = ln
		if ta, ok := ln.Addr().(*net.TCPAddr); ok {
			m.ports[name] = ta.Port
		}
		switch db.Engine {
		case "postgres":
			go func(name string, db config.DatabaseConfig, password string) {
				if err := pg.ListenAndServe(ln, db, db.Password, password, m.logf); err != nil && !isListenerClosed(err) {
					m.logger.Warn("postgres relay stopped", "database", name, "err", err)
				}
			}(name, db, password)
		case "mysql":
			go func(name string, db config.DatabaseConfig, password string) {
				if err := mysql.ListenAndServe(ln, db, db.Password, password, m.logf); err != nil && !isListenerClosed(err) {
					m.logger.Warn("mysql relay stopped", "database", name, "err", err)
				}
			}(name, db, password)
		}
		m.computeEnv(db.Engine, name, db, password)
	}
	names := make([]string, 0, len(m.listens))
	for name := range m.listens {
		names = append(names, name)
	}
	m.logger.Info("database relays listening", "databases", strings.Join(names, ","))
	return nil
}

// computeEnv builds the entry's injected connection URL and records the
// inherited env vars that must be stripped: the entry's env name (a real
// DATABASE_URL in the parent shell would defeat isolation) plus the engine's
// standard CLI password variable.
func (m *Manager) computeEnv(engine, name string, db config.DatabaseConfig, password string) {
	m.Env[db.Env] = buildURL(engine, db.User, password, m.ports[name], db.Database)
	m.Strip = append(m.Strip, db.Env)
	if engine == "postgres" {
		m.Strip = append(m.Strip, "PGPASSWORD")
	} else {
		m.Strip = append(m.Strip, "MYSQL_PWD")
	}
}

// Stop closes every relay listener. Idempotent; safe with nothing running.
// Per-connection goroutines terminate when their connections close.
func (m *Manager) Stop() {
	m.stopOnce.Do(func() {
		for name, ln := range m.listens {
			if err := ln.Close(); err != nil {
				m.logger.Warn("failed to close relay listener", "database", name, "err", err)
			}
		}
		m.listens = nil
	})
}

// buildURL constructs the injected connection string with net/url so special
// characters in user/password are percent-encoded exactly as drivers expect.
// The path is the database the backend actually pins (db.Database), not the
// config alias — the child's URL must tell the truth about where it lands.
func buildURL(engine, user, password string, port int, database string) string {
	scheme := engine // "postgres" and "mysql" are already the URL schemes
	u := url.URL{
		Scheme: scheme,
		User:   url.UserPassword(user, password),
		Host:   net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		Path:   "/" + database,
	}
	if engine == "postgres" {
		// The relay listens on loopback only and TLS on that leg is a
		// non-goal; lib/pq defaults to sslmode=require and would refuse to
		// connect without this. Backend-leg TLS still applies via the
		// database entry's params — a different leg.
		q := u.Query()
		q.Set("sslmode", "disable")
		u.RawQuery = q.Encode()
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

func sessionPassword() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (m *Manager) logf(format string, args ...any) {
	m.logger.Warn(fmt.Sprintf(format, args...))
}

func isListenerClosed(err error) bool {
	return errors.Is(err, net.ErrClosed)
}
