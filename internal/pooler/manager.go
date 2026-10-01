package pooler

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/technopoetic/credproxy/internal/config"
)

// proc is one running pooler process plus the ports it must open before the
// manager considers it ready.
type proc struct {
	name    string
	cmd     *exec.Cmd
	sqlPort int   // the port used in injected connection URLs
	ports   []int // every port that must accept connections
	waitCh  chan struct{}
	mu      sync.Mutex
	exitErr error
	stopped bool
}

// startProc starts the process and launches its watch goroutine. Both live
// here because the goroutine must exist before waitForListen runs, yet
// Wait() must not be called before Start() succeeds.
func startProc(name string, cmd *exec.Cmd, ports []int, sqlPort int, logger *slog.Logger) (*proc, error) {
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := &proc{name: name, cmd: cmd, ports: ports, sqlPort: sqlPort, waitCh: make(chan struct{})}
	go func() {
		err := cmd.Wait()
		p.mu.Lock()
		p.exitErr = err
		stopped := p.stopped
		p.mu.Unlock()
		close(p.waitCh)
		if !stopped {
			// A pooler that dies mid-session leaves the child's DB calls
			// failing visibly; surface it in the log like the MITM proxy dying.
			logger.Warn("pooler process exited unexpectedly; database connections through it will fail",
				"pooler", name, "err", err)
		}
	}()
	return p, nil
}

func (p *proc) exitError() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.exitErr
}

func (p *proc) stop() {
	p.mu.Lock()
	p.stopped = true
	p.mu.Unlock()
	if p.cmd.Process == nil {
		return
	}
	// Polite first: SIGTERM lets pgbouncer finish pooled sessions. Escalate
	// if the process ignores it.
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.waitCh:
	case <-time.After(3 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.waitCh
	}
}

// waitForListen polls every port until all accept TCP connections, the
// process exits (failure), or the timeout elapses (failure).
func waitForListen(p *proc, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		if err := p.exitError(); err != nil {
			return fmt.Errorf("%s exited during startup: %v", p.name, err)
		}
		allOpen := true
		for _, port := range p.ports {
			conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 250*time.Millisecond)
			if err != nil {
				allOpen = false
				lastErr = err
				break
			}
			conn.Close()
		}
		if allOpen {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s did not open ports %v within %s: %v", p.name, p.ports, timeout, lastErr)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// startupTimeout bounds how long a pooler binary has to open its listening
// ports after launch before start fails.
const startupTimeout = 15 * time.Second

// Manager owns the session poolers: config generation, process lifecycle,
// and the child env vars that point at them.
type Manager struct {
	cfg      *config.Config
	logger   *slog.Logger
	logFile  io.Writer
	dir      string
	procs    []*proc
	sqlPorts map[string]int // engine -> SQL listener port
	Env      map[string]string
	Strip    []string
	stopOnce sync.Once
}

func NewManager(cfg *config.Config, logger *slog.Logger, logFile io.Writer) *Manager {
	return &Manager{cfg: cfg, logger: logger, logFile: logFile, sqlPorts: make(map[string]int)}
}

// Start launches one pooler per engine that has configured databases. It is
// a no-op when none are configured. All binaries are discovered before any
// process starts, so a missing binary fails the session fast.
func (m *Manager) Start(ctx context.Context) error {
	byEngine := make(map[string]map[string]config.DatabaseConfig)
	for name, db := range m.cfg.Databases {
		if byEngine[db.Engine] == nil {
			byEngine[db.Engine] = make(map[string]config.DatabaseConfig)
		}
		byEngine[db.Engine][name] = db
	}
	if len(byEngine) == 0 {
		return nil
	}

	engines := make([]string, 0, len(byEngine))
	for e := range byEngine {
		engines = append(engines, e)
	}
	sort.Strings(engines)

	bins := make(map[string]string, len(engines))
	for _, engine := range engines {
		bin, err := lookPath(m.cfg, engine)
		if err != nil {
			return err
		}
		bins[engine] = bin
	}

	dir, err := os.MkdirTemp("", "credproxy-poolers-*")
	if err != nil {
		return fmt.Errorf("creating pooler temp dir: %w", err)
	}
	m.dir = dir
	if err := os.Chmod(dir, 0700); err != nil {
		m.Stop()
		return fmt.Errorf("restricting pooler temp dir: %w", err)
	}
	m.Env = make(map[string]string, len(m.cfg.Databases))

	password, err := sessionPassword()
	if err != nil {
		m.Stop()
		return fmt.Errorf("generating session password: %w", err)
	}

	for _, engine := range engines {
		var p *proc
		var err error
		switch engine {
		case "postgres":
			p, err = startPgbouncer(m.logger, m.logFile, bins[engine], dir, password, byEngine[engine])
		case "mysql":
			p, err = startProxySQL(ctx, m.logger, m.logFile, bins[engine], dir, password, byEngine[engine])
		}
		if err != nil {
			m.Stop()
			return fmt.Errorf("starting %s pooler: %w", engine, err)
		}
		m.procs = append(m.procs, p)
		m.sqlPorts[engine] = p.sqlPort
		m.computeEnv(engine, password, byEngine[engine])
	}
	m.logger.Info("database poolers started", "engines", strings.Join(engines, ","), "dir", dir)
	return nil
}

// computeEnv builds each entry's injected connection URL and records the
// inherited env vars that must be stripped: the entry's env name (a real
// DATABASE_URL in the parent shell would defeat isolation) plus the engine's
// standard CLI password variable.
func (m *Manager) computeEnv(engine, password string, dbs map[string]config.DatabaseConfig) {
	for name, db := range dbs {
		m.Env[db.Env] = buildURL(engine, db.User, password, m.sqlPorts[engine], name)
		m.Strip = append(m.Strip, db.Env)
	}
	if engine == "postgres" {
		m.Strip = append(m.Strip, "PGPASSWORD")
	} else {
		m.Strip = append(m.Strip, "MYSQL_PWD")
	}
}

// Stop terminates poolers and removes the temp dir. Idempotent; safe with
// nothing running.
func (m *Manager) Stop() {
	m.stopOnce.Do(func() {
		for _, p := range m.procs {
			p.stop()
		}
		m.procs = nil
		if m.dir != "" {
			if err := os.RemoveAll(m.dir); err != nil {
				m.logger.Warn("failed to remove pooler temp dir", "dir", m.dir, "err", err)
			}
			m.dir = ""
		}
	})
}

// lookPath resolves the pooler binary for an engine: config override first,
// then PATH. The error names the fix, because silently running without
// isolation is worse than not starting.
func lookPath(cfg *config.Config, engine string) (string, error) {
	override, bin := cfg.PgbouncerPath, "pgbouncer"
	if engine == "mysql" {
		override, bin = cfg.ProxySQLPath, "proxysql"
	}
	if override != "" {
		if _, err := os.Stat(override); err != nil {
			return "", fmt.Errorf("%s_path %q: %w", bin, override, err)
		}
		return override, nil
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		return "", fmt.Errorf("%s binary not found on PATH — install it or set %s_path in config: %w", bin, bin, err)
	}
	return path, nil
}
