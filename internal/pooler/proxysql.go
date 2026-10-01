package pooler

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql" // registers the "mysql" driver for admin provisioning

	"github.com/technopoetic/credproxy/internal/config"
)

// proxysqlConfig renders the static cnf: interfaces, variables, and backend
// servers. It deliberately contains NO passwords — users (with the real
// password) are provisioned through the admin interface at startup, so the
// on-disk file never holds secrets.
//
// The file is libconfig grammar (see the image's default cnf): datadir is
// quoted, and the admin binding is mysql_ifaces. Both differ from plain ini
// assumptions and were verified by spike against ProxySQL 3.0.11
// (docs/plans/2026-10-01-db-pooler-spike-findings.md).
func proxysqlConfig(dir string, adminPort, sqlPort int, adminPassword string, dbs map[string]config.DatabaseConfig) string {
	var b strings.Builder
	fmt.Fprintf(&b, "datadir=%q\n", dir)
	fmt.Fprintf(&b, "errorlog=%q\n", dir+"/proxysql-error.log")
	fmt.Fprintf(&b, "\nadmin_variables=\n{\n\tadmin_credentials=\"admin:%s\"\n\tmysql_ifaces=\"127.0.0.1:%d\"\n}\n", adminPassword, adminPort)
	fmt.Fprintf(&b, "\nmysql_variables=\n{\n\tthreads=2\n\tmax_connections=64\n\tinterfaces=\"127.0.0.1:%d\"\n\tdefault_query_delay=0\n\tdefault_query_timeout=36000000\n}\n", sqlPort)
	b.WriteString("\nmysql_servers =\n(\n")
	for i, name := range sortedNames(dbs) {
		db := dbs[name]
		fmt.Fprintf(&b, "\t{ address=%q , port=%d , hostgroup=%d , max_connections=20 }\n", db.Host, db.Port, i)
	}
	b.WriteString(")\n")
	return b.String()
}

// proxysqlUserSQL builds the admin-interface statements. Per spike findings,
// the frontend/backend split is TWO mysql_users rows per entry sharing the
// username: the frontend row authenticates clients with the session
// password, the backend row connects to the real server with the real
// credential. The attributes.frontend_password overlay is NOT honored for
// frontend auth on ProxySQL 3.0.11 and must not be used. Hostgroups follow
// sorted entry order, matching proxysqlConfig. The first entry's real
// credential doubles as the monitor credential so health checks pass.
func proxysqlUserSQL(names []string, dbs map[string]config.DatabaseConfig, password string) []string {
	var out []string
	for i, name := range names {
		db := dbs[name]
		useSSL := proxysqlUseSSL(db.Params)
		// Frontend row: session password, no backend rights.
		out = append(out, fmt.Sprintf(
			"INSERT INTO mysql_users (username, password, active, use_ssl, default_hostgroup, frontend, backend) VALUES ('%s', '%s', 1, %d, %d, 1, 0)",
			sqlEscape(db.User), sqlEscape(password), useSSL, i))
		// Backend row: real credential, no frontend rights.
		out = append(out, fmt.Sprintf(
			"INSERT INTO mysql_users (username, password, active, use_ssl, default_hostgroup, frontend, backend) VALUES ('%s', '%s', 1, %d, %d, 0, 1)",
			sqlEscape(db.User), sqlEscape(db.Password), useSSL, i))
	}
	out = append(out, "LOAD MYSQL USERS TO RUNTIME")
	if len(names) > 0 {
		first := dbs[names[0]]
		out = append(out,
			fmt.Sprintf("UPDATE global_variables SET variable_value='%s' WHERE variable_name='mysql-monitor_username'", sqlEscape(first.User)),
			fmt.Sprintf("UPDATE global_variables SET variable_value='%s' WHERE variable_name='mysql-monitor_password'", sqlEscape(first.Password)),
			"LOAD MYSQL VARIABLES TO RUNTIME")
	}
	return out
}

func proxysqlUseSSL(params string) int {
	for _, kv := range strings.Split(params, ",") {
		parts := strings.SplitN(strings.TrimSpace(kv), "=", 2)
		if len(parts) == 2 && parts[0] == "use_ssl" && parts[1] == "1" {
			return 1
		}
	}
	return 0
}

func sqlEscape(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// startProxySQL writes a secret-free cnf, launches with --initial (fresh
// runtime DB from the file), waits for both interfaces, then provisions the
// user rows through the admin interface — the real password enters ProxySQL's
// runtime memory via SQL and never lands in the static config file. Shapes
// and the dual-row split follow the spike findings (ProxySQL 3.0.11).
func startProxySQL(ctx context.Context, logger *slog.Logger, logFile io.Writer, binPath, dir, password string, dbs map[string]config.DatabaseConfig) (*proc, error) {
	adminPort, err := pickPort()
	if err != nil {
		return nil, fmt.Errorf("picking proxysql admin port: %w", err)
	}
	sqlPort, err := pickPort()
	if err != nil {
		return nil, fmt.Errorf("picking proxysql sql port: %w", err)
	}
	adminPassword, err := sessionPassword()
	if err != nil {
		return nil, fmt.Errorf("generating proxysql admin password: %w", err)
	}

	cnfPath := filepath.Join(dir, "proxysql.cnf")
	if err := os.WriteFile(cnfPath, []byte(proxysqlConfig(dir, adminPort, sqlPort, adminPassword, dbs)), 0600); err != nil {
		return nil, fmt.Errorf("writing proxysql.cnf: %w", err)
	}

	cmd := exec.Command(binPath, "--initial", "-f", "-c", cnfPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	p, err := startProc("proxysql", cmd, []int{adminPort, sqlPort}, sqlPort, logger)
	if err != nil {
		return nil, fmt.Errorf("starting proxysql: %w", err)
	}
	if err := waitForListen(p, startupTimeout); err != nil {
		p.stop()
		return nil, err
	}
	if err := provisionProxySQLUsers(ctx, adminPort, adminPassword, dbs, password, logger); err != nil {
		p.stop()
		return nil, fmt.Errorf("provisioning proxysql users: %w", err)
	}
	return p, nil
}

// provisionProxySQLUsers runs the generated SQL through the admin interface.
// Statements carry real passwords, so they are never logged individually —
// only the success count is.
func provisionProxySQLUsers(ctx context.Context, adminPort int, adminPassword string, dbs map[string]config.DatabaseConfig, password string, logger *slog.Logger) error {
	dsn := fmt.Sprintf("admin:%s@tcp(127.0.0.1:%d)/", adminPassword, adminPort)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return fmt.Errorf("opening proxysql admin connection: %w", err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for _, q := range proxysqlUserSQL(sortedNames(dbs), dbs, password) {
		if _, err := db.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("proxysql admin statement failed: %w", err)
		}
	}
	logger.Info("proxysql users provisioned", "count", len(dbs))
	return nil
}
