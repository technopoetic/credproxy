package pooler

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/technopoetic/credproxy/internal/config"
)

// pgbouncerConfig renders the ini. The [databases] line forces the backend
// user/password (real credential — pgbouncer docs: "When the user is part of
// the connection string, the connection between PgBouncer and PostgreSQL is
// forced to the given user, whatever the client user"); client auth comes
// from auth_file (session password). Real passwords exist only in this file,
// written 0600 into the session temp dir.
func pgbouncerConfig(dir string, port int, dbs map[string]config.DatabaseConfig) string {
	var b strings.Builder
	b.WriteString("[databases]\n")
	for _, name := range sortedNames(dbs) {
		db := dbs[name]
		b.WriteString(name)
		b.WriteString(" = host=")
		b.WriteString(db.Host)
		b.WriteString(" port=")
		b.WriteString(strconv.Itoa(db.Port))
		b.WriteString(" dbname=")
		b.WriteString(db.Database)
		b.WriteString(" user=")
		b.WriteString(db.User)
		b.WriteString(" password=")
		b.WriteString(db.Password)
		if db.Params != "" {
			b.WriteString(" ")
			b.WriteString(db.Params)
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, `
[pgbouncer]
listen_addr = 127.0.0.1
listen_port = %d
auth_type = scram-sha-256
auth_file = %s
pool_mode = session
unix_socket_dir = %s
pidfile = %s
; admin_users intentionally unset — the pgbouncer admin console is unreachable
`, port, filepath.Join(dir, "userlist.txt"), dir, filepath.Join(dir, "pgbouncer.pid"))
	return b.String()
}

// pgbouncerUserlist renders client auth entries: one line per distinct
// username, all sharing the session password.
func pgbouncerUserlist(dbs map[string]config.DatabaseConfig, password string) string {
	users := make(map[string]bool, len(dbs))
	for _, db := range dbs {
		users[db.User] = true
	}
	names := make([]string, 0, len(users))
	for u := range users {
		names = append(names, u)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, u := range names {
		fmt.Fprintf(&b, "%q %q\n", u, password)
	}
	return b.String()
}
