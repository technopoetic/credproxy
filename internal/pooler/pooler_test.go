package pooler

import (
	"strings"
	"testing"

	"github.com/technopoetic/credproxy/internal/config"
)

func testDBs() map[string]config.DatabaseConfig {
	return map[string]config.DatabaseConfig{
		"mydb": {Engine: "postgres", Host: "db.example.com", Port: 5432, User: "app_user", Password: "REALPW", Database: "appdb", Params: "sslmode=require", Env: "DATABASE_URL"},
	}
}

func testDBsWithMySQL() map[string]config.DatabaseConfig {
	dbs := testDBs()
	dbs["mdb"] = config.DatabaseConfig{Engine: "mysql", Host: "mysql.example.com", Port: 3306, User: "mu", Password: "MPW", Database: "mdb", Env: "MYSQL_URL"}
	return dbs
}

func TestSessionPasswordLengthAndAlphabet(t *testing.T) {
	pw, err := sessionPassword()
	if err != nil {
		t.Fatal(err)
	}
	if len(pw) < 40 {
		t.Fatalf("session password too short: %d chars", len(pw))
	}
	// base64 RawURL alphabet only — safe in URLs, ini files, and SQL strings
	for _, c := range pw {
		if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", c) {
			t.Fatalf("unexpected character %q in session password", c)
		}
	}
	other, _ := sessionPassword()
	if pw == other {
		t.Fatal("two generated passwords must differ")
	}
}

func TestBuildURLEscapesSpecialChars(t *testing.T) {
	u := buildURL("postgres", "user@x", "p:ss", 6432, "mydb")
	if !strings.HasPrefix(u, "postgres://user%40x:p%3Ass@127.0.0.1:6432/mydb") {
		t.Fatalf("URL not properly escaped: %s", u)
	}
	u = buildURL("mysql", "app_user", "abc-_123", 3307, "mydb")
	if u != "mysql://app_user:abc-_123@127.0.0.1:3307/mydb" {
		t.Fatalf("plain URL wrong: %s", u)
	}
}

func TestPgbouncerConfigContainsSplitCredentials(t *testing.T) {
	ini := pgbouncerConfig("/tmp/sess", 6432, testDBs())
	if !strings.Contains(ini, "mydb = host=db.example.com port=5432 dbname=appdb user=app_user password=REALPW sslmode=require") {
		t.Fatalf("forced-user backend line missing: %s", ini)
	}
	if !strings.Contains(ini, "listen_port = 6432") ||
		!strings.Contains(ini, "auth_type = scram-sha-256") ||
		!strings.Contains(ini, "auth_file = /tmp/sess/userlist.txt") {
		t.Fatalf("pgbouncer section wrong: %s", ini)
	}
	for _, line := range strings.Split(ini, "\n") {
		if strings.HasPrefix(line, "admin_users") {
			t.Fatal("admin_users must stay unset — admin console must be unreachable")
		}
	}
}

func TestPgbouncerUserlistOneLinePerUser(t *testing.T) {
	dbs := testDBs()
	dbs["second"] = config.DatabaseConfig{Engine: "postgres", Host: "h2", Port: 5432, User: "app_user", Password: "P2", Database: "d2", Env: "SECOND_URL"}
	list := pgbouncerUserlist(dbs, "sesspw")
	if list != "\"app_user\" \"sesspw\"\n" {
		t.Fatalf("userlist wrong: %q", list)
	}
}

func TestProxySQLConfigHasServersAndNoSecrets(t *testing.T) {
	cnf := proxysqlConfig("/tmp/sess", 6032, 6033, "adminpw", testDBsWithMySQL())
	// Spike findings: libconfig grammar — datadir quoted, admin binding is mysql_ifaces
	if !strings.Contains(cnf, "datadir=\"/tmp/sess\"") {
		t.Fatalf("datadir must be quoted (libconfig): %s", cnf)
	}
	if !strings.Contains(cnf, "admin_credentials=\"admin:adminpw\"") ||
		!strings.Contains(cnf, "mysql_ifaces=\"127.0.0.1:6032\"") ||
		!strings.Contains(cnf, "interfaces=\"127.0.0.1:6033\"") {
		t.Fatalf("proxysql interfaces wrong: %s", cnf)
	}
	// hostgroups follow sorted entry order (mdb < mydb)
	if !strings.Contains(cnf, "{ address=\"db.example.com\" , port=5432 , hostgroup=1") ||
		!strings.Contains(cnf, "{ address=\"mysql.example.com\" , port=3306 , hostgroup=0") {
		t.Fatalf("mysql_servers wrong (hostgroups must follow sorted entry order): %s", cnf)
	}
	// the session password and REAL db passwords must not appear in the file
	if strings.Contains(cnf, "REALPW") || strings.Contains(cnf, "MPW") || strings.Contains(cnf, "sesspw") {
		t.Fatal("proxysql.cnf must contain no passwords")
	}
}

func TestProxySQLUserSQLDualRows(t *testing.T) {
	// Spike ruling: the split is two mysql_users rows per entry — frontend
	// row with the session password, backend row with the real password. The
	// attributes.frontend_password overlay is NOT honored on 3.0.11.
	names := []string{"mdb"}
	queries := proxysqlUserSQL(names, testDBsWithMySQL(), "sesspw")
	joined := strings.Join(queries, "\n")
	if !strings.Contains(joined, "VALUES ('mu', 'sesspw', 1, 0, 0, 1, 0)") {
		t.Fatalf("frontend row (session password) missing: %s", joined)
	}
	if !strings.Contains(joined, "VALUES ('mu', 'MPW', 1, 0, 0, 0, 1)") {
		t.Fatalf("backend row (real password) missing: %s", joined)
	}
	if !strings.Contains(joined, "LOAD MYSQL USERS TO RUNTIME") {
		t.Fatal("missing LOAD MYSQL USERS TO RUNTIME")
	}
	if !strings.Contains(joined, "mysql-monitor_username") || !strings.Contains(joined, "mysql-monitor_password") {
		t.Fatal("monitor credentials must be set to the real backend credential")
	}
	if strings.Contains(joined, "attributes") {
		t.Fatal("attributes overlay must not be used (ignored on 3.0.11)")
	}
}

func TestProxySQLUserSQLEscapesQuotes(t *testing.T) {
	dbs := testDBsWithMySQL()
	db := dbs["mdb"]
	db.Password = "real'pass"
	dbs["mdb"] = db
	queries := proxysqlUserSQL([]string{"mdb"}, dbs, "sesspw")
	joined := strings.Join(queries, "\n")
	if !strings.Contains(joined, "'real''pass'") {
		t.Fatalf("single quotes in secrets must be doubled for SQL: %s", joined)
	}
}

func TestProxySQLUseSSL(t *testing.T) {
	if proxysqlUseSSL("use_ssl=1") != 1 {
		t.Fatal("use_ssl=1 must map to 1")
	}
	if proxysqlUseSSL("sslmode=require") != 0 {
		t.Fatal("non-use_ssl params must map to 0")
	}
	if proxysqlUseSSL("") != 0 {
		t.Fatal("empty params must map to 0")
	}
}

func TestBuildURLPostgresDisablesTLS(t *testing.T) {
	// The pooler listens on loopback only, and TLS on that leg is a spec
	// non-goal — but lib/pq defaults to sslmode=require, so the injected
	// URL must say otherwise or every lib/pq client fails with
	// "SSL is not enabled on the server".
	u := buildURL("postgres", "app_user", "pw", 6432, "mydb")
	if !strings.Contains(u, "sslmode=disable") {
		t.Fatalf("postgres URL must carry sslmode=disable (loopback, TLS non-goal): %s", u)
	}
	mu := buildURL("mysql", "app_user", "pw", 3307, "mdb")
	if strings.Contains(mu, "sslmode") {
		t.Fatalf("mysql URL must not carry sslmode: %s", mu)
	}
}

func TestPgbouncerConfigIgnoresExtraFloatDigits(t *testing.T) {
	// lib/pq sends extra_float_digits in its startup packet; pgbouncer
	// rejects unknown startup parameters (hit live in Task 10). Clients
	// shouldn't fail because of a display-precision hint.
	ini := pgbouncerConfig("/tmp/sess", 6432, testDBs())
	if !strings.Contains(ini, "ignore_startup_parameters = extra_float_digits") {
		t.Fatalf("ignore_startup_parameters missing: %s", ini)
	}
}
