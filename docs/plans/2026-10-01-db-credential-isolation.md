# DB Credential Isolation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep real DB credentials out of the wrapped child's hands by starting session-scoped poolers (pgbouncer/ProxySQL) whose client auth uses a random per-session password and whose backend auth uses the real `op://`-resolved credential, injecting localhost-only connection URLs into the child env.

**Architecture:** New `internal/pooler` package owns pooler config generation, process lifecycle, and child-env computation; `internal/config` gains `[databases.*]` with merge/profile/validation/resolution; `cmd/credproxy/main.go` wires the manager into wrap mode and strips colliding inherited env vars. No wire-protocol parsing — poolers do client/backend auth decoupling natively.

**Tech Stack:** Go (stdlib + BurntSushi/toml as today), pgbouncer, ProxySQL (admin interface provisioned via `github.com/go-sql-driver/mysql`), podman/docker for test targets, `github.com/lib/pq` for the live-test Postgres client.

**Spec:** `docs/prds/db-credential-isolation.md`

## Global Constraints

- `go.mod` stays at `go 1.20`; do not bump or add toolchain directives.
- New dependencies allowed ONLY: `github.com/go-sql-driver/mysql` (production — ProxySQL admin provisioning) and `github.com/lib/pq` (live-test client only). Both pure Go. No others.
- Pooler config files written 0600 into a session temp dir created with `os.MkdirTemp` (0700); dir removed on session exit.
- Never log real passwords or pooler config contents; pooler stdout/stderr goes to credproxy's log file, provisioning SQL is never logged statement-by-statement.
- Engine names: exactly `postgres` and `mysql`; anything else fails config validation.
- No `[databases.*]` configured → zero behavior change: no temp dir, no processes, no env changes.
- POSIX only; no Windows support.
- Commit messages explain why; no conventional-commit prefixes.
- Existing tests must keep passing (`go test ./...` green at every commit).

## Review Focus

The failure modes most likely to bite a person using this software, most likely first. Each is pinned by a test in the task that owns it.

1. Parent shell already exports `DATABASE_URL` (or `PGPASSWORD`/`MYSQL_PWD`) — the real credential silently defeats the whole scheme. Expected: stripped from child env whenever a matching database is configured. Test in Task 8.
2. Two `[databases]` entries share one `env` var name — second injection would overwrite the first. Expected: startup validation error naming both entries. Test in Task 3.
3. A database `env` name collides with a var credproxy itself injects (`PATH`, `HTTPS_PROXY`, `SSL_CERT_FILE`, …) — pooler URL would shadow or be shadowed unpredictably. Expected: startup validation error. Test in Task 3.
4. Pooler binary missing (pgbouncer/proxysql not installed) — silently running without isolation would be worse than failing. Expected: fail-fast at startup with actionable message, checked only for engines that have configured databases. Test in Task 7.
5. `op://` password resolution fails for a database — the pooler would start with a broken backend credential. Expected: startup fails fast, joined error names the entry. Test in Task 3.
6. Username containing URL-special characters (`user@x`, `u:s`) — a hand-concatenated URL would break parsing or leak the wrong username. Expected: `url.UserPassword` percent-encodes; drivers decode; pooler sees the raw username. Test in Task 4.

---

### Task 1: Spike — verify pooler auth-split mechanics in containers

Throwaway probe, not production code. Everything runs in podman containers (this machine has podman 5.8.5 via `docker` shim, no Homebrew, no host pooler binaries). Output is a findings document that pins the exact configs Tasks 4/6 generate.

**Files:**
- Create: `docs/plans/2026-10-01-db-pooler-spike-findings.md` (the deliverable)
- Create (throwaway, deleted after): `/tmp/dbpooler-spike/*`

**Interfaces:**
- Produces: verified config shapes for `pgbouncer.ini` (forced-user `[databases]` line + `auth_file` client auth under SCRAM) and ProxySQL (`mysql_users` attributes-overlay `frontend_password` vs dual-row; monitor credential behavior; `caching_sha2_password` backend viability). Findings referenced by Tasks 4 and 6.

- [ ] **Step 1: Prepare spike workspace and network**

```bash
mkdir -p /tmp/dbpooler-spike && cd /tmp/dbpooler-spike
docker network create spike
docker run -d --name spike-pg --network spike \
  -e POSTGRES_USER=app_user -e POSTGRES_PASSWORD=realpgpass -e POSTGRES_DB=appdb \
  -p 15432:5432 docker.io/library/postgres:16-alpine
docker run -d --name spike-mysql --network spike \
  -e MYSQL_ROOT_PASSWORD=rootpass -e MYSQL_USER=app_user -e MYSQL_PASSWORD=realmysqlpass \
  -e MYSQL_DATABASE=appdb -p 13306:3306 \
  docker.io/library/mysql:8.0
```

Wait for both to accept connections (`docker exec spike-pg pg_isready`, `docker exec spike-mysql mysqladmin ping -uroot -prootpass`).

- [ ] **Step 2: Probe pgbouncer forced-user + SCRAM client auth**

Write `spike-pgbouncer.ini` (mounted read-only; container runs as its own user):

```ini
[databases]
mydb = host=spike-pg port=5432 dbname=appdb user=app_user password=realpgpass

[pgbouncer]
listen_addr = 0.0.0.0
listen_port = 6432
auth_type = scram-sha-256
auth_file = /etc/pgbouncer/userlist.txt
pool_mode = session
```

`userlist.txt`: `"app_user" "sessionpw123"`.

```bash
docker run -d --name spike-pgbouncer --network spike \
  -v /tmp/dbpooler-spike/spike-pgbouncer.ini:/etc/pgbouncer/pgbouncer.ini:ro \
  -v /tmp/dbpooler-spike/userlist.txt:/etc/pgbouncer/userlist.txt:ro \
  -p 16432:6432 docker.io/pgbouncer/pgbouncer:latest
# positive: session password connects
docker run --rm --network spike docker.io/library/postgres:16-alpine \
  psql "postgres://app_user:sessionpw123@spike-pgbouncer:6432/mydb" -c "select 1"
# negative: wrong client password rejected
docker run --rm --network spike docker.io/library/postgres:16-alpine \
  psql "postgres://app_user:WRONG@spike-pgbouncer:6432/mydb" -c "select 1" || echo "rejected as expected"
```

Record: does the session-password client connect and does `select 1` round-trip to the real backend? Does the wrong password fail?

- [ ] **Step 3: Probe ProxySQL user provisioning — two variants**

Variant A (primary, implemented in Task 6): static `proxysql.cnf` with servers/variables only; users inserted at runtime through the admin interface with the attributes overlay:

```sql
INSERT INTO mysql_users (username, password, active, use_ssl, default_hostgroup, frontend, backend, attributes)
  VALUES ('app_user', 'realmysqlpass', 1, 0, 0, 1, 1, '{"frontend_password":"sessionpw123"}');
LOAD MYSQL USERS TO RUNTIME;
```

Variant B (fallback): `mysql_users` row embedded directly in `proxysql.cnf` with the same attributes JSON (tests whether the config-file parser tolerates `\"` escapes).

Static cnf (variant A):

```ini
datadir=/var/lib/proxysql
admin_variables=
{
	admin_credentials="admin:adminpw456"
	mysql_interfaces="127.0.0.1:6032"
}
mysql_variables=
{
	threads=2
	max_connections=64
	interfaces="0.0.0.0:6033"
	default_query_delay=0
	default_query_timeout=36000000
}
mysql_servers =
(
	{ address="spike-mysql" , port=3306 , hostgroup=0 , max_connections=20 }
)
```

```bash
docker run -d --name spike-proxysql --network spike \
  -v /tmp/dbpooler-spike/proxysql.cnf:/etc/proxysql.cnf:ro \
  -p 16032:6032 -p 16033:6033 docker.io/proxysql/proxysql:latest
docker run --rm --network spike -it docker.io/library/mysql:8.0 \
  mysql -h spike-proxysql -P 6032 -u admin -padminpw456 \
  -e "INSERT ...; LOAD MYSQL USERS TO RUNTIME;"
```

Then test the SQL frontend with the session password, and record:

```bash
docker run --rm --network spike docker.io/library/mysql:8.0 \
  mysql -h spike-proxysql -P 6033 -u app_user -psessionpw123 -e "select 1, current_user()"
```

- [ ] **Step 4: Probe backend auth plugin compatibility**

The mysql:8.0 default user is `caching_sha2_password`. If the frontend test in Step 3 fails at the *backend* leg, repeat with a `mysql_native_password` user (`ALTER USER 'app_user' IDENTIFIED WITH mysql_native_password BY 'realmysqlpass';` inside the mysql container) and record which works through ProxySQL without TLS/RSA. Also record whether ProxySQL marks the backend SHUNNED (check `SELECT hostgroup, srv_host, status FROM runtime_mysql_servers;` and the monitor tables) with monitor credentials unset, and whether setting `mysql-monitor_username`/`mysql-monitor_password` to the real backend credential via `UPDATE global_variables ... ; LOAD MYSQL VARIABLES TO RUNTIME;` changes anything.

- [ ] **Step 5: Write findings and tear down**

Write `docs/plans/2026-10-01-db-pooler-spike-findings.md` with: exact working pgbouncer.ini (host-side variant notes: `listen_addr = 127.0.0.1`, temp-dir paths), working ProxySQL provisioning variant (A or B), working auth plugin + any needed `mysql_native_password` conversion, monitor verdict, ProxySQL image version tested (`docker inspect spike-proxysql`), and any `ignore_startup_parameters` pgbouncer needed. Then:

```bash
docker rm -f spike-pg spike-mysql spike-pgbouncer spike-proxysql
docker network rm spike
```

- [ ] **Step 6: Commit findings**

```bash
git add docs/plans/2026-10-01-db-pooler-spike-findings.md
git commit -m "Record spike findings for pooler auth-split mechanics

Container probes pin the exact pgbouncer forced-user config and ProxySQL
user-provisioning variant before any code is built around them."
```

---

### Task 2: Config — `[databases.*]` parsing, merge, profile overlay, binary path overrides

**Files:**
- Modify: `internal/config/config.go`
- Test: `internal/config/config_test.go` (read existing tests first; extend, don't break)

**Interfaces:**
- Consumes: existing `Config`, `ProfileConfig`, `Merge`, `ApplyProfile`, `SetDefaults` shapes as of commit `604da28`.
- Produces: `DatabaseConfig` struct; `Config.Databases map[string]DatabaseConfig`; `Config.PgbouncerPath`, `Config.ProxySQLPath` strings; profile overlay key `[profiles.<name>.databases]`. Later tasks construct `config.DatabaseConfig` values directly in tests.

- [ ] **Step 1: Write failing tests**

```go
func TestLoadDatabases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	tomlData := `
[databases.mydb]
engine = "postgres"
host = "db.example.com"
port = 5432
user = "app_user"
password = "op://Private/mydb/password"
database = "appdb"
params = "sslmode=require"
env = "DATABASE_URL"

[databases.other]
engine = "mysql"
host = "mysql.example.com"
port = 3306
user = "mu"
password = "literal"
database = "mdb"
env = "OTHER_DB_URL"
`
	if err := os.WriteFile(path, []byte(tomlData), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Databases) != 2 {
		t.Fatalf("expected 2 databases, got %d", len(cfg.Databases))
	}
	db := cfg.Databases["mydb"]
	if db.Engine != "postgres" || db.Host != "db.example.com" || db.Port != 5432 ||
		db.User != "app_user" || db.Password != "op://Private/mydb/password" ||
		db.Database != "appdb" || db.Params != "sslmode=require" || db.Env != "DATABASE_URL" {
		t.Fatalf("mydb parsed wrong: %+v", db)
	}
	if cfg.Databases["other"].Engine != "mysql" {
		t.Fatalf("other parsed wrong: %+v", cfg.Databases["other"])
	}
}

func TestMergeDatabasesProjectWinsPerEntry(t *testing.T) {
	global := &Config{
		Env:      map[string]string{},
		Hosts:    map[string]HostConfig{},
		Profiles: map[string]ProfileConfig{},
		Databases: map[string]DatabaseConfig{
			"mydb":  {Engine: "postgres", Host: "global.example.com", Port: 5432, User: "u", Password: "p", Database: "d", Env: "DATABASE_URL"},
			"gonly": {Engine: "postgres", Host: "g.example.com", Port: 5432, User: "u", Password: "p", Database: "d", Env: "G_URL"},
		},
	}
	overlay := &Config{
		Env:      map[string]string{},
		Hosts:    map[string]HostConfig{},
		Profiles: map[string]ProfileConfig{},
		Databases: map[string]DatabaseConfig{
			"mydb": {Engine: "postgres", Host: "project.example.com", Port: 5433, User: "u2", Password: "p2", Database: "d2", Env: "DATABASE_URL"},
		},
	}
	merged := global.Merge(overlay)
	if merged.Databases["mydb"].Host != "project.example.com" {
		t.Fatalf("overlay entry should win wholesale: %+v", merged.Databases["mydb"])
	}
	if _, ok := merged.Databases["gonly"]; !ok {
		t.Fatal("global-only entry must survive merge")
	}
}

func TestMergeBinaryPathOverrides(t *testing.T) {
	global := &Config{Env: map[string]string{}, Hosts: map[string]HostConfig{}, Profiles: map[string]ProfileConfig{}, PgbouncerPath: "/g/pgbouncer"}
	overlay := &Config{Env: map[string]string{}, Hosts: map[string]HostConfig{}, Profiles: map[string]ProfileConfig{}, ProxySQLPath: "/p/proxysql"}
	merged := global.Merge(overlay)
	if merged.PgbouncerPath != "/g/pgbouncer" || merged.ProxySQLPath != "/p/proxysql" {
		t.Fatalf("scalar path merge wrong: %+v", merged)
	}
}

func TestApplyProfileDatabases(t *testing.T) {
	cfg := &Config{
		Env:      map[string]string{},
		Hosts:    map[string]HostConfig{},
		Databases: map[string]DatabaseConfig{
			"mydb": {Engine: "postgres", Host: "prod.example.com", Port: 5432, User: "u", Password: "p", Database: "d", Env: "DATABASE_URL"},
		},
		Profiles: map[string]ProfileConfig{
			"staging": {Hosts: map[string]HostConfig{}, Env: map[string]string{}, Databases: map[string]DatabaseConfig{
				"mydb": {Engine: "postgres", Host: "staging.example.com", Port: 5432, User: "u", Password: "p", Database: "d", Env: "DATABASE_URL"},
			}},
		},
	}
	applied, err := cfg.ApplyProfile("staging")
	if err != nil {
		t.Fatal(err)
	}
	if applied.Databases["mydb"].Host != "staging.example.com" {
		t.Fatalf("profile databases should overlay: %+v", applied.Databases["mydb"])
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/config/ -run 'TestLoadDatabases|TestMergeDatabases|TestMergeBinaryPath|TestApplyProfileDatabases' -v`
Expected: FAIL — compile error, `DatabaseConfig`/`Databases`/`PgbouncerPath` undefined.

- [ ] **Step 3: Implement**

In `internal/config/config.go` add/modify (exact shapes):

```go
type DatabaseConfig struct {
	Engine   string `toml:"engine"`
	Host     string `toml:"host"`
	Port     int    `toml:"port"`
	User     string `toml:"user"`
	Password string `toml:"password"`
	Database string `toml:"database"`
	Params   string `toml:"params"`
	Env      string `toml:"env"`
}

type ProfileConfig struct {
	Hosts     map[string]HostConfig     `toml:"hosts"`
	Env       map[string]string         `toml:"env"`
	Databases map[string]DatabaseConfig `toml:"databases"`
}

type Config struct {
	PgbouncerPath string                    `toml:"pgbouncer_path"`
	ProxySQLPath  string                    `toml:"proxysql_path"`
	Env           map[string]string         `toml:"env"`
	Hosts         map[string]HostConfig     `toml:"hosts"`
	Databases     map[string]DatabaseConfig `toml:"databases"`
	Profiles      map[string]ProfileConfig  `toml:"profiles"`
	hostsSet      map[string]bool
}
```

`SetDefaults`: nil `Databases` → empty map; inside the existing profile loop, nil `p.Databases` → empty map.

`Merge`: initialize `merged.Databases` and copy base then overlay entries (whole-entry replacement, same as hosts); copy `PgbouncerPath`/`ProxySQLPath` from base, then override from overlay when non-empty.

`ApplyProfile`: initialize `result.Databases` from base, overlay `profile.Databases` entries.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/config/ -v`
Expected: PASS, including all pre-existing tests.

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "Add [databases.*] config with merge, profile overlay, and binary path overrides

Database entries merge wholesale per entry, matching HostConfig semantics,
so a project override replaces the global entry rather than mixing fields
from two environments."
```

---

### Task 3: Config validation + `op://` password resolution

**Files:**
- Modify: `internal/config/config.go` (refactor the concurrent-resolve worker out of `ResolveEnv` so database passwords share it)
- Test: `internal/config/config_test.go`

**Interfaces:**
- Consumes: `DatabaseConfig` from Task 2; existing `EnvResolver` interface and `envResolveTimeout` constant.
- Produces: `func (c *Config) ValidateDatabases() error` and `func (c *Config) ResolveDatabasePasswords(ctx context.Context, r EnvResolver) error`. Task 8 calls both from `main.go`.

- [ ] **Step 1: Write failing tests**

```go
func TestValidateDatabasesRejectsUnknownEngine(t *testing.T) {
	cfg := minimalValidDatabases(t) // helper below
	cfg.Databases["mydb"].Engine = "mongodb"
	if err := cfg.ValidateDatabases(); err == nil {
		t.Fatal("expected error for unknown engine")
	}
}

func TestValidateDatabasesRequiresFields(t *testing.T) {
	cfg := minimalValidDatabases(t)
	cfg.Databases["mydb"].Host = ""
	if err := cfg.ValidateDatabases(); err == nil {
		t.Fatal("expected error for missing host")
	}
}

func TestValidateDatabasesRejectsDuplicateEnvNames(t *testing.T) {
	cfg := minimalValidDatabases(t)
	cfg.Databases["second"] = DatabaseConfig{
		Engine: "postgres", Host: "h", Port: 5432, User: "u",
		Password: "p", Database: "d", Env: "DATABASE_URL",
	}
	err := cfg.ValidateDatabases()
	if err == nil {
		t.Fatal("expected error for duplicate env var name")
	}
	if !strings.Contains(err.Error(), "second") || !strings.Contains(err.Error(), "mydb") {
		t.Fatalf("error should name both entries: %v", err)
	}
}

func TestValidateDatabasesRejectsReservedEnvNames(t *testing.T) {
	for _, name := range []string{"PATH", "HTTPS_PROXY", "SSL_CERT_FILE", "CREDPROXY_TOKEN"} {
		cfg := minimalValidDatabases(t)
		cfg.Databases["mydb"].Env = name
		if err := cfg.ValidateDatabases(); err == nil {
			t.Fatalf("expected error for reserved env name %s", name)
		}
	}
}

func TestValidateDatabasesNoDatabasesOK(t *testing.T) {
	cfg := &Config{}
	if err := cfg.ValidateDatabases(); err != nil {
		t.Fatalf("empty config should validate: %v", err)
	}
}

func TestResolveDatabasePasswordsResolvesAndFailsFast(t *testing.T) {
	cfg := minimalValidDatabases(t)
	cfg.Databases["mydb"].Password = "op://x/y/z"
	fake := &fakeResolver{values: map[string]string{"op://x/y/z": "resolved-pw"}}
	if err := cfg.ResolveDatabasePasswords(context.Background(), fake); err != nil {
		t.Fatal(err)
	}
	if cfg.Databases["mydb"].Password != "resolved-pw" {
		t.Fatalf("password not written back: %q", cfg.Databases["mydb"].Password)
	}

	broken := &fakeResolver{err: errors.New("vault locked")}
	cfg2 := minimalValidDatabases(t)
	cfg2.Databases["mydb"].Password = "op://x/y/z"
	if err := cfg2.ResolveDatabasePasswords(context.Background(), broken); err == nil {
		t.Fatal("expected fail-fast on resolution error")
	}
}

// helpers
func minimalValidDatabases(t *testing.T) *Config {
	t.Helper()
	return &Config{
		Databases: map[string]DatabaseConfig{
			"mydb": {Engine: "postgres", Host: "h", Port: 5432, User: "u", Password: "p", Database: "d", Env: "DATABASE_URL"},
		},
	}
}

type fakeResolver struct{ values map[string]string; err error }

func (f *fakeResolver) Resolve(ctx context.Context, uri string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.values[uri], nil
}
```

(If `fakeResolver` or a similar stub already exists in `config_test.go`, reuse it instead of declaring a duplicate.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/config/ -run 'TestValidateDatabases|TestResolveDatabasePasswords' -v`
Expected: FAIL — `ValidateDatabases`/`ResolveDatabasePasswords` undefined.

- [ ] **Step 3: Implement**

Extract the shared concurrent-resolve worker from `ResolveEnv` (behavior-preserving refactor — existing `ResolveEnv` tests must stay green):

```go
// resolveURIs resolves every value in items that starts with "op://" through r,
// concurrently, each with its own 30s deadline. apply writes a resolved value
// back into the caller's structure. The first error fails the batch; all
// errors are returned joined.
func resolveURIs(ctx context.Context, r EnvResolver, items map[string]string, label string, apply func(key, value string)) error {
	type pending struct{ key, uri string }
	var work []pending
	for k, v := range items {
		if strings.HasPrefix(v, "op://") {
			work = append(work, pending{k, v})
		}
	}
	if len(work) == 0 {
		return nil
	}
	type result struct {
		key, value string
		err        error
	}
	results := make(chan result, len(work))
	var wg sync.WaitGroup
	for _, p := range work {
		wg.Add(1)
		go func(p pending) {
			defer wg.Done()
			callCtx, cancel := context.WithTimeout(ctx, envResolveTimeout)
			defer cancel()
			val, err := r.Resolve(callCtx, p.uri)
			results <- result{p.key, val, err}
		}(p)
	}
	wg.Wait()
	close(results)

	var errs []error
	for res := range results {
		if res.err != nil {
			errs = append(errs, fmt.Errorf("resolving %s %s: %w", label, res.key, res.err))
			continue
		}
		apply(res.key, res.value)
	}
	return errors.Join(errs...)
}

func (c *Config) ResolveEnv(ctx context.Context, r EnvResolver) error {
	return resolveURIs(ctx, r, c.Env, "env", func(k, v string) { c.Env[k] = v })
}

// ResolveDatabasePasswords resolves op:// URIs in [databases.*] passwords at
// startup, fail-fast, before any pooler is started with a broken credential.
func (c *Config) ResolveDatabasePasswords(ctx context.Context, r EnvResolver) error {
	uris := make(map[string]string, len(c.Databases))
	for name, db := range c.Databases {
		uris[name] = db.Password
	}
	return resolveURIs(ctx, r, uris, "database password", func(name, pw string) {
		db := c.Databases[name]
		db.Password = pw
		c.Databases[name] = db
	})
}
```

Keep the existing `ResolveEnv` doc comment on the method. Validation:

```go
// reservedEnvNames are variables credproxy itself injects or filters in the
// child env. A database env var with one of these names would fight the
// proxy's own wiring, so it is rejected at validation time.
var reservedEnvNames = map[string]bool{
	"PATH": true, "HOME": true, "BASH_ENV": true,
	"HTTPS_PROXY": true, "HTTP_PROXY": true, "https_proxy": true, "http_proxy": true,
	"NO_PROXY": true, "no_proxy": true,
	"SSL_CERT_FILE": true, "REQUESTS_CA_BUNDLE": true, "NODE_EXTRA_CA_CERTS": true,
	"CURL_CA_BUNDLE": true, "CREDPROXY_TOKEN": true,
	"PGPASSWORD": true, "MYSQL_PWD": true,
}

// ValidateDatabases checks every [databases.*] entry: known engine, required
// fields present, port in range, unique env var names, and no reserved env
// var names. All problems are reported in one joined error.
func (c *Config) ValidateDatabases() error {
	var errs []error
	seenEnv := make(map[string]string, len(c.Databases))
	for name, db := range c.Databases {
		if db.Engine != "postgres" && db.Engine != "mysql" {
			errs = append(errs, fmt.Errorf("database %q: engine must be \"postgres\" or \"mysql\", got %q", name, db.Engine))
		}
		for field, val := range map[string]string{
			"host": db.Host, "user": db.User, "password": db.Password,
			"database": db.Database, "env": db.Env,
		} {
			if val == "" {
				errs = append(errs, fmt.Errorf("database %q: %s is required", name, field))
			}
		}
		if db.Port <= 0 || db.Port > 65535 {
			errs = append(errs, fmt.Errorf("database %q: port must be between 1 and 65535, got %d", name, db.Port))
		}
		if reservedEnvNames[db.Env] {
			errs = append(errs, fmt.Errorf("database %q: env var name %q is reserved by credproxy", name, db.Env))
		}
		if prev, ok := seenEnv[db.Env]; ok && db.Env != "" {
			errs = append(errs, fmt.Errorf("database %q: env var %q already used by database %q", name, db.Env, prev))
		}
		seenEnv[db.Env] = name
	}
	return errors.Join(errs...)
}
```

- [ ] **Step 4: Run all config tests**

Run: `go test ./internal/config/ -v`
Expected: PASS — new tests and pre-existing `ResolveEnv` tests.

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "Add database config validation and op:// password resolution

Invalid database config must fail startup before a pooler launches with a
broken backend credential; the resolve worker is shared with ResolveEnv so
both paths keep the same 30s per-call timeout and joined-error behavior."
```

---

### Task 4: Pooler package — pure generators (configs, userlist, SQL, URLs, password)

**Files:**
- Create: `internal/pooler/pooler.go` (shared helpers)
- Create: `internal/pooler/pgbouncer.go` (generation functions only in this task)
- Create: `internal/pooler/proxysql.go` (generation functions only in this task)
- Test: `internal/pooler/pooler_test.go`

**Interfaces:**
- Consumes: `config.DatabaseConfig` from Task 2. Spike findings from Task 1 for exact config shapes.
- Produces (used by Tasks 5–7):
  - `func sessionPassword() (string, error)`
  - `func pickPort() (int, error)`
  - `func buildURL(engine, user, password string, port int, alias string) string`
  - `func pgbouncerConfig(dir string, port int, dbs map[string]config.DatabaseConfig) string`
  - `func pgbouncerUserlist(dbs map[string]config.DatabaseConfig, password string) string`
  - `func proxysqlConfig(dir string, adminPort, sqlPort int, adminPassword string, dbs map[string]config.DatabaseConfig) string`
  - `func proxysqlUserSQL(names []string, dbs map[string]config.DatabaseConfig, sessionPassword string) []string`
  - `type proxysqlEntry struct { User, RealPassword, SessionPassword string; Hostgroup, UseSSL int }`

- [ ] **Step 1: Write failing tests**

```go
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

func TestSessionPasswordLengthAndAlphabet(t *testing.T) {
	pw, err := sessionPassword()
	if err != nil {
		t.Fatal(err)
	}
	if len(pw) < 40 {
		t.Fatalf("session password too short: %d chars", len(pw))
	}
	// base64 RawURL alphabet only — safe in URLs and ini/sql strings
	for _, c := range pw {
		if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", c) {
			t.Fatalf("unexpected character %q in session password", c)
		}
	}
	if pw == sessionPasswordForcedDifferent(t) {
		t.Fatal("two generated passwords must differ")
	}
}

func sessionPasswordForcedDifferent(t *testing.T) string {
	t.Helper()
	pw, _ := sessionPassword()
	return pw
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
	if strings.Contains(ini, "admin_users") {
		t.Fatal("admin_users must stay unset — admin console must be unreachable")
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
	dbs := testDBs()
	dbs["mdb"] = config.DatabaseConfig{Engine: "mysql", Host: "mysql.example.com", Port: 3306, User: "mu", Password: "MPW", Database: "mdb", Env: "MYSQL_URL"}
	cnf := proxysqlConfig("/tmp/sess", 6032, 6033, "adminpw", dbs)
	if !strings.Contains(cnf, "admin_credentials=\"admin:adminpw\"") ||
		!strings.Contains(cnf, "mysql_interfaces=\"127.0.0.1:6032\"") ||
		!strings.Contains(cnf, "interfaces=\"127.0.0.1:6033\"") {
		t.Fatalf("proxysql interfaces wrong: %s", cnf)
	}
	if !strings.Contains(cnf, "{ address=\"db.example.com\" , port=5432 , hostgroup=0") ||
		!strings.Contains(cnf, "{ address=\"mysql.example.com\" , port=3306 , hostgroup=1") {
		t.Fatalf("mysql_servers wrong (hostgroups must follow sorted entry order): %s", cnf)
	}
	// the session password and REAL db passwords must not appear in the file
	if strings.Contains(cnf, "REALPW") || strings.Contains(cnf, "MPW") || strings.Contains(cnf, "sesspw") {
		t.Fatal("proxysql.cnf must contain no passwords")
	}
}

func TestProxySQLUserSQLAttributesOverlay(t *testing.T) {
	names := []string{"mdb"}
	queries := proxysqlUserSQL(names, testDBsWithMySQL(), "sesspw")
	joined := strings.Join(queries, "\n")
	if !strings.Contains(joined, `VALUES ('mu', 'MPW', 1, 0, 0, 1, 1, '{"frontend_password":"sesspw"}')`) {
		t.Fatalf("user INSERT wrong: %s", joined)
	}
	if !strings.Contains(joined, "LOAD MYSQL USERS TO RUNTIME") {
		t.Fatal("missing LOAD MYSQL USERS TO RUNTIME")
	}
	if !strings.Contains(joined, "mysql-monitor_username") || !strings.Contains(joined, "mysql-monitor_password") {
		t.Fatal("monitor credentials must be set to the real backend credential")
	}
}

func TestProxySQLUserSQLEscapesQuotes(t *testing.T) {
	dbs := testDBsWithMySQL()
	dbs["mdb"].Password = "real'pass"
	queries := proxysqlUserSQL([]string{"mdb"}, dbs, "sesspw")
	joined := strings.Join(queries, "\n")
	if !strings.Contains(joined, "'real''pass'") {
		t.Fatalf("single quotes in secrets must be doubled for SQL: %s", joined)
	}
}
```

(`testDBsWithMySQL` returns `testDBs()` plus an `mdb` mysql entry identical to the one in `TestProxySQLConfigHasServersAndNoSecrets` — define it once as a helper, not duplicated inline.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/pooler/ -v`
Expected: FAIL — package doesn't exist yet / functions undefined.

- [ ] **Step 3: Implement**

`internal/pooler/pooler.go`:

```go
package pooler

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
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
	scheme := engine // "postgres" or "mysql" are already the URL schemes
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
```

`internal/pooler/pgbouncer.go` (generation half):

```go
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
// user/password (real credential); client auth comes from auth_file
// (session password). Real passwords exist only in this file, 0600.
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
```

`internal/pooler/proxysql.go` (generation half):

```go
package pooler

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/technopoetic/credproxy/internal/config"
)

type proxysqlEntry struct {
	User            string
	RealPassword    string
	SessionPassword string
	Hostgroup       int
	UseSSL          int
}

// proxysqlConfig renders the static cnf: interfaces, variables, and backend
// servers. It deliberately contains NO passwords — users (with the real
// password) are provisioned through the admin interface at startup, so the
// on-disk file never holds secrets.
func proxysqlConfig(dir string, adminPort, sqlPort int, adminPassword string, dbs map[string]config.DatabaseConfig) string {
	var b strings.Builder
	fmt.Fprintf(&b, "datadir=%q\n", dir)
	fmt.Fprintf(&b, "\nadmin_variables=\n{\n\tadmin_credentials=\"admin:%s\"\n\tmysql_interfaces=\"127.0.0.1:%d\"\n}\n", adminPassword, adminPort)
	fmt.Fprintf(&b, "\nmysql_variables=\n{\n\tthreads=2\n\tmax_connections=64\n\tinterfaces=\"127.0.0.1:%d\"\n\tdefault_query_delay=0\n\tdefault_query_timeout=36000000\n}\n", sqlPort)
	b.WriteString("\nmysql_servers =\n(\n")
	for i, name := range sortedNames(dbs) {
		db := dbs[name]
		fmt.Fprintf(&b, "\t{ address=%q , port=%d , hostgroup=%d , max_connections=20 }\n", db.Host, db.Port, i)
	}
	b.WriteString(")\n")
	return b.String()
}

// proxysqlUserSQL builds the admin-interface statements. One user row per
// entry: the row password is the real backend credential, the attributes
// overlay carries the frontend_password (session password) — ProxySQL's
// documented frontend/backend decoupling for a single username. Hostgroups
// follow sorted entry order, matching proxysqlConfig. The first entry's real
// credential doubles as the monitor credential so health checks pass.
func proxysqlUserSQL(names []string, dbs map[string]config.DatabaseConfig, password string) []string {
	entries := make([]proxysqlEntry, 0, len(names))
	for i, name := range names {
		db := dbs[name]
		entries = append(entries, proxysqlEntry{
			User:            db.User,
			RealPassword:    db.Password,
			SessionPassword: password,
			Hostgroup:       i,
			UseSSL:          proxysqlUseSSL(db.Params),
		})
	}
	var out []string
	for _, e := range entries {
		attrs, err := json.Marshal(map[string]string{"frontend_password": e.SessionPassword})
		if err != nil {
			continue // unreachable: map[string]string marshals unconditionally
		}
		out = append(out, fmt.Sprintf(
			"INSERT INTO mysql_users (username, password, active, use_ssl, default_hostgroup, frontend, backend, attributes) VALUES ('%s', '%s', 1, %d, %d, 1, 1, '%s')",
			sqlEscape(e.User), sqlEscape(e.RealPassword), e.UseSSL, e.Hostgroup, sqlEscape(string(attrs))))
	}
	out = append(out, "LOAD MYSQL USERS TO RUNTIME")
	if len(entries) > 0 {
		first := entries[0]
		out = append(out,
			fmt.Sprintf("UPDATE global_variables SET variable_value='%s' WHERE variable_name='mysql-monitor_username'", sqlEscape(first.User)),
			fmt.Sprintf("UPDATE global_variables SET variable_value='%s' WHERE variable_name='mysql-monitor_password'", sqlEscape(first.RealPassword)),
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
```

Add `"sort"` to pooler.go imports.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/pooler/ -v && go build ./...`
Expected: PASS; build clean.

- [ ] **Step 5: Commit**

```bash
git add internal/pooler/ go.mod go.sum
git commit -m "Add pooler config generators for pgbouncer and ProxySQL

Pure functions first: the generated ini/cnf/SQL shapes are the contract
the launch code depends on, and they are cheap to pin with table tests.
ProxySQL's cnf intentionally holds no passwords — users are provisioned
via the admin interface so secrets stay out of the static file."
```

---

### Task 5: Pooler process lifecycle (proc, waitForListen, stop) with fake binaries

**Files:**
- Create: `internal/pooler/manager.go` (lifecycle primitives only in this task)
- Test: `internal/pooler/manager_test.go`

**Interfaces:**
- Consumes: nothing from Tasks 2–4 yet (self-contained primitives).
- Produces (used by Tasks 6–7):
  - `type proc struct { name string; cmd *exec.Cmd; sqlPort int; ports []int; waitCh chan struct{}; exitErr error; mu sync.Mutex; stopped bool }`
  - `func startProc(name string, cmd *exec.Cmd, ports []int, sqlPort int, logger *slog.Logger) (*proc, error)` — owns `cmd.Start()`; returns an error when the process cannot start
  - `func (p *proc) stop()`
  - `func waitForListen(p *proc, timeout time.Duration) error`
  - `const startupTimeout = 15 * time.Second` (declared here; Tasks 6–7 use it)

- [ ] **Step 1: Write failing tests**

Fake pooler processes use the standard Go subprocess re-exec pattern — the
test binary re-executes itself in listener mode, which avoids netcat's
BSD/GNU flag differences:

```go
// fakeListenerMain is the body of the subprocess used by lifecycle tests:
// when invoked with "--fake-listen", it opens the requested ports and blocks.
func fakeListenerMain(ports []int) {
	listeners := make([]net.Listener, 0, len(ports))
	for _, p := range ports {
		l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		listeners = append(listeners, l)
	}
	select {}
}

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "--fake-listen" {
		ports := make([]int, 0, len(os.Args)-2)
		for _, a := range os.Args[2:] {
			p, _ := strconv.Atoi(a)
			ports = append(ports, p)
		}
		fakeListenerMain(ports)
		return
	}
	os.Exit(m.Run())
}

func intStrings(xs []int) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = strconv.Itoa(x)
	}
	return out
}

func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func startFakeListener(t *testing.T, ports []int) *proc {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, append([]string{"--fake-listen"}, intStrings(ports)...)...)
	p, err := startProc("fake", cmd, ports, ports[len(ports)-1], testLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestWaitForListenSuccess(t *testing.T) {
	port1, _ := pickPort()
	port2, _ := pickPort()
	p := startFakeListener(t, []int{port1, port2})
	defer p.stop()
	if err := waitForListen(p, 5*time.Second); err != nil {
		t.Fatalf("expected listen: %v", err)
	}
}

func TestWaitForListenProcessExits(t *testing.T) {
	port, _ := pickPort()
	cmd := exec.Command("false") // exits 1 immediately
	p, err := startProc("exiter", cmd, []int{port}, port, testLogger(t))
	if err != nil {
		t.Fatal(err) // start succeeds; the exit happens after
	}
	err = waitForListen(p, 5*time.Second)
	if err == nil {
		t.Fatal("expected error when process exits during startup")
	}
	if !strings.Contains(err.Error(), "exited during startup") {
		t.Fatalf("wrong error: %v", err)
	}
}

func TestWaitForListenTimeout(t *testing.T) {
	port, _ := pickPort() // reserved above, nothing listening
	cmd := exec.Command("sleep", "30")
	p, err := startProc("silent", cmd, []int{port}, port, testLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	defer p.stop()
	start := time.Now()
	err = waitForListen(p, 300*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("timeout not respected")
	}
}

func TestStopKillsProcess(t *testing.T) {
	port, _ := pickPort()
	p := startFakeListener(t, []int{port})
	if err := waitForListen(p, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	p.stop()
	select {
	case <-p.waitCh:
	case <-time.After(3 * time.Second):
		t.Fatal("process not reaped after stop")
	}
	p.mu.Lock()
	stopped := p.stopped
	p.mu.Unlock()
	if !stopped {
		t.Fatal("stop must set the stopped flag so unexpected-exit logging is suppressed")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/pooler/ -run 'TestWaitForListen|TestStopKills' -v`
Expected: FAIL — `proc`/`startProc`/`waitForListen` undefined.

- [ ] **Step 3: Implement** (in `internal/pooler/manager.go`)

`startProc` owns `cmd.Start()` so the watch goroutine never calls `Wait()`
before the process exists:

```go
package pooler

import (
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"time"
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

// startProc starts the process and launches its watch goroutine. The
// goroutine must be created before waitForListen runs but Wait() must not be
// called before Start() succeeds, so both live here.
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/pooler/ -v`
Expected: PASS — Task 4 tests still green.

- [ ] **Step 5: Commit**

```bash
git add internal/pooler/manager.go internal/pooler/manager_test.go
git commit -m "Add pooler process lifecycle primitives

waitForListen doubles as the startup gate: a pooler that exits while
reading its config fails the session fast instead of leaving a half-up
proxy. The subprocess re-exec pattern in tests avoids netcat portability
traps on BSD vs GNU."
```

---

### Task 6: Engine launches — startPgbouncer + startProxySQL with admin provisioning

**Files:**
- Modify: `internal/pooler/pgbouncer.go` (add launch)
- Modify: `internal/pooler/proxysql.go` (add launch + provisioning)
- Modify: `go.mod` / `go.sum` (add `github.com/go-sql-driver/mysql`)

**Interfaces:**
- Consumes: generators from Task 4; `proc`/`startProc`/`waitForListen` from Task 5; spike findings from Task 1 (adjust generated shapes if findings differ from the primary variants below).
- Produces: `func startPgbouncer(ctx context.Context, logger *slog.Logger, logFile io.Writer, binPath, dir, password string, dbs map[string]config.DatabaseConfig) (*proc, error)` and `func startProxySQL(ctx context.Context, logger *slog.Logger, logFile io.Writer, binPath, dir, password string, dbs map[string]config.DatabaseConfig) (*proc, error)`. Task 7 dispatches on engine name to these.

There is no unit-testable surface here (real binaries required); correctness is `go build`/`go vet` plus the live run in Task 10. The generators beneath this code are already pinned by Task 4 tests.

- [ ] **Step 1: Add the mysql driver dependency**

```bash
go get github.com/go-sql-driver/mysql
```

- [ ] **Step 2: Implement pgbouncer launch** (append to `internal/pooler/pgbouncer.go`)

```go
import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/technopoetic/credproxy/internal/config"
)

// startPgbouncer writes the ini and userlist into dir and launches the
// binary in the foreground, logging to credproxy's log file. Client auth is
// the session password via auth_file; backend auth is forced by the
// [databases] lines (real credential).
func startPgbouncer(ctx context.Context, logger *slog.Logger, logFile io.Writer, binPath, dir, password string, dbs map[string]config.DatabaseConfig) (*proc, error) {
	port, err := pickPort()
	if err != nil {
		return nil, fmt.Errorf("picking pgbouncer port: %w", err)
	}
	iniPath := filepath.Join(dir, "pgbouncer.ini")
	if err := os.WriteFile(iniPath, []byte(pgbouncerConfig(dir, port, dbs)), 0600); err != nil {
		return nil, fmt.Errorf("writing pgbouncer.ini: %w", err)
	}
	userlistPath := filepath.Join(dir, "userlist.txt")
	if err := os.WriteFile(userlistPath, []byte(pgbouncerUserlist(dbs, password)), 0600); err != nil {
		return nil, fmt.Errorf("writing userlist.txt: %w", err)
	}

	cmd := exec.Command(binPath, iniPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	p, err := startProc("pgbouncer", cmd, []int{port}, port, logger)
	if err != nil {
		return nil, fmt.Errorf("starting pgbouncer: %w", err)
	}
	if err := waitForListen(p, startupTimeout); err != nil {
		p.stop()
		return nil, err
	}
	return p, nil
}
```

(`startupTimeout` is already declared in manager.go by Task 5.)

- [ ] **Step 3: Implement ProxySQL launch + admin provisioning** (append to `internal/pooler/proxysql.go`)

```go
import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	_ "github.com/go-sql-driver/mysql" // registers the "mysql" driver for admin provisioning

	"github.com/technopoetic/credproxy/internal/config"
)

// startProxySQL writes a secret-free cnf, launches with --initial (fresh
// runtime DB from the file), waits for both interfaces, then provisions the
// user rows through the admin interface — the real password enters ProxySQL's
// runtime memory via SQL and never lands in the static config file.
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
```

- [ ] **Step 4: Build and vet**

Run: `go build ./... && go vet ./...`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add internal/pooler/ go.mod go.sum
git commit -m "Add pgbouncer and ProxySQL launch with admin-interface provisioning

ProxySQL's static cnf stays secret-free: the real backend credential is
injected through the admin interface after startup, so the on-disk file a
hunting process would find holds interfaces and servers but no passwords."
```

---

### Task 7: Manager — orchestration, env computation, strip list, binary discovery

**Files:**
- Modify: `internal/pooler/manager.go` (add Manager on top of Task 5 primitives)
- Test: `internal/pooler/manager_test.go`

**Interfaces:**
- Consumes: `startPgbouncer`/`startProxySQL` from Task 6; `proc` from Task 5; `config.Config` from Tasks 2–3.
- Produces (consumed by Task 8):
  - `func NewManager(cfg *config.Config, logger *slog.Logger, logFile io.Writer) *Manager`
  - `func (m *Manager) Start(ctx context.Context) error`
  - `func (m *Manager) Stop()` — idempotent, safe with no poolers
  - `Manager.Env map[string]string` (injected vars), `Manager.Strip []string` (inherited names to strip)

- [ ] **Step 1: Write failing tests**

```go
func TestManagerNoDatabasesIsNoop(t *testing.T) {
	m := NewManager(&config.Config{}, testLogger(t), io.Discard)
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m.Env != nil || len(m.Strip) != 0 {
		t.Fatalf("no-op manager must not set env/strip: env=%v strip=%v", m.Env, m.Strip)
	}
	m.Stop() // must be safe with nothing running
}

func TestManagerMissingBinaryFailsFast(t *testing.T) {
	cfg := &config.Config{
		Databases: map[string]config.DatabaseConfig{
			"mydb": {Engine: "postgres", Host: "h", Port: 5432, User: "u", Password: "p", Database: "d", Env: "DATABASE_URL"},
		},
		PgbouncerPath: "/nonexistent/pgbouncer",
	}
	m := NewManager(cfg, testLogger(t), io.Discard)
	err := m.Start(context.Background())
	if err == nil {
		t.Fatal("expected fail-fast on missing binary")
	}
	if !strings.Contains(err.Error(), "pgbouncer") {
		t.Fatalf("error should name the binary: %v", err)
	}
}

func TestComputeEnvURLsAndStrip(t *testing.T) {
	m := NewManager(&config.Config{}, testLogger(t), io.Discard)
	m.sqlPorts["postgres"] = 6432
	m.Env = map[string]string{}
	dbs := map[string]config.DatabaseConfig{
		"mydb": {Engine: "postgres", Host: "h", Port: 5432, User: "app_user", Password: "REAL", Database: "d", Env: "DATABASE_URL"},
	}
	m.computeEnv("postgres", "sesspw", dbs)
	want := "postgres://app_user:sesspw@127.0.0.1:6432/mydb"
	if m.Env["DATABASE_URL"] != want {
		t.Fatalf("env URL wrong: %s", m.Env["DATABASE_URL"])
	}
	if len(m.Strip) != 2 || m.Strip[0] != "DATABASE_URL" || m.Strip[1] != "PGPASSWORD" {
		t.Fatalf("strip list wrong: %v", m.Strip)
	}
}

func TestComputeEnvMySQLStrip(t *testing.T) {
	m := NewManager(&config.Config{}, testLogger(t), io.Discard)
	m.sqlPorts["mysql"] = 3307
	m.Env = map[string]string{}
	dbs := map[string]config.DatabaseConfig{
		"mdb": {Engine: "mysql", Host: "h", Port: 3306, User: "mu", Password: "REAL", Database: "d", Env: "MYSQL_URL"},
	}
	m.computeEnv("mysql", "sesspw", dbs)
	if m.Env["MYSQL_URL"] != "mysql://mu:sesspw@127.0.0.1:3307/mdb" {
		t.Fatalf("mysql env URL wrong: %s", m.Env["MYSQL_URL"])
	}
	if len(m.Strip) != 2 || m.Strip[1] != "MYSQL_PWD" {
		t.Fatalf("mysql strip list wrong: %v", m.Strip)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/pooler/ -run 'TestManager|TestComputeEnv' -v`
Expected: FAIL — `NewManager`/`Start`/`Stop`/`computeEnv`/`lookPath` undefined.

- [ ] **Step 3: Implement** (append to `internal/pooler/manager.go`)

```go
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
		switch engine {
		case "postgres":
			p, err = startPgbouncer(ctx, m.logger, m.logFile, bins[engine], dir, password, byEngine[engine])
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
```

manager.go imports grow to: `context, fmt, io, log/slog, os, os/exec, path/filepath (only if used), sort, strings, sync, time` plus `github.com/technopoetic/credproxy/internal/config`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/pooler/ -v && go build ./...`
Expected: PASS — Tasks 4, 5, 7 tests all green.

- [ ] **Step 5: Commit**

```bash
git add internal/pooler/manager.go internal/pooler/manager_test.go
git commit -m "Add pooler manager: lifecycle orchestration and child env computation

Binary discovery happens before any process starts so a missing pooler
fails the session cleanly instead of launching half-isolated."
```

---

### Task 8: Wrap mode integration — main.go wiring and env hygiene

**Files:**
- Modify: `cmd/credproxy/main.go`
- Test: `cmd/credproxy/main_test.go` (update existing `buildChildEnv` tests to the new signature; add strip/precedence tests)

**Interfaces:**
- Consumes: `pooler.NewManager/Start/Stop`, `Manager.Env/Strip` from Task 7; `cfg.ValidateDatabases/ResolveDatabasePasswords` from Task 3.
- Produces: complete wrap-mode behavior. `buildChildEnv(cfg, proxyPort, childPath, caCertPath, shimDir string, poolerEnv map[string]string, poolerStrip []string) []string`.

- [ ] **Step 1: Update existing tests to the new signature and add the new ones**

Existing four `buildChildEnv` call sites gain `, nil, nil`:

```go
env := buildChildEnv(&config.Config{}, "9999", "/usr/bin:/bin", "/tmp/ca.pem", "", nil, nil)
```

New tests:

```go
func TestBuildChildEnvStripsInheritedDatabaseEnv(t *testing.T) {
	t.Setenv("HOME", "/Users/test")
	t.Setenv("DATABASE_URL", "postgres://app_user:REALPW@prod.example.com/db")
	t.Setenv("PGPASSWORD", "REALPW")
	poolerEnv := map[string]string{"DATABASE_URL": "postgres://app_user:sess@127.0.0.1:6432/mydb"}

	env := buildChildEnv(&config.Config{}, "9999", "/usr/bin:/bin", "/tmp/ca.pem", "",
		poolerEnv, []string{"DATABASE_URL", "PGPASSWORD"})
	for _, e := range env {
		if strings.HasPrefix(e, "DATABASE_URL=postgres://app_user:REALPW@") {
			t.Fatalf("inherited real DATABASE_URL leaked into child env: %s", e)
		}
		if strings.HasPrefix(e, "PGPASSWORD=") {
			t.Fatalf("PGPASSWORD leaked into child env: %s", e)
		}
	}
	found := false
	for _, e := range env {
		if e == "DATABASE_URL=postgres://app_user:sess@127.0.0.1:6432/mydb" {
			found = true
		}
	}
	if !found {
		t.Fatal("pooler URL not injected into child env")
	}
}

func TestBuildChildEnvPoolerWinsOverConfigEnv(t *testing.T) {
	t.Setenv("HOME", "/Users/test")
	cfg := &config.Config{Env: map[string]string{"DATABASE_URL": "postgres://config-value@confighost/db"}}
	env := buildChildEnv(cfg, "9999", "/usr/bin:/bin", "/tmp/ca.pem", "",
		map[string]string{"DATABASE_URL": "postgres://pooler-value@127.0.0.1:6432/mydb"}, nil)
	var last string
	for _, e := range env {
		if strings.HasPrefix(e, "DATABASE_URL=") {
			last = e
		}
	}
	if last != "DATABASE_URL=postgres://pooler-value@127.0.0.1:6432/mydb" {
		t.Fatalf("pooler env must win over [env] config (os/exec last-wins): %q", last)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/credproxy/ -run 'TestBuildChildEnv' -v`
Expected: FAIL — compile error (wrong argument count).

- [ ] **Step 3: Implement**

`main()` in `cmd/credproxy/main.go`, after the resolver is configured and before `runWrap`:

```go
	if err := cfg.ValidateDatabases(); err != nil {
		fmt.Fprintf(os.Stderr, "invalid database config: %v\n", err)
		os.Exit(1)
	}

	if err := cfg.ResolveEnv(context.Background(), res); err != nil {
		fmt.Fprintf(os.Stderr, "failed to resolve env credentials: %v\n", err)
		os.Exit(1)
	}

	if err := cfg.ResolveDatabasePasswords(context.Background(), res); err != nil {
		fmt.Fprintf(os.Stderr, "failed to resolve database credentials: %v\n", err)
		os.Exit(1)
	}

	runWrap(cfg, caProvider, res, logger, logFile, args)
```

`runWrap` — new signature and pooler wiring (rest of the function unchanged):

```go
func runWrap(cfg *config.Config, caProvider *ca.Provider, res *resolver.Resolver, logger *slog.Logger, logFile *os.File, command []string) {
	addr := ":0"
	srv := mitm.New(addr, caProvider, res, logger)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to start proxy: %v\n", err)
		os.Exit(1)
	}
	defer ln.Close()

	go srv.Serve(ln)

	// Poolers start before the child exists so the injected URLs are known;
	// Start is a no-op when no [databases.*] are configured.
	mgr := pooler.NewManager(cfg, logger, logFile)
	if err := mgr.Start(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start database poolers: %v\n", err)
		os.Exit(1)
	}
	defer mgr.Stop()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())

	childPath, shimDir, cleanupShims := stripSecretStoreCLIs(os.Getenv("PATH"))
	defer cleanupShims()
	caCertPath, err := caProvider.WriteTrustBundle(config.DefaultCADir())
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to write CA trust bundle: %v\n", err)
		os.Exit(1)
	}
	childEnv := buildChildEnv(cfg, portStr, childPath, caCertPath, shimDir, mgr.Env, mgr.Strip)
	// ... remainder of the existing function unchanged ...
}
```

`buildChildEnv` — new signature, strip check, and pooler-env precedence:

```go
func buildChildEnv(cfg *config.Config, proxyPort string, childPath string, caCertPath string, shimDir string, poolerEnv map[string]string, poolerStrip []string) []string {
	strip := make(map[string]bool, len(poolerStrip))
	for _, k := range poolerStrip {
		strip[k] = true
	}
	env := os.Environ()
	configEnv := cfg.EnvVars()
	filtered := make([]string, 0, len(env)+len(configEnv)+len(poolerEnv))
	prevBashEnv := os.Getenv("BASH_ENV")
	for _, e := range env {
		key := strings.SplitN(e, "=", 2)[0]
		// (all existing `continue` branches stay exactly as they are)
		if strip[key] {
			// An inherited DB credential would defeat pooler isolation.
			continue
		}
		if _, ok := configEnv[key]; ok {
			continue
		}
		filtered = append(filtered, e)
	}
	for k, v := range configEnv {
		filtered = append(filtered, k+"="+v)
	}
	// Pooler URLs go last: os/exec keeps the last value for duplicate keys,
	// so they win over both inherited values and [env] config values.
	for k, v := range poolerEnv {
		filtered = append(filtered, k+"="+v)
	}
	filtered = append(filtered,
		"PATH="+childPath,
		"HTTPS_PROXY=http://localhost:"+proxyPort,
		// ... remainder identical ...
	)
	// ... shimDir block identical ...
	return filtered
}
```

Add the import: `"github.com/technopoetic/credproxy/internal/pooler"`.

- [ ] **Step 4: Run the full suite**

Run: `go test ./...`
Expected: PASS — all packages.

- [ ] **Step 5: Commit**

```bash
git add cmd/credproxy/main.go cmd/credproxy/main_test.go
git commit -m "Wire pooler manager into wrap mode with env hygiene

Inherited DATABASE_URL/PGPASSWORD/MYSQL_PWD are stripped so a parent
shell's real credential cannot silently bypass the pooler, and pooler
URLs are appended last so they win over [env] config collisions."
```

---

### Task 9: Docs — config examples, README, AGENTS.md

**Files:**
- Modify: `internal/config/default-config.toml` (embedded first-run config)
- Modify: `config.toml.example`
- Modify: `README.md`
- Modify: `AGENTS.md`

**Interfaces:**
- Consumes: final behavior from Task 8.
- Produces: documentation only.

- [ ] **Step 1: Add a commented `[databases]` block to both config examples**

Append to `internal/config/default-config.toml` and `config.toml.example` (identical text):

```toml
# Database credential isolation (optional)
# Each entry starts a local pooler at session start (pgbouncer for postgres,
# ProxySQL for mysql); the wrapped child gets <env> pointing at 127.0.0.1
# with a random per-session password. The real password never reaches the
# child. Requires the pgbouncer / proxysql binaries on PATH (or *_path
# overrides below).
#
# [databases.mydb]
# engine = "postgres"              # or "mysql"
# host = "db.example.com"
# port = 5432
# user = "app_user"
# password = "op://Private/mydb/password"   # op:// URI or literal
# database = "appdb"
# params = "sslmode=require"       # optional, engine-interpreted
# env = "DATABASE_URL"             # env var injected into the wrapped child
#
# pgbouncer_path = "/usr/local/bin/pgbouncer"   # optional binary overrides
# proxysql_path = "/usr/local/bin/proxysql"
```

- [ ] **Step 2: Add a README section**

After the existing env/profile documentation, add:

````markdown
## Database Credential Isolation

`[databases.*]` entries keep real database passwords out of the wrapped
process. At session start credproxy launches a local pooler — pgbouncer for
`engine = "postgres"`, ProxySQL for `engine = "mysql"` — that authenticates
the child with a random per-session password while authenticating to the real
database with the real credential (resolved from `op://` at startup, like
host credentials). The child receives a localhost-only connection string via
the env var you name in `env`:

```toml
[databases.mydb]
engine = "postgres"
host = "db.example.com"
port = 5432
user = "app_user"
password = "op://Private/mydb/password"
database = "appdb"
env = "DATABASE_URL"
```

The child sees `DATABASE_URL=postgres://app_user:<random>@127.0.0.1:<port>/mydb`
and every driver/ORM works unchanged — no sentinel convention to learn. Inherited
`DATABASE_URL`, `PGPASSWORD`, and `MYSQL_PWD` are stripped from the child env.

**Honest limitation:** the real password exists in session-scoped `0600` files
under a temp dir (and in ProxySQL's runtime state) for the life of the
session. A same-user process that deliberately hunts the filesystem can find
it. This scheme kills the accidental leak paths — env vars, `.env` files,
logs, prompts — not a targeted same-user attacker.

**Requirements:** `pgbouncer` / `proxysql` binaries on PATH, or
`pgbouncer_path` / `proxysql_path` set in config. A missing binary fails
startup rather than running unprotected.
````

- [ ] **Step 3: Update AGENTS.md**

Add to Project State list:

```markdown
- DB credential isolation: `[databases.*]` config entries start session-scoped
  poolers (pgbouncer/ProxySQL) at wrap time; child gets a localhost-only URL
  with a random per-session password, real `op://`-resolved credential stays
  backend-side. `internal/pooler/`. ProxySQL users are provisioned through the
  admin interface at startup so the static cnf holds no secrets.
```

Add to Architecture list:

```markdown
- `internal/pooler/` — Session-scoped pgbouncer/ProxySQL lifecycle and config generation
```

Add a Known Issues line:

```markdown
- MySQL live testing on the dev machine has no proxysql binary available (no
  Homebrew; mise registry lacks it); ProxySQL mechanics are spike-verified in
  containers and the credproxy launch path is covered by fake-binary tests.
```

- [ ] **Step 4: Commit**

```bash
git add internal/config/default-config.toml config.toml.example README.md AGENTS.md
git commit -m "Document database credential isolation

Config examples, README security model, and AGENTS.md project state;
the documented temp-dir limitation is stated plainly rather than buried."
```

---

### Task 10: Live verification — containers up, host pgbouncer build, run `-tags live`

**Files:**
- Create: `internal/pooler/live_test.go` (build-tag guarded)
- Create: `docs/live-testing-db-poolers.md`
- Modify: `go.mod` / `go.sum` (add `github.com/lib/pq` for the live client)

**Interfaces:**
- Consumes: the full stack from Tasks 4–8; container images for target DBs.
- Produces: evidence (test output) and a reproducible live-test procedure.

- [ ] **Step 1: Write the live test** (`internal/pooler/live_test.go`)

```go
//go:build live

// Live verification against real servers. Guarded by the `live` build tag so
// normal `go test ./...` never touches the network:
//
//	go test -tags live -run TestLive ./internal/pooler/ -v
//
// Env vars: CREDPROXY_LIVE_PG_HOST/PORT/USER/PASSWORD/DATABASE and
// CREDPROXY_LIVE_MYSQL_HOST/PORT/USER/PASSWORD/DATABASE.
package pooler

import (
	"context"
	"database/sql"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/technopoetic/credproxy/internal/config"
)

func TestLivePostgres(t *testing.T) {
	cfg := &config.Config{
		Databases: map[string]config.DatabaseConfig{
			"mydb": {
				Engine: "postgres",
				Host:   requireEnv(t, "CREDPROXY_LIVE_PG_HOST"),
				Port:   requireEnvInt(t, "CREDPROXY_LIVE_PG_PORT"),
				User:   requireEnv(t, "CREDPROXY_LIVE_PG_USER"),
				// The manager must resolve op:// before Start; live tests pass
				// literals and skip resolution by calling Start directly.
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
	m := NewManager(cfg, testLogger(t), io.Discard)
	defer m.Stop()
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("manager start: %v", err)
	}
	dsn := m.Env["DATABASE_URL"]
	if !strings.Contains(dsn, "@127.0.0.1:") {
		t.Fatalf("URL must point at loopback: %s", dsn)
	}
	realPW := cfg.Databases["mydb"].Password
	if realPW == "" {
		realPW = cfg.Databases["mdb"].Password
	}
	if realPW != "" && strings.Contains(dsn, realPW) {
		t.Fatal("real password leaked into injected URL")
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
```

- [ ] **Step 2: Add the live client dependency**

```bash
go get github.com/lib/pq
go mod tidy
```

- [ ] **Step 3: Bring up target databases**

```bash
docker run -d --name credproxy-live-pg \
  -e POSTGRES_USER=app_user -e POSTGRES_PASSWORD=realpgpass -e POSTGRES_DB=appdb \
  -p 15432:5432 docker.io/library/postgres:16-alpine
docker run -d --name credproxy-live-mysql \
  -e MYSQL_ROOT_PASSWORD=rootpass -e MYSQL_USER=app_user -e MYSQL_PASSWORD=realmysqlpass \
  -e MYSQL_DATABASE=appdb -p 13306:3306 \
  docker.io/library/mysql:8.0
# wait for readiness, then (if the spike found mysql_native_password needed):
docker exec credproxy-live-mysql mysql -uroot -prootpass \
  -e "ALTER USER 'app_user' IDENTIFIED WITH mysql_native_password BY 'realmysqlpass'; FLUSH PRIVILEGES;"
```

- [ ] **Step 4: Obtain a host pgbouncer binary**

This machine has no Homebrew and mise lacks pgbouncer; build from source (libevent and openssl are present):

```bash
mise ls-remote pandoc | tail -1          # pick latest
mise install pandoc@<latest>             # pgbouncer's build needs pandoc
git clone --depth 1 --branch <latest-stable-tag> https://github.com/pgbouncer/pgbouncer.git /tmp/pgbouncer-src
cd /tmp/pgbouncer-src
./configure --prefix=/tmp/pgbouncer-install
make -j4 && make install
# binary lands at /tmp/pgbouncer-install/bin/pgbouncer
```

If the build fails, STOP and record the failure in `docs/live-testing-db-poolers.md`; fall back to running pgbouncer in a container and note that the host end-to-end path for Postgres is verified only via the spike. Do not silently skip.

- [ ] **Step 5: Run the Postgres live test**

```bash
CREDPROXY_LIVE_PG_HOST=127.0.0.1 \
CREDPROXY_LIVE_PG_PORT=15432 \
CREDPROXY_LIVE_PG_USER=app_user \
CREDPROXY_LIVE_PG_PASSWORD=realpgpass \
CREDPROXY_LIVE_PG_DATABASE=appdb \
PGBOUNCER_PATH=/tmp/pgbouncer-install/bin/pgbouncer \
go test -tags live -run TestLivePostgres ./internal/pooler/ -v
```

Note: `PGBOUNCER_PATH` must reach the manager — if the live config above doesn't set `PgbouncerPath`, add `PgbouncerPath: os.Getenv("PGBOUNCER_PATH")` to the live test's config (only when the env var is set) rather than installing the binary system-wide. Expected: PASS with the query round-tripping through pgbouncer.

- [ ] **Step 6: Run the MySQL live test (expected environment gap)**

```bash
CREDPROXY_LIVE_MYSQL_HOST=127.0.0.1 \
CREDPROXY_LIVE_MYSQL_PORT=13306 \
CREDPROXY_LIVE_MYSQL_USER=app_user \
CREDPROXY_LIVE_MYSQL_PASSWORD=realmysqlpass \
CREDPROXY_LIVE_MYSQL_DATABASE=appdb \
PROXYSQL_PATH=/nonexistent \
go test -tags live -run TestLiveMySQL ./internal/pooler/ -v
```

Expected: FAILS at binary discovery (`proxysql binary not found on PATH`) — this is the documented environment gap (no Homebrew, no mise formula, source build not viable on this host). The ProxySQL mechanics themselves are spike-verified in containers (Task 1). Record the outcome honestly in `docs/live-testing-db-poolers.md`.

- [ ] **Step 7: Write the live-test procedure doc**

`docs/live-testing-db-poolers.md` documents: container bring-up commands (Step 3), pgbouncer build (Step 4), the two test invocations, teardown (`docker rm -f credproxy-live-pg credproxy-live-mysql`), and the status of each path on this machine (Postgres: host end-to-end verified / MySQL: spike-verified in containers, host launch blocked on binary availability — with the three options: accept documented procedure, amend spec for container-launched poolers, or install Homebrew/obtain proxysql).

- [ ] **Step 8: Clean teardown and commit**

```bash
docker rm -f credproxy-live-pg credproxy-live-mysql
git add internal/pooler/live_test.go docs/live-testing-db-poolers.md go.mod go.sum
git commit -m "Add live tests and procedure for pooler verification

The live tag keeps network-dependent tests out of CI; Postgres is verified
end-to-end on the host, MySQL is spike-verified in containers pending a
proxysql binary for this machine."
```

---
