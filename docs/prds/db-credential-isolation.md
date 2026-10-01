# credproxy DB Credential Isolation — PRD

## What

Add local database credential isolation to credproxy's wrap mode. credproxy starts a session-scoped pooler (pgbouncer for Postgres, ProxySQL for MySQL) that authenticates the child process with a random per-session password while authenticating to the real database with the real credential, resolved from 1Password at startup. The child receives a localhost-only connection string via env var injection. The real DB password never appears in the child's environment, config files, or process arguments.

## Why

credproxy's MITM proxy keeps HTTP credentials out of agent hands, but database credentials entered in config or `.env` files are handed directly to the child. An agent that logs its env, leaks a connection string into a prompt, or exfiltrates a `.env` file leaks the real DB password. This applies IronCurtain's "agent never holds the real secret" principle (see note: DB Credential Isolation Tool) to database access by reusing poolers whose client-auth vs backend-auth decoupling is a native, first-class feature — no custom wire-protocol parsing.

The agent's DB driver/ORM/client works completely normally: it connects to `127.0.0.1:<port>` with a password that is only valid against our own pooler. No sentinel-typing convention is needed (unlike the HTTP `CREDPROXY_TOKEN` pattern).

## How It Works

```
$ credproxy opencode
    │
    ├─ Load global + project config, apply profile (existing)
    ├─ Resolve op:// credentials in [env] (existing)
    ├─ Resolve op:// passwords in [databases.*] (new)
    ├─ Generate pooler configs in session temp dir, 0600 (new)
    ├─ Start one pooler process per engine with databases configured (new)
    ├─ Start MITM proxy on random port (existing)
    ├─ Inject env vars, including per-database connection URLs (new)
    ├─ Strip inherited env vars that collide with injected URLs (new)
    ├─ Exec child process
    │
    │   Agent connects to postgres://app_user:<random>@127.0.0.1:<port>/mydb
    │       ↓ pgbouncer authenticates client (random password, SCRAM)
    │       ↓ pgbouncer connects to real host with real password (forced user)
    │
    └─ When child exits: kill poolers, remove temp dir, proxy shuts down
```

## Phase 1 Scope

**Goal: keep real DB credentials out of the agent's hands. Nothing else.**

Explicitly OUT of scope (deferred, not forgotten):

- Query-level policy (read-only enforcement, table/column allowlists, statement-type restrictions)
- SQL parsing / AST-based inspection
- Row caps, query timeouts, query audit logging
- Escalation/approval workflows for writes or DDL
- A semantic MCP-style query gateway (`db_query(sql)`) — needs a real SQL parser per engine and doesn't generalize to non-SQL stores
- Engines without a native client/backend auth-split pooler (Mongo, Neo4j, Redis) — phase 1 fails config validation with a clear error if configured
- Fixed pooler listen ports (same known gap as the HTTP proxy: a long-lived child can outlive the session pooler; noted in credproxy's AGENTS.md "Remaining Work")
- Unix domain socket injection (driver-specific URL syntax breaks ORMs that only parse tcp URLs)
- Kernel-level egress enforcement (sandbox-exec) — tracked separately in credproxy's AGENTS.md

## Config Format

New `[databases.*]` section in the existing cascading config (global + project merge, profile overlay — both free via existing machinery):

```toml
[databases.mydb]
engine = "postgres"                          # "postgres" | "mysql"
host = "db.example.com"                      # real target host
port = 5432                                  # real target port
user = "app_user"                            # real username
password = "op://Private/mydb/password"      # op:// URI or literal
database = "appdb"                           # real database name
params = "sslmode=require"                   # optional, engine-interpreted
env = "DATABASE_URL"                         # env var name injected into child
```

### Why discrete fields, not a URL

Parsing `postgres://user:op://Private/x/y@host/db` is ambiguous — the `op://` path contains slashes that collide with URL structure. Discrete fields are unambiguous, merge per-field, and credproxy constructs both the pooler config and the injected URL itself, so no URL parsing of secrets ever ships.

### Field semantics

| Field | Required | Notes |
|------|----------|-------|
| `engine` | yes | `postgres` or `mysql`; anything else fails config validation |
| `host` | yes | Real database host |
| `port` | yes | Real database port |
| `user` | yes | Real username; also used as the pooler client username (least surprise for ORMs) |
| `password` | yes | Real password; `op://` URIs resolved at startup via the existing provider registry |
| `database` | yes | Real database name |
| `params` | no | Engine-interpreted passthrough: pgbouncer gets it verbatim in the `[databases]` line (`sslmode=require`); ProxySQL maps supported values (`use_ssl=1` → `use_ssl`) |
| `env` | yes | Name of the env var injected into the child. Entries must have unique `env` names |

### Injected URL shape

```
DATABASE_URL=postgres://app_user:<random-session-password>@127.0.0.1:<port>/mydb
DATABASE_URL=mysql://app_user:<random-session-password>@127.0.0.1:<port>/mydb
```

- `<random-session-password>`: 32 bytes from crypto/rand, base64 (URL-safe), generated per credproxy session. Not the literal `CREDPROXY_TOKEN` sentinel — an agent that knows credproxy's conventions could guess the sentinel; it cannot guess a random per-session value.
- `mydb` is the config entry name, used as the pooler-side database alias. Two entries pointing at real databases with colliding names don't conflict. When entry name equals the real database name (the common case), this is invisible.
- Client username is the real username. Client password is the random per-session value.

## Credential Split Mechanics

### Postgres — pgbouncer

Generated `pgbouncer.ini` (in session temp dir, 0600):

```ini
[databases]
mydb = host=db.example.com port=5432 dbname=appdb user=app_user password=<REAL> sslmode=require

[pgbouncer]
listen_addr = 127.0.0.1
listen_port = <picked>
auth_type = scram-sha-256
auth_file = <tempdir>/userlist.txt
pool_mode = session
unix_socket_dir = <tempdir>
pidfile = <tempdir>/pgbouncer.pid
; admin_users intentionally unset — the "pgbouncer" admin console is unreachable
```

`userlist.txt` (0600): `"app_user" "<random-session-password>"` (plaintext — pgbouncer derives the SCRAM exchange from it).

Split: client auth comes from `auth_file` (random password); backend auth is forced by the `[databases]` line's `user=`/`password=` (real credential). Per pgbouncer docs: "When the user is part of the connection string, the connection between PgBouncer and PostgreSQL is forced to the given user, whatever the client user." The real password never appears in any client-visible surface.

Known upstream issue pgbouncer#1461 (SCRAM + forced user) only bites when `use_scram_keys = true`, which we never set. The implementation spike verifies forced-user SCRAM end-to-end against a real server regardless; documented fallback if a backend SCRAM incompatibility appears: `auth_type = plain` client auth (loopback-only exposure).

### MySQL — ProxySQL

ProxySQL is configured via its admin interface (SQLite-backed) rather than a static file describing users. Startup sequence: write a minimal `proxysql.cnf` (randomized admin credentials, admin interface bound to 127.0.0.1 on a picked port, SQL frontend bound to 127.0.0.1 on a picked port, one hostgroup containing the real server, disk DB in the session temp dir), start `proxysql --initial -f -c <tempdir>/proxysql.cnf` (foreground), then feed it the split-credential user config through the admin interface.

`mysql_users` rows per database — frontend and backend decoupled (documented ProxySQL capability: "A user can have both flags set to 1, or they can be decoupled for advanced security architectures"):

- Frontend row: `username=app_user`, `password=<random>`, `frontend=1`, `backend=0`, `default_hostgroup=0`
- Backend row: `username=app_user`, `password=<REAL>`, `frontend=0`, `backend=1`

The exact dual-row mechanics (vs. the newer `attributes` overlay) are pinned in the implementation spike against the ProxySQL version we test with; the tested version is documented.

### Auth flow summary

| | Client → pooler | Pooler → real DB |
|---|---|---|
| Username | real username | real username |
| Password | random per-session | real, from `op://` or literal |
| Visible to child | yes (this pair only) | never |

## Security Model Impact

What this stops (the realistic leak paths):

- Real password in child env, `.env` files, dotenv dumps, `printenv`, error messages, prompts — the child only ever holds a localhost-only pair
- Credential replay outside the machine — the random password is worthless off-box and dies with the session
- Cross-session credential reuse — every session gets fresh random client credentials

The honest gap (documented, not hidden): the real password exists in the pooler's config — `0600` files in a session temp dir (`os.MkdirTemp`, `0700`), deleted on session exit. A same-user process that deliberately goes filesystem-hunting can read it. This is weaker than the HTTP side, where the real secret exists only in credproxy's memory. Phase 1 accepts this because it kills the common accidental-leak paths; stronger options (backend `auth_query` so the pooler fetches the password at connect time, config truncation after startup) are phase 2.

Related exposure: the random client password is visible to the child (necessarily — it must connect). It grants access only through the pooler, which is exactly the intended isolation boundary.

### Env hygiene (critical detail)

credproxy already filters inherited env before spawning the child. It additionally:

- Strips any inherited env var whose name matches a configured database's `env` name — a real `DATABASE_URL` in the parent shell must not silently defeat the scheme
- Strips `PGPASSWORD` when any postgres database is configured, `MYSQL_PWD` when any mysql database is configured (the engines' standard CLI password vars)

Pooler-injected URLs override `[env]` config values on name collision. Documented: don't put DB URLs in `[env]` when using `[databases.*]`.

## Pooler Lifecycle

- Binary discovery: `exec.LookPath("pgbouncer" / "proxysql")`, overridable per engine via config (`pgbouncer_path`, `proxysql_path`). A missing binary for an engine that has configured databases → fail-fast at startup with an actionable message; engines with no configured databases are never checked. Silently running without isolation would be worse than not starting (same philosophy as `op://` resolution failure).
- One pooler process per engine per session (a single pgbouncer serves all postgres entries via aliases; same for ProxySQL). No databases configured → pooler machinery never runs, zero behavior change.
- Pooler stderr piped to credproxy's log file.
- Ports: pre-picked free ports (bind `:0`, close, reuse — small race window, acceptable for local dev; ProxySQL has no port-0 support). One rebind retry on collision.
- Crash after startup: surfaced in credproxy's log, session continues — the child's DB calls fail visibly (same philosophy as the MITM proxy dying).
- Signals: existing SIGINT/SIGTERM forwarding extended — child gets the signal (existing behavior), poolers are terminated, temp dir removed. Normal child exit: kill poolers, remove temp dir, exit with child's code.

## Implementation Plan

### 1. Config (`internal/config/config.go`)

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

type Config struct {
    // existing fields...
    Databases map[string]DatabaseConfig `toml:"databases"`
}
```

- `[databases.*]` participates in global+project merge (project wins per field) and profile overlay (`[profiles.<name>.databases]`)
- Validation: engine ∈ {postgres, mysql}, unique `env` names, required fields present
- Password resolution: extend the startup resolution phase to resolve `op://` values in `Databases[*].Password` (same resolver, same 30s per-call timeout, fail-fast on error)

### 2. Pooler package (`internal/pooler/`)

- `manager.go` — lifecycle owner: temp dir, per-engine process start/stop, env var computation for injection, signal/cleanup wiring
- `pgbouncer.go` — pgbouncer config generation + launch
- `proxysql.go` — ProxySQL config generation, launch, admin-interface provisioning
- Engine interface kept narrow (Generate, Start, Stop) but no premature abstraction beyond the two engines

### 3. Wrap mode integration (`cmd/credproxy/main.go`)

- After config resolution, before child exec: `pooler.Manager` starts engines, computes injected vars
- `buildChildEnv` extended: strip colliding inherited vars, add injected URLs
- Signal handling and shutdown extended to stop poolers and remove the temp dir

## Testing

- **Unit (no Docker):** config parse/merge/profile with `[databases.*]`; validation errors; pgbouncer.ini / userlist.txt / proxysql.cnf generation (assert content, no real secrets in client-visible sections); URL construction; env stripping logic
- **Spike (first implementation step, throwaway scripts):** against Dockerized Postgres + MySQL — verify pgbouncer forced-user SCRAM split and ProxySQL frontend/backend dual-row split end-to-end before building around them; record ProxySQL version and exact working row config
- **Live (documented manual procedure):** `docker run postgres` / `docker run mysql`; wrap a small Go client or `psql`/`mysql` CLI under credproxy; assert connection succeeds, child env contains only the localhost URL with the random password, and the real password appears nowhere in child env or `ps` output

## Acceptance Criteria

- `credproxy <cmd>` with a configured postgres database: child's `DATABASE_URL` points at `127.0.0.1:<port>` with the random password; connections work; real password absent from child env
- Same for mysql via ProxySQL
- No `[databases.*]` in config → behavior identical to today
- Missing pgbouncer/proxysql binary → startup fails with actionable error
- Inherited `DATABASE_URL` stripped when a database with `env="DATABASE_URL"` is configured; `PGPASSWORD`/`MYSQL_PWD` stripped per engine
- Two entries with colliding real database names work (aliasing)
- `op://` password resolution failure → startup fails fast
- Poolers terminate and temp dir removed on child exit and on SIGINT/SIGTERM
- Real password absent from client-visible pooler surfaces (injected URLs, userlist.txt)

## Non-Goals

- Query-level policy, SQL parsing, audit logging, rate/timeout limits, approval workflows
- MCP-style semantic query gateway
- Mongo / Neo4j / Redis / other non-auth-split engines
- Fixed listen ports or persistent (daemon) poolers
- TLS on the pooler listener (loopback only)
- Windows support (pooler binaries and process handling are POSIX-oriented, matching credproxy today)

## Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| pgbouncer forced-user SCRAM edge cases (#1461) | Low | High — postgres support broken | Spike first; `use_scram_keys` never set; documented `plain` fallback (loopback-only) |
| ProxySQL dual-row semantics vary by version | Medium | High — mysql support broken | Spike pins tested version; document exact working config |
| Port collision race (bind-close-reuse) | Low | Low — one retry, then fail | Retry once; fail with clear message |
| Real password readable in temp dir by same-user processes | Certain | Medium — accidental-leak paths closed, targeted inspection not | Documented gap; phase 2 auth_query |
| Long-lived child outlives session pooler | Low | Medium — dead URL in long-running service | Same known gap as HTTP proxy; future fixed-port work |
| Parent-shell `DATABASE_URL` silently defeats scheme | Medium if unhandled | High | Strip matching inherited vars; acceptance criterion |
| User puts real DB URL in `[env]` instead of `[databases.*]` | Medium | High — real credential in child env | Pooler vars win on collision; docs; README guidance |

## Out of Scope (Future)

- `auth_query` backend credential fetch (removes the temp-file gap)
- Pooler config truncation after startup
- Fixed listen ports for long-lived children
- Additional engines (via auth-split-capable poolers only)
- Query policy / audit (phase 2+)
