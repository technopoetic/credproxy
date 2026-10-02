# credproxy DB Credential Isolation — PRD (amended: embedded auth-split relay)

> **Amendment (2026-10-01, same day as original).** The original spec fronted
> databases with external poolers (pgbouncer for Postgres, ProxySQL for
> MySQL, launched as host binaries). That mechanism is superseded. Why: the
> pooler binaries are unobtainable on macOS (no brew formula, no darwin
> artifacts upstream, no MacPorts port — all verified), source builds are
> snowflakes, container-per-session launch was rejected as violating
> credproxy's size/simplicity model, and the feature must be team-portable —
> one `go install credproxy` with zero extra installs. The replacement keeps
> every property the original was chosen for and drops the dependency on any
> external binary or container. The original mechanism lives in git history.

## What

Add database credential isolation to credproxy's wrap mode. For each configured `[databases.*]` entry, credproxy itself listens on a local port and runs an **embedded auth-split relay**: it authenticates the child process with a random per-session password, opens the backend connection with the real `op://`-resolved credential (held only in credproxy's memory), and then relays bytes transparently. The child receives a localhost-only connection string via env var injection. The real DB password never appears in the child's environment, config files, process arguments, **or anywhere on disk**.

No external pooler binary. No container. No pooling or multiplexing — one backend connection per client connection.

## Why

credproxy's MITM proxy keeps HTTP credentials out of agent hands, but database credentials in config or `.env` files are handed directly to the child, and any leak path (env dumps, `.env` exfiltration, logs, prompts) leaks the real password. This applies IronCurtain's "agent never holds the real secret" principle to database access.

The original note's "don't build a custom DB wire-protocol parser" was a judgment about **poolers** — parsing, pooling, routing, multiplexing. None of that is needed here. A relay needs only the connection handshake: authenticate the local client, open the authenticated backend, then behave like credproxy's existing CONNECT tunnel for unconfigured hosts — a byte pipe. Protocol fiddly bits are delegated to vetted pure-Go libraries (`jackc/pgx`'s pgproto3, `xdg-go/scram`, `go-mysql-org/go-mysql`) rather than hand-rolled. Query interpretation remains out of scope, exactly as before.

Team portability is the binding constraint: credproxy is one Go binary; the DB isolation feature must not change that.

## How It Works

```
$ credproxy opencode
    │
    ├─ Load global + project config, apply profile (existing)
    ├─ Resolve op:// credentials in [env] and [databases.*] (existing)
    ├─ For each database entry: net.Listen on 127.0.0.1:<picked port> (new)
    ├─ Inject env vars, including per-database connection URLs (new)
    ├─ Strip inherited env vars that collide with injected URLs (new)
    ├─ Exec child process
    │
    │   Agent connects to postgres://app_user:<random>@127.0.0.1:<port>/mydb
    │       ↓ relay authenticates client (session password)
    │       ↓ relay connects to real host with real password (memory-only)
    │       ↓ bytes relayed both ways until either side closes
    │
    └─ Child exits → listeners close, goroutines gone; nothing survives
```

## Phase 1 Scope

**Goal: keep real DB credentials out of the agent's hands. Nothing else.**

Explicitly OUT of scope (deferred, not forgotten):

- Query-level policy (read-only enforcement, table/column allowlists, statement-type restrictions)
- SQL parsing / AST-based inspection — the relay never looks at post-auth traffic
- Row caps, query timeouts, query audit logging
- Escalation/approval workflows for writes or DDL
- A semantic MCP-style query gateway (`db_query(sql)`)
- Connection pooling / multiplexing (one backend connection per client connection; the word "pooler" is hereby retired)
- Engines other than postgres and mysql
- TLS on the local relay listener (loopback only)
- Kernel-level egress enforcement (sandbox-exec) — tracked separately in credproxy's AGENTS.md
- Windows support beyond what Go cross-compilation gives for free (the op/bw shim machinery is POSIX-oriented, as today)

## Config Format

**Unchanged from the original spec.** `[databases.*]` with discrete fields (engine, host, port, user, password, database, params, env), cascading global+project merge (whole-entry replacement), profile overlay, `op://` resolution with fail-fast, validation (engine whitelist, required fields, port range, unique env names, reserved env names, unique mysql usernames, no whitespace in postgres-interpolated fields — all already implemented).

`params` is engine-interpreted backend connection tuning:

| Engine | Param | Values | Default |
|---|---|---|---|
| postgres | `sslmode` | `disable`, `prefer`, `require`, `verify-full` | `prefer` (attempt TLS, allow fallback) |
| mysql | `sslmode` | `disabled`, `required`, `verify_ca`, `verify_identity` | (no TLS) |
| mysql | `use_ssl` | `0`, `1` (legacy alias for sslmode) | `0` |

### Injected URL shape

```
DATABASE_URL=postgres://app_user:<random-session-password>@127.0.0.1:<port>/mydb?sslmode=disable
DATABASE_URL=mysql://app_user:<random-session-password>@127.0.0.1:<port>/mydb
```

- `<random-session-password>`: 32 bytes from crypto/rand, base64url, generated per session — not the guessable `CREDPROXY_TOKEN` sentinel.
- The config entry name is the alias used as the database name in the URL (two entries with colliding real database names don't conflict).
- `sslmode=disable` on postgres URLs because the loopback leg does no TLS by design; backend-leg TLS is governed by `params`, a different leg.

## Credential Split Mechanics

The relay is a server toward the child and a client toward the real database. After authentication completes on both legs, it is a transparent byte pipe — prepared statements, extended query protocols, and driver quirks work by construction because nothing is interpreted.

### Postgres

- **Frontend (child → relay):** handle the `SSLRequest` probe (`'N'` — no SSL on loopback), read the `StartupMessage`, respond `AuthenticationCleartextPassword`, verify the session password, send `AuthenticationOk`, relay. Cleartext-password auth is supported by every Postgres client library; on loopback it exposes only the worthless session password.
- **Backend (relay → real server):** open a real connection with the real username; negotiate whatever the server's pg_hba demands:
  - `SCRAM-SHA-256` (default for modern servers) via `xdg-go/scram` client
  - `md5` (legacy, trivial salted-MD5)
  - cleartext password — only ever sent when the backend leg is TLS (`sslmode` in `params` demands it)
- The server chooses the method; the relay must speak all three.

### MySQL

- **Frontend (child → relay):** serve the Initial Handshake Packet offering `mysql_native_password` (the relay implements the SHA-1 challenge-response itself in Go — it needs no server-side plugin support, so MySQL 8.4/9.0 dropping the plugin server-side is irrelevant), verify the session-password token, send OK, relay. The relay chooses the plugin; clients universally support this one.
- **Backend (relay → real server):** client handshake with the real credentials:
  - `mysql_native_password`: SHA-1 challenge-response (safe over cleartext — the token is nonce-bound and non-reversible)
  - `caching_sha2_password` fast-auth path: SHA-256 token, also nonce-bound and non-reversible over cleartext
  - `caching_sha2_password` full-auth: the password would otherwise cross the wire in cleartext — so it is sent **RSA-OAEP-encrypted** with the server's public key over a cleartext channel, or in cleartext only when backend TLS is on (`use_ssl=1`)
- `go-mysql-org/go-mysql`'s server and client packages provide the handshake framing; anything they lack (notably full-auth RSA if absent upstream) is bounded, documented protocol work pinned by the spike.

### Auth flow summary

| | Client → relay | Relay → real DB |
|---|---|---|
| Username | real username | real username |
| Password | random per-session | real, from `op://` or literal |
| Visible to child | yes (this pair only) | never — memory-only inside credproxy |

## Security Model Impact

What this stops (the realistic leak paths):

- Real password in child env, `.env` files, dotenv dumps, `printenv`, error messages, prompts
- Credential replay off-box or after the session — the random password is worthless off-box and dies with the session
- Cross-session credential reuse — fresh random client credentials every session
- **Real password on disk — impossible by construction.** The original spec's documented gap (real password in 0600 temp files readable by a same-user process) no longer exists: the real password lives only in credproxy's process memory, same as the HTTP MITM side. Reading it requires debugger-grade privileges (`task_for_pid` entitlements on macOS), a materially stronger boundary than a filesystem.

The random client password is visible to the child (necessarily — it must connect). It grants access only through the relay, which is exactly the intended isolation boundary.

Trust boundary note, stated honestly: the handshake code is now credproxy's, not pgbouncer's decade of patching. Bugs in it become our bugs. Mitigations: protocol framing comes from vetted libraries, post-auth traffic is never interpreted (the blast radius of a relay bug is a broken connection, not a wrong query), and the docker live tests pin real-server behavior for both engines.

### Env hygiene (unchanged, already implemented)

- Strips inherited env vars whose names match a configured database's `env` name — a real `DATABASE_URL` in the parent shell must not silently defeat the scheme
- Strips `PGPASSWORD` when any postgres database is configured, `MYSQL_PWD` when any mysql database is configured
- Pooler-injected URLs override `[env]` config values on name collision (last-wins)

## Relay Lifecycle

- One listener per database entry, `net.Listen("tcp", "127.0.0.1:0")`, **kept open** — the bind-close-reuse port race from the original spec disappears because credproxy owns the socket.
- No child processes, no temp dir, no binary discovery, no SIGTERM escalation. Listeners and per-connection goroutines are owned by the session and die when it does; `runWrap`'s existing exit-code plumbing (returns the child's code; `main` exits after defers) covers cleanup.
- Per client connection: authenticate → dial backend → start two copy goroutines → on either EOF/error, close both.
- Backend dial failure: the client connection is closed with the engine's natural error; the session continues (same philosophy as the MITM proxy dying mid-session — visible failure, not silent).
- Fail-fast validation at startup (config validation, `op://` resolution) is unchanged.

## Implementation Plan

### 1. New packages

- `internal/dbproxy/pg` — Postgres listener: SSLRequest/startup handshake, cleartext-password client auth, backend dial with md5/SCRAM/cleartext+TLS negotiation, byte relay
- `internal/dbproxy/mysql` — MySQL listener: Initial Handshake serving `mysql_native_password`, session-password verification, backend dial with native/caching_sha2 token paths and full-auth RSA, byte relay

### 2. Manager rework (`internal/pooler` → slimmed)

- Keeps: grouping by engine, env computation (`buildURL`), strip list, `Start`/`Stop`/idempotence, session password generation
- Drops: binary discovery (`lookPath`), temp dir, `proc`/process supervision, `waitForListen` (listeners are ours), per-engine binary launch
- Failure mode shifts: no "binary missing" startup error; startup failures are listen errors (address in use) — still fail-fast

### 3. Config

- No new fields; `params` semantics pinned per the table above (validation for these values lands with the relay packages)

### 4. Dependencies (all pure Go)

- `github.com/jackc/pgx/v5` (for `pgproto3`) — the canonical Go Postgres driver's wire-protocol package
- `github.com/xdg-go/scram` — SCRAM-SHA-256 client
- `github.com/go-mysql-org/go-mysql` — MySQL server/client handshake framing
- `github.com/lib/pq`, `github.com/go-sql-driver/mysql` — live-test clients only (already present)
- Removed: none required (go-sql-driver's admin-provisioning use disappears with ProxySQL, but it remains as the live-test mysql client)

### 5. Wrap mode integration (`cmd/credproxy/main.go`)

- Unchanged from the already-merged implementation except that the manager now starts relays instead of processes; env stripping and URL injection untouched

## Testing

- **Unit:** handshake message round-trips per engine (encode/decode via pgproto3 and go-mysql types), session-password verification vectors (SHA-1 native token, SCRAM exchange against a test verifier, caching_sha2 fast-auth token), auth-method negotiation branches, relay loops over `net.Pipe` with fake backends, env hygiene and URL construction (existing tests carry over)
- **Spike (first implementation step, throwaway):** drive both relay packages end-to-end against Dockerized Postgres 16 + MySQL 8 before wiring into the manager — pin the caching_sha2 full-auth path (library coverage vs hand-rolled RSA), the SSLRequest dance, and driver compatibility for lib/pq and go-sql-driver
- **Live (docker targets, existing harness):** `go test -tags live` — wrap real queries through the relay to real containers; assert the real password is absent from the injected URL **and that no `credproxy-*` temp files are created at all**; the pgbouncer source-build section of `docs/live-testing-db-poolers.md` is deleted — no binaries exist in this design

## Acceptance Criteria

- `credproxy <cmd>` with a configured postgres database: child's `DATABASE_URL` points at `127.0.0.1:<port>` with the random password; connections work (including parameterized/prepared-statement queries); real password absent from child env **and from the filesystem**
- Same for mysql, including against `caching_sha2_password` (MySQL 8 default) and `mysql_native_password` users
- No `[databases.*]` in config → behavior identical to today
- Inherited `DATABASE_URL` stripped when a database with `env="DATABASE_URL"` is configured; `PGPASSWORD`/`MYSQL_PWD` stripped per engine
- Two entries with colliding real database names work (aliasing)
- `op://` password resolution failure → startup fails fast
- Listeners close and goroutines stop on child exit and on SIGINT/SIGTERM
- Real password never written to disk, never logged, never present in child env
- **Zero new install requirements**: no pooler binaries, no containers, no config beyond `[databases.*]`

## Non-Goals

- Query-level policy, SQL parsing, audit logging, rate/timeout limits, approval workflows
- MCP-style semantic query gateway
- Connection pooling / multiplexing (explicitly: one backend connection per client connection)
- Engines beyond postgres and mysql
- TLS on the relay's loopback listener
- Fixed ports or persistent listeners across sessions

## Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Handshake edge cases are our bugs now (driver quirks, auth-method corners) | Medium | Medium — connection failures, visible not silent | Vetted protocol libraries for framing; relay never interprets post-auth bytes; docker live tests pin real drivers (lib/pq, go-sql-driver) and servers (PG 16, MySQL 8) |
| caching_sha2 full-auth RSA path missing in go-mysql client | Medium | Medium — blocked against MySQL 8 default users | Spike pins it first; RSA-OAEP exchange is bounded, documented protocol work if hand-rolling is needed |
| pg SCRAM backend verifier edge cases (server-side channel binding demands) | Low | Medium — blocked against modern PG | xdg-go/scram is the same library family MongoDB drivers use; live test against PG 16 default pg_hba |
| Dependency weight (pgx, go-mysql) grows the binary | Certain | Low — a few MB | Pure Go, no cgo; credproxy remains a single static binary |
| Driver requests SSL on the loopback leg | Medium | Low — connection refused with clear error, not a leak | `sslmode=disable` injected in postgres URLs; SSLRequest answered `'N'`; documented |
| Parent-shell `DATABASE_URL` silently defeats scheme | Medium if unhandled | High | Already handled: strip matching inherited vars (implemented, tested) |
| User puts real DB URL in `[env]` instead of `[databases.*]` | Medium | High | Pooler vars win on collision; docs; README guidance (already merged) |

## Out of Scope (Future)

- Connection pooling / multiplexing
- TLS on the relay listener
- Additional engines
- Query policy / audit (phase 2+)
- Pooler-in-container mode (rejected — violates size/simplicity and team portability)
