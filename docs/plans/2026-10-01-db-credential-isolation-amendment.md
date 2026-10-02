# DB Credential Isolation — Amendment Plan (embedded relay)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans (native, inline). Steps use checkbox (`- [ ]`) syntax.
> **Supersedes** Tasks 4–7 of `2026-10-01-db-credential-isolation.md` for the mechanism (embedded relay replaces external poolers); Tasks 1–3, 8 (config/validation core), 9 (docs) carry over. Spec: `docs/prds/db-credential-isolation.md` (amended version, commit d6d13ec). Branch continues: `db-credential-isolation`.

**Goal:** Replace external pooler binaries with an in-process auth-split relay: credproxy listens on 127.0.0.1 itself, authenticates the child with the session password, dials the real database with the real credential (memory-only), and relays bytes transparently.

**Architecture:** `internal/dbproxy` (shared byte relay) + `internal/dbproxy/pg` and `internal/dbproxy/mysql` (handshake + auth, one package per engine) + `internal/dbrelay` (renamed from `internal/pooler`: Manager keeps env computation and listener lifecycle, drops process supervision, temp dir, binary discovery). Handshakes are hand-rolled on documented framing (MySQL packets: 3-byte len + seq + payload; PG messages: type + int32 len + body) with stdlib crypto and `github.com/xdg-go/scram` for SCRAM. **No go-mysql dependency** — its server package wants to be a full server post-auth, its client does not expose the raw conn a relay needs; the MySQL handshake is simple, documented framing.

**Tech Stack:** Go stdlib crypto (sha1/sha256/rsa/hmac), `github.com/xdg-go/scram` (new dep), existing live-test clients (lib/pq, go-sql-driver). Docker/podman targets unchanged.

## Global Constraints

- Deps added: ONLY `github.com/xdg-go/scram`. Deps removed: none (go-sql-driver and lib/pq stay as live-test clients). `go.mod` already at 1.21.0.
- The real password must never be written to disk or logged — it exists only in credproxy memory. No temp dirs, no config files with secrets.
- Post-auth traffic is never interpreted: after auth completes, both legs are raw `io.Copy`.
- No `[databases.*]` configured → zero behavior change (no listeners, no env changes).
- Every task: RED→GREEN (watch the test fail first), full suite green before commit, commit messages explain why.

## Review Focus

1. **Real password on disk** — the old design's temp files are gone; a regression that writes them back must fail tests. Pinned by live-test assertion (Task 6).
2. **Driver requests SSL on the loopback leg** — must be declined cleanly, not crash: PG `SSLRequest` answered `'N'` and retried as startup; MySQL `CLIENT_SSL` never advertised. Pinned in Task 2/3 unit tests.
3. **caching_sha2 full-auth** — the real password must cross the wire only RSA-OAEP-encrypted (or over backend TLS when `use_ssl=1`). Never plaintext on a non-TLS socket. Pinned in Task 3/5.
4. **CancelRequest / non-startup first packets** (new PG connection with a cancel) must close cleanly without corrupting other relays. Pinned in Task 2.
5. **Same-username mysql entries** — ProxySQL's per-username routing constraint is gone; the old validation rule must be removed correctly (Task 4), test updated to assert it now validates.
6. **Prepared statements / extended query protocol** through the relay — pinned live in Task 6 (parameterized query via lib/pq), free by construction if the relay truly never interprets.

---

### Task 1: `internal/dbproxy` — shared relay

**Files:** Create `internal/dbproxy/relay.go`; Test: `internal/dbproxy/relay_test.go`
**Produces:** `func Relay(a, b net.Conn)` — copies both ways, closes both on first error/EOF (second copy unblocks via Close).

- [ ] RED: test with two `net.Pipe` pairs simulating client↔relay↔backend; bytes flow both directions; closing backend unblocks and closes client.
- [ ] GREEN: implementation (standard double-copy pattern, ~25 lines).
- [ ] Commit.

### Task 2: `internal/dbproxy/pg` — Postgres relay

**Files:** Create `internal/dbproxy/pg/pg.go` (framing + frontend auth), `internal/dbproxy/pg/backend.go` (backend dial + auth), Test: `internal/dbproxy/pg/pg_test.go`
**Consumes:** `dbproxy.Relay`.
**Produces (for Task 4):**
- `func ListenAndServe(ln net.Listener, cfg config.DatabaseConfig, realPassword, sessionPassword string) error` — accept loop: authenticate frontend, dial backend, forward backend post-auth preamble, `dbproxy.Relay`. (Manager owns goroutine-per-listener.)
- `func FrontendAuth(conn net.Conn, sessionPassword string) error` — SSLRequest→`'N'` loop, CancelRequest→clean close, StartupMessage parse (keep extra params for backend), `AuthenticationCleartextPassword`, constant-time session-password check.
- `func DialBackend(ctx context.Context, cfg config.DatabaseConfig, realPassword string, extraParams map[string]string) (net.Conn, []byte, error)` — TLS negotiation per `sslmode` param, startup with real user/database + forwarded client params, auth loop (cleartext only over TLS when demanded / md5 / SCRAM-SHA-256 via xdg-go/scram), returns conn + raw post-auth bytes (AuthenticationOk…ReadyForQuery) to forward.

Test fixtures: in-process fake PG server (hand-rolled framing, same package test helpers): asserts startup shape, verifies cleartext password, serves SCRAM/md5/cleartext variants; error-response paths; SSLRequest probe; CancelRequest close. SCRAM verified against a fake server using `xdg-go/scram` server-side (cross-checks our client).
- [ ] RED→GREEN per test; suite green; commit.

### Task 3: `internal/dbproxy/mysql` — MySQL relay

**Files:** Create `internal/dbproxy/mysql/mysql.go` (packet framing + frontend auth), `internal/dbproxy/mysql/backend.go` (backend dial + auth), Test: `internal/dbproxy/mysql/mysql_test.go`
**Produces:** `ListenAndServe`, `FrontendAuth(conn, sessionPassword)`, `DialBackend(ctx, cfg, realPassword)` — same shape as pg.
**Mechanics:**
- Packet framing: 3-byte little-endian length + 1-byte sequence; per-connection sequence counters (write increments, read validates/hops on continuation).
- Frontend: Initial Handshake V10 advertising `CLIENT_PROTOCOL_41 | CLIENT_PLUGIN_AUTH | CLIENT_SECURE_CONNECTION | CLIENT_LONG_PASSWORD | CLIENT_TRANSACTIONS | CLIENT_INTERACTIVE`, 20-byte random scramble (no NUL bytes), plugin `mysql_native_password`; parse `HandshakeResponse41`; if client replies with another plugin → `AuthSwitchRequest` to native; verify token = `SHA1(pw) XOR SHA1(scramble ∥ SHA1(SHA1(pw)))` constant-time; write OK packet.
- Backend: read server Initial Handshake (scramble 8+12, plugin name); optional TLS (only when `use_ssl=1` and server advertises `CLIENT_SSL`); send `HandshakeResponse41` with real user/password/database; handle: OK, ERR, `AuthSwitchRequest` (recompute token for the new plugin), caching_sha2 flow — fast-auth token `SHA256(pw) XOR SHA256(SHA256(SHA256(pw)) ∥ scramble)`, fast-auth-success byte `0x01 0x03`, full-auth `0x01 0x04` → read server RSA public key from next AuthMoreData → send RSA-OAEP(SHA1) of `XOR(password ∥ NUL, scramble)`; **plaintext password never sent on a non-TLS backend socket**.
Test fixtures: fake MySQL server (framing helpers) driving native, caching_sha2 fast-auth, caching_sha2 full-auth (with a test RSA keypair), auth-switch, and ERR paths; native-token cross-checked against an independently computed fixture vector (generate with python3 hashlib, hardcode, comment the generator); frontend auth-fail → ERR packet 1045.
- [ ] RED→GREEN per test; suite green; commit.

### Task 4: Manager rework (`internal/pooler` → `internal/dbrelay`) + config validation adjustments

**Files:** `git mv internal/pooler internal/dbrelay`; rewrite `manager.go`; update `cmd/credproxy/main.go` imports + `NewManager` signature (drop `logFile` param); update `internal/config/config.go` validations.
**Changes:**
- Manager keeps: entry grouping, `computeEnv`/`Strip` (unchanged), session password, `Start`/`Stop` idempotence, `Env`/`Strip` fields.
- Manager drops: `proc`, `lookPath`, temp dir, `waitForListen`, `sqlPorts` per engine (now per entry), `startPgbouncer`/`startProxySQL` and the pg/mysql generator files (`pgbouncer.go`, `proxysql.go` deleted with their tests).
- New `Start`: per entry, `net.Listen("tcp","127.0.0.1:0")`, `go pg/mysql.ListenAndServe(...)`; failure to listen → fail fast; backend dial failures happen lazily at child query time (visible failure, session continues).
- Old `runWrap` integration test (`poolersim` subprocess test) replaced: in-process test asserting listeners close on `Stop()` and dial is refused after; subprocess integration no longer meaningful (no child processes).
- Config validation: REMOVE unique-mysql-username rule (ProxySQL routing gone; test now asserts same username validates); REPLACE whitespace rule — only `host` may not contain whitespace (network address; password/user/database now flow through URL-escaping and binary-safe protocols); ADD `params` validation (postgres `sslmode` ∈ {disable,prefer,require,verify-full}, mysql `use_ssl` ∈ {0,1}); ADD `CREDPROXY_PREV_BASH_ENV` to reserved env names (deferred minor, one line while here).
- [ ] RED→GREEN on every changed test; full suite; commit.

### Task 5: Live tests + docs

**Files:** rewrite `internal/pooler/live_test.go` → `internal/dbrelay/live_test.go`; rewrite `docs/live-testing-db-poolers.md`; update `README.md` DB section; update `AGENTS.md` (project state line, delete proxysql-binary known issue).
**Live tests (docker targets unchanged):**
- Postgres: connect, `SELECT 1`, parameterized query (`SELECT $1::int` — pins extended query protocol), real-password-absent assertion, **no `credproxy-*` temp files created** (replaces the old no-leak glob semantics: now zero must exist).
- MySQL: two users — `app_user` (caching_sha2 default) and `app_native` (mysql_native_password via ALTER USER) — both connect through the relay; same assertions.
- Remove all binary-path env vars (`PGBOUNCER_PATH`/`PROXYSQL_PATH`) — nothing to discover.
- [ ] Suite green; live run for both engines recorded; commit.

### Task 6: Final ledger + cleanup

- [ ] Rulings ledgered; workspace deleted per executing-plans; final review (whole-branch delta against `d6d13ec`).

---
