# DB Pooler Spike Findings — 2026-10-01

Throwaway probes against containerized targets (podman 5.8.5 via `docker` shim,
podman network `spike`, torn down after). These findings pin the exact config
shapes Tasks 4 and 6 generate; where they contradict the plan, the plan code is
corrected per the ledger rulings below.

## Postgres — pgbouncer (VERIFIED end-to-end)

- Image `pgbouncer/pgbouncer:latest` = **PgBouncer 1.25.2** (libevent 2.1.13,
  OpenSSL 3.5.8). The image's entrypoint generates its own config from env vars
  and ignores a mounted ini; to run our config, override the entrypoint:
  `--entrypoint /opt/pgbouncer/pgbouncer <image> /etc/pgbouncer/pgbouncer.ini`
  (binary is NOT at /usr/bin/pgbouncer; not on PATH as `pgbouncer` either).
- Config shape VERIFIED against `postgres:16-alpine` (SCRAM-sha-256 backend, the
  modern default):
  - `[databases] mydb = host=<real> port=5432 dbname=<db> user=<user> password=<REAL>`
    forces the backend credential — exactly the plan's shape.
  - `auth_type = scram-sha-256` + plaintext `userlist.txt` (`"user" "sessionpw"`)
    works: pgbouncer derives the SCRAM exchange from the plaintext entry.
  - Positive: session-password client connects, `select 1` round-trips.
  - Negative: wrong client password → `FATAL: SASL authentication failed`.
  - No `ignore_startup_parameters` needed for psql; pgbouncer issue #1461 not
    triggered (`use_scram_keys` never set).
- Host-side config uses `listen_addr = 127.0.0.1`; the spike used `0.0.0.0`
  only because clients came from other containers.
- podman-on-macOS: `/tmp` is not shared into the VM; bind mounts must use
  `/private/tmp/...` paths.

## MySQL — ProxySQL (VERIFIED end-to-end, with plan corrections)

- Image `proxysql/proxysql:latest` = **ProxySQL 3.0.11** (codename Truls).
  Ships `/usr/bin/mysql` client inside the image — admin provisioning via
  `docker exec` hits the admin interface on the container's own loopback, the
  same shape as production's `127.0.0.1` admin connection.

### Config file corrections (plan Task 4 `proxysqlConfig` is WRONG in two places)

The cnf is **libconfig** grammar, not plain ini:

1. `datadir` must be quoted: `datadir="/var/lib/proxysql"` — unquoted fails with
   `Parse error at /etc/proxysql.cnf:1 - syntax error`.
2. The admin binding variable is **`mysql_ifaces`**, not `mysql_interfaces`
   (the image's default cnf: `mysql_ifaces="0.0.0.0:6032"` under
   `admin_variables`). The SQL frontend binding under `mysql_variables` IS
   named `interfaces` as planned.
3. Optional but useful: top-level `errorlog="/path/proxysql-error.log"`.

### User provisioning — attributes overlay REJECTED, dual rows VERIFIED

- **`attributes.frontend_password` does NOT work on 3.0.11.** A single
  `mysql_users` row with `password=<REAL>` and
  `attributes='{"frontend_password":"<session>"}'` (frontend=1, backend=1)
  expands at runtime into two rows, but BOTH carry `password=<REAL>` and the
  frontend authenticates with the **real** password. The session password in
  attributes was never consulted. (Direct evidence: frontend accepted
  `realmysqlpass`, rejected `sessionpw123`.)
- **Dual rows with the same username ARE accepted** and produce the correct
  split (this was believed impossible per old issue #814; 3.0.11 allows it):

  ```sql
  DELETE FROM mysql_users WHERE username='app_user';
  INSERT INTO mysql_users (username, password, active, use_ssl, default_hostgroup, frontend, backend) VALUES
    ('app_user', '<session-password>', 1, 0, 0, 1, 0),
    ('app_user', '<REAL>',            1, 0, 0, 0, 1);
  LOAD MYSQL USERS TO RUNTIME;
  ```

  Runtime confirmed: frontend row `frontend=1 backend=0 password=<session>`,
  backend row `frontend=0 backend=1 password=<REAL>`.
- End-to-end VERIFIED: frontend accepts the session password, `select 1,
  current_user()` round-trips to the real backend (proving the backend row's
  real credential is used for the backend leg), wrong password →
  `ERROR 1045 (28000) ... Access denied`.

### Backend auth plugin

- `mysql:8.0` default user (`caching_sha2_password`) works through ProxySQL
  3.0.11 **without** TLS/RSA and **without** converting to
  `mysql_native_password`. No `ALTER USER` needed; no `use_ssl` needed.

### Monitor

- With monitor credentials unset: `Access denied` log spam from
  `monitor_connect_thread`, but the server stays ONLINE and queries flow — no
  shunning observed.
- Fix verified: `UPDATE global_variables SET variable_value='<real-user>' WHERE
  variable_name='mysql-monitor_username';` (and password), then `LOAD MYSQL
  VARIABLES TO RUNTIME;` — errors stop. Keep these statements in provisioning.
- `stats_mysql_connection_pool` after the fix: `status=ONLINE, ConnOK=1,
  ConnERR=0, Queries=2`.

## Consequences for Tasks 4/6 (rulings carried in the ledger)

- `proxysqlConfig`: quote `datadir`, use `mysql_ifaces`, add `errorlog`.
- `proxysqlUserSQL`: **two INSERTs per database entry** (frontend row with the
  session password, backend row with the real password) — no `attributes`
  column. Monitor credential statements stay.
- `proxysqlUseSSL` stays (use_ssl column on both rows; backend-relevant).
- pgbouncer launch code must not assume the binary name resolves via PATH
  inside containers — irrelevant for the host launch path, which uses
  `exec.LookPath("pgbouncer")` / `pgbouncer_path` override as planned.
