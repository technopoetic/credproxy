# Live Testing — DB Poolers

How to verify database credential isolation against real servers. The
`live` build tag keeps these tests out of normal runs (`go test ./...`
never needs pooler binaries or containers).

## Bring up targets

```bash
docker run -d --name credproxy-live-pg \
  -e POSTGRES_USER=app_user -e POSTGRES_PASSWORD=realpgpass -e POSTGRES_DB=appdb \
  -p 15432:5432 docker.io/library/postgres:16-alpine

docker run -d --name credproxy-live-mysql \
  -e MYSQL_ROOT_PASSWORD=rootpass -e MYSQL_USER=app_user -e MYSQL_PASSWORD=realmysqlpass \
  -e MYSQL_DATABASE=appdb -p 13306:3306 docker.io/library/mysql:8.0
# wait for readiness
docker exec credproxy-live-pg pg_isready -U app_user
docker exec credproxy-live-mysql mysqladmin ping -uroot -prootpass
```

## Postgres — verified end-to-end on this machine (2026-10-01)

Needs a host pgbouncer binary. This machine has no Homebrew; the binary was
built from source (pgbouncer 1.26.0):

```bash
# one-time toolchain (kept in /private/tmp, rebuild if rebooted):
#   gnu-tools prefix: m4, autoconf 2.72, automake 1.17, libtool 2.5.4 (built
#   from GNU tarballs into /private/tmp/gnu-tools), pandoc 3.12 (mise),
#   ACLOCAL_PATH=/opt/local/share/aclocal for pkg.m4 (MacPorts pkg-config)
git clone --depth 1 --branch pgbouncer_1_26_0 https://github.com/pgbouncer/pgbouncer.git /private/tmp/pgbouncer-src
cd /private/tmp/pgbouncer-src
export PATH="/private/tmp/gnu-tools/bin:$HOME/.local/share/mise/installs/pandoc/3.12/bin:$PATH"
export ACLOCAL_PATH="/opt/local/share/aclocal"
./autogen.sh
./configure --prefix=/private/tmp/pgbouncer-install CPPFLAGS="-I/opt/local/include" LDFLAGS="-L/opt/local/lib"
make -j4 && make install   # -> /private/tmp/pgbouncer-install/bin/pgbouncer
```

Run:

```bash
CREDPROXY_LIVE_PG_HOST=127.0.0.1 \
CREDPROXY_LIVE_PG_PORT=15432 \
CREDPROXY_LIVE_PG_USER=app_user \
CREDPROXY_LIVE_PG_PASSWORD=realpgpass \
CREDPROXY_LIVE_PG_DATABASE=appdb \
PGBOUNCER_PATH=/private/tmp/pgbouncer-install/bin/pgbouncer \
go test -tags live -run TestLivePostgres ./internal/pooler/ -v
```

Status: **PASS** (2026-10-01) — SELECT 1 round-trips through credproxy's
generated config → host pgbouncer 1.26.0 (SCRAM client auth with the session
password) → real Postgres 16 with the forced backend user. The real password
is absent from the injected URL.

Two product fixes fell out of this live run:

1. Injected postgres URLs carry `sslmode=disable` — lib/pq defaults to
   `sslmode=require`, and TLS on the loopback pooler leg is a spec non-goal.
2. Generated pgbouncer.ini sets `ignore_startup_parameters =
   extra_float_digits` — pgbouncer rejects unknown startup parameters and
   lib/pq always sends that one.

## MySQL — blocked on this machine, mechanics spike-verified

```bash
CREDPROXY_LIVE_MYSQL_HOST=127.0.0.1 \
CREDPROXY_LIVE_MYSQL_PORT=13306 \
CREDPROXY_LIVE_MYSQL_USER=app_user \
CREDPROXY_LIVE_MYSQL_PASSWORD=realmysqlpass \
CREDPROXY_LIVE_MYSQL_DATABASE=appdb \
PROXYSQL_PATH=/nonexistent \
go test -tags live -run TestLiveMySQL ./internal/pooler/ -v
```

Status: **fails fast at binary discovery** (`proxysql_path "/nonexistent":
no such file or directory`) — correct behavior, honest gap. There is no
proxysql binary obtainable on this host: no Homebrew, no mise formula, and a
source build is not viable. The ProxySQL mechanics themselves (libconfig cnf
with `mysql_ifaces`, dual `mysql_users` rows per username, monitor
credentials, caching_sha2 backend without TLS) are verified end-to-end in
containers — see `docs/plans/2026-10-01-db-pooler-spike-findings.md`.

Options to close the gap:

1. Accept the documented container-verified status (current).
2. Amend the spec to let the manager launch poolers in containers — a
   product change, needs design approval.
3. Install Homebrew (or another way to obtain a proxysql darwin binary) and
   re-run the test above unchanged.

## Teardown

```bash
docker rm -f credproxy-live-pg credproxy-live-mysql
```
