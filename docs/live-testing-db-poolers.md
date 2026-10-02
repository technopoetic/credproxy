# Live Testing — Database Relays

How to verify database credential isolation against real servers. The
`live` build tag keeps these tests out of normal runs (`go test ./...`
never touches the network and needs no external services).

There are no pooler binaries to install — the relay is embedded in
credproxy. The only requirement for live testing is container targets.

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
# second MySQL user with the legacy auth plugin (the container's default
# app_user uses caching_sha2_password, MySQL 8's default)
docker exec credproxy-live-mysql mysql -uroot -prootpass -e \
  "CREATE USER IF NOT EXISTS 'app_native'@'%' IDENTIFIED WITH mysql_native_password BY 'realmysqlpass'; GRANT ALL PRIVILEGES ON appdb.* TO 'app_native'@'%';"
```

## Run

```bash
CREDPROXY_LIVE_PG_HOST=127.0.0.1 \
CREDPROXY_LIVE_PG_PORT=15432 \
CREDPROXY_LIVE_PG_USER=app_user \
CREDPROXY_LIVE_PG_PASSWORD=realpgpass \
CREDPROXY_LIVE_PG_DATABASE=appdb \
CREDPROXY_LIVE_MYSQL_HOST=127.0.0.1 \
CREDPROXY_LIVE_MYSQL_PORT=13306 \
CREDPROXY_LIVE_MYSQL_USER=app_user \
CREDPROXY_LIVE_MYSQL_NATIVE_USER=app_native \
CREDPROXY_LIVE_MYSQL_PASSWORD=realmysqlpass \
CREDPROXY_LIVE_MYSQL_DATABASE=appdb \
go test -tags live -run TestLive ./internal/dbrelay/ -v
```

Status: **all PASS (2026-10-02)** —

- Postgres: lib/pq through the relay against Postgres 16 (SCRAM backend);
  simple and parameterized queries (the latter pins extended query protocol
  passing through untouched)
- MySQL, caching_sha2_password (MySQL 8 default): fast-auth and full-auth
  RSA paths both exercised against the real server
- MySQL, mysql_native_password: legacy plugin end-to-end
- Each test asserts the real password is absent from the injected URL and
  that the relay wrote nothing to the temp dir

## Teardown

```bash
docker rm -f credproxy-live-pg credproxy-live-mysql
```
