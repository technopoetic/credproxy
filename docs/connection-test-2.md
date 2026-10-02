# DB relay connection — second diagnostic

**What works**
- Relay ports are listening. Prod relay: `127.0.0.1:64542`, staging relay:
  `127.0.0.1:64543` (confirmed via `/dev/tcp` connect).
- `MEKANIK_PROD_DATABASE_URL` and `MEKANIK_STAGING_DATABASE_URL` are in env,
  pointing at the relay ports with random passwords (base64 strings, ~43 chars).
  No real DigitalOcean host or real DB password is visible in the child env —
  credential isolation is doing its job.
- credproxy log confirms the relay started cleanly for this session:
  `10:38:47.701  INFO  database relays listening  databases=mekanik_prod,mekanik_staging`.

**What fails**

All `mycli` connections — both prod and staging, default flags and with
`--ssl-mode=off` — fail identically:

```
Connection to server lost. If this error persists, it may be a mismatch between
the server and client SSL configuration. To troubleshoot the issue, try
--ssl-mode=off or --ssl-mode=on.
(2013, 'Lost connection to MySQL server during query')
```

mycli is `2.28.0`, reached at `/Users/r/.local/bin/mycli`.

**credproxy-side log lines** corresponding to those connections (this session):

```
2026-10-02T10:40:36.693-04:00  WARN  mysql relay: frontend auth: EOF
2026-10-02T10:40:36.697-04:00  WARN  mysql relay: frontend auth: EOF
2026-10-02T10:40:50.278-04:00  WARN  mysql relay: frontend auth: EOF
2026-10-02T10:40:50.279-04:00  WARN  mysql relay: frontend auth: auth plugin: unterminated cstring
2026-10-02T10:41:14.360-04:00  WARN  mysql relay: frontend auth: EOF
2026-10-02T10:41:14.360-04:00  WARN  mysql relay: frontend auth: auth plugin: unterminated cstring
```

The first attempt usually dies on EOF` immediately. On some attempts the relay
reads enough bytes to attempt parsing the handshake and chokes on
`unterminated cstring`. Same shape on both prod and staging.

**Pre-session entries from today, before the current opencode run started:**

```
2026-10-02T09:33:46.245-04:00  WARN  mysql relay: frontend auth: auth plugin: unterminated cstring
2026-10-02T09:35:08.343-04:00  WARN  mysql relay: frontend auth: auth plugin: unterminated cstring
2026-10-02T09:36:03.462-04:00  WARN  mysql relay: backend dial: backend auth failed:
                                              1045: Access denied for user
                                              'agent-user'@'76.216.18.99' (using password: YES)
```

The 09:36 entry is the *one* attempt that made it past frontend auth — and
failed on the backend with a real MySQL 1045 against the DigitalOcean host. That
predates the 2d50d59 commit's caching_sha2 fix described in `connection_test.md`.
Whether it is the same bug or a different attempt to re-authenticate is not
clear from the log alone.

**Observations**

1. The current run's `unterminated cstring` warnings reproduce the same
   frontend-parser issue `connection_test.md` flagged for pymysql. Now it's
   reproducing with mycli too. The 09:36 backend 1045 (under a different
   binary, pre-fix) suggests that *when* the frontend handshake does succeed,
   the backend can actually be reached — i.e. this is a frontend-parser bug,
   not a backend reachability problem.

3. Test style did not try any further workarounds — per instruction, just
   reporting facts.

---

## Resolution (2026-10-02, later same day)

**Frontend parser fixed** (commit following 2d50d59): the relay read
`CLIENT_CONNECT_WITH_DB` as promising a database field, but pymysql sets that
flag and omits the field entirely — its packet runs user → auth response →
plugin name with nothing between auth and plugin. The relay consumed
`"mysql_native_password"` as the database name, then found zero bytes for
the plugin name → `auth plugin: unterminated cstring` (and the EOF variant:
mycli closing after failing to parse the relay's greeting client-side). Real
servers treat a truncated response as "field absent"; the relay now does too
— only the session-password check gates access, everything after the auth
response is cosmetic.

Evidence: byte-level repro (hermetic relay + logging proxy) captured pymysql
90 bytes vs go-driver 98 bytes for the same login; unit test pins the
pymysql layout (red first, then green); hermetic rerun moved pymysql's
failure from `2013 Lost connection` to the expected backend-dial error;
end-to-end pymysql → relay → real DigitalOcean staging → **connected**.
mycli is pymysql-based and should now work — verify interactively.

**Environment details (for repro)**

- Env var: `MEKANIK_PROD_DATABASE_URL=mysql://agent-user:KX8HkD4FQDuNsfbS0nNcQkWjukcCVnPcWi80e_fJMUY@127.0.0.1:64542/mekanik_production`
- Env var: `MEKANIK_STAGING_DATABASE_URL=mysql://agent-user:3vnzieHpj0VLVNd31YfX3XxTuQeSsYC6xkyTg-79msk@127.0.0.1:64543/mekanik_staging`
- Config: `~/.config/credproxy/config.toml` has both `[databases.mekanik_prod]`
  and `[databases.mekanik_staging]`, `engine = "mysql"`, `port = 25060`,
  `params = "use_ssl=1"`, password via `op://HAP/Mekanik {prod,staging} DB/password`.
- Tools available: `mycli 2.28.0`, `python3 3.14.7`, `go 1.27.1`,
  `nc`, `uv 0.12.18`. No native `psql` or `mysql` client.
- TCP probe: `127.0.0.1:64542` and `127.0.0.1:64543` both accept connections.