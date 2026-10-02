# Staging DB connection — diagnostic report

**What works**
- Relay ports are listening (staging:54427, prod:54426)
- MEKANIK_STAGING_DATABASE_URL and MEKANIK_PROD_DATABASE_URL in env are the relay URLs (127.0.0.1 + ephemeral port + random base64 password). The real DigitalOcean host is not in context — credential isolation is doing its job.

**What fails**
- Backend auth to the real DigitalOcean MySQL:
    mysql relay: backend dial: backend auth failed:
    1045: Access denied for user 'agent-user'@'76.216.18.99' (using password: YES)
  The relay is forwarding correctly; DO is rejecting the credentials. Three plausible causes: (a) the 1Password-resolved password is stale or wrong, (b) the egress IP isn't on the DO agent-user grant, (c) the user itself changed.

- pymysql's handshake trips a separate warning:
    mysql relay: frontend auth: auth plugin: unterminated cstring
  pymysql sends something the relay's parser doesn't like. The Go driver (go-sql-driver/mysql, same one used in the live tests) negotiates cleanly — use that for any actual work, not pymysql.

**Observations from the codebase**

1. internal/dbrelay/manager.go:52 generates the session password ONCE outside the loop and reuses it for every relay. Comment says "per-session," code matches. Within one session, anyone who learns the staging relay URL (and could find the prod port by scanning 127.0.0.1) can also authenticate to the prod relay. Whether that's acceptable depends on the threat model — flagging because the file advertises "per-session password" and the opposite might be assumed.

2. [databases.mekanik_prod] in ~/.config/credproxy/config.toml has database = "mekanik_staging". The injected MEKANIK_PROD_DATABASE_URL ends in /mekanik_prod anyway, so credproxy is using the alias key as the database name, not the database field — that field appears to be ignored for the URL path. Either fix the config or fix the code, but right now the two disagree.

**Where direction is needed**
- The backend-auth failure is the blocker. Options:
  (a) retry now with a fresh credproxy session (in case the cached op-resolved password is stale),
  (b) check what's actually in 1Password for Mekanik staging DB/password (need to confirm op isn't shimmed out of path first),
  (c) look for an agent-user@76.216.18.99 grant on the DO side (no DO API token in env, so probably no),
  (d) already triaged this — focus on the two observations instead.

---

## Resolution (2026-10-02, same day)

**Backend 1045 — root cause found and fixed (commit 2d50d59).** The relay's
caching_sha2 *full-auth* path XOR-masked the password before sending it over
TLS. Masking is only correct for the RSA path; over TLS the server hashes
whatever bytes it receives, so masked bytes fail with 1045 even with a correct
credential. This fires only on full-auth — server-side cache hits use
fast-auth, which is why pre-migration live tests passed and the first
connection from the new machine (new client host → cache miss → full-auth)
failed. Verified three ways: direct go-sql-driver probe with the op-resolved
password → AUTH OK (8.0.45); existing unit test corrected to pin the spec
(red first, then green); end-to-end through the relay → AUTH OK.

The 1Password items were also confirmed valid directly (and independently by
Richard in another process). Option (c) partially answered: `agent-user`
authenticates from this network (the 1045 was never a grant problem for
staging).

**New finding — prod relay is not usable as configured.** Direct probe as
`agent-user` against `mekanik_prod`: Error 1044 (auth OK, no database grant).
`agent-user` has no `mekanik_prod` grants. Combined with observation 2 this
was worse than cosmetic: the relay pins the backend to the config's
`database` field (mekanik_staging) and ignores what the child requests, while
the old URL advertised /mekanik_prod — the "prod" relay would have silently
landed on staging. URLs now advertise the pinned database (2d50d59). Needs a
Richard-side DO user/grant for prod plus a config fix before the prod relay
means anything.

**New issue — op:// resolution fails when the approval prompt isn't approved in
time.** The provider renames `argv[0]` to `credproxy-op`; 1Password treats
that as a separate client identity and shows an approval prompt on each cold
authorization. When nobody is at the keyboard (or approval takes >30s), the
per-call deadline kills it → "context deadline exceeded" on wrap startup.
Reproduced: same binary+item, real `op` identity → 12ms (pre-authorized, no
prompt); renamed identity → prompt on screen, and with Richard AFK it sat
unapproved until the deadline. Decision pending: drop the rename (startup
never requires a human), or keep it and make the prompt state visible.

**Still open:** pymysql frontend "unterminated cstring" (frontend parser;
use go-sql-driver for now).
