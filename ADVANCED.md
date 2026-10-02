# credproxy — Advanced Configuration and Internals

Everything beyond the [README](README.md) quickstart: how credproxy works internally, and every configuration surface (profiles, env injection, database relays, security model).

## How It Works

```
$ credproxy opencode
    │
    ├─ Load global config (~/.config/credproxy/config.toml)
    ├─ Load project config (.credproxy.toml from cwd)
    ├─ Start MITM proxy on random port
    ├─ Set HTTPS_PROXY, NO_PROXY, SSL_CERT_FILE, CREDPROXY_TOKEN in child env
    ├─ Strip OP_SERVICE_ACCOUNT_TOKEN, op, bw from child env/PATH
    ├─ Exec child process (opencode)
    │
    │   Agent makes HTTP call to api.unsplash.com
    │   with ?client_id=CREDPROXY_TOKEN
    │       ↓ HTTPS through CONNECT tunnel
    │   credproxy MITM proxy
    │       ↓ terminates TLS, reads plaintext
    │       ↓ matches on host → looks up credential from 1Password
    │       ↓ swaps CREDPROXY_TOKEN → real key
    │       ↓ re-encrypts, forwards to upstream
    │
    └─ When child exits, proxy shuts down
```

credproxy is the parent process. It loads config, starts the proxy, configures the child's environment, runs the agent, and cleans up on exit. No manual env vars, no port management. When the child exits, the proxy dies with it — real credentials only exist in credproxy's memory, for the lifetime of the session.

The sentinel is substituted in headers, query strings, and request bodies. The agent doesn't know which credential goes where — it uses `CREDPROXY_TOKEN` for everything, and credproxy resolves the right secret based on the target host.

## Configuration

### Config files

- **Global:** `~/.config/credproxy/config.toml`
- **Project:** `.credproxy.toml` at the project root (or any parent directory up to `~`)

Project config overlays global. Same host in both → project wins.

```toml
# ~/.config/credproxy/config.toml
[hosts."api.github.com"]
credential = "op://Personal/github-pat/token"

[hosts."api.stripe.com"]
credential = "op://Business/stripe-live/key"
```

```toml
# .credproxy.toml (project)
[hosts."api.unsplash.com"]
credential = "op://shipstops/Unsplash app creds/Access Key"
```

The host key must be the exact hostname as it appears in the URL — full FQDN, no scheme, no port, no path. For a URL like `https://my-cluster.region.provider.example.com`, the key is `my-cluster.region.provider.example.com`.

### Credential URIs

| Scheme | Provider | Example |
|--------|----------|---------|
| `op://` | 1Password CLI | `op://Vault/item/field` |

### CLI flags

```
--config <path>          Override global config path
--profile <name>         Select config profile (staging, production, etc.)
--sentinel <string>      Sentinel string to substitute (default: CREDPROXY_TOKEN)
--open-proxy             Allow all hosts (not recommended)
--version                Print version and exit
```

The version string comes from Go's embedded build info: installs via `go install ...@vX.Y.Z` report the tag; `go build` from a checkout reports `devel` plus the commit.

## Auth Compatibility

credproxy substitutes a sentinel string in headers, query strings, and request bodies. This works for any auth scheme where the credential is a static value injected into a request. It does not work for schemes that compute a signature or require a challenge-response handshake.

| Auth scheme | Status | Notes |
|-------------|--------|-------|
| Bearer token | Works | `Authorization: Bearer CREDPROXY_TOKEN` |
| API key in header | Works | `X-Api-Key: CREDPROXY_TOKEN` |
| API key in query string | Works | `?api_key=CREDPROXY_TOKEN` |
| Basic auth | Works | credproxy decodes, substitutes, re-encodes; see below |
| AWS SigV4 | Won't work | Signature covers headers, body, and timestamp — must be computed pre-flight |
| Digest auth | Won't work | Challenge-response: server nonce must be hashed with credentials |
| NTLM / Kerberos | Won't work | Multi-round-trip handshake |
| mTLS | Won't work | credproxy doesn't attach client certificates to upstream connections |
| Two-secret APIs | Limited | Only one sentinel; works if `client_id` is public, not if both values are secret |

### Basic auth

Most HTTP clients encode Basic auth credentials automatically — `curl -u`, Python `requests`, and similar tools base64-encode the credentials before sending. credproxy detects `Authorization: Basic <encoded>` headers, decodes the credential, substitutes the sentinel in the decoded string, and re-encodes. Store the raw credential in your secret store; no manual encoding required.

**Example — Atlassian (Confluence / Jira):**

```toml
[hosts."your-domain.atlassian.net"]
credential = "op://Vault/Atlassian/api-token"
```

The credential stored in 1Password is the raw API token (e.g. `myapitoken`). The agent puts the email in the username slot and the sentinel in the password slot:

```bash
curl -u "user@example.com:CREDPROXY_TOKEN" https://your-domain.atlassian.net/rest/api/3/myself
```

credproxy sees `Basic dXNlckBleGFtcGxlLmNvbTpDUkVEUFJPWFlfVE9LRU4=`, decodes to `user@example.com:CREDPROXY_TOKEN`, substitutes, and re-encodes with the real token.

**API key as username (empty password).** Some APIs (legacy Stripe, some Jenkins configs) treat the API key as the Basic auth username with no password. Use `CREDPROXY_TOKEN:` (empty password) as the curl `-u` argument — the sentinel will be substituted in the username position.

## CA Certificate Trust

credproxy generates a self-signed CA on first run at `~/.config/credproxy/ca.pem`. Trusting it once in the OS store (per the README) is the reliable path.

credproxy also sets `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, and `CURL_CA_BUNDLE` in the child's environment. These point at a `trust-bundle.pem` that combines credproxy's CA with the standard public root bundle, so tools that treat those variables as a full trust-store replacement (gcloud, uv, Hugging Face Hub) still verify real, non-intercepted TLS connections correctly. This covers Python, Node.js, and curl without requiring system-level trust — but some runtimes still need the system cert store.

## Profiles

Profiles let the same hostname resolve to different credentials depending on environment — staging vs production, for example. Selected at startup with `--profile <name>`, immutable for the session.

```toml
# Default credential (no profile active)
[hosts."api.stripe.com"]
credential = "op://Business/stripe-test/key"

# Staging profile
[profiles.staging.hosts."api.stripe.com"]
credential = "op://Business/stripe-test/key"

[profiles.staging.env]
RAILS_ENV = "staging"
PORT = "3000"

# Production profile
[profiles.production.hosts."api.stripe.com"]
credential = "op://Business/stripe-live/key"

[profiles.production.env]
RAILS_ENV = "production"
PORT = "443"
```

```bash
credproxy --profile staging opencode
credproxy --profile production opencode
```

## Env Var Injection

credproxy injects non-secret environment variables from config into the child process. This replaces tools like direnv/dotenv for environment switching.

```toml
[env]
TERM = "xterm-256color"
EDITOR = "nvim"
```

To pass the sentinel as an env var value (for tools/SDKs that read API keys from the environment):

```toml
[env]
MINIMAX_API_KEY = "CREDPROXY_TOKEN"
STRIPE_SECRET_KEY = "CREDPROXY_TOKEN"
```

The child process sees `MINIMAX_API_KEY=CREDPROXY_TOKEN`. When the agent uses that value in an HTTP request to a configured host, credproxy substitutes the real credential at the network layer.

### Resolving `op://` URIs in env vars

Env values starting with `op://` are resolved at startup via 1Password and the resolved value is written into the child env. Use this when you're comfortable with the wrapped tool reading the real credential directly:

```toml
[env]
DATABASE_URL = "op://Business/prod-db/password"
SOPS_AGE_KEY = "AGE-SECRET-KEY-..."
```

> **Security caveat:** Unlike the host-based MITM flow, this path puts the real credential in the child process's environment. Any process spawned by the wrapped tool — or any code that reads env vars — can see it. The MITM flow keeps the agent blind; this one hands it the key. Use it for tools/SDKs that need a real secret at startup and that you trust not to exfiltrate it. Failure to resolve aborts startup.

Resolution is concurrent (one `op read` per env var, all running in parallel) with a 30s per-call timeout. Resolved values persist for the lifetime of the child process.

### Overlay cascade

Final child env = parent env ∪ global `[env]` ∪ profile `[profiles.<name>.env]`. Profile wins on conflict. Proxy-injected vars (`HTTPS_PROXY`, `NO_PROXY`, `PATH`, CA cert vars, `CREDPROXY_TOKEN`) always override config env vars.

## Database Credential Isolation

`[databases.*]` entries keep real database passwords out of the wrapped process. At session start credproxy opens a local relay per database — it authenticates the child with a random per-session password, opens the backend connection with the real credential (resolved from `op://` at startup, like host credentials), and relays bytes transparently. The child receives a localhost-only connection string via the env var you name in `env`:

```toml
[databases.mydb]
engine = "postgres"              # or "mysql"
host = "db.example.com"
port = 5432
user = "app_user"
password = "op://Private/mydb/password"
database = "appdb"
params = "sslmode=require"       # optional backend TLS: sslmode (both engines) or mysql use_ssl
env = "DATABASE_URL"
```

The child sees `DATABASE_URL=postgres://app_user:<random>@127.0.0.1:<port>/mydb?sslmode=disable` and every driver/ORM works unchanged — prepared statements included, because the relay never interprets post-auth traffic. No sentinel convention to learn. Inherited `DATABASE_URL`, `PGPASSWORD`, and `MYSQL_PWD` are stripped from the child env, so a real connection string in your shell cannot silently bypass the relay. This is the safe alternative to putting a resolved `DATABASE_URL` in `[env]` (see the security caveat above).

**Security property:** the real password exists only inside credproxy's memory — never in the child env, never on disk. The child's session password is random, valid only against the local relay, and dies with the session. Supported backend auth: Postgres SCRAM-SHA-256 / md5 / cleartext-over-TLS; MySQL caching_sha2 (fast-auth, and full-auth with RSA key exchange) and mysql_native_password.

**Requirements: none beyond credproxy itself.** No pooler binaries, no containers.

## Security

### What credproxy prevents

- **Casual credential exfiltration** — the agent only has `CREDPROXY_TOKEN` in its context. Env dumps, config file reads, and header logs all yield the sentinel.
- **Silent secret-store access** — `OP_SERVICE_ACCOUNT_TOKEN` and `BW_SESSION` are stripped from the child env, and `op`/`bw` are replaced with shims that exit 1. The shims survive macOS `path_helper` in nested non-interactive shells (via `BASH_ENV`); shells invoked directly as login shells inside the child are not covered. The agent cannot silently resolve credentials.
- **Lateral host access** — only configured hosts are MITM'd. Unconfigured hosts are tunneled through without interception.

### What credproxy does NOT prevent

- **Authenticated actions on your behalf** — credproxy prevents credential theft, not credential misuse. A compromised agent can still make authenticated API calls to configured hosts. Limit credential scope (read-only tokens, restricted API keys) to reduce blast radius.
- **Full OS access** — the agent can still read files, execute commands, and access the network. For execution isolation, use microVMs, gVisor, or similar.
- **Determined attacker with known paths** — if the agent knows the absolute path to `op` and the `OP_SERVICE_ACCOUNT_TOKEN`, it can bypass credproxy. credproxy strips both.
- **1Password app integration** — if the 1Password desktop app is running with biometric auth, `op read` surfaces an authorization prompt. This is a user-visible backstop, not a bypass.

### Same-host LLM conflict

When the LLM provider host and a configured credential host are the same (e.g., your project uses `api.minimax.io` as both the LLM API and a third-party service API), credproxy will MITM the LLM requests too. The sentinel substitution is indiscriminate — it replaces `CREDPROXY_TOKEN` everywhere in the request body, including the system prompt. The LLM will receive your agent instructions with the real credential value substituted where the sentinel appeared.

This is not a bug — the resolver is doing exactly what it's designed to do. But it means the agent will see the real credential value in its system prompt, violating the core isolation guarantee.

**Mitigation:** Use a different LLM provider than the one configured as a credential host. If your project calls `api.minimax.io` as a third-party API, don't use MiniMax as your LLM provider in the same credproxy session.

### Zero introspection surface

credproxy has no management API, no status endpoints, no CLI output containing real secrets, and no `/resolve` endpoint. The agent can send traffic through credproxy, but it cannot *ask* credproxy for secrets.

## Project Structure

```
cmd/credproxy/main.go        Entrypoint
internal/ca/ca.go             Self-signed CA + per-host leaf cert minting
internal/config/config.go     Host-keyed config with cascading merge
internal/mitm/mitm.go         MITM proxy (CONNECT + TLS termination + forwarding)
internal/providers/            Credential providers (1Password CLI)
internal/resolver/resolver.go  Sentinel detection and substitution
internal/dbrelay/              Session relay lifecycle and child env computation
internal/dbproxy/              Postgres and MySQL auth-split relays
```
