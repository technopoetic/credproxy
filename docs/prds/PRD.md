# credproxy — PRD

## What

Local, single-user MITM proxy that injects credentials from 1Password into agent HTTP requests. Agents never see or handle real secrets.

## Why

AI coding agents (Claude Code, OpenCode, etc.) make HTTP tool calls that require API keys. You don't want the agent to have real credentials — prompt injection can exfiltrate anything in agent context. credproxy substitutes dummy values for real credentials at the network layer, so the agent never possesses the secrets.

## How It Works

```
Agent (HTTPS_PROXY=http://localhost:8042, ANTHROPIC_API_KEY=__anthropic_key__)
    ↓ HTTPS request through CONNECT tunnel
credproxy MITM proxy
    ↓ terminates TLS, reads plaintext request
    ↓ swaps __anthropic_key__ → real key from 1Password
    ↓ re-encrypts, forwards to upstream
    ↓ streams response back to agent
```

The agent uses dummy values in env vars and request headers. The proxy swaps them for real credentials at the network layer. The agent can't exfiltrate what it doesn't have.

## Dummy Value Convention

Agents use placeholder strings in env vars and headers. The proxy recognizes these and substitutes real values:

```
ANTHROPIC_API_KEY=__anthropic_key__
Authorization: Bearer __github_pat__
```

Placeholder format: `__<name>__` — double-underscore delimited, matches the key name in config.

This approach requires no agent training — the agent just uses env vars as normal, with dummy values instead of real ones.

## Configuration

Location: `~/.config/credproxy/credentials.toml`

```toml
[credentials]
anthropic_key = "op://Personal/anthropic-api-key/secret"
github_pat = "op://Personal/github-pat/token"
stripe_key = "op://Business/stripe-live/key"

allowed_hosts = [
    "api.anthropic.com",
    "api.github.com",
    "api.stripe.com",
]
```

### Sections

- `[credentials]` — Maps a logical name to a credential URI. The logical name is used in the dummy value (`__<name>__`).
- `allowed_hosts` — Array of hosts the proxy will forward to. Requests to unlisted hosts are rejected with 403.

### Credential URI Schemes

| Scheme | Provider | Example |
|--------|----------|---------|
| `op://` | 1Password CLI | `op://Personal/github-api-key/token` |

Additional schemes via the provider plugin interface (future).

## MITM Proxy Architecture

The proxy must see inside HTTPS requests to substitute credentials. It does this via MITM:

1. Agent sends `CONNECT api.stripe.com:443` to credproxy
2. credproxy responds `200 Connection Established`
3. credproxy terminates client-side TLS (presents a per-host leaf cert signed by a local CA)
4. Agent sends the actual HTTP/1.1 request over the TLS connection
5. credproxy reads the plaintext, finds `__<name>__` placeholders in headers and body
6. credproxy resolves placeholders via `op read`, substitutes real values
7. credproxy opens a fresh TLS connection to the upstream and forwards the modified request
8. Response streams back to the agent

### CA Certificate

On first run, credproxy generates a self-signed CA key pair and stores it at `~/.config/credproxy/ca.pem` and `~/.config/credproxy/ca-key.pem`. The user must trust this CA once:

```bash
# macOS
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.config/credproxy/ca.pem

# Linux (Ubuntu/Debian)
sudo cp ~/.config/credproxy/ca.pem /usr/local/share/ca-certificates/credproxy.crt
sudo update-ca-certificates
```

The CLI prints instructions on first run.

## Provider Interface

Providers resolve URIs to raw secret values. Interface:

```go
type Provider interface {
    Resolve(ctx context.Context, uri string) (string, error)
    Schemes() []string
}
```

## 1Password Provider

Uses the `op` CLI.

**Authentication**: `OP_SERVICE_ACCOUNT_TOKEN` environment variable.

**CLI dependency**: `op` must be installed and on PATH. The proxy invokes `op read <uri>` to retrieve secrets.

**Caching**: Resolved secrets are cached in-memory for the proxy's lifetime. `op read` is called once per credential, then the value is reused. This avoids hitting 1Password on every request.

**Retry**: 2 retries with 100ms backoff on `op read` failure.

## Security

- **Host whitelisting**: Only configured hosts are proxied. Unconfigured hosts return 403.
- **No credential logging**: Resolved secrets are never written to logs or stdout.
- **Agent isolation**: The agent only sees dummy values (`__key__`). Real credentials exist only in the proxy process memory.
- **Error handling**: Missing credentials return HTTP 502 (no secret leakage in error messages).
- **CA key protection**: `ca-key.pem` is written with 0600 permissions.

## Agent Integration

```bash
# Start credproxy in a terminal
credproxy

# In another terminal, set env vars
export HTTPS_PROXY=http://localhost:8042
export NO_PROXY=localhost,127.0.0.1
export OP_SERVICE_ACCOUNT_TOKEN=your-service-account-token
export ANTHROPIC_API_KEY=__anthropic_key__
export GITHUB_PAT=__github_pat__

# Start agent — it inherits HTTPS_PROXY and dummy env vars
claude-code
# or
opencode
```

Both Claude Code and OpenCode respect `HTTPS_PROXY` and `HTTP_PROXY` (confirmed via docs).

## Error Handling

- **1Password lookup fails**: Retry 2x with 100ms backoff. Return HTTP 502.
- **Host not in `[allowed_hosts]`**: Return HTTP 403.
- **Placeholder not in `[credentials]` config**: Pass through unchanged (no substitution).
- **Streaming responses**: Pass through unchanged.

## CLI

```bash
# Run foreground (Ctrl-C to exit)
credproxy

# Flags
--port 8042          # proxy listen port (default: 8042)
--config ~/.config/credproxy/credentials.toml  # config path
--open-proxy         # allow all hosts (not recommended)
```

## Project Structure

```
credproxy/
├── cmd/
│   └── credproxy/
│       └── main.go
├── internal/
│   ├── ca/
│   │   └── ca.go           # CA key pair generation, leaf cert minting
│   ├── mitm/
│   │   └── mitm.go          # MITM proxy (CONNECT + TLS termination + forwarding)
│   ├── resolver/
│   │   └── resolver.go      # Placeholder detection and substitution
│   ├── config/
│   │   └── config.go        # Config file loading and parsing
│   └── providers/
│       ├── provider.go      # Provider interface + registry
│       └── onepassword.go   # 1Password CLI provider
├── credentials.toml.example
├── docs/
│   └── prds/
│       └── PRD.md
├── go.mod
└── go.sum
```

## Future (Out of Scope for v1)

- Response body redaction
- Daemon mode (launchd, systemd)
- Homebrew distribution
- Additional providers: AWS Secrets Manager, HashiCorp Vault, Bitwarden CLI, env vars
- Multiple credentials per host
- Metrics/observability
- MCP server wrapper for non-HTTP tool calls

## Dependencies

- Go 1.21+
- `op` CLI (1Password) — installed separately, not vendored

## Distribution

- `go install` for early adopters
- Homebrew tap (future)
- Binary releases (future)