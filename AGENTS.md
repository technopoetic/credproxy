# credproxy — AGENTS.md

## Project State

v2 core implementation complete and live-tested:
- Host-based sentinel matching (CREDPROXY_TOKEN)
- Wrap mode (`credproxy opencode`)
- Cascading config (global + project)
- TLS tunneling for unconfigured hosts
- Query string, header, and body substitution
- CA cert env vars injected (SSL_CERT_FILE, REQUESTS_CA_BUNDLE, NODE_EXTRA_CA_CERTS, CURL_CA_BUNDLE)
- CREDPROXY_TOKEN env var set to literal sentinel in child env
- PATH shim approach (not directory stripping) for blocking op/bw

## Remaining Work

- Cut daemon mode from code (YAGNI — wrap mode handles everything)
- Consider adding `no_proxy_hosts` config to avoid routing LLM traffic through proxy
- Investigate TLS "bad record MAC" on first `op read` (handshake timeout during 1Password auth prompt)

## Known Issues

- First `op read` call can cause TLS handshake timeout if 1Password auth prompt takes >30s. The credential caches after first resolution, so subsequent requests work.
- 1Password biometric prompt shows "tmux" (not "credproxy-op") when running inside tmux — 1Password reads the controlling terminal, not argv[0]
- Logs go to `~/.config/credproxy/credproxy.log`, not stderr (avoids TUI ghosting)

## How to Build & Test

```bash
go build ./...          # build all
go test ./...           # run tests
go install ./cmd/credproxy/  # install to ~/go/bin/credproxy
```

## Architecture

- `internal/config/` — Host-keyed config with cascading merge (global + project .credproxy.toml)
- `internal/resolver/` — Sentinel matching in headers, body, and query strings
- `internal/mitm/` — MITM proxy for configured hosts, plain tunnel for unconfigured hosts
- `internal/providers/` — 1Password CLI provider (op read)
- `internal/ca/` — Self-signed CA + per-host leaf cert minting
- `cmd/credproxy/` — Wrap mode entrypoint

## Config Locations

- Global: `~/.config/credproxy/config.toml`
- Project: `.credproxy.toml` (walked up from cwd)
- Logs: `~/.config/credproxy/credproxy.log`

## Sentinel

Default: `CREDPROXY_TOKEN`. No markdown syntax characters. Configurable via `--sentinel` flag.
