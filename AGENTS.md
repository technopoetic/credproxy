# credproxy — AGENTS.md

## Project State

v2 implementation in progress. Core functionality working:
- Host-based sentinel matching (CREDPROXY_TOKEN)
- Wrap mode (`credproxy opencode`)
- Cascading config (global + project)
- TLS tunneling for unconfigured hosts
- Query string, header, and body substitution

## Remaining Work

- Verify query string substitution fixes Unsplash 401 in live testing
- Investigate TLS "bad record MAC" on first `op read` (handshake timeout during 1Password auth prompt)
- Consider adding `no_proxy_hosts` config to avoid routing LLM traffic through proxy

## Known Issues

- First `op read` call can cause TLS handshake timeout if 1Password auth prompt takes >30s. The credential caches after first resolution, so subsequent requests work.
- `argv[0]` set to `credproxy-op` for `op read` calls — 1Password prompt shows this instead of the terminal name
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
- `cmd/credproxy/` — Wrap mode + daemon mode entrypoint

## Config Locations

- Global: `~/.config/credproxy/config.toml`
- Project: `.credproxy.toml` (walked up from cwd)
- Logs: `~/.config/credproxy/credproxy.log`

## Sentinel

Default: `CREDPROXY_TOKEN`. No markdown syntax characters. Configurable via `--sentinel` flag.
