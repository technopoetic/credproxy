# credproxy — AGENTS.md

## Project State

v2 core implementation complete and live-tested:
- Host-based sentinel matching (CREDPROXY_TOKEN)
- Wrap mode (`credproxy opencode`)
- Cascading config (global + project)
- Profiles (`--profile <name>`) for per-environment credential and env var selection
- Env var injection from config (`[env]` and `[profiles.<name>.env]`)
- TLS tunneling for unconfigured hosts
- Query string, header, and body substitution
- CA cert env vars injected (SSL_CERT_FILE, REQUESTS_CA_BUNDLE, NODE_EXTRA_CA_CERTS, CURL_CA_BUNDLE), pointed at
  `trust-bundle.pem` — credproxy's CA cert followed by a vendored public root bundle (`internal/ca/mozilla-bundle.pem`),
  regenerated on every run via `Provider.WriteTrustBundle`. Fixes tools (gcloud, uv, HF Hub) that treat these vars as a
  full trust-store replacement rather than a merge — they'd otherwise fail TLS on any real, unconfigured-host
  connection, since only `ca.pem` (credproxy's own CA, no public roots) was exposed before. `ca.pem`/`ca-key.pem`
  themselves are untouched — still the stable, generate-once CA identity used for MITM leaf-cert signing.
- CREDPROXY_TOKEN env var set to literal sentinel in child env
- PATH shim approach (not directory stripping) for blocking op/bw

## Remaining Work

- Cut daemon mode from code (YAGNI — wrap mode handles everything)
- Consider adding `no_proxy_hosts` config to avoid routing LLM traffic through proxy
- Investigate TLS "bad record MAC" on first `op read` (handshake timeout during 1Password auth prompt)

## Known Issues

- (Fixed) Real, unconfigured-host TLS connections used to fail `CERTIFICATE_VERIFY_FAILED` in any tool that treats
  `SSL_CERT_FILE`/`REQUESTS_CA_BUNDLE`/`CURL_CA_BUNDLE` as a full trust-store replacement — hit repeatedly (`uv`,
  abby-normal's HF Hub fallback, `gcloud auth`) before being tracked down and fixed at the root via `trust-bundle.pem`
  (see Project State above). If a similar cert failure resurfaces in a new tool, check `echo $SSL_CERT_FILE` resolves
  to `trust-bundle.pem` (not `ca.pem`) first — a stale/reinstalled `credproxy` binary predating this fix would still
  only write `ca.pem`.

- First `op read` call can cause TLS handshake timeout if 1Password auth prompt takes >30s. The credential caches after first resolution, so subsequent requests work.
- 1Password biometric prompt shows "tmux" (not "credproxy-op") when running inside tmux — 1Password reads the controlling terminal, not argv[0]
- Logs go to `~/.config/credproxy/credproxy.log`, not stderr (avoids TUI ghosting)
- Same-host LLM conflict: when the LLM provider host is also a configured credential host, credproxy substitutes the sentinel in the system prompt body on its way to the LLM, exposing the real credential. Mitigation: use a different LLM provider than the credential host. Documented in README.

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
