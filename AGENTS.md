# credproxy — AGENTS.md

## Project State

v2 core implementation complete and live-tested. Tagged v0.1.0:
- Host-based sentinel matching (CREDPROXY_TOKEN)
- Wrap mode (`credproxy opencode`)
- Cascading config (global + project)
- Profiles (`--profile <name>`) for per-environment credential and env var selection
- Env var injection from config (`[env]` and `[profiles.<name>.env]`)
- `op://` URI resolution in env values at startup (resolves concurrently, 30s per-call timeout, fail-fast on error)
- TLS tunneling for unconfigured hosts (CONNECT) and forward-proxy path (absolute URI) with HTTPS scheme preservation
- Query string, header, and body substitution
- CA cert env vars injected (SSL_CERT_FILE, REQUESTS_CA_BUNDLE, NODE_EXTRA_CA_CERTS, CURL_CA_BUNDLE), pointed at
  `trust-bundle.pem` — credproxy's CA cert followed by a vendored public root bundle (`internal/ca/mozilla-bundle.pem`),
  regenerated on every run via `Provider.WriteTrustBundle`. Fixes tools (gcloud, uv, HF Hub) that treat these vars as a
  full trust-store replacement rather than a merge — they'd otherwise fail TLS on any real, unconfigured-host
  connection, since only `ca.pem` (credproxy's own CA, no public roots) was exposed before. `ca.pem`/`ca-key.pem`
  themselves are untouched — still the stable, generate-once CA identity used for MITM leaf-cert signing.
- CREDPROXY_TOKEN env var set to literal sentinel in child env
- PATH shim approach (not directory stripping) for blocking op/bw, hardened for macOS login shells: the shim dir is
  written to a `path.sh` script exported via `BASH_ENV`, which every non-interactive bash in the child tree sources.
  This defeats `path_helper` (run by /etc/profile in login shells), which rebuilds PATH with system dirs first and
  leaves the shim dir present but behind `/usr/local/bin` — where the real `op` lives. `BW_SESSION` is also stripped
  from the child env so an unlocked Bitwarden session cannot leak through.
- First-run scaffolding: creates `~/.config/credproxy/`, writes example config if none exists, touches log file (fixes crash on fresh install where log OpenFile ran before dir existed)
- DB credential isolation: `[databases.*]` config entries start embedded
  auth-split relays at wrap time (in-process, no external binaries or
  containers); child gets a localhost-only URL with a random per-session
  password, real `op://`-resolved credential stays in credproxy memory only —
  never on disk. `internal/dbrelay/` + `internal/dbproxy/{pg,mysql}/`.
  Handshakes are hand-rolled on documented framing (pg: pgproto-free, scram
  via xdg-go/scram; mysql: native + caching_sha2 incl. full-auth RSA).

## Remaining Work

- Cut daemon mode from code (YAGNI — wrap mode handles everything)
- Consider adding a fixed listen-port option: wrap mode binds an ephemeral port per session, so a long-lived child
  (e.g. `opencode serve --service`) can outlive the credproxy session and keep failing network calls against the dead
  proxy URL — hit 2026-09-28 when a Sep 25 service poisoned opencode's provider catalog fetches for days
- Consider adding `no_proxy_hosts` config to avoid routing LLM traffic through proxy
- Investigate TLS "bad record MAC" on first `op read` (handshake timeout during 1Password auth prompt)

## Known Issues

- op/bw shim does not cover shells invoked *as* login shells (`bash -l`, `bash -lc`) inside the wrapped child: those
  read profile files, not `BASH_ENV`, and `path_helper` puts the real `op` back ahead of the shim. The common case
  (agent tool calls spawning non-interactive `bash -c`, including nested under a login parent) is covered via
  `BASH_ENV`; a login shell running `which op` in the child still resolves `/usr/local/bin/op`.
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
# On a fresh machine (no repo checkout):
#   go install github.com/technopoetic/credproxy/cmd/credproxy@latest
```

## Architecture

- `internal/config/` — Host-keyed config with cascading merge (global + project .credproxy.toml)
- `internal/resolver/` — Sentinel matching in headers, body, and query strings
- `internal/mitm/` — MITM proxy for configured hosts, plain tunnel for unconfigured hosts, forward-proxy for absolute-URI requests
- `internal/providers/` — 1Password CLI provider (op read)
- `internal/dbrelay/` — Session relay lifecycle and child env computation
- `internal/dbproxy/` — Embedded auth-split relay: shared byte pipe, Postgres and MySQL handshakes
- `internal/ca/` — Self-signed CA + per-host leaf cert minting
- `cmd/credproxy/` — Wrap mode entrypoint

## Config Locations

- Global: `~/.config/credproxy/config.toml`
- Project: `.credproxy.toml` (walked up from cwd)
- Logs: `~/.config/credproxy/credproxy.log`

## Sentinel

Default: `CREDPROXY_TOKEN`. No markdown syntax characters. Configurable via `--sentinel` flag.
