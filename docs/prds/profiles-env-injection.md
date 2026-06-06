# credproxy Profiles & Environment Injection — PRD

## What

Add profile-based credential selection and arbitrary env var injection to credproxy. Profiles let the same hostname resolve to different credentials (staging vs production) selected at startup. Env var injection lets credproxy set non-secret environment variables in the child process, replacing tools like direnv/dotenv.

## Why

Currently credproxy maps one credential per hostname globally. This breaks down when the same API host needs different credentials depending on environment — `api.stripe.com` in staging vs production, for example. Host-based matching can't distinguish between them.

Separately, developers working across environments routinely toggle non-secret env vars (`RAILS_ENV`, `DATABASE_URL`, `PORT`, feature flags). credproxy already injects `HTTPS_PROXY` and `CREDPROXY_TOKEN` into the child — extending this to arbitrary env vars from config is a natural fit that makes credproxy a complete environment manager, not just a credential proxy.

## How It Works

```
$ credproxy --profile staging opencode
    │
    ├─ Load global config (~/.config/credproxy/config.toml)
    ├─ Load project config (.credproxy.toml from cwd, walk up)
    ├─ Select profile "staging" from merged config
    ├─ Start MITM proxy on random port
    ├─ Inject env vars: global env ∪ profile env (profile wins)
    ├─ Strip OP_SERVICE_ACCOUNT_TOKEN, op, bw from child env/PATH
    ├─ Set HTTPS_PROXY, NO_PROXY, CREDPROXY_TOKEN in child env
    ├─ Exec child process (opencode)
    │
    │   Agent makes HTTP call to api.stripe.com
    │   with Authorization: BREDPROXY_TOKEN
    │       ↓ credproxy resolves credential from active profile
    │       ↓ swaps CREDPROXY_TOKEN → staging key from 1Password
    │       ↓ re-encrypts, forwards to upstream
    │
    └─ When child exits, proxy shuts down
```

## Profiles

### Startup-time selection only

`credproxy --profile <name> <command>`

The profile is selected when credproxy starts and is **immutable for the session**. To switch profiles, exit and rewrap. No runtime swap.

**Why no runtime swap:** A child→parent IPC channel that lets the agent switch profiles mid-session is a management API. credproxy's security model depends on zero introspection surface — the agent cannot influence which credential gets used for a host. Runtime swap would let an agent silently shift from staging to production credentials. Startup-time selection preserves "config determines credential, agent has zero influence."

### Config format

```toml
# Global host config (used when no profile is active, or as base)
[hosts."api.github.com"]
credential = "op://Personal/github-pat/token"

[hosts."api.stripe.com"]
credential = "op://Business/stripe-live/key"

# Profile definitions
[profiles.staging.hosts."api.stripe.com"]
credential = "op://Business/stripe-test/key"

[profiles.staging.env]
RAILS_ENV = "staging"
DATABASE_URL = "postgres://staging.db:5432/app"
PORT = "3000"
DEBUG = "on"

[profiles.production.env]
RAILS_ENV = "production"
DATABASE_URL = "postgres://prod.db:5432/app"
PORT = "443"
```

### Merge rules

When a profile is active, the final config is:

1. Start with global config (hosts + env)
2. Overlay profile config (hosts + env)
3. Same host in both → profile wins
4. Same env var in both → profile wins
5. No profile selected → global config only (current behavior, unchanged)

```toml
# Global env (always injected)
[env]
TERM = "xterm-256color"
EDITOR = "nvim"

# Profile overlays global
[profiles.staging.env]
RAILS_ENV = "staging"        # added
PORT = "3000"                # added
EDITOR = "code"              # overrides global

# Final child env for --profile staging:
# TERM=xterm-256color  (from global, not overridden)
# EDITOR=code           (profile wins)
# RAILS_ENV=staging     (from profile)
# PORT=3000             (from profile)
```

### Env var overlay cascade

Final child env = parent env ∪ global `[env]` ∪ profile `[profiles.<name>.env]`

- Parent env: the environment credproxy itself inherited
- Global env vars: from `[env]` in config
- Profile env vars: from `[profiles.<name>.env]` in config
- Profile wins on conflict
- No per-host env vars — env vars are process-wide, not per-connection

### No profile (default behavior)

Running `credproxy opencode` without `--profile` uses only global config. Existing behavior is unchanged. Global `[env]` vars are still injected.

## Config Format Decision: TOML

YAML was considered and rejected for this security-adjacent tool:

- YAML's implicit typing converts `on`, `off`, `yes`, `no`, `true`, `false` to booleans — a credential URI like `op://vault/stripe/On` would silently become `op://vault/stripe/true`
- YAML's indentation sensitivity causes fragility in hand-edited config (mixed tabs, wrong-line errors)
- Env var values are frequently ambiguous types: `PORT=8080` (integer), `DEBUG=on` (boolean), `VERSION=1.10` (float)
- TOML requires explicit quoting for all string values — no ambiguity, no `!!str` escape tags

If profile nesting makes TOML sections deeply nested (`[profiles.staging.hosts."api.stripe.com"]`), the escape hatch is file-per-profile:

```
~/.config/credproxy/
  config.toml              # base config
  profiles/
    staging.toml           # overlay
    production.toml        # overlay
```

File-per-profile is not in scope for the initial implementation but is noted as a future option if single-file nesting becomes unwieldy.

## Security Model Impact

Profiles do **not** change credproxy's core security properties:

- The agent still only sees `CREDPROXY_TOKEN` — never real secrets
- The agent still cannot introspect which profile is active (no IPC, no status API)
- The agent still cannot influence which credential resolves for a given host
- Env var injection is for **non-secret** values only — secrets remain behind the MITM proxy
- `OP_SERVICE_ACCOUNT_TOKEN` and secret-store CLIs remain stripped from child env

### New risk: profile name leakage

The profile name could leak via process args visible in `/proc/<pid>/cmdline` or `ps aux`. This is low-severity — the profile name is not a secret (it's "staging" or "production", not a credential). No mitigation needed.

### Guard rail: env vars vs credentials

Env vars in config are intentionally a simple string map with no URI resolution. They are for non-secret configuration values. If a user puts a real secret in `[env]`, it will be visible to the child process — same as writing it in `.env` or `.bashrc`. credproxy cannot prevent this, but the config documentation and examples should make clear that `[env]` is for non-secret values and `[hosts.<name>.credential]` is for secrets.

## CLI

```bash
# Wrap mode with profile
credproxy --profile staging opencode
credproxy --profile production -- claude-code

# Wrap mode without profile (unchanged)
credproxy opencode

# New flag
--profile <name>    # select profile from config (default: no profile)
```

## Config Schema (Full)

```toml
# Optional global settings
projects_dir = "/home/user/code"

# Global env vars (always injected)
[env]
TERM = "xterm-256color"
EDITOR = "nvim"

# Global host config
[hosts."api.github.com"]
credential = "op://Personal/github-pat/token"

[hosts."api.stripe.com"]
credential = "op://Business/stripe-live/key"

# Profile definitions
[profiles.staging.hosts."api.stripe.com"]
credential = "op://Business/stripe-test/key"

[profiles.staging.env]
RAILS_ENV = "staging"
DATABASE_URL = "postgres://staging.db:5432/app"
PORT = "3000"

[profiles.production.hosts."api.stripe.com"]
credential = "op://Business/stripe-live/key"

[profiles.production.env]
RAILS_ENV = "production"
DATABASE_URL = "postgres://prod.db:5432/app"
PORT = "443"
```

## Implementation Plan

### 1. Config struct changes (`internal/config/config.go`)

```go
type Config struct {
    ProjectsDir string                       `toml:"projects_dir"`
    Env        map[string]string             `toml:"env"`
    Hosts      map[string]HostConfig         `toml:"hosts"`
    Profiles   map[string]ProfileConfig      `toml:"profiles"`
    hostsSet   map[string]bool
}

type ProfileConfig struct {
    Hosts map[string]HostConfig `toml:"hosts"`
    Env   map[string]string     `toml:"env"`
}
```

### 2. Merge logic update

Current `Merge()` handles global→project overlay. Add `ApplyProfile(name string)` that:

1. Starts with base config (global + project merged)
2. If profile exists in merged config, overlays profile hosts and profile env
3. Same host → profile wins. Same env var → profile wins.

### 3. Wrap mode env injection (`cmd/credproxy/main.go`)

After building final config and before `exec`, iterate final env map and set each key in child environment. Existing env var injection (`HTTPS_PROXY`, `NO_PROXY`, `CREDPROXY_TOKEN`, CA cert vars) continues as-is — profile env is additive.

### 4. CLI flag

Add `--profile <name>` flag. Validate that the profile exists in merged config before starting the proxy. Error with available profile names if profile not found.

## Acceptance Criteria

- `credproxy --profile staging opencode` selects the staging profile
- Profile hosts override global hosts for the same hostname
- Profile env vars are injected into the child process
- Profile env vars override global env vars on conflict
- `credproxy opencode` (no `--profile`) behaves identically to current behavior
- Invalid profile name prints available profiles and exits with error
- `[env]` at global level injects env vars even without a profile
- Real credentials are never present in child env (only `CREDPROXY_TOKEN`)

## Non-Goals

- Runtime profile switching (no child→parent IPC)
- Per-host env vars (env vars are process-wide)
- Secret values in `[env]` (use `[hosts.<name>.credential]` for secrets)
- File-per-profile config layout (future option, not blocking)
- Profile inheritance (one profile extending another)
- Profile-specific sentinel values
- Encrypted env var values

## Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Users put real secrets in `[env]` | Medium | High — secret visible to child | Documentation, examples show only non-secret values |
| Profile name leaks via `/proc` | Low | Low — profile name is not a secret | Accept. Not a credential. |
| TOML nesting becomes unwieldy with many profiles | Low | Medium — readability | File-per-profile escape hatch (future) |
| Env var collision with proxy-injected vars (`HTTPS_PROXY`, etc.) | Low | Medium — proxy vars must win | Proxy-injected vars always override config env vars |

## Out of Scope (Future)

- File-per-profile config layout (`profiles/staging.toml`)
- Profile inheritance or composition
- Profile-specific `projects_dir` or `no_proxy_hosts`
- Secret env var injection with sentinel substitution (env vars that contain `CREDPROXY_TOKEN` resolved at injection time)
- Profile listing/describing CLI commands
