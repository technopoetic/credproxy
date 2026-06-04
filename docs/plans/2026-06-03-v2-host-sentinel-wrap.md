# v2 Implementation Plan: Host-Based Sentinel, Wrap Mode, Cascading Config

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite credproxy from named-placeholder matching to host-based sentinel substitution with wrap mode and cascading config.

**Architecture:** Config becomes host-keyed (`[hosts."api.unsplash.com"] credential = "op://..."`) instead of credential-name-keyed. Resolver matches on target host, substitutes a single sentinel (`CREDPROXY_TOKEN`) everywhere in the request (headers, body, query string). Main entrypoint detects wrap mode (`credproxy <command>`) vs daemon mode, starts proxy, configures child environment, strips secret-store CLIs, and execs the child. Cascading config loads global `~/.config/credproxy/config.toml` + project `.credproxy.toml` (walked up from cwd), project overlays global.

**Status:** All 6 tasks implemented. Remaining: fix TLS handshake timeout on first `op read`, verify query string substitution fixes Unsplash 401 in live testing.

**Tech Stack:** Go 1.21+, BurntSushi/toml v1.6, existing MITM proxy internals (ca, mitm, providers)

---

## File Structure

| File | Change | Responsibility |
|------|--------|----------------|
| `internal/config/config.go` | Rewrite | Host-keyed config struct, cascading merge, project config walk |
| `internal/resolver/resolver.go` | Rewrite | Host-based sentinel matching and substitution |
| `cmd/credproxy/main.go` | Rewrite | Wrap mode, daemon mode, env/PATH stripping |
| `internal/mitm/mitm.go` | Modify | Pass hostname to resolver for host-based lookup |
| `internal/ca/ca.go` | No change | CA generation and leaf cert minting |
| `internal/providers/provider.go` | No change | Provider interface and registry |
| `internal/providers/onepassword.go` | No change | 1Password CLI provider |

---

### Task 1: Rewrite config package for host-keyed format and cascading merge

**Files:**
- Rewrite: `internal/config/config.go`
- Create: `internal/config/config_test.go`

The Config struct changes from credential-name-keyed to host-keyed. Add `ProjectsDir` for project config discovery. Add `Merge` for overlaying project onto global. Add `WalkProjectConfig` for finding `.credproxy.toml` from cwd.

- [ ] **Step 1: Write the failing tests**

```go
package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadHostKeyedConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
projects_dir = "/home/user/code"

[hosts."api.github.com"]
credential = "op://Personal/github-pat/token"

[hosts."api.stripe.com"]
credential = "op://Business/stripe-live/key"
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.ProjectsDir != "/home/user/code" {
		t.Errorf("ProjectsDir = %q, want /home/user/code", cfg.ProjectsDir)
	}

	uri, ok := cfg.GetCredentialURI("api.github.com")
	if !ok {
		t.Fatal("expected api.github.com to be configured")
	}
	if uri != "op://Personal/github-pat/token" {
		t.Errorf("api.github.com credential = %q, want op://Personal/github-pat/token", uri)
	}

	if !cfg.IsHostAllowed("api.github.com") {
		t.Error("api.github.com should be allowed")
	}
	if cfg.IsHostAllowed("api.evil.com") {
		t.Error("api.evil.com should not be allowed")
	}
}

func TestMergeProjectOverlaysGlobal(t *testing.T) {
	globalDir := t.TempDir()
	globalPath := filepath.Join(globalDir, "config.toml")
	globalContent := `
projects_dir = "/home/user/code"

[hosts."api.github.com"]
credential = "op://Personal/github-pat/token"

[hosts."api.stripe.com"]
credential = "op://Business/stripe-live/key"
`
	if err := os.WriteFile(globalPath, []byte(globalContent), 0644); err != nil {
		t.Fatal(err)
	}

	projectDir := t.TempDir()
	projectPath := filepath.Join(projectDir, ".credproxy.toml")
	projectContent := `
[hosts."api.unsplash.com"]
credential = "op://shipstops/Unsplash app creds/Access Key"

[hosts."api.github.com"]
credential = "op://Work/github-enterprise/token"
`
	if err := os.WriteFile(projectPath, []byte(projectContent), 0644); err != nil {
		t.Fatal(err)
	}

	global, err := Load(globalPath)
	if err != nil {
		t.Fatal(err)
	}
	project, err := Load(projectPath)
	if err != nil {
		t.Fatal(err)
	}

	merged := global.Merge(project)

	uri, ok := merged.GetCredentialURI("api.github.com")
	if !ok {
		t.Fatal("expected api.github.com to be configured")
	}
	if uri != "op://Work/github-enterprise/token" {
		t.Errorf("merged api.github.com = %q, want project override", uri)
	}

	uri, ok = merged.GetCredentialURI("api.stripe.com")
	if !ok {
		t.Fatal("expected api.stripe.com to be configured from global")
	}
	if uri != "op://Business/stripe-live/key" {
		t.Errorf("merged api.stripe.com = %q, want global value", uri)
	}

	uri, ok = merged.GetCredentialURI("api.unsplash.com")
	if !ok {
		t.Fatal("expected api.unsplash.com from project")
	}
	if uri != "op://shipstops/Unsplash app creds/Access Key" {
		t.Errorf("merged api.unsplash.com = %q, want project value", uri)
	}
}

func TestWalkProjectConfig(t *testing.T) {
	rootDir := t.TempDir()
	projectDir := filepath.Join(rootDir, "myproject")
	subDir := filepath.Join(projectDir, "src", "pkg")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}

	projectConfig := `
[hosts."api.unsplash.com"]
credential = "op://shipstops/Unsplash app creds/Access Key"
`
	if err := os.WriteFile(filepath.Join(projectDir, ".credproxy.toml"), []byte(projectConfig), 0644); err != nil {
		t.Fatal(err)
	}

	found, err := WalkProjectConfig(subDir, rootDir)
	if err != nil {
		t.Fatal(err)
	}
	if found != filepath.Join(projectDir, ".credproxy.toml") {
		t.Errorf("WalkProjectConfig = %q, want %q", found, filepath.Join(projectDir, ".credproxy.toml"))
	}
}

func TestWalkProjectConfigStopsAtRoot(t *testing.T) {
	dir := t.TempDir()
	subDir := filepath.Join(dir, "sub")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}

	found, err := WalkProjectConfig(subDir, dir)
	if err != nil {
		t.Fatal(err)
	}
	if found != "" {
		t.Errorf("WalkProjectConfig = %q, want empty (no config found)", found)
	}
}

func TestDefaultConfigPath(t *testing.T) {
	path := DefaultConfigPath()
	if path == "" {
		t.Error("DefaultConfigPath returned empty string")
	}
}

func TestDefaultProjectsDir(t *testing.T) {
	dir := DefaultProjectsDir()
	if dir == "" {
		t.Error("DefaultProjectsDir returned empty string")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/config/ -v`
Expected: FAIL — struct fields don't match, methods don't exist

- [ ] **Step 3: Rewrite config.go**

```go
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

type HostConfig struct {
	Credential string `toml:"credential"`
}

type Config struct {
	ProjectsDir string               `toml:"projects_dir"`
	Hosts       map[string]HostConfig `toml:"hosts"`
	hostsSet    map[string]bool
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	cfg.setDefaults()
	return &cfg, nil
}

func (c *Config) setDefaults() {
	if c.Hosts == nil {
		c.Hosts = make(map[string]HostConfig)
	}
	c.hostsSet = make(map[string]bool, len(c.Hosts))
	for host := range c.Hosts {
		c.hostsSet[host] = true
	}
}

func (c *Config) Merge(overlay *Config) *Config {
	merged := &Config{
		ProjectsDir: c.ProjectsDir,
		Hosts:       make(map[string]HostConfig, len(c.Hosts)+len(overlay.Hosts)),
		hostsSet:    make(map[string]bool, len(c.Hosts)+len(overlay.Hosts)),
	}
	for host, hc := range c.Hosts {
		merged.Hosts[host] = hc
		merged.hostsSet[host] = true
	}
	for host, hc := range overlay.Hosts {
		merged.Hosts[host] = hc
		merged.hostsSet[host] = true
	}
	return merged
}

func (c *Config) IsHostAllowed(host string) bool {
	return c.hostsSet[host]
}

func (c *Config) GetCredentialURI(host string) (string, bool) {
	hc, ok := c.Hosts[host]
	if !ok {
		return "", false
	}
	return hc.Credential, true
}

func (c *Config) AllowAll() {
	c.hostsSet["*"] = true
}

func WalkProjectConfig(cwd, stopAt string) (string, error) {
	for {
		candidate := filepath.Join(cwd, ".credproxy.toml")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}

		parent := filepath.Dir(cwd)
		if parent == cwd || cwd == stopAt {
			return "", nil
		}
		cwd = parent
	}
}

func DefaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "credproxy", "config.toml")
}

func DefaultProjectsDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, "code")
}

func DefaultCADir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "credproxy")
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/config/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "Rewrite config for host-keyed format with cascading merge"
```

---

### Task 2: Rewrite resolver for host-based sentinel matching

**Files:**
- Rewrite: `internal/resolver/resolver.go`
- Create: `internal/resolver/resolver_test.go`

Resolver changes from `__name__` regex matching to `**token**` sentinel matching. It receives the target hostname, looks up the credential URI from config, resolves it via the provider registry, and substitutes every occurrence of the sentinel in headers and body.

- [ ] **Step 1: Write the failing tests**

```go
package resolver

import (
	"context"
	"strings"
	"testing"

	"github.com/rhibbitts/credproxy/internal/config"
	"github.com/rhibbitts/credproxy/internal/providers"
)

type mockProvider struct {
	values map[string]string
}

func (m *mockProvider) Schemes() []string {
	return []string{"mock"}
}

func (m *mockProvider) Resolve(ctx context.Context, uri string) (string, error) {
	if v, ok := m.values[uri]; ok {
		return v, nil
	}
	return "", fmt.Errorf("not found: %s", uri)
}

func newTestConfig() *config.Config {
	return &config.Config{
		Hosts: map[string]config.HostConfig{
			"api.github.com":   {Credential: "mock://github/token"},
			"api.unsplash.com": {Credential: "mock://unsplash/key"},
		},
	}
}

func newTestResolver(cfg *config.Config) *Resolver {
	reg := providers.NewRegistry()
	reg.Register(&mockProvider{
		values: map[string]string{
			"mock://github/token":  "gh_real_token_123",
			"mock://unsplash/key":  "unsplash_real_key_456",
		},
	})
	return New(cfg, reg)
}

func TestResolveHeadersSubstitutesSentinel(t *testing.T) {
	r := newTestResolver(newTestConfig())

	req := httptest.NewRequest("GET", "https://api.github.com/v1/repos", nil)
	req.Header.Set("Authorization", "Bearer **token**")
	req.Header.Set("Accept", "application/json")

	err := r.ResolveRequest(req, "api.github.com")
	if err != nil {
		t.Fatalf("ResolveRequest: %v", err)
	}

	if req.Header.Get("Authorization") != "Bearer gh_real_token_123" {
		t.Errorf("Authorization = %q, want Bearer gh_real_token_123", req.Header.Get("Authorization"))
	}
	if req.Header.Get("Accept") != "application/json" {
		t.Errorf("Accept = %q, want application/json (unchanged)", req.Header.Get("Accept"))
	}
}

func TestResolveBodySubstitutesSentinel(t *testing.T) {
	r := newTestResolver(newTestConfig())

	body := `{"api_key": "**token**", "name": "test"}`
	req := httptest.NewRequest("POST", "https://api.unsplash.com/photos", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	err := r.ResolveRequest(req, "api.unsplash.com")
	if err != nil {
		t.Fatalf("ResolveRequest: %v", err)
	}

	resolved, _ := io.ReadAll(req.Body)
	if !strings.Contains(string(resolved), "unsplash_real_key_456") {
		t.Errorf("body = %q, want sentinel replaced with real key", string(resolved))
	}
	if strings.Contains(string(resolved), "**token**") {
		t.Errorf("body still contains sentinel: %q", string(resolved))
	}
}

func TestUnconfiguredHostPassesThrough(t *testing.T) {
	r := newTestResolver(newTestConfig())

	req := httptest.NewRequest("GET", "https://api.unknown.com/v1", nil)
	req.Header.Set("Authorization", "Bearer **token**")

	err := r.ResolveRequest(req, "api.unknown.com")
	if err != nil {
		t.Fatalf("ResolveRequest: %v", err)
	}

	if req.Header.Get("Authorization") != "Bearer **token**" {
		t.Errorf("Authorization = %q, want sentinel passed through unchanged for unconfigured host", req.Header.Get("Authorization"))
	}
}

func TestIsHostAllowed(t *testing.T) {
	r := newTestResolver(newTestConfig())

	if !r.IsHostAllowed("api.github.com") {
		t.Error("api.github.com should be allowed")
	}
	if r.IsHostAllowed("api.evil.com") {
		t.Error("api.evil.com should not be allowed")
	}
}

func TestCustomSentinel(t *testing.T) {
	cfg := newTestConfig()
	r := New(cfg, providers.NewRegistry())
	r.SetSentinel("__CREDPROXY_TOKEN__")

	req := httptest.NewRequest("GET", "https://api.github.com/v1", nil)
	req.Header.Set("Authorization", "Bearer __CREDPROXY_TOKEN__")

	reg := providers.NewRegistry()
	reg.Register(&mockProvider{
		values: map[string]string{
			"mock://github/token": "gh_real_token_123",
		},
	})
	r.reg = reg

	err := r.ResolveRequest(req, "api.github.com")
	if err != nil {
		t.Fatalf("ResolveRequest: %v", err)
	}

	if req.Header.Get("Authorization") != "Bearer gh_real_token_123" {
		t.Errorf("Authorization = %q, want Bearer gh_real_token_123", req.Header.Get("Authorization"))
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/resolver/ -v`
Expected: FAIL — struct and methods don't match new design

- [ ] **Step 3: Rewrite resolver.go**

```go
package resolver

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/rhibbitts/credproxy/internal/config"
	"github.com/rhibbitts/credproxy/internal/providers"
)

type Resolver struct {
	cfg      *config.Config
	reg      *providers.Registry
	cache    map[string]string
	sentinel string
}

func New(cfg *config.Config, reg *providers.Registry) *Resolver {
	return &Resolver{
		cfg:      cfg,
		reg:      reg,
		cache:    make(map[string]string),
		sentinel: "**token**",
	}
}

func (r *Resolver) SetSentinel(s string) {
	r.sentinel = s
}

func (r *Resolver) IsHostAllowed(host string) bool {
	return r.cfg.IsHostAllowed(host)
}

func (r *Resolver) ResolveRequest(req *http.Request, host string) error {
	ctx := req.Context()

	credential, err := r.resolveForHost(host, ctx)
	if err != nil {
		return err
	}

	if credential == "" {
		return nil
	}

	r.substituteHeaders(req.Header, credential)
	r.substituteBody(req, credential)

	return nil
}

func (r *Resolver) resolveForHost(host string, ctx context.Context) (string, error) {
	if val, ok := r.cache[host]; ok {
		return val, nil
	}

	uri, ok := r.cfg.GetCredentialURI(host)
	if !ok {
		return "", nil
	}

	val, err := r.reg.Resolve(ctx, uri)
	if err != nil {
		return "", fmt.Errorf("resolving %s: %w", uri, err)
	}

	r.cache[host] = val
	return val, nil
}

func (r *Resolver) substituteHeaders(h http.Header, credential string) {
	for key, values := range h {
		for i, val := range values {
			if strings.Contains(val, r.sentinel) {
				h[key][i] = strings.ReplaceAll(val, r.sentinel, credential)
			}
		}
	}
}

func (r *Resolver) substituteBody(req *http.Request, credential string) {
	if req.Body == nil || req.Body == http.NoBody {
		return
	}

	body, err := io.ReadAll(req.Body)
	req.Body.Close()
	if err != nil {
		return
	}

	if !bytes.Contains(body, []byte(r.sentinel)) {
		req.Body = io.NopCloser(bytes.NewReader(body))
		return
	}

	resolved := bytes.ReplaceAll(body, []byte(r.sentinel), []byte(credential))
	req.Body = io.NopCloser(bytes.NewReader(resolved))
	req.ContentLength = int64(len(resolved))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/resolver/ -v`
Expected: PASS (note: may need `fmt` and `net/http/httptest` imports in test file)

- [ ] **Step 5: Commit**

```bash
git add internal/resolver/resolver.go internal/resolver/resolver_test.go
git commit -m "Rewrite resolver for host-based sentinel matching"
```

---

### Task 3: Update MITM proxy to pass hostname for host-based resolution

**Files:**
- Modify: `internal/mitm/mitm.go`

The MITM proxy already passes the hostname to `resolver.ResolveRequest`. The current call signature is `r.ResolveRequest(req, host)` which matches the new resolver API. The only change needed is that `resolver.ResolveRequest` now returns an error only on actual resolution failures (not on unconfigured hosts — those pass through). Update the proxy to match.

- [ ] **Step 1: Review current mitm.go call sites**

Read `internal/mitm/mitm.go` and identify all calls to `r.ResolveRequest` or `p.resolver.ResolveRequest`. There are two:
- Line 127 (in `handleConnect`, via the http.HandlerFunc)
- Line 151 (in `handleForward`)

- [ ] **Step 2: Update mitm.go to handle the new resolver semantics**

The key change: previously, `ResolveRequest` would return an error for unconfigured placeholders. Now, it returns `nil` for unconfigured hosts (pass-through). Errors only happen on actual provider resolution failures. The proxy's error handling for `ResolveRequest` already returns 502, which is still correct for resolution failures.

No code changes needed in mitm.go — the call signature and error semantics are compatible. Verify the build compiles.

- [ ] **Step 3: Verify build**

Run: `go build ./...`
Expected: PASS

- [ ] **Step 4: Commit (only if changes were needed)**

If no changes needed, skip this step. The resolver rewrite in Task 2 already handles the interface change.

---

### Task 4: Rewrite main.go for wrap mode and daemon mode

**Files:**
- Rewrite: `cmd/credproxy/main.go`

Main entrypoint now has two modes:
1. **Wrap mode**: `credproxy opencode` — load config, start proxy on random port, strip secret-store CLIs from PATH, strip OP_SERVICE_ACCOUNT_TOKEN from child env, set HTTPS_PROXY/NO_PROXY in child env, exec child
2. **Daemon mode**: `credproxy` — load config, start proxy on specified port, print banner, run foreground

- [ ] **Step 1: Rewrite main.go**

```go
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/rhibbitts/credproxy/internal/ca"
	"github.com/rhibbitts/credproxy/internal/config"
	"github.com/rhibbitts/credproxy/internal/mitm"
	"github.com/rhibbitts/credproxy/internal/providers"
	"github.com/rhibbitts/credproxy/internal/resolver"
)

func main() {
	port := flag.Int("port", 0, "proxy listen port (0 = random, daemon mode default 8042)")
	configPath := flag.String("config", config.DefaultConfigPath(), "path to global config")
	sentinel := flag.String("sentinel", "**token**", "sentinel string to substitute")
	openProxy := flag.Bool("open-proxy", false, "allow all hosts (not recommended)")
	flag.Parse()

	args := flag.Args()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := loadMergedConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	if *openProxy {
		cfg.AllowAll()
	}

	caProvider, err := ca.LoadOrGenerate(config.DefaultCADir())
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to init CA: %v\n", err)
		os.Exit(1)
	}

	reg := providers.NewRegistry()
	reg.Register(providers.NewOnePasswordProvider())

	res := resolver.New(cfg, reg)
	res.SetSentinel(*sentinel)

	if len(args) > 0 {
		runWrap(cfg, caProvider, res, logger, args)
	} else {
		if *port == 0 {
			*port = 8042
		}
		runDaemon(cfg, caProvider, res, logger, *port)
	}
}

func loadMergedConfig(globalPath string) (*config.Config, error) {
	global, err := config.Load(globalPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		global = &config.Config{
			Hosts:       make(map[string]config.HostConfig),
			ProjectsDir: config.DefaultProjectsDir(),
		}
		global.setDefaults()
	}

	stopAt := global.ProjectsDir
	if stopAt == "" {
		home, _ := os.UserHomeDir()
		stopAt = home
	}

	projectPath, err := config.WalkProjectConfig(mustGetwd(), stopAt)
	if err != nil {
		return nil, fmt.Errorf("walking for project config: %w", err)
	}

	if projectPath == "" {
		return global, nil
	}

	project, err := config.Load(projectPath)
	if err != nil {
		return nil, fmt.Errorf("loading project config %s: %w", projectPath, err)
	}

	return global.Merge(project), nil
}

func mustGetwd() string {
	dir, err := os.Getwd()
	if err != nil {
		return "."
	}
	return dir
}

func runWrap(cfg *config.Config, caProvider *ca.Provider, res *resolver.Resolver, logger *slog.Logger, command []string) {
	addr := ":0"
	srv := mitm.New(addr, caProvider, res, logger)

	ln, err := startProxy(srv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to start proxy: %v\n", err)
		os.Exit(1)
	}
	defer ln.Close()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())

	childEnv := buildChildEnv(portStr)
	childPath := stripSecretStoreCLIs(os.Getenv("PATH"))

	bin, err := exec.LookPath(command[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "command not found: %s\n", command[0])
		os.Exit(1)
	}

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		ln.Close()
	}()

	if err := syscall.Exec(bin, command, childEnv); err != nil {
		fmt.Fprintf(os.Stderr, "exec failed: %v\n", err)
		os.Exit(1)
	}
}

func runDaemon(cfg *config.Config, caProvider *ca.Provider, res *resolver.Resolver, logger *slog.Logger, port int) {
	addr := fmt.Sprintf(":%d", port)
	srv := mitm.New(addr, caProvider, res, logger)

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		fmt.Println("\nshutting down")
		os.Exit(0)
	}()

	caPath := config.DefaultCADir() + "/ca.pem"
	fmt.Printf("credproxy listening on %s\n", addr)
	fmt.Printf("CA cert: %s\n", caPath)
	fmt.Println()
	fmt.Println("Trust the CA cert to use HTTPS proxying:")
	fmt.Println("  macOS:   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain " + caPath)
	fmt.Println("  Linux:   sudo cp " + caPath + " /usr/local/share/ca-certificates/credproxy.crt && sudo update-ca-certificates")
	fmt.Println()
	fmt.Println("Wrap mode (recommended):")
	fmt.Println("  credproxy opencode")
	fmt.Println("  credproxy -- claude-code")
	fmt.Println()
	fmt.Println("Agent instructions — add to AGENTS.md:")
	fmt.Println("  When making authenticated API calls, use **token** as the credential value.")
	fmt.Println()
	fmt.Println("press Ctrl-C to exit")

	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

func startProxy(srv *mitm.Proxy) (net.Listener, error) {
	ln, err := net.Listen("tcp", srv.Addr())
	if err != nil {
		return nil, err
	}
	go srv.Serve(ln)
	return ln, nil
}

func buildChildEnv(proxyPort string) []string {
	env := os.Environ()
	filtered := make([]string, 0, len(env))
	for _, e := range env {
		if strings.HasPrefix(e, "OP_SERVICE_ACCOUNT_TOKEN=") {
			continue
		}
		if strings.HasPrefix(e, "HTTPS_PROXY=") || strings.HasPrefix(e, "HTTP_PROXY=") {
			continue
		}
		if strings.HasPrefix(e, "NO_PROXY=") {
			continue
		}
		filtered = append(filtered, e)
	}
	filtered = append(filtered,
		"HTTPS_PROXY=http://localhost:"+proxyPort,
		"NO_PROXY=localhost,127.0.0.1",
	)
	return filtered
}

func stripSecretStoreCLIs(pathEnv string) string {
	dirs := filepath.SplitList(pathEnv)
	strippedClIs := []string{"op", "bw"}
	filtered := make([]string, 0, len(dirs))
	for _, dir := range dirs {
		skip := false
		for _, cli := range strippedClIs {
			if filepath.Base(dir) == cli || strings.Contains(dir, "/"+cli+"/") {
				skip = true
				break
			}
			if _, err := os.Stat(filepath.Join(dir, cli)); err == nil {
				skip = true
				break
			}
		}
		if !skip {
			filtered = append(filtered, dir)
		}
	}
	return strings.Join(filtered, string(filepath.ListSeparator))
}
```

- [ ] **Step 2: Verify build**

Run: `go build ./cmd/credproxy/`
Expected: May need small fixes — the mitm.Proxy doesn't currently expose `Addr()` or `Serve()`. May need to add those or adjust. Fix any compilation errors iteratively.

- [ ] **Step 3: Fix compilation issues**

The current `mitm.Proxy` has `ListenAndServe()` which creates its own listener. For wrap mode, we need to create the listener ourselves to capture the assigned port. Add an `Addr()` method and a `Serve(ln)` method to mitm.Proxy:

In `internal/mitm/mitm.go`, add:

```go
func (p *Proxy) Addr() string {
	return p.addr
}

func (p *Proxy) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("accept: %w", err)
		}
		go p.handleConn(conn)
	}
}
```

Then update `ListenAndServe` to use `Serve`:

```go
func (p *Proxy) ListenAndServe() error {
	ln, err := net.Listen("tcp", p.addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	return p.Serve(ln)
}
```

- [ ] **Step 4: Add missing imports to main.go**

Ensure `net` and `net/url` (for `SplitHostPort`) are imported in main.go.

- [ ] **Step 5: Verify build**

Run: `go build ./cmd/credproxy/`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add cmd/credproxy/main.go internal/mitm/mitm.go
git commit -m "Add wrap mode, daemon mode, env/PATH stripping in main"
```

---

### Task 5: Integration smoke test

**Files:**
- Modify: `cmd/credproxy/main.go` (if needed)

- [ ] **Step 1: Create a test config**

```bash
mkdir -p ~/.config/credproxy
cat > ~/.config/credproxy/config.toml << 'EOF'
[hosts."api.github.com"]
credential = "op://Personal/github-pat/token"
EOF
```

- [ ] **Step 2: Build and run daemon mode**

```bash
go build -o credproxy ./cmd/credproxy/ && ./credproxy --port 8042
```

Expected: Prints banner with wrap mode instructions, listens on :8042

- [ ] **Step 3: Test wrap mode with a simple command**

```bash
go build -o credproxy ./cmd/credproxy/ && ./credproxy -- env | grep -E 'HTTPS_PROXY|NO_PROXY|OP_SERVICE'
```

Expected: Shows `HTTPS_PROXY=http://localhost:XXXX` and `NO_PROXY=localhost,127.0.0.1`. Does NOT show `OP_SERVICE_ACCOUNT_TOKEN` if it was set.

- [ ] **Step 4: Verify PATH stripping**

```bash
go build -o credproxy ./cmd/credproxy/ && ./credproxy -- which op
```

Expected: `op` not found (or error), confirming it was stripped from PATH

- [ ] **Step 5: Commit any fixes**

```bash
git add -A && git commit -m "Fix integration issues from smoke testing"
```

---

### Task 6: Update .gitignore and examples, final cleanup

**Files:**
- Modify: `.gitignore`
- Verify: `config.toml.example`, `dot-credproxy.example`

- [ ] **Step 1: Verify .gitignore covers new files**

Check that `.gitignore` already includes `config.toml` (updated in earlier commit). Also add `.credproxy.toml` to project-level gitignore consideration — but since it's a project config file that should be committed (it only has `op://` URIs, not real secrets), it should NOT be in the global gitignore.

- [ ] **Step 2: Verify example files are correct**

Confirm `config.toml.example` and `dot-credproxy.example` match the new format.

- [ ] **Step 3: Run full build and vet**

Run: `go build ./... && go vet ./...`
Expected: PASS

- [ ] **Step 4: Final commit**

```bash
git add -A && git commit -m "Final cleanup for v2 implementation"
```
