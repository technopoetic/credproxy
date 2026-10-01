package config

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLoadHostKeyedConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
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

func TestAllowAll(t *testing.T) {
	cfg := &Config{
		Hosts: map[string]HostConfig{
			"api.github.com": {Credential: "op://test"},
		},
	}
	cfg.SetDefaults()

	if cfg.IsHostAllowed("api.evil.com") {
		t.Error("api.evil.com should not be allowed before AllowAll")
	}

	cfg.AllowAll()

	if !cfg.IsHostAllowed("api.evil.com") {
		t.Error("api.evil.com should be allowed after AllowAll")
	}
}

func TestDefaultConfigPath(t *testing.T) {
	path := DefaultConfigPath()
	if path == "" {
		t.Error("DefaultConfigPath returned empty string")
	}
}

func TestLoadGlobalEnvVars(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
[env]
RAILS_ENV = "production"
PORT = "443"
DEBUG = "on"

[hosts."api.github.com"]
credential = "op://Personal/github-pat/token"
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Env["RAILS_ENV"] != "production" {
		t.Errorf("RAILS_ENV = %q, want %q", cfg.Env["RAILS_ENV"], "production")
	}
	if cfg.Env["PORT"] != "443" {
		t.Errorf("PORT = %q, want %q", cfg.Env["PORT"], "443")
	}
	if cfg.Env["DEBUG"] != "on" {
		t.Errorf("DEBUG = %q, want %q", cfg.Env["DEBUG"], "on")
	}
}

func TestLoadProfileConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
[hosts."api.stripe.com"]
credential = "op://Business/stripe-live/key"

[profiles.staging.hosts."api.stripe.com"]
credential = "op://Business/stripe-test/key"

[profiles.staging.env]
RAILS_ENV = "staging"
PORT = "3000"

[profiles.production.env]
RAILS_ENV = "production"
PORT = "443"
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(cfg.Profiles) != 2 {
		t.Fatalf("expected 2 profiles, got %d", len(cfg.Profiles))
	}

	staging, ok := cfg.Profiles["staging"]
	if !ok {
		t.Fatal("expected staging profile")
	}
	if staging.Hosts["api.stripe.com"].Credential != "op://Business/stripe-test/key" {
		t.Errorf("staging stripe credential = %q, want op://Business/stripe-test/key", staging.Hosts["api.stripe.com"].Credential)
	}
	if staging.Env["RAILS_ENV"] != "staging" {
		t.Errorf("staging RAILS_ENV = %q, want staging", staging.Env["RAILS_ENV"])
	}
	if staging.Env["PORT"] != "3000" {
		t.Errorf("staging PORT = %q, want 3000", staging.Env["PORT"])
	}

	prod, ok := cfg.Profiles["production"]
	if !ok {
		t.Fatal("expected production profile")
	}
	if prod.Env["RAILS_ENV"] != "production" {
		t.Errorf("production RAILS_ENV = %q, want production", prod.Env["RAILS_ENV"])
	}
}

func TestApplyProfileOverridesHosts(t *testing.T) {
	cfg := &Config{
		Hosts: map[string]HostConfig{
			"api.stripe.com": {Credential: "op://Business/stripe-live/key"},
			"api.github.com": {Credential: "op://Personal/github-pat/token"},
		},
		Profiles: map[string]ProfileConfig{
			"staging": {
				Hosts: map[string]HostConfig{
					"api.stripe.com": {Credential: "op://Business/stripe-test/key"},
				},
				Env: map[string]string{
					"RAILS_ENV": "staging",
				},
			},
		},
	}
	cfg.SetDefaults()

	result, err := cfg.ApplyProfile("staging")
	if err != nil {
		t.Fatalf("ApplyProfile: %v", err)
	}

	uri, ok := result.GetCredentialURI("api.stripe.com")
	if !ok {
		t.Fatal("expected api.stripe.com after profile")
	}
	if uri != "op://Business/stripe-test/key" {
		t.Errorf("profile override: api.stripe.com = %q, want op://Business/stripe-test/key", uri)
	}

	uri, ok = result.GetCredentialURI("api.github.com")
	if !ok {
		t.Fatal("expected api.github.com to persist from global")
	}
	if uri != "op://Personal/github-pat/token" {
		t.Errorf("global host: api.github.com = %q, want op://Personal/github-pat/token", uri)
	}
}

func TestApplyProfileOverlayEnvVars(t *testing.T) {
	cfg := &Config{
		Env: map[string]string{
			"TERM":   "xterm-256color",
			"EDITOR": "nvim",
		},
		Hosts: map[string]HostConfig{
			"api.github.com": {Credential: "op://Personal/github-pat/token"},
		},
		Profiles: map[string]ProfileConfig{
			"staging": {
				Env: map[string]string{
					"RAILS_ENV": "staging",
					"EDITOR":    "code",
				},
			},
		},
	}
	cfg.SetDefaults()

	result, err := cfg.ApplyProfile("staging")
	if err != nil {
		t.Fatalf("ApplyProfile: %v", err)
	}

	if result.Env["TERM"] != "xterm-256color" {
		t.Errorf("global env TERM = %q, want xterm-256color", result.Env["TERM"])
	}
	if result.Env["EDITOR"] != "code" {
		t.Errorf("profile overrides EDITOR = %q, want code", result.Env["EDITOR"])
	}
	if result.Env["RAILS_ENV"] != "staging" {
		t.Errorf("profile env RAILS_ENV = %q, want staging", result.Env["RAILS_ENV"])
	}
}

func TestApplyProfileNotFound(t *testing.T) {
	cfg := &Config{
		Hosts:    map[string]HostConfig{},
		Profiles: map[string]ProfileConfig{},
	}
	cfg.SetDefaults()

	_, err := cfg.ApplyProfile("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent profile")
	}
}

func TestApplyProfileNoProfileReturnsBase(t *testing.T) {
	cfg := &Config{
		Env: map[string]string{
			"TERM": "xterm",
		},
		Hosts: map[string]HostConfig{
			"api.github.com": {Credential: "op://test"},
		},
	}
	cfg.SetDefaults()

	result, err := cfg.ApplyProfile("")
	if err != nil {
		t.Fatalf("ApplyProfile empty string: %v", err)
	}

	if result.Env["TERM"] != "xterm" {
		t.Errorf("base env TERM = %q, want xterm", result.Env["TERM"])
	}
	uri, ok := result.GetCredentialURI("api.github.com")
	if !ok || uri != "op://test" {
		t.Errorf("base host unchanged: %q, want op://test", uri)
	}
}

func TestMergePreservesEnvVars(t *testing.T) {
	globalDir := t.TempDir()
	globalPath := filepath.Join(globalDir, "config.toml")
	globalContent := `
[env]
TERM = "xterm-256color"
EDITOR = "nvim"

[hosts."api.github.com"]
credential = "op://Personal/github-pat/token"
`
	if err := os.WriteFile(globalPath, []byte(globalContent), 0644); err != nil {
		t.Fatal(err)
	}

	projectDir := t.TempDir()
	projectPath := filepath.Join(projectDir, ".credproxy.toml")
	projectContent := `
[env]
EDITOR = "code"

[hosts."api.unsplash.com"]
credential = "op://shipstops/Unsplash/key"
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

	if merged.Env["TERM"] != "xterm-256color" {
		t.Errorf("merged TERM = %q, want xterm-256color from global", merged.Env["TERM"])
	}
	if merged.Env["EDITOR"] != "code" {
		t.Errorf("merged EDITOR = %q, want code from project override", merged.Env["EDITOR"])
	}
}

func TestProfileNames(t *testing.T) {
	cfg := &Config{
		Hosts: map[string]HostConfig{},
		Profiles: map[string]ProfileConfig{
			"staging":    {},
			"production": {},
		},
	}
	cfg.SetDefaults()

	names := cfg.ProfileNames()
	if len(names) != 2 {
		t.Fatalf("expected 2 profile names, got %d", len(names))
	}
	found := map[string]bool{}
	for _, n := range names {
		found[n] = true
	}
	if !found["staging"] || !found["production"] {
		t.Errorf("ProfileNames = %v, want staging and production", names)
	}
}

func TestMergePreservesProfiles(t *testing.T) {
	globalDir := t.TempDir()
	globalPath := filepath.Join(globalDir, "config.toml")
	globalContent := `
[profiles.staging.env]
RAILS_ENV = "staging"

[hosts."api.github.com"]
credential = "op://Personal/github-pat/token"
`
	if err := os.WriteFile(globalPath, []byte(globalContent), 0644); err != nil {
		t.Fatal(err)
	}

	projectDir := t.TempDir()
	projectPath := filepath.Join(projectDir, ".credproxy.toml")
	projectContent := `
[profiles.production.env]
RAILS_ENV = "production"

[hosts."api.unsplash.com"]
credential = "op://shipstops/Unsplash/key"
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

	if len(merged.Profiles) != 2 {
		t.Fatalf("expected 2 profiles after merge, got %d", len(merged.Profiles))
	}
	if _, ok := merged.Profiles["staging"]; !ok {
		t.Error("staging profile missing from merged config")
	}
	if _, ok := merged.Profiles["production"]; !ok {
		t.Error("production profile missing from merged config")
	}
}

type stubResolver struct {
	mu        sync.Mutex
	resolved  map[string]string
	err       map[string]error
	delay     time.Duration
	callCount int32
	concurrent int32
	maxConcurrent int32
}

func (s *stubResolver) Resolve(ctx context.Context, uri string) (string, error) {
	cur := atomic.AddInt32(&s.callCount, 1)
	defer atomic.AddInt32(&s.callCount, -1)

	for {
		peak := atomic.LoadInt32(&s.maxConcurrent)
		live := atomic.LoadInt32(&s.concurrent)
		if live+1 <= peak {
			break
		}
		if atomic.CompareAndSwapInt32(&s.maxConcurrent, peak, live+1) {
			break
		}
	}
	defer atomic.AddInt32(&s.concurrent, -1)
	atomic.AddInt32(&s.concurrent, 1)

	_ = cur

	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.err[uri]; ok {
		return "", e
	}
	return s.resolved[uri], nil
}

func TestResolveEnvResolvesOpUris(t *testing.T) {
	cfg := &Config{
		Env: map[string]string{
			"DATABASE_URL": "op://Business/prod-db/password",
			"PORT":         "5432",
		},
	}
	stub := &stubResolver{
		resolved: map[string]string{"op://Business/prod-db/password": "secret-123"},
	}

	if err := cfg.ResolveEnv(context.Background(), stub); err != nil {
		t.Fatalf("ResolveEnv: %v", err)
	}

	if got := cfg.Env["DATABASE_URL"]; got != "secret-123" {
		t.Errorf("DATABASE_URL = %q, want %q", got, "secret-123")
	}
	if got := cfg.Env["PORT"]; got != "5432" {
		t.Errorf("PORT = %q, want %q", got, "5432")
	}
}

func TestResolveEnvEmptyEnv(t *testing.T) {
	cfg := &Config{Env: map[string]string{}}
	stub := &stubResolver{resolved: map[string]string{}}

	if err := cfg.ResolveEnv(context.Background(), stub); err != nil {
		t.Fatalf("ResolveEnv: %v", err)
	}
	if atomic.LoadInt32(&stub.callCount) != 0 {
		t.Errorf("expected zero resolver calls for empty env, got %d", stub.callCount)
	}
}

func TestResolveEnvNoOpUrisIsNoop(t *testing.T) {
	cfg := &Config{
		Env: map[string]string{
			"PORT":  "3000",
			"RAILS": "staging",
		},
	}
	stub := &stubResolver{resolved: map[string]string{}}

	if err := cfg.ResolveEnv(context.Background(), stub); err != nil {
		t.Fatalf("ResolveEnv: %v", err)
	}
	if atomic.LoadInt32(&stub.callCount) != 0 {
		t.Errorf("expected zero resolver calls, got %d", stub.callCount)
	}
	if cfg.Env["PORT"] != "3000" || cfg.Env["RAILS"] != "staging" {
		t.Errorf("non-op:// env values were modified: %v", cfg.Env)
	}
}

func TestResolveEnvReportsErrorPerVar(t *testing.T) {
	cfg := &Config{
		Env: map[string]string{
			"GOOD_KEY":   "op://Business/good/secret",
			"BAD_KEY":    "op://Business/bad/secret",
			"GOOD_KEY_2": "op://Business/good2/secret",
		},
	}
	stub := &stubResolver{
		resolved: map[string]string{
			"op://Business/good/secret":  "g1",
			"op://Business/good2/secret": "g2",
		},
		err: map[string]error{
			"op://Business/bad/secret": errors.New("not found"),
		},
	}

	err := cfg.ResolveEnv(context.Background(), stub)
	if err == nil {
		t.Fatal("expected error from ResolveEnv")
	}
	if !strings.Contains(err.Error(), "BAD_KEY") || !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should name the failing key and underlying message: %v", err)
	}

	if got := cfg.Env["GOOD_KEY"]; got != "g1" {
		t.Errorf("GOOD_KEY = %q, want %q (successful resolutions should still apply on partial failure)", got, "g1")
	}
	if got := cfg.Env["GOOD_KEY_2"]; got != "g2" {
		t.Errorf("GOOD_KEY_2 = %q, want %q", got, "g2")
	}
	if got := cfg.Env["BAD_KEY"]; got != "op://Business/bad/secret" {
		t.Errorf("BAD_KEY = %q, want unchanged URI on failure", got)
	}
}

func TestResolveEnvRunsConcurrently(t *testing.T) {
	const n = 8
	cfg := &Config{Env: map[string]string{}}
	for i := 0; i < n; i++ {
		key := strings.Repeat("K", 1) + string(rune('A'+i))
		cfg.Env[key] = "op://Business/key-" + string(rune('A'+i))
	}

	stub := &stubResolver{
		resolved: map[string]string{},
		delay:    100 * time.Millisecond,
	}
	for i := 0; i < n; i++ {
		uri := "op://Business/key-" + string(rune('A'+i))
		stub.resolved[uri] = "v" + string(rune('A'+i))
	}

	start := time.Now()
	if err := cfg.ResolveEnv(context.Background(), stub); err != nil {
		t.Fatalf("ResolveEnv: %v", err)
	}
	elapsed := time.Since(start)

	serialFloor := time.Duration(n) * 100 * time.Millisecond
	concurrentCeiling := 500 * time.Millisecond
	if elapsed >= serialFloor {
		t.Errorf("resolution appears serial: %v >= %v (8 calls of 100ms each)", elapsed, serialFloor)
	}
	if elapsed > concurrentCeiling {
		t.Errorf("resolution took too long: %v > %v", elapsed, concurrentCeiling)
	}

	if atomic.LoadInt32(&stub.maxConcurrent) < 2 {
		t.Errorf("expected concurrent execution, max concurrency observed: %d", stub.maxConcurrent)
	}
}

func TestResolveEnvPerCallTimeout(t *testing.T) {
	cfg := &Config{
		Env: map[string]string{
			"SLOW_KEY": "op://Business/slow/secret",
		},
	}
	stub := &stubResolver{
		resolved: map[string]string{},
		delay:    5 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := cfg.ResolveEnv(ctx, stub)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "SLOW_KEY") {
		t.Errorf("error should name SLOW_KEY: %v", err)
	}
	if elapsed > 2*time.Second {
		t.Errorf("ResolveEnv did not honor per-call timeout: %v", elapsed)
	}
}


func TestLoadDatabases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	tomlData := `
[databases.mydb]
engine = "postgres"
host = "db.example.com"
port = 5432
user = "app_user"
password = "op://Private/mydb/password"
database = "appdb"
params = "sslmode=require"
env = "DATABASE_URL"

[databases.other]
engine = "mysql"
host = "mysql.example.com"
port = 3306
user = "mu"
password = "literal"
database = "mdb"
env = "OTHER_DB_URL"
`
	if err := os.WriteFile(path, []byte(tomlData), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Databases) != 2 {
		t.Fatalf("expected 2 databases, got %d", len(cfg.Databases))
	}
	db := cfg.Databases["mydb"]
	if db.Engine != "postgres" || db.Host != "db.example.com" || db.Port != 5432 ||
		db.User != "app_user" || db.Password != "op://Private/mydb/password" ||
		db.Database != "appdb" || db.Params != "sslmode=require" || db.Env != "DATABASE_URL" {
		t.Fatalf("mydb parsed wrong: %+v", db)
	}
	if cfg.Databases["other"].Engine != "mysql" {
		t.Fatalf("other parsed wrong: %+v", cfg.Databases["other"])
	}
}

func TestMergeDatabasesProjectWinsPerEntry(t *testing.T) {
	global := &Config{
		Env:      map[string]string{},
		Hosts:    map[string]HostConfig{},
		Profiles: map[string]ProfileConfig{},
		Databases: map[string]DatabaseConfig{
			"mydb":  {Engine: "postgres", Host: "global.example.com", Port: 5432, User: "u", Password: "p", Database: "d", Env: "DATABASE_URL"},
			"gonly": {Engine: "postgres", Host: "g.example.com", Port: 5432, User: "u", Password: "p", Database: "d", Env: "G_URL"},
		},
	}
	overlay := &Config{
		Env:      map[string]string{},
		Hosts:    map[string]HostConfig{},
		Profiles: map[string]ProfileConfig{},
		Databases: map[string]DatabaseConfig{
			"mydb": {Engine: "postgres", Host: "project.example.com", Port: 5433, User: "u2", Password: "p2", Database: "d2", Env: "DATABASE_URL"},
		},
	}
	merged := global.Merge(overlay)
	if merged.Databases["mydb"].Host != "project.example.com" {
		t.Fatalf("overlay entry should win wholesale: %+v", merged.Databases["mydb"])
	}
	if _, ok := merged.Databases["gonly"]; !ok {
		t.Fatal("global-only entry must survive merge")
	}
}

func TestMergeBinaryPathOverrides(t *testing.T) {
	global := &Config{Env: map[string]string{}, Hosts: map[string]HostConfig{}, Profiles: map[string]ProfileConfig{}, PgbouncerPath: "/g/pgbouncer"}
	overlay := &Config{Env: map[string]string{}, Hosts: map[string]HostConfig{}, Profiles: map[string]ProfileConfig{}, ProxySQLPath: "/p/proxysql"}
	merged := global.Merge(overlay)
	if merged.PgbouncerPath != "/g/pgbouncer" || merged.ProxySQLPath != "/p/proxysql" {
		t.Fatalf("scalar path merge wrong: %+v", merged)
	}
}

func TestApplyProfileDatabases(t *testing.T) {
	cfg := &Config{
		Env:       map[string]string{},
		Hosts:     map[string]HostConfig{},
		Databases: map[string]DatabaseConfig{
			"mydb": {Engine: "postgres", Host: "prod.example.com", Port: 5432, User: "u", Password: "p", Database: "d", Env: "DATABASE_URL"},
		},
		Profiles: map[string]ProfileConfig{
			"staging": {Hosts: map[string]HostConfig{}, Env: map[string]string{}, Databases: map[string]DatabaseConfig{
				"mydb": {Engine: "postgres", Host: "staging.example.com", Port: 5432, User: "u", Password: "p", Database: "d", Env: "DATABASE_URL"},
			}},
		},
	}
	applied, err := cfg.ApplyProfile("staging")
	if err != nil {
		t.Fatal(err)
	}
	if applied.Databases["mydb"].Host != "staging.example.com" {
		t.Fatalf("profile databases should overlay: %+v", applied.Databases["mydb"])
	}
}

func minimalValidDatabases() *Config {
	return &Config{
		Databases: map[string]DatabaseConfig{
			"mydb": {Engine: "postgres", Host: "h", Port: 5432, User: "u", Password: "p", Database: "d", Env: "DATABASE_URL"},
		},
	}
}

func TestValidateDatabasesRejectsUnknownEngine(t *testing.T) {
	cfg := minimalValidDatabases()
	db := cfg.Databases["mydb"]
	db.Engine = "mongodb"
	cfg.Databases["mydb"] = db
	if err := cfg.ValidateDatabases(); err == nil {
		t.Fatal("expected error for unknown engine")
	}
}

func TestValidateDatabasesRequiresFields(t *testing.T) {
	cfg := minimalValidDatabases()
	db := cfg.Databases["mydb"]
	db.Host = ""
	cfg.Databases["mydb"] = db
	if err := cfg.ValidateDatabases(); err == nil {
		t.Fatal("expected error for missing host")
	}
}

func TestValidateDatabasesRejectsInvalidPort(t *testing.T) {
	cfg := minimalValidDatabases()
	db := cfg.Databases["mydb"]
	db.Port = 0
	cfg.Databases["mydb"] = db
	if err := cfg.ValidateDatabases(); err == nil {
		t.Fatal("expected error for port 0")
	}
}

func TestValidateDatabasesRejectsDuplicateEnvNames(t *testing.T) {
	cfg := minimalValidDatabases()
	cfg.Databases["second"] = DatabaseConfig{
		Engine: "postgres", Host: "h", Port: 5432, User: "u",
		Password: "p", Database: "d", Env: "DATABASE_URL",
	}
	err := cfg.ValidateDatabases()
	if err == nil {
		t.Fatal("expected error for duplicate env var name")
	}
	if !strings.Contains(err.Error(), "second") || !strings.Contains(err.Error(), "mydb") {
		t.Fatalf("error should name both entries: %v", err)
	}
}

func TestValidateDatabasesRejectsReservedEnvNames(t *testing.T) {
	for _, name := range []string{"PATH", "HTTPS_PROXY", "SSL_CERT_FILE", "CREDPROXY_TOKEN", "PGPASSWORD"} {
		cfg := minimalValidDatabases()
		db := cfg.Databases["mydb"]
	db.Env = name
	cfg.Databases["mydb"] = db
		if err := cfg.ValidateDatabases(); err == nil {
			t.Fatalf("expected error for reserved env name %s", name)
		}
	}
}

func TestValidateDatabasesNoDatabasesOK(t *testing.T) {
	cfg := &Config{}
	if err := cfg.ValidateDatabases(); err != nil {
		t.Fatalf("empty config should validate: %v", err)
	}
}

func TestResolveDatabasePasswordsResolvesAndFailsFast(t *testing.T) {
	cfg := minimalValidDatabases()
	db := cfg.Databases["mydb"]
	db.Password = "op://x/y/z"
	cfg.Databases["mydb"] = db
	fake := &stubResolver{resolved: map[string]string{"op://x/y/z": "resolved-pw"}}
	if err := cfg.ResolveDatabasePasswords(context.Background(), fake); err != nil {
		t.Fatal(err)
	}
	if cfg.Databases["mydb"].Password != "resolved-pw" {
		t.Fatalf("password not written back: %q", cfg.Databases["mydb"].Password)
	}

	broken := &stubResolver{err: map[string]error{"op://x/y/z": errors.New("vault locked")}}
	cfg2 := minimalValidDatabases()
	db2 := cfg2.Databases["mydb"]
	db2.Password = "op://x/y/z"
	cfg2.Databases["mydb"] = db2
	if err := cfg2.ResolveDatabasePasswords(context.Background(), broken); err == nil {
		t.Fatal("expected fail-fast on resolution error")
	}
}
