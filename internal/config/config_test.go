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

