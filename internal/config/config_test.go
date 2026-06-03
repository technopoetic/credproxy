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
