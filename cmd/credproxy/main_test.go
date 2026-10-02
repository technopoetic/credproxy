package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/technopoetic/credproxy/internal/config"
)

func TestStripSecretStoreCLIsShimsDirContainingOp(t *testing.T) {
	fakeDir := t.TempDir()
	for _, cli := range []string{"op", "bw"} {
		if err := os.WriteFile(filepath.Join(fakeDir, cli), []byte("#!/bin/sh\n"), 0755); err != nil {
			t.Fatal(err)
		}
	}

	childPath, shimDir, cleanup := stripSecretStoreCLIs(fakeDir)
	defer cleanup()

	if shimDir == "" {
		t.Fatal("expected a shim dir when PATH contains op/bw")
	}
	dirs := filepath.SplitList(childPath)
	if len(dirs) == 0 || dirs[0] != shimDir {
		t.Fatalf("shim dir not prepended to child PATH: %q", childPath)
	}
	for _, cli := range []string{"op", "bw"} {
		info, err := os.Stat(filepath.Join(shimDir, cli))
		if err != nil {
			t.Fatalf("shim for %s missing: %v", cli, err)
		}
		if info.Mode()&0111 == 0 {
			t.Fatalf("shim for %s not executable", cli)
		}
	}
	// path.sh must exist so BASH_ENV can re-assert the shim dir in shells
	// whose PATH was rewritten (macOS path_helper in login shells).
	if _, err := os.Stat(filepath.Join(shimDir, "path.sh")); err != nil {
		t.Fatalf("path.sh missing from shim dir: %v", err)
	}
}

func TestStripSecretStoreCLIsNoShimWithoutTargets(t *testing.T) {
	empty := t.TempDir()
	childPath, shimDir, cleanup := stripSecretStoreCLIs(empty)
	defer cleanup()

	if shimDir != "" {
		t.Fatalf("expected no shim dir, got %q", shimDir)
	}
	if childPath != empty {
		t.Fatalf("PATH should be returned unchanged, got %q", childPath)
	}
}

func TestBuildChildEnvStripsSecretSessions(t *testing.T) {
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "secret")
	t.Setenv("BW_SESSION", "unlocked")
	t.Setenv("HOME", "/Users/test")

	env := buildChildEnv(&config.Config{}, "9999", "/usr/bin:/bin", "/tmp/ca.pem", "", nil, nil)
	for _, e := range env {
		if strings.HasPrefix(e, "OP_SERVICE_ACCOUNT_TOKEN=") || strings.HasPrefix(e, "BW_SESSION=") {
			t.Fatalf("secret session var leaked into child env: %s", e)
		}
	}
}

func TestBuildChildEnvSetsBASHEnvWhenShimsExist(t *testing.T) {
	t.Setenv("HOME", "/Users/test")
	t.Setenv("BASH_ENV", "") // ensure no inherited value

	// Produce a genuine shim dir (path.sh included) the same way run() does.
	fakeDir := t.TempDir()
	for _, cli := range []string{"op", "bw"} {
		if err := os.WriteFile(filepath.Join(fakeDir, cli), []byte("#!/bin/sh\n"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	_, shimDir, cleanup := stripSecretStoreCLIs(fakeDir)
	defer cleanup()

	env := buildChildEnv(&config.Config{}, "9999", "/usr/bin:/bin", "/tmp/ca.pem", shimDir, nil, nil)

	var bashEnv string
	for _, e := range env {
		if strings.HasPrefix(e, "BASH_ENV=") {
			bashEnv = strings.TrimPrefix(e, "BASH_ENV=")
		}
	}
	if bashEnv == "" {
		t.Fatal("BASH_ENV not set when shim dir exists")
	}
	if !strings.HasPrefix(bashEnv, shimDir) {
		t.Fatalf("BASH_ENV %q does not point inside shim dir %q", bashEnv, shimDir)
	}
	if _, err := os.Stat(bashEnv); err != nil {
		t.Fatalf("BASH_ENV target missing: %v", err)
	}
}

func TestBuildChildEnvPreservesInheritedBASHEnv(t *testing.T) {
	t.Setenv("HOME", "/Users/test")
	t.Setenv("BASH_ENV", "/Users/test/.my_bash_env")

	fakeDir := t.TempDir()
	for _, cli := range []string{"op", "bw"} {
		if err := os.WriteFile(filepath.Join(fakeDir, cli), []byte("#!/bin/sh\n"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	_, shimDir, cleanup := stripSecretStoreCLIs(fakeDir)
	defer cleanup()
	env := buildChildEnv(&config.Config{}, "9999", "/usr/bin:/bin", "/tmp/ca.pem", shimDir, nil, nil)

	var prev, bashEnv string
	for _, e := range env {
		if strings.HasPrefix(e, "CREDPROXY_PREV_BASH_ENV=") {
			prev = strings.TrimPrefix(e, "CREDPROXY_PREV_BASH_ENV=")
		}
		if strings.HasPrefix(e, "BASH_ENV=") {
			bashEnv = strings.TrimPrefix(e, "BASH_ENV=")
		}
	}
	if prev != "/Users/test/.my_bash_env" {
		t.Fatalf("inherited BASH_ENV not preserved, got %q", prev)
	}
	if bashEnv == prev {
		t.Fatal("BASH_ENV was not redirected to credproxy's script")
	}
}

func TestPathShimScriptReprependsShimDir(t *testing.T) {
	fakeDir := t.TempDir()
	for _, cli := range []string{"op", "bw"} {
		if err := os.WriteFile(filepath.Join(fakeDir, cli), []byte("#!/bin/sh\n"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	_, shimDir, cleanup := stripSecretStoreCLIs(fakeDir)
	defer cleanup()
	if shimDir == "" {
		t.Fatal("no shim dir created")
	}

	// Simulate a login-shell child: path_helper-style PATH with the shim dir
	// demoted to the end, real op resolvable ahead of it.
	demoted := "/usr/local/bin:/usr/bin:/bin:" + shimDir
	script := filepath.Join(shimDir, "path.sh")
	out, err := execScript(t, script, demoted)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, shimDir) {
		t.Fatalf("path.sh did not re-prepend shim dir; which op -> %q", out)
	}
}

// execScript runs a non-interactive bash with BASH_ENV=script and the given
// PATH, executing `command -v op`, and returns the resolved path. This mirrors
// how agent tool calls (bash -c) resolve op under a login-shell-demoted PATH.
func execScript(t *testing.T, script string, pathEnv string) (string, error) {
	t.Helper()
	cmd := exec.Command("/bin/bash", "-c", "command -v op")
	cmd.Env = []string{"PATH=" + pathEnv, "BASH_ENV=" + script, "HOME=" + t.TempDir()}
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return strings.TrimSpace(stdout.String()), nil
}

func TestBuildChildEnvStripsInheritedDatabaseEnv(t *testing.T) {
	t.Setenv("HOME", "/Users/test")
	t.Setenv("DATABASE_URL", "postgres://app_user:REALPW@prod.example.com/db")
	t.Setenv("PGPASSWORD", "REALPW")
	poolerEnv := map[string]string{"DATABASE_URL": "postgres://app_user:sess@127.0.0.1:6432/mydb"}

	env := buildChildEnv(&config.Config{}, "9999", "/usr/bin:/bin", "/tmp/ca.pem", "",
		poolerEnv, []string{"DATABASE_URL", "PGPASSWORD"})
	for _, e := range env {
		if strings.HasPrefix(e, "DATABASE_URL=postgres://app_user:REALPW@") {
			t.Fatalf("inherited real DATABASE_URL leaked into child env: %s", e)
		}
		if strings.HasPrefix(e, "PGPASSWORD=") {
			t.Fatalf("PGPASSWORD leaked into child env: %s", e)
		}
	}
	found := false
	for _, e := range env {
		if e == "DATABASE_URL=postgres://app_user:sess@127.0.0.1:6432/mydb" {
			found = true
		}
	}
	if !found {
		t.Fatal("pooler URL not injected into child env")
	}
}

func TestBuildChildEnvPoolerWinsOverConfigEnv(t *testing.T) {
	t.Setenv("HOME", "/Users/test")
	cfg := &config.Config{Env: map[string]string{"DATABASE_URL": "postgres://config-value@confighost/db"}}
	env := buildChildEnv(cfg, "9999", "/usr/bin:/bin", "/tmp/ca.pem", "",
		map[string]string{"DATABASE_URL": "postgres://pooler-value@127.0.0.1:6432/mydb"}, nil)
	var last string
	for _, e := range env {
		if strings.HasPrefix(e, "DATABASE_URL=") {
			last = e
		}
	}
	if last != "DATABASE_URL=postgres://pooler-value@127.0.0.1:6432/mydb" {
		t.Fatalf("pooler env must win over [env] config (os/exec last-wins): %q", last)
	}
}
