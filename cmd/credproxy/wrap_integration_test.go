package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestRunWrapStopsPoolersOnChildExit pins the whole session-cleanup contract:
// whatever the child's exit code, credproxy must stop the poolers and remove
// the temp dir holding the real password. Regression for the review finding
// that os.Exit(exitErr.ExitCode()) skipped every deferred cleanup.
func TestRunWrapStopsPoolersOnChildExit(t *testing.T) {
	bin := t.TempDir()
	sim := filepath.Join(bin, "poolersim")
	if out, err := exec.Command("go", "build", "-o", sim, "testdata/poolersim/main.go").CombinedOutput(); err != nil {
		t.Fatalf("building poolersim: %v\n%s", err, out)
	}
	cred := filepath.Join(bin, "credproxy")
	if out, err := exec.Command("go", "build", "-o", cred, ".").CombinedOutput(); err != nil {
		t.Fatalf("building credproxy: %v\n%s", err, out)
	}

	home := t.TempDir()
	cfgDir := filepath.Join(home, ".config", "credproxy")
	if err := os.MkdirAll(cfgDir, 0700); err != nil {
		t.Fatal(err)
	}
	// pgbouncer_path must precede any [table] header in TOML.
	cfg := "pgbouncer_path = \"" + sim + "\"\n\n" +
		"[databases.mydb]\n" +
		"engine = \"postgres\"\n" +
		"host = \"127.0.0.1\"\n" +
		"port = 5432\n" +
		"user = \"u\"\n" +
		"password = \"p\"\n" +
		"database = \"d\"\n" +
		"env = \"DATABASE_URL\"\n"
	cfgPath := filepath.Join(cfgDir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}

	marker := filepath.Join(bin, "marker")
	cmd := exec.Command(cred, "--config", cfgPath, "sh", "-c", "exit 3")
	cmd.Env = append(os.Environ(), "HOME="+home, "POOLER_SIM_MARKER="+marker)
	out, err := cmd.CombinedOutput()
	exitCode := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		exitCode = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("running credproxy: %v\n%s", err, out)
	}
	if exitCode != 3 {
		t.Fatalf("credproxy should propagate child exit code 3, got %d\n%s", exitCode, out)
	}

	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatal("pooler was not stopped on child exit — the marker file survived, meaning the temp dir with the real password leaks past the session")
	}
	matches, _ := filepath.Glob(filepath.Join(os.TempDir(), "credproxy-poolers-*"))
	if len(matches) != 0 {
		t.Fatalf("pooler temp dirs leaked past the session: %v", matches)
	}
}
