package config

import (
	"context"
	"sync/atomic"
	"testing"
)

// These tests confirm resolveURIs (via ResolveEnv/ResolveDatabasePasswords)
// resolves bw:// in [env]/[databases.*] the same way it already resolves
// op://, via the credentialURISchemes allowlist in config.go -- it
// originally checked only the literal "op://" prefix.

func TestResolveEnvResolvesBwUris(t *testing.T) {
	cfg := &Config{
		Env: map[string]string{
			"UNSPLASH_KEY": "bw://password/unsplash-app-creds",
			"PORT":         "5432",
		},
	}
	stub := &stubResolver{
		resolved: map[string]string{"bw://password/unsplash-app-creds": "unsplash-secret"},
	}

	if err := cfg.ResolveEnv(context.Background(), stub); err != nil {
		t.Fatalf("ResolveEnv: %v", err)
	}

	if got := cfg.Env["UNSPLASH_KEY"]; got != "unsplash-secret" {
		t.Errorf("UNSPLASH_KEY = %q, want %q", got, "unsplash-secret")
	}
	if got := cfg.Env["PORT"]; got != "5432" {
		t.Errorf("PORT = %q, want %q", got, "5432")
	}
}

func TestResolveDatabasePasswordsResolvesBwUris(t *testing.T) {
	cfg := &Config{
		Databases: map[string]DatabaseConfig{
			"primary": {Engine: "postgres", Password: "bw://password/prod-db"},
		},
	}
	stub := &stubResolver{
		resolved: map[string]string{"bw://password/prod-db": "db-secret"},
	}

	if err := cfg.ResolveDatabasePasswords(context.Background(), stub); err != nil {
		t.Fatalf("ResolveDatabasePasswords: %v", err)
	}

	if got := cfg.Databases["primary"].Password; got != "db-secret" {
		t.Errorf("primary.Password = %q, want %q", got, "db-secret")
	}
}

// TestResolveEnvLeavesOrdinaryURLsUntouched is a regression test: an
// earlier version matched any "scheme://" value as a credential reference,
// which broke a real config (CALDAV_URL = "https://dav.example.com") by
// trying to resolve it and failing with "unknown credential scheme".
// Ordinary URLs with schemes no provider is registered for must pass
// through unchanged, just like a plain literal value.
func TestResolveEnvLeavesOrdinaryURLsUntouched(t *testing.T) {
	cfg := &Config{
		Env: map[string]string{
			"CALDAV_URL": "https://dav.example.com",
		},
	}
	stub := &stubResolver{resolved: map[string]string{}}

	if err := cfg.ResolveEnv(context.Background(), stub); err != nil {
		t.Fatalf("ResolveEnv: %v", err)
	}
	if got := cfg.Env["CALDAV_URL"]; got != "https://dav.example.com" {
		t.Errorf("CALDAV_URL = %q, want unchanged https://dav.example.com", got)
	}
	if atomic.LoadInt32(&stub.callCount) != 0 {
		t.Errorf("expected zero resolver calls for a non-credential URL, got %d", stub.callCount)
	}
}

func TestResolveEnvLeavesNonURIValuesUntouched(t *testing.T) {
	cfg := &Config{
		Env: map[string]string{
			"PLAIN":   "just-a-literal-value",
			"NOT_URI": "bw-but-no-scheme-separator",
		},
	}
	stub := &stubResolver{resolved: map[string]string{}}

	if err := cfg.ResolveEnv(context.Background(), stub); err != nil {
		t.Fatalf("ResolveEnv: %v", err)
	}
	if cfg.Env["PLAIN"] != "just-a-literal-value" || cfg.Env["NOT_URI"] != "bw-but-no-scheme-separator" {
		t.Errorf("non-URI env values were modified: %v", cfg.Env)
	}
}
