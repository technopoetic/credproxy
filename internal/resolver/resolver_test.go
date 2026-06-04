package resolver

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rhibbitts/credproxy/internal/config"
	"github.com/rhibbitts/credproxy/internal/providers"
)

type mockProvider struct {
	resolved map[string]string
}

func (m *mockProvider) Resolve(_ context.Context, uri string) (string, error) {
	if v, ok := m.resolved[uri]; ok {
		return v, nil
	}
	return "", &providers.UnknownSchemeError{URI: uri}
}

func (m *mockProvider) Schemes() []string {
	return []string{"mock"}
}

func newTestConfig(hosts map[string]string) *config.Config {
	hostConfig := make(map[string]config.HostConfig, len(hosts))
	for h, cred := range hosts {
		hostConfig[h] = config.HostConfig{Credential: cred}
	}
	cfg := &config.Config{Hosts: hostConfig}
	cfg.SetDefaults()
	return cfg
}

func newTestResolver(hosts map[string]string, resolved map[string]string) *Resolver {
	cfg := newTestConfig(hosts)
	reg := providers.NewRegistry()
	reg.Register(&mockProvider{resolved: resolved})
	return New(cfg, reg)
}

func TestHeadersWithSentinelSubstituted(t *testing.T) {
	r := newTestResolver(
		map[string]string{"api.unsplash.com": "mock://unsplash/key"},
		map[string]string{"mock://unsplash/key": "secret-key-123"},
	)

	req := httptest.NewRequest(http.MethodGet, "https://api.unsplash.com/photos", nil)
	req.Header.Set("Authorization", "Bearer CREDPROXY_TOKEN")

	err := r.ResolveRequest(req, "api.unsplash.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := req.Header.Get("Authorization"); got != "Bearer secret-key-123" {
		t.Errorf("header not substituted: got %q, want %q", got, "Bearer secret-key-123")
	}
}

func TestBodyWithSentinelSubstituted(t *testing.T) {
	r := newTestResolver(
		map[string]string{"api.stripe.com": "mock://stripe/key"},
		map[string]string{"mock://stripe/key": "sk_live_abc"},
	)

	body := strings.NewReader(`{"api_key": "CREDPROXY_TOKEN"}`)
	req := httptest.NewRequest(http.MethodPost, "https://api.stripe.com/charges", body)

	err := r.ResolveRequest(req, "api.stripe.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	respBody, _ := io.ReadAll(req.Body)
	if !bytes.Contains(respBody, []byte("sk_live_abc")) {
		t.Errorf("body not substituted: got %q", string(respBody))
	}
	if bytes.Contains(respBody, []byte("CREDPROXY_TOKEN")) {
		t.Errorf("sentinel still present in body: %q", string(respBody))
	}
}

func TestQueryStringSubstituted(t *testing.T) {
	r := newTestResolver(
		map[string]string{"api.unsplash.com": "mock://unsplash/key"},
		map[string]string{"mock://unsplash/key": "secret-key-123"},
	)

	req := httptest.NewRequest(http.MethodGet, "https://api.unsplash.com/search/photos?client_id=CREDPROXY_TOKEN&query=cats", nil)

	err := r.ResolveRequest(req, "api.unsplash.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(req.URL.RawQuery, "secret-key-123") {
		t.Errorf("query string not substituted: got %q", req.URL.RawQuery)
	}
	if strings.Contains(req.URL.RawQuery, "CREDPROXY_TOKEN") {
		t.Errorf("sentinel still present in query: %q", req.URL.RawQuery)
	}
}

func TestUnconfiguredHostPassesThrough(t *testing.T) {
	r := newTestResolver(
		map[string]string{"api.unsplash.com": "mock://unsplash/key"},
		map[string]string{"mock://unsplash/key": "secret-key-123"},
	)

	req := httptest.NewRequest(http.MethodGet, "https://api.unknown.com/data", nil)
	req.Header.Set("Authorization", "Bearer CREDPROXY_TOKEN")

	err := r.ResolveRequest(req, "api.unknown.com")
	if err != nil {
		t.Fatalf("unconfigured host should not error: %v", err)
	}

	if got := req.Header.Get("Authorization"); got != "Bearer CREDPROXY_TOKEN" {
		t.Errorf("unconfigured host should pass sentinel through: got %q", got)
	}
}

func TestIsHostAllowed(t *testing.T) {
	cfg := newTestConfig(map[string]string{
		"api.unsplash.com": "mock://unsplash/key",
	})
	reg := providers.NewRegistry()
	r := New(cfg, reg)

	if !r.IsHostAllowed("api.unsplash.com") {
		t.Error("configured host should be allowed")
	}
	if r.IsHostAllowed("evil.com") {
		t.Error("unconfigured host should not be allowed")
	}
}

func TestCustomSentinel(t *testing.T) {
	r := newTestResolver(
		map[string]string{"api.unsplash.com": "mock://unsplash/key"},
		map[string]string{"mock://unsplash/key": "secret-key-123"},
	)
	r.SetSentinel("{{CREDENTIAL}}")

	req := httptest.NewRequest(http.MethodGet, "https://api.unsplash.com/photos", nil)
	req.Header.Set("X-Api-Key", "{{CREDENTIAL}}")

	err := r.ResolveRequest(req, "api.unsplash.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := req.Header.Get("X-Api-Key"); got != "secret-key-123" {
		t.Errorf("custom sentinel not substituted: got %q, want %q", got, "secret-key-123")
	}
}

func TestNoSentinelNoChanges(t *testing.T) {
	r := newTestResolver(
		map[string]string{"api.unsplash.com": "mock://unsplash/key"},
		map[string]string{"mock://unsplash/key": "secret-key-123"},
	)

	req := httptest.NewRequest(http.MethodGet, "https://api.unsplash.com/photos", nil)
	req.Header.Set("Authorization", "Bearer real-key-already")

	err := r.ResolveRequest(req, "api.unsplash.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := req.Header.Get("Authorization"); got != "Bearer real-key-already" {
		t.Errorf("unchanged header should not be modified: got %q", got)
	}
}

func TestMultipleSentinelOccurrences(t *testing.T) {
	r := newTestResolver(
		map[string]string{"api.unsplash.com": "mock://unsplash/key"},
		map[string]string{"mock://unsplash/key": "secret-key-123"},
	)

	req := httptest.NewRequest(http.MethodGet, "https://api.unsplash.com/photos", nil)
	req.Header.Set("Authorization", "CREDPROXY_TOKEN CREDPROXY_TOKEN")
	req.Header.Set("X-Custom", "prefix-CREDPROXY_TOKEN-suffix")

	err := r.ResolveRequest(req, "api.unsplash.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := req.Header.Get("Authorization"); got != "secret-key-123 secret-key-123" {
		t.Errorf("multiple sentinel in header: got %q", got)
	}
	if got := req.Header.Get("X-Custom"); got != "prefix-secret-key-123-suffix" {
		t.Errorf("sentinel with surrounding text: got %q", got)
	}
}

func TestProviderResolutionFailure(t *testing.T) {
	r := newTestResolver(
		map[string]string{"api.unsplash.com": "mock://unsplash/key"},
		map[string]string{},
	)

	req := httptest.NewRequest(http.MethodGet, "https://api.unsplash.com/photos", nil)
	req.Header.Set("Authorization", "Bearer CREDPROXY_TOKEN")

	err := r.ResolveRequest(req, "api.unsplash.com")
	if err == nil {
		t.Fatal("expected error for provider resolution failure")
	}
}
