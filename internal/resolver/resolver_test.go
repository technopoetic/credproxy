package resolver

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/technopoetic/credproxy/internal/config"
	"github.com/technopoetic/credproxy/internal/providers"
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

// TestBasicAuthAutoEncoded covers tools like `curl -u user:CREDPROXY_TOKEN` that
// base64-encode the credentials before sending. credproxy must decode, substitute,
// and re-encode so the upstream server sees a valid Basic auth header.
func TestBasicAuthAutoEncoded(t *testing.T) {
	r := newTestResolver(
		map[string]string{"your-domain.atlassian.net": "mock://atlassian/token"},
		map[string]string{"mock://atlassian/token": "myapitoken"},
	)

	// curl -u "user@example.com:CREDPROXY_TOKEN" produces this header
	encoded := base64.StdEncoding.EncodeToString([]byte("user@example.com:CREDPROXY_TOKEN"))
	req := httptest.NewRequest(http.MethodGet, "https://your-domain.atlassian.net/rest/api/3/myself", nil)
	req.Header.Set("Authorization", "Basic "+encoded)

	if err := r.ResolveRequest(req, "your-domain.atlassian.net"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("user@example.com:myapitoken"))
	if got := req.Header.Get("Authorization"); got != want {
		t.Errorf("basic auth not substituted: got %q, want %q", got, want)
	}
}

func TestBasicAuthAutoEncodedSentinelOnly(t *testing.T) {
	r := newTestResolver(
		map[string]string{"api.example.com": "mock://example/cred"},
		map[string]string{"mock://example/cred": "user:secret"},
	)

	// Sentinel is the entire decoded value (both user and pass stored together)
	encoded := base64.StdEncoding.EncodeToString([]byte("CREDPROXY_TOKEN"))
	req := httptest.NewRequest(http.MethodGet, "https://api.example.com/", nil)
	req.Header.Set("Authorization", "Basic "+encoded)

	if err := r.ResolveRequest(req, "api.example.com"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:secret"))
	if got := req.Header.Get("Authorization"); got != want {
		t.Errorf("basic auth not substituted: got %q, want %q", got, want)
	}
}

func TestBasicAuthNoSentinelUnchanged(t *testing.T) {
	r := newTestResolver(
		map[string]string{"api.example.com": "mock://example/cred"},
		map[string]string{"mock://example/cred": "secret"},
	)

	// Valid Basic auth with no sentinel — must not be modified
	original := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:alreadyreal"))
	req := httptest.NewRequest(http.MethodGet, "https://api.example.com/", nil)
	req.Header.Set("Authorization", original)

	if err := r.ResolveRequest(req, "api.example.com"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := req.Header.Get("Authorization"); got != original {
		t.Errorf("header should be unchanged: got %q, want %q", got, original)
	}
}

func TestBasicAuthInvalidBase64FallsThrough(t *testing.T) {
	r := newTestResolver(
		map[string]string{"api.example.com": "mock://example/cred"},
		map[string]string{"mock://example/cred": "secret"},
	)

	// Literal sentinel (not base64-encoded) — falls through to regular substitution
	req := httptest.NewRequest(http.MethodGet, "https://api.example.com/", nil)
	req.Header.Set("Authorization", "Basic CREDPROXY_TOKEN")

	if err := r.ResolveRequest(req, "api.example.com"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := req.Header.Get("Authorization"); got != "Basic secret" {
		t.Errorf("literal sentinel not substituted: got %q, want %q", got, "Basic secret")
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

func TestResolveHostAgnostic(t *testing.T) {
	r := newTestResolver(
		map[string]string{},
		map[string]string{"mock://anywhere/key": "secret-xyz"},
	)

	got, err := r.Resolve(context.Background(), "mock://anywhere/key")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "secret-xyz" {
		t.Errorf("Resolve = %q, want %q", got, "secret-xyz")
	}
}

func TestResolveUnknownScheme(t *testing.T) {
	r := newTestResolver(map[string]string{}, map[string]string{})

	_, err := r.Resolve(context.Background(), "vault://some/path")
	if err == nil {
		t.Fatal("expected error for unregistered scheme")
	}
}
