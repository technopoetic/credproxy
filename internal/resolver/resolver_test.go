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

// TestEncodedAuthBasicCurl covers `curl -u user:CREDPROXY_TOKEN` which base64-encodes
// the full user:password string before sending Authorization: Basic <b64>.
func TestEncodedAuthBasicCurl(t *testing.T) {
	r := newTestResolver(
		map[string]string{"your-domain.atlassian.net": "mock://atlassian/token"},
		map[string]string{"mock://atlassian/token": "myapitoken"},
	)

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

// TestEncodedAuthApiKey covers elasticsearch-py with api_key="CREDPROXY_TOKEN",
// which base64-encodes the string and sends Authorization: ApiKey <b64>.
func TestEncodedAuthApiKey(t *testing.T) {
	r := newTestResolver(
		map[string]string{"search.es.io": "mock://es/key"},
		map[string]string{"mock://es/key": "myid:myapikey"},
	)

	encoded := base64.StdEncoding.EncodeToString([]byte("CREDPROXY_TOKEN"))
	req := httptest.NewRequest(http.MethodGet, "https://search.es.io/", nil)
	req.Header.Set("Authorization", "ApiKey "+encoded)

	if err := r.ResolveRequest(req, "search.es.io"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := "ApiKey " + base64.StdEncoding.EncodeToString([]byte("myid:myapikey"))
	if got := req.Header.Get("Authorization"); got != want {
		t.Errorf("api key auth not substituted: got %q, want %q", got, want)
	}
}

// TestEncodedAuthSentinelOnly covers a client that passes the sentinel as the
// entire credential value (no user: prefix), which some credential stores return
// as a single opaque token.
func TestEncodedAuthSentinelOnly(t *testing.T) {
	r := newTestResolver(
		map[string]string{"api.example.com": "mock://example/cred"},
		map[string]string{"mock://example/cred": "user:secret"},
	)

	encoded := base64.StdEncoding.EncodeToString([]byte("CREDPROXY_TOKEN"))
	req := httptest.NewRequest(http.MethodGet, "https://api.example.com/", nil)
	req.Header.Set("Authorization", "Basic "+encoded)

	if err := r.ResolveRequest(req, "api.example.com"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:secret"))
	if got := req.Header.Get("Authorization"); got != want {
		t.Errorf("sentinel-only encoded auth not substituted: got %q, want %q", got, want)
	}
}

// TestEncodedAuthNoSentinelUnchanged ensures a valid encoded Authorization header
// with no sentinel is passed through unmodified.
func TestEncodedAuthNoSentinelUnchanged(t *testing.T) {
	r := newTestResolver(
		map[string]string{"api.example.com": "mock://example/cred"},
		map[string]string{"mock://example/cred": "secret"},
	)

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

// TestAuthorizationLiteralSentinelSubstituted covers the plain case: the sentinel
// appears literally in the Authorization header value (no encoding). The plain
// sentinel check fires first — no decoding needed.
func TestAuthorizationLiteralSentinelSubstituted(t *testing.T) {
	r := newTestResolver(
		map[string]string{"api.example.com": "mock://example/cred"},
		map[string]string{"mock://example/cred": "secret"},
	)

	req := httptest.NewRequest(http.MethodGet, "https://api.example.com/", nil)
	req.Header.Set("Authorization", "ApiKey CREDPROXY_TOKEN")

	if err := r.ResolveRequest(req, "api.example.com"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := req.Header.Get("Authorization"); got != "ApiKey secret" {
		t.Errorf("literal sentinel not substituted: got %q, want %q", got, "ApiKey secret")
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
