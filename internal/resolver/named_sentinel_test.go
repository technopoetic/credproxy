package resolver

import (
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

func newNamedTestResolver(hc config.HostConfig, resolved map[string]string) *Resolver {
	cfg := &config.Config{Hosts: map[string]config.HostConfig{"api.trello.com": hc}}
	cfg.SetDefaults()
	reg := providers.NewRegistry()
	reg.Register(&mockProvider{resolved: resolved})
	return New(cfg, reg)
}

var trelloCreds = map[string]string{
	"mock://trello/key":         "key-value",
	"mock://trello/token":       "personal-token",
	"mock://trello/token2":      "second-token",
	"mock://trello/agent-token": "agent-token-value",
}

func trelloHost() config.HostConfig {
	return config.HostConfig{
		Credential: "mock://trello/key",
		Credentials: map[string]string{
			"token":       "mock://trello/token",
			"token2":      "mock://trello/token2",
			"agent-token": "mock://trello/agent-token",
		},
	}
}

func TestNamedSentinelInQueryStringSubstituted(t *testing.T) {
	r := newNamedTestResolver(trelloHost(), trelloCreds)

	req := httptest.NewRequest(http.MethodGet, "https://api.trello.com/1/boards?key=CREDPROXY_TOKEN&token=CREDPROXY_TOKEN:agent-token", nil)
	if err := r.ResolveRequest(req, "api.trello.com"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := "key=key-value&token=agent-token-value"
	if req.URL.RawQuery != want {
		t.Errorf("query = %q, want %q", req.URL.RawQuery, want)
	}
}

func TestNamedSentinelInHeaderSubstituted(t *testing.T) {
	r := newNamedTestResolver(trelloHost(), trelloCreds)

	req := httptest.NewRequest(http.MethodGet, "https://api.trello.com/1/members/me", nil)
	req.Header.Set("X-Trello-Token", "CREDPROXY_TOKEN:token")

	if err := r.ResolveRequest(req, "api.trello.com"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := req.Header.Get("X-Trello-Token"); got != "personal-token" {
		t.Errorf("header = %q, want %q", got, "personal-token")
	}
}

func TestNamedSentinelInBodySubstituted(t *testing.T) {
	r := newNamedTestResolver(trelloHost(), trelloCreds)

	body := strings.NewReader(`{"token": "CREDPROXY_TOKEN:agent-token", "key": "CREDPROXY_TOKEN"}`)
	req := httptest.NewRequest(http.MethodPost, "https://api.trello.com/1/cards", body)
	if err := r.ResolveRequest(req, "api.trello.com"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, _ := io.ReadAll(req.Body)
	want := `{"token": "agent-token-value", "key": "key-value"}`
	if string(got) != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

func TestBareSentinelUsesDefaultWhenNamedCredentialsExist(t *testing.T) {
	r := newNamedTestResolver(trelloHost(), trelloCreds)

	req := httptest.NewRequest(http.MethodGet, "https://api.trello.com/1/members/me", nil)
	req.Header.Set("Authorization", "CREDPROXY_TOKEN")
	if err := r.ResolveRequest(req, "api.trello.com"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "key-value" {
		t.Errorf("bare sentinel = %q, want default credential %q", got, "key-value")
	}
}

func defaultOnlyHost() config.HostConfig {
	return config.HostConfig{Credential: "mock://trello/key"}
}

func TestUnconfiguredSuffixIsLiteralOnHostWithoutNamedCredentials(t *testing.T) {
	r := newNamedTestResolver(defaultOnlyHost(), trelloCreds)

	req := httptest.NewRequest(http.MethodGet, "https://api.trello.com/1/boards?token=CREDPROXY_TOKEN:nope", nil)
	if err := r.ResolveRequest(req, "api.trello.com"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := "token=key-value:nope"; req.URL.RawQuery != want {
		t.Errorf("query = %q, want %q", req.URL.RawQuery, want)
	}
}

func TestUnmatchedNameOnHostWithNamedCredentialsFailsClosed(t *testing.T) {
	calls := map[string]int{}
	cfg := &config.Config{Hosts: map[string]config.HostConfig{"api.trello.com": trelloHost()}}
	cfg.SetDefaults()
	reg := providers.NewRegistry()
	reg.Register(&countingProvider{mockProvider: mockProvider{resolved: trelloCreds}, calls: calls})
	r := New(cfg, reg)

	req := httptest.NewRequest(http.MethodGet, "https://api.trello.com/1/boards?token=CREDPROXY_TOKEN:agent_tokn", nil)
	if err := r.ResolveRequest(req, "api.trello.com"); err == nil {
		t.Fatal("expected error for unmatched name on a host with named credentials")
	}
	if calls["mock://trello/key"] != 0 {
		t.Errorf("default credential resolved %d times, want 0", calls["mock://trello/key"])
	}
}

func TestUnconfiguredSuffixWithoutDefaultFailsClosed(t *testing.T) {
	hc := config.HostConfig{Credentials: map[string]string{"token": "mock://trello/token"}}
	r := newNamedTestResolver(hc, trelloCreds)

	req := httptest.NewRequest(http.MethodGet, "https://api.trello.com/1/boards?token=CREDPROXY_TOKEN:nope", nil)
	if err := r.ResolveRequest(req, "api.trello.com"); err == nil {
		t.Fatal("expected error when no default credential exists")
	}
}

func TestBasicAuthFixedPasswordKeepsDefaultCredential(t *testing.T) {
	r := newNamedTestResolver(defaultOnlyHost(), trelloCreds)

	encoded := base64.StdEncoding.EncodeToString([]byte("CREDPROXY_TOKEN:x-oauth-basic"))
	req := httptest.NewRequest(http.MethodGet, "https://api.trello.com/1/members/me", nil)
	req.Header.Set("Authorization", "Basic "+encoded)
	if err := r.ResolveRequest(req, "api.trello.com"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(req.Header.Get("Authorization"), "Basic "))
	if err != nil {
		t.Fatalf("decoding header: %v", err)
	}
	if string(decoded) != "key-value:x-oauth-basic" {
		t.Errorf("basic auth = %q, want %q", decoded, "key-value:x-oauth-basic")
	}
}

func TestNamedSentinelPrefixCollisionMatchesLongestName(t *testing.T) {
	hc := config.HostConfig{
		Credential:  "mock://trello/key",
		Credentials: map[string]string{"token": "mock://trello/token"},
	}
	r := newNamedTestResolver(hc, trelloCreds)

	req := httptest.NewRequest(http.MethodGet, "https://api.trello.com/1/boards?token=CREDPROXY_TOKEN:token2", nil)
	if err := r.ResolveRequest(req, "api.trello.com"); err == nil {
		t.Fatalf("expected error, got query %q (token2 must not match token)", req.URL.RawQuery)
	}
}

func TestNamedSentinelWithoutDefaultFailsClosed(t *testing.T) {
	hc := config.HostConfig{Credentials: map[string]string{"token": "mock://trello/token"}}
	r := newNamedTestResolver(hc, trelloCreds)

	req := httptest.NewRequest(http.MethodGet, "https://api.trello.com/1/members/me", nil)
	req.Header.Set("Authorization", "CREDPROXY_TOKEN")
	if err := r.ResolveRequest(req, "api.trello.com"); err == nil {
		t.Fatal("expected error when bare sentinel has no default credential")
	}
}

func TestNamedSentinelInBasicAuthSubstituted(t *testing.T) {
	r := newNamedTestResolver(trelloHost(), trelloCreds)

	encoded := base64.StdEncoding.EncodeToString([]byte("user:CREDPROXY_TOKEN:agent-token"))
	req := httptest.NewRequest(http.MethodGet, "https://api.trello.com/1/members/me", nil)
	req.Header.Set("Authorization", "Basic "+encoded)
	if err := r.ResolveRequest(req, "api.trello.com"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(req.Header.Get("Authorization"), "Basic "))
	if err != nil {
		t.Fatalf("decoding header: %v", err)
	}
	if string(decoded) != "user:agent-token-value" {
		t.Errorf("basic auth = %q, want %q", decoded, "user:agent-token-value")
	}
}

func TestNamedCredentialResolvedLazily(t *testing.T) {
	calls := map[string]int{}
	cfg := &config.Config{Hosts: map[string]config.HostConfig{"api.trello.com": trelloHost()}}
	cfg.SetDefaults()
	reg := providers.NewRegistry()
	reg.Register(&countingProvider{mockProvider: mockProvider{resolved: trelloCreds}, calls: calls})
	r := New(cfg, reg)

	req := httptest.NewRequest(http.MethodGet, "https://api.trello.com/1/members/me", nil)
	req.Header.Set("Authorization", "CREDPROXY_TOKEN")
	if err := r.ResolveRequest(req, "api.trello.com"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if calls["mock://trello/key"] != 1 {
		t.Errorf("default resolved %d times, want 1", calls["mock://trello/key"])
	}
	if calls["mock://trello/agent-token"] != 0 {
		t.Errorf("unused named credential resolved %d times, want 0", calls["mock://trello/agent-token"])
	}
}

type countingProvider struct {
	mockProvider
	calls map[string]int
}

func (c *countingProvider) Resolve(ctx context.Context, uri string) (string, error) {
	c.calls[uri]++
	return c.mockProvider.Resolve(ctx, uri)
}
