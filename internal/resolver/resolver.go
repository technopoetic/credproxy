package resolver

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/technopoetic/credproxy/internal/config"
	"github.com/technopoetic/credproxy/internal/providers"
)

const defaultSentinel = "CREDPROXY_TOKEN"
const credentialCacheTTL = 5 * time.Minute
const maxBodySize = 10 * 1024 * 1024

type cacheEntry struct {
	value   string
	expires time.Time
}

type Resolver struct {
	cfg      *config.Config
	reg      *providers.Registry
	cache    map[string]cacheEntry
	mu       sync.Mutex
	sentinel string
}

func New(cfg *config.Config, reg *providers.Registry) *Resolver {
	return &Resolver{
		cfg:      cfg,
		reg:      reg,
		cache:    make(map[string]cacheEntry),
		sentinel: defaultSentinel,
	}
}

func (r *Resolver) SetSentinel(s string) {
	r.sentinel = s
}

// Resolve looks up an arbitrary credential URI through the provider registry.
// It is the host-agnostic counterpart to ResolveRequest and is used for
// resolving env var values at startup.
func (r *Resolver) Resolve(ctx context.Context, uri string) (string, error) {
	return r.reg.Resolve(ctx, uri)
}

func (r *Resolver) IsHostAllowed(host string) bool {
	return r.cfg.IsHostAllowed(host)
}

func (r *Resolver) ResolveRequest(req *http.Request, host string) error {
	uri, ok := r.cfg.GetCredentialURI(host)
	if !ok {
		return nil
	}

	credential, err := r.resolveForHost(req.Context(), host, uri)
	if err != nil {
		return fmt.Errorf("resolving credential for %s: %w", host, err)
	}

	r.substituteHeaders(req.Header, credential)

	if req.URL.RawQuery != "" && strings.Contains(req.URL.RawQuery, r.sentinel) {
		req.URL.RawQuery = strings.ReplaceAll(req.URL.RawQuery, r.sentinel, credential)
	}

	if req.Body != nil && req.Body != http.NoBody {
		if err := r.substituteBody(req, credential); err != nil {
			return fmt.Errorf("substituting body: %w", err)
		}
	}

	return nil
}

func (r *Resolver) resolveForHost(ctx context.Context, host, uri string) (string, error) {
	r.mu.Lock()
	if entry, ok := r.cache[host]; ok && time.Now().Before(entry.expires) {
		r.mu.Unlock()
		return entry.value, nil
	}
	r.mu.Unlock()

	val, err := r.reg.Resolve(ctx, uri)
	if err != nil {
		return "", err
	}

	r.mu.Lock()
	r.cache[host] = cacheEntry{value: val, expires: time.Now().Add(credentialCacheTTL)}
	r.mu.Unlock()
	return val, nil
}

func (r *Resolver) substituteHeaders(h http.Header, credential string) {
	for key, values := range h {
		for i, val := range values {
			// Plain sentinel check first — the common case. continue so we don't
			// also run the encoded path against the original val below.
			if strings.Contains(val, r.sentinel) {
				h[key][i] = strings.ReplaceAll(val, r.sentinel, credential)
				continue
			}
			// For Authorization headers, some clients base64-encode credentials
			// before sending (e.g. curl -u for Basic auth, elasticsearch-py for
			// ApiKey auth). Try decoding each token to find an encoded sentinel.
			// TODO: expand to all headers if we encounter encoded credentials
			// outside of Authorization.
			if key == "Authorization" {
				if newVal, ok := r.substituteEncodedAuthHeader(val, credential); ok {
					h[key][i] = newVal
				}
			}
		}
	}
}

// substituteEncodedAuthHeader handles clients that base64-encode credentials
// before sending them in an Authorization header. It tries to base64-decode each
// space-separated token; if a decoded token contains the sentinel, it substitutes
// and re-encodes that token. All matching tokens are substituted.
//
// Only standard base64 is attempted. URL-safe base64 (-/_) is not currently
// handled — add base64.URLEncoding fallback here if that becomes necessary.
//
// Returns the modified header value and true if any substitution was made,
// or "", false if no encoded sentinel was found.
func (r *Resolver) substituteEncodedAuthHeader(val, credential string) (string, bool) {
	tokens := strings.Split(val, " ")
	modified := false
	for i, token := range tokens {
		if token == "" {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(token)
		if err != nil {
			continue
		}
		if !strings.Contains(string(decoded), r.sentinel) {
			continue
		}
		substituted := strings.ReplaceAll(string(decoded), r.sentinel, credential)
		tokens[i] = base64.StdEncoding.EncodeToString([]byte(substituted))
		modified = true
	}
	if !modified {
		return "", false
	}
	return strings.Join(tokens, " "), true
}

func (r *Resolver) substituteBody(req *http.Request, credential string) error {
	body, err := io.ReadAll(io.LimitReader(req.Body, maxBodySize+1))
	req.Body.Close()
	if err != nil {
		return fmt.Errorf("reading body: %w", err)
	}
	if len(body) > maxBodySize {
		return fmt.Errorf("request body exceeds %d bytes", maxBodySize)
	}

	if bytes.Contains(body, []byte(r.sentinel)) {
		body = bytes.ReplaceAll(body, []byte(r.sentinel), []byte(credential))
	}

	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	return nil
}
