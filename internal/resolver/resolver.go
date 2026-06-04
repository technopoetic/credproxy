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
			if key == "Authorization" {
				if newVal, ok := r.substituteBasicAuth(val, credential); ok {
					h[key][i] = newVal
					continue
				}
			}
			if strings.Contains(val, r.sentinel) {
				h[key][i] = strings.ReplaceAll(val, r.sentinel, credential)
			}
		}
	}
}

// substituteBasicAuth handles tools that automatically base64-encode Basic auth
// credentials (e.g. curl -u). It decodes the credential, substitutes the sentinel
// in the decoded string, then re-encodes. Returns false if the header is not Basic
// auth or the decoded value contains no sentinel.
func (r *Resolver) substituteBasicAuth(val, credential string) (string, bool) {
	rest, ok := strings.CutPrefix(val, "Basic ")
	if !ok {
		return "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(rest)
	if err != nil {
		return "", false
	}
	if !strings.Contains(string(decoded), r.sentinel) {
		return "", false
	}
	substituted := strings.ReplaceAll(string(decoded), r.sentinel, credential)
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(substituted)), true
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
