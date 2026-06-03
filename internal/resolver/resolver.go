package resolver

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/rhibbitts/credproxy/internal/config"
	"github.com/rhibbitts/credproxy/internal/providers"
)

const defaultSentinel = "**token**"

type Resolver struct {
	cfg      *config.Config
	reg      *providers.Registry
	cache    map[string]string
	sentinel string
}

func New(cfg *config.Config, reg *providers.Registry) *Resolver {
	return &Resolver{
		cfg:      cfg,
		reg:      reg,
		cache:    make(map[string]string),
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

	credential, err := r.resolveForHost(host, uri, req.Context())
	if err != nil {
		return fmt.Errorf("resolving credential for %s: %w", host, err)
	}

	r.substituteHeaders(req.Header, credential)

	if req.Body != nil && req.Body != http.NoBody {
		if err := r.substituteBody(req, credential); err != nil {
			return fmt.Errorf("substituting body: %w", err)
		}
	}

	return nil
}

func (r *Resolver) resolveForHost(host, uri string, ctx context.Context) (string, error) {
	if val, ok := r.cache[host]; ok {
		return val, nil
	}

	val, err := r.reg.Resolve(ctx, uri)
	if err != nil {
		return "", err
	}

	r.cache[host] = val
	return val, nil
}

func (r *Resolver) substituteHeaders(h http.Header, credential string) {
	for key, values := range h {
		for i, val := range values {
			if strings.Contains(val, r.sentinel) {
				h[key][i] = strings.ReplaceAll(val, r.sentinel, credential)
			}
		}
	}
}

func (r *Resolver) substituteBody(req *http.Request, credential string) error {
	body, err := io.ReadAll(req.Body)
	req.Body.Close()
	if err != nil {
		return fmt.Errorf("reading body: %w", err)
	}

	if bytes.Contains(body, []byte(r.sentinel)) {
		body = bytes.ReplaceAll(body, []byte(r.sentinel), []byte(credential))
	}

	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	return nil
}
