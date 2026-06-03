package resolver

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"

	"github.com/rhibbitts/credproxy/internal/config"
	"github.com/rhibbitts/credproxy/internal/providers"
)

var placeholderRe = regexp.MustCompile(`__([a-zA-Z0-9_-]+)__`)

type Resolver struct {
	cfg    *config.Config
	reg    *providers.Registry
	cache  map[string]string
}

func New(cfg *config.Config, reg *providers.Registry) *Resolver {
	return &Resolver{
		cfg:   cfg,
		reg:   reg,
		cache: make(map[string]string),
	}
}

func (r *Resolver) IsHostAllowed(host string) bool {
	return r.cfg.IsHostAllowed(host)
}

func (r *Resolver) ResolveRequest(req *http.Request, host string) error {
	ctx := req.Context()

	if err := r.resolveHeaders(req.Header, ctx); err != nil {
		return err
	}

	if req.Body != nil && req.Body != http.NoBody {
		body, err := io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return fmt.Errorf("reading body: %w", err)
		}
		resolved, err := r.resolveBytes(body, ctx)
		if err != nil {
			return fmt.Errorf("resolving body: %w", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(resolved))
		req.ContentLength = int64(len(resolved))
	}

	return nil
}

func (r *Resolver) resolveHeaders(h http.Header, ctx context.Context) error {
	for key, values := range h {
		for i, val := range values {
			resolved, err := r.resolveString(val, ctx)
			if err != nil {
				return fmt.Errorf("resolving header %s: %w", key, err)
			}
			h[key][i] = resolved
		}
	}
	return nil
}

func (r *Resolver) resolveString(input string, ctx context.Context) (string, error) {
	var err error
	result := placeholderRe.ReplaceAllStringFunc(input, func(match string) string {
		name := placeholderRe.FindStringSubmatch(match)[1]
		val, resolveErr := r.resolveName(name, ctx)
		if resolveErr != nil {
			err = resolveErr
			return match
		}
		return val
	})
	return result, err
}

func (r *Resolver) resolveBytes(input []byte, ctx context.Context) ([]byte, error) {
	var err error
	result := placeholderRe.ReplaceAllFunc(input, func(match []byte) []byte {
		subs := placeholderRe.FindSubmatch(match)
		name := string(subs[1])
		val, resolveErr := r.resolveName(name, ctx)
		if resolveErr != nil {
			err = resolveErr
			return match
		}
		return []byte(val)
	})
	return result, err
}

func (r *Resolver) resolveName(name string, ctx context.Context) (string, error) {
	if val, ok := r.cache[name]; ok {
		return val, nil
	}

	uri, ok := r.cfg.GetCredentialURI(name)
	if !ok {
		return "", &NotConfiguredError{Name: name}
	}

	val, err := r.reg.Resolve(ctx, uri)
	if err != nil {
		return "", fmt.Errorf("resolving %s: %w", uri, err)
	}

	r.cache[name] = val
	return val, nil
}

type NotConfiguredError struct {
	Name string
}

func (e *NotConfiguredError) Error() string {
	return "credential not configured: " + e.Name
}
