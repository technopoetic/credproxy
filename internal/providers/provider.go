package providers

import (
	"context"
)

type Provider interface {
	Resolve(ctx context.Context, uri string) (string, error)
	Schemes() []string
}

type Registry struct {
	providers map[string]Provider
}

func NewRegistry() *Registry {
	return &Registry{providers: make(map[string]Provider)}
}

func (r *Registry) Register(p Provider) {
	for _, scheme := range p.Schemes() {
		r.providers[scheme] = p
	}
}

func (r *Registry) Resolve(ctx context.Context, uri string) (string, error) {
	scheme, ok := splitURI(uri)
	if !ok {
		return "", &UnknownSchemeError{URI: uri}
	}
	p, ok := r.providers[scheme]
	if !ok {
		return "", &UnknownSchemeError{URI: uri}
	}
	return p.Resolve(ctx, uri)
}

func splitURI(uri string) (scheme string, ok bool) {
	for i := 0; i < len(uri); i++ {
		if uri[i] == ':' {
			if i+2 < len(uri) && uri[i+1] == '/' && uri[i+2] == '/' {
				return uri[:i], true
			}
		}
	}
	return "", false
}

type UnknownSchemeError struct {
	URI string
}

func (e *UnknownSchemeError) Error() string {
	return "unknown credential scheme in URI: " + e.URI
}