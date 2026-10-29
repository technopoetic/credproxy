package providers

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

type OnePasswordProvider struct {
	retries int
	backoff time.Duration
}

func NewOnePasswordProvider() *OnePasswordProvider {
	return &OnePasswordProvider{
		retries: 2,
		backoff: 100 * time.Millisecond,
	}
}

func (p *OnePasswordProvider) Schemes() []string {
	return []string{"op"}
}

func (p *OnePasswordProvider) Resolve(ctx context.Context, uri string) (string, error) {
	var lastErr error
	for attempt := 0; attempt <= p.retries; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(p.backoff):
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}
		val, err := p.read(ctx, uri)
		if err == nil {
			return val, nil
		}
		lastErr = err
	}
	return "", lastErr
}

func (p *OnePasswordProvider) read(ctx context.Context, uri string) (string, error) {
	opPath, err := exec.LookPath("op")
	if err != nil {
		return "", fmt.Errorf("op CLI not found on PATH: %w", err)
	}

	cmd := p.buildCmd(ctx, opPath, uri, os.Environ())
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("op read failed: %s: %w", strings.TrimSpace(stderr.String()), err)
	}
	return strings.TrimSpace(string(out)), nil
}

func (p *OnePasswordProvider) buildCmd(ctx context.Context, opPath string, uri string, env []string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, opPath, "read", uri)
	cmd.Args[0] = "credproxy-op"
	cmd.Env = stripProxyEnv(env)
	return cmd
}

func stripProxyEnv(env []string) []string {
	filtered := make([]string, 0, len(env))
	for _, e := range env {
		key := strings.SplitN(e, "=", 2)[0]
		switch strings.ToUpper(key) {
		case "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY",
			"SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE",
			"NODE_EXTRA_CA_CERTS", "CURL_CA_BUNDLE":
			continue
		}
		filtered = append(filtered, e)
	}
	return filtered
}
