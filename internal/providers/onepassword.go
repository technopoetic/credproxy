package providers

import (
	"bytes"
	"context"
	"fmt"
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
	cmd := exec.CommandContext(ctx, "op", "read", uri)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("op read failed: %s: %w", strings.TrimSpace(stderr.String()), err)
	}
	return strings.TrimSpace(string(out)), nil
}
