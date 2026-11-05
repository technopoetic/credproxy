package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// BitwardenProvider resolves bw:// credential URIs through the Bitwarden
// CLI. Two URI shapes are supported:
//
//   - bw://<object>/<item>        -- maps directly to `bw get <object> <item>`
//     for object in {password, username, uri, totp, notes}. totp in
//     particular is a live code computed by the bw CLI itself from the
//     stored seed; there is no JSON field to read it from directly, so this
//     form exists specifically to reuse bw's own computation rather than
//     reimplementing TOTP.
//   - bw://item/<item>/<field>    -- for a custom field on an item, which bw
//     has no dedicated `get` verb for. Fetches `bw get item <item>` as JSON
//     and looks up the named field.
//
// Unlike OnePasswordProvider, the Bitwarden CLI has no passwordless unlock
// path (no OS biometric/keychain integration, no service-account token that
// substitutes for the vault's master password at decrypt time): a session
// must already be unlocked via `bw unlock`, with its session key present in
// BW_SESSION in credproxy's own environment before it starts. Resolve fails
// fast if BW_SESSION is absent rather than spawning `bw` only to have it
// fail (or, worse, prompt interactively and hang).
type BitwardenProvider struct {
	retries int
	backoff time.Duration
}

func NewBitwardenProvider() *BitwardenProvider {
	return &BitwardenProvider{
		retries: 2,
		backoff: 100 * time.Millisecond,
	}
}

func (p *BitwardenProvider) Schemes() []string {
	return []string{"bw"}
}

func (p *BitwardenProvider) Resolve(ctx context.Context, uri string) (string, error) {
	ref, err := parseBWURI(uri)
	if err != nil {
		return "", err
	}
	if os.Getenv("BW_SESSION") == "" {
		return "", errors.New("BW_SESSION not set: run `export BW_SESSION=$(bw unlock --raw)` before starting credproxy")
	}

	var lastErr error
	for attempt := 0; attempt <= p.retries; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(p.backoff):
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}
		val, err := p.read(ctx, ref)
		if err == nil {
			return val, nil
		}
		lastErr = err
	}
	return "", lastErr
}

func (p *BitwardenProvider) read(ctx context.Context, ref bwRef) (string, error) {
	bwPath, err := exec.LookPath("bw")
	if err != nil {
		return "", fmt.Errorf("bw CLI not found on PATH: %w", err)
	}

	if ref.object == "item" {
		return p.readItemField(ctx, bwPath, ref)
	}

	cmd := p.buildCmd(ctx, bwPath, []string{"get", ref.object, ref.item}, os.Environ())
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("bw get %s failed: %s: %w", ref.object, strings.TrimSpace(stderr.String()), err)
	}
	return strings.TrimSpace(string(out)), nil
}

func (p *BitwardenProvider) readItemField(ctx context.Context, bwPath string, ref bwRef) (string, error) {
	cmd := p.buildCmd(ctx, bwPath, []string{"get", "item", ref.item}, os.Environ())
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("bw get item failed: %s: %w", strings.TrimSpace(stderr.String()), err)
	}

	var item struct {
		Fields []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"fields"`
	}
	if err := json.Unmarshal(out, &item); err != nil {
		return "", fmt.Errorf("bw get item returned invalid JSON: %w", err)
	}
	for _, f := range item.Fields {
		if f.Name == ref.field {
			return f.Value, nil
		}
	}
	return "", fmt.Errorf("bw item %q has no custom field named %q", ref.item, ref.field)
}

// buildCmd does not rename cmd.Args[0] the way OnePasswordProvider's does
// (to "credproxy-op"): that rename exists because 1Password's desktop app
// treats argv[0] as a distinct client identity for approval prompts. The bw
// CLI has no equivalent concept, so there is nothing for a rename to
// accomplish here.
func (p *BitwardenProvider) buildCmd(ctx context.Context, bwPath string, args []string, env []string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, bwPath, args...)
	cmd.Env = stripProxyEnv(env)
	return cmd
}

// bwRef is a parsed bw:// URI. field is only populated when object == "item".
type bwRef struct {
	object string
	item   string
	field  string
}

var bwObjects = map[string]bool{
	"password": true,
	"username": true,
	"uri":      true,
	"totp":     true,
	"notes":    true,
	"item":     true,
}

// parseBWURI parses "bw://<object>/<item>" or "bw://item/<item>/<field>".
// For the item form, the field name is taken after the last "/" so that
// item names themselves may contain "/".
func parseBWURI(uri string) (bwRef, error) {
	rest, ok := strings.CutPrefix(uri, "bw://")
	if !ok {
		return bwRef{}, fmt.Errorf("invalid bw URI %q: missing bw:// scheme", uri)
	}

	slash := strings.Index(rest, "/")
	if slash < 0 {
		return bwRef{}, fmt.Errorf("invalid bw URI %q: expected bw://<object>/<item>", uri)
	}
	object := rest[:slash]
	remainder := rest[slash+1:]
	if remainder == "" {
		return bwRef{}, fmt.Errorf("invalid bw URI %q: missing item", uri)
	}
	if !bwObjects[object] {
		return bwRef{}, fmt.Errorf("invalid bw URI %q: unknown object %q (want password, username, uri, totp, notes, or item)", uri, object)
	}

	if object != "item" {
		return bwRef{object: object, item: remainder}, nil
	}

	lastSlash := strings.LastIndex(remainder, "/")
	if lastSlash < 0 {
		return bwRef{}, fmt.Errorf("invalid bw URI %q: expected bw://item/<item>/<field>", uri)
	}
	item := remainder[:lastSlash]
	field := remainder[lastSlash+1:]
	if item == "" || field == "" {
		return bwRef{}, fmt.Errorf("invalid bw URI %q: expected bw://item/<item>/<field>", uri)
	}
	return bwRef{object: object, item: item, field: field}, nil
}
