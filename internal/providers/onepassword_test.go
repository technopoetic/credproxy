package providers

import (
	"context"
	"strings"
	"testing"
)

func TestStripProxyEnv(t *testing.T) {
	env := []string{
		"HOME=/Users/test",
		"PATH=/usr/bin:/bin",
		"HTTPS_PROXY=http://localhost:8080",
		"https_proxy=http://localhost:8080",
		"HTTP_PROXY=http://localhost:8080",
		"http_proxy=http://localhost:8080",
		"ALL_PROXY=socks5://localhost:1080",
		"all_proxy=socks5://localhost:1080",
		"NO_PROXY=localhost,127.0.0.1",
		"no_proxy=localhost,127.0.0.1",
		"SSL_CERT_FILE=/tmp/ca.pem",
		"ssl_cert_file=/tmp/ca.pem",
		"SSL_CERT_DIR=/etc/ssl/certs",
		"REQUESTS_CA_BUNDLE=/tmp/ca.pem",
		"NODE_EXTRA_CA_CERTS=/tmp/ca.pem",
		"CURL_CA_BUNDLE=/tmp/ca.pem",
		"curl_ca_bundle=/tmp/ca.pem",
		"OP_SERVICE_ACCOUNT_TOKEN=op_secret",
		"USER=test",
	}

	filtered := stripProxyEnv(env)

	disallowed := map[string]bool{
		"HTTPS_PROXY":         true,
		"HTTP_PROXY":          true,
		"ALL_PROXY":           true,
		"NO_PROXY":            true,
		"SSL_CERT_FILE":       true,
		"SSL_CERT_DIR":        true,
		"REQUESTS_CA_BUNDLE":  true,
		"NODE_EXTRA_CA_CERTS": true,
		"CURL_CA_BUNDLE":      true,
	}

	for _, e := range filtered {
		key := strings.ToUpper(strings.SplitN(e, "=", 2)[0])
		if disallowed[key] {
			t.Errorf("stripProxyEnv retained %s", e)
		}
	}

	expectedPreserved := map[string]string{
		"HOME":                     "/Users/test",
		"PATH":                     "/usr/bin:/bin",
		"OP_SERVICE_ACCOUNT_TOKEN": "op_secret",
		"USER":                     "test",
	}

	found := make(map[string]string)
	for _, e := range filtered {
		parts := strings.SplitN(e, "=", 2)
		found[parts[0]] = parts[1]
	}

	for k, wantVal := range expectedPreserved {
		if gotVal, ok := found[k]; !ok || gotVal != wantVal {
			t.Errorf("stripProxyEnv missing or incorrect for %s: got %q, want %q", k, gotVal, wantVal)
		}
	}
}

func TestOnePasswordBuildCmdSetsCleanEnv(t *testing.T) {
	p := NewOnePasswordProvider()
	ctx := context.Background()
	dirtyEnv := []string{
		"HOME=/Users/test",
		"HTTPS_PROXY=http://localhost:8080",
		"SSL_CERT_FILE=/tmp/ca.pem",
		"CURL_CA_BUNDLE=/tmp/ca.pem",
	}

	cmd := p.buildCmd(ctx, "/usr/bin/op", "op://vault/item/field", dirtyEnv)

	if cmd.Args[0] != "credproxy-op" {
		t.Errorf("cmd.Args[0] = %q, want credproxy-op", cmd.Args[0])
	}
	if len(cmd.Args) < 3 || cmd.Args[1] != "read" || cmd.Args[2] != "op://vault/item/field" {
		t.Errorf("cmd.Args = %v, want [credproxy-op read op://vault/item/field]", cmd.Args)
	}

	for _, e := range cmd.Env {
		key := strings.ToUpper(strings.SplitN(e, "=", 2)[0])
		if key == "HTTPS_PROXY" || key == "SSL_CERT_FILE" || key == "CURL_CA_BUNDLE" {
			t.Errorf("cmd.Env leaked %s", e)
		}
	}
	hasHome := false
	for _, e := range cmd.Env {
		if e == "HOME=/Users/test" {
			hasHome = true
			break
		}
	}
	if !hasHome {
		t.Error("cmd.Env missing HOME=/Users/test")
	}
}
