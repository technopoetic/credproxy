package ca

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteTrustBundleContainsCAAndPublicRoots(t *testing.T) {
	dir := t.TempDir()

	p, err := LoadOrGenerate(dir)
	if err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}

	bundlePath, err := p.WriteTrustBundle(dir)
	if err != nil {
		t.Fatalf("WriteTrustBundle: %v", err)
	}
	if bundlePath != filepath.Join(dir, "trust-bundle.pem") {
		t.Fatalf("unexpected bundle path: %s", bundlePath)
	}

	bundlePEM, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("reading bundle: %v", err)
	}

	// First block must be credproxy's own CA cert (so tools that only trust
	// this bundle can still validate credproxy's MITM'd leaf certs).
	block, rest := pem.Decode(bundlePEM)
	if block == nil {
		t.Fatal("no PEM block found at start of bundle")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing leading cert: %v", err)
	}
	if caCert.Subject.CommonName != "credproxy CA" {
		t.Fatalf("expected credproxy CA as first cert, got %q", caCert.Subject.CommonName)
	}

	// The rest of the file should hold multiple public root certs.
	rootCount := 0
	for {
		var next *pem.Block
		next, rest = pem.Decode(rest)
		if next == nil {
			break
		}
		if _, err := x509.ParseCertificate(next.Bytes); err != nil {
			t.Fatalf("parsing bundled root cert %d: %v", rootCount, err)
		}
		rootCount++
	}
	if rootCount < 50 {
		t.Fatalf("expected the vendored public root bundle to be concatenated, got %d certs", rootCount)
	}
}

func TestWriteTrustBundleDoesNotBreakSubsequentLoad(t *testing.T) {
	dir := t.TempDir()

	p, err := LoadOrGenerate(dir)
	if err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}
	if _, err := p.WriteTrustBundle(dir); err != nil {
		t.Fatalf("WriteTrustBundle: %v", err)
	}

	// ca.pem itself must remain untouched by the bundle write, and a fresh
	// LoadOrGenerate against the same dir must still succeed (this is the
	// path every `credproxy <cmd>` invocation takes on startup).
	reloaded, err := LoadOrGenerate(dir)
	if err != nil {
		t.Fatalf("LoadOrGenerate after WriteTrustBundle: %v", err)
	}
	if reloaded.cert.SerialNumber.Cmp(p.cert.SerialNumber) != 0 {
		t.Fatal("reloaded CA cert differs from the original — ca.pem was mutated")
	}
}
