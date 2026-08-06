package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// mozillaRoots is a vendored snapshot of the public CA root bundle (sourced
// from certifi/Mozilla). It has no bearing on credproxy's own CA identity —
// see WriteTrustBundle for why it's concatenated onto the CA cert rather than
// mixed into ca.pem itself.
//
//go:embed mozilla-bundle.pem
var mozillaRoots []byte

type Provider struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
	mu      sync.Mutex
	serial  int64
}

func LoadOrGenerate(dir string) (*Provider, error) {
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")

	certPEM, err := os.ReadFile(certPath)
	if err == nil {
		keyPEM, err := os.ReadFile(keyPath)
		if err == nil {
			return loadFromPEM(certPEM, keyPEM)
		}
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create ca dir: %w", err)
	}

	p, err := generate()
	if err != nil {
		return nil, err
	}

	if err := os.WriteFile(certPath, p.certPEM, 0644); err != nil {
		return nil, fmt.Errorf("write ca cert: %w", err)
	}
	if err := os.WriteFile(keyPath, encodeKey(p.key), 0600); err != nil {
		return nil, fmt.Errorf("write ca key: %w", err)
	}

	return p, nil
}

func (p *Provider) RootPEM() []byte {
	return p.certPEM
}

// WriteTrustBundle writes credproxy's CA cert followed by a vendored public
// root bundle to trust-bundle.pem in dir, and returns its path.
//
// Child processes get SSL_CERT_FILE/REQUESTS_CA_BUNDLE/CURL_CA_BUNDLE pointed
// at this file rather than at ca.pem directly. ca.pem holds only credproxy's
// own CA (needed to trust MITM'd leaf certs on configured hosts); tools that
// treat these env vars as a full replacement trust store — not a merge with
// their own default bundle — would otherwise fail TLS verification on every
// unconfigured host, since credproxy tunnels those through untouched with
// their real upstream certificate (see README: "Unconfigured hosts are
// tunneled through without interception"). Bundling the public roots here
// means both cases validate. This file is a derived artifact recomputed on
// every run (unlike ca.pem/ca-key.pem, which are generated once and kept
// stable), so it always reflects the current CA even if regenerated.
func (p *Provider) WriteTrustBundle(dir string) (string, error) {
	bundlePath := filepath.Join(dir, "trust-bundle.pem")

	var buf []byte
	buf = append(buf, p.certPEM...)
	if len(buf) > 0 && buf[len(buf)-1] != '\n' {
		buf = append(buf, '\n')
	}
	buf = append(buf, mozillaRoots...)

	if err := os.WriteFile(bundlePath, buf, 0644); err != nil {
		return "", fmt.Errorf("write trust bundle: %w", err)
	}

	return bundlePath, nil
}

func (p *Provider) MintLeaf(host string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	p.mu.Lock()
	p.serial++
	serial := p.serial
	p.mu.Unlock()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate leaf key: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{host},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, p.cert, &key.PublicKey, p.key)
	if err != nil {
		return nil, nil, fmt.Errorf("create leaf cert: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse leaf cert: %w", err)
	}

	return cert, key, nil
}

func generate() (*Provider, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ca key: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "credproxy CA"},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create ca cert: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse ca cert: %w", err)
	}

	return &Provider{
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
	}, nil
}

func loadFromPEM(certPEM, keyPEM []byte) (*Provider, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("decode ca cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("decode ca key PEM")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca key: %w", err)
	}

	return &Provider{
		cert:    cert,
		key:     key,
		certPEM: certPEM,
	}, nil
}

func encodeKey(key *ecdsa.PrivateKey) []byte {
	b, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
}
