// Package x509cert generates the subject keypair for an X.509 certificate request
// and writes the signed result where a TLS client can load it.
//
// The keypair is generated here, per request, and the private half never leaves
// this process except to disk on the requesting machine. SikkerKey signs a public
// key it is handed; it never sees or issues a private key.
package x509cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// Subject is a freshly generated P-256 keypair awaiting a certificate.
type Subject struct {
	priv *ecdsa.PrivateKey
	// PublicKey is the SubjectPublicKeyInfo as base64-encoded DER — a single line,
	// because a signed route carries it in an HTTP header, which cannot hold the
	// newlines a PEM block has. The server base64-decodes and parses it.
	PublicKey string
}

// NewSubject generates the P-256 keypair whose public half gets signed. P-256 is
// the algorithm the SikkerKey CA signs and the one TLS stacks accept broadly.
func NewSubject() (*Subject, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("encode public key: %w", err)
	}
	return &Subject{priv: priv, PublicKey: base64.StdEncoding.EncodeToString(spki)}, nil
}

// Installed reports where the certificate material was written, so the caller can
// tell the user what to point their TLS client at.
type Installed struct {
	CertPath string
	KeyPath  string
	// ChainPath is empty when the server returned no issuing CA certificate.
	ChainPath string
}

// Install writes the leaf certificate, its private key, and the issuing CA chain
// as PEM files under ~/.sikkerkey/certificates/. certPEM is the signed leaf;
// chainPEM is the issuing CA certificate and may be empty.
//
// Unlike the SSH path there is no agent to load into: a TLS client is pointed at
// files, so files are the whole delivery.
func Install(s *Subject, certPEM, chainPEM, name string) (*Installed, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("locate home directory: %w", err)
	}
	dir := filepath.Join(home, ".sikkerkey", "certificates")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create %s: %w", dir, err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(s.priv)
	if err != nil {
		return nil, fmt.Errorf("encode private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	certPath := filepath.Join(dir, name+".crt")
	keyPath := filepath.Join(dir, name+".key")
	chainPath := filepath.Join(dir, name+".chain.pem")

	// The key is written 0600 from creation: a TLS library refuses a world-readable
	// key, so a wider mode would only fail at use time.
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write %s: %w", keyPath, err)
	}
	if err := os.WriteFile(certPath, []byte(withNewline(certPEM)), 0o644); err != nil {
		return nil, fmt.Errorf("write %s: %w", certPath, err)
	}
	installed := &Installed{CertPath: certPath, KeyPath: keyPath}
	if chainPEM != "" {
		if err := os.WriteFile(chainPath, []byte(withNewline(chainPEM)), 0o644); err != nil {
			return nil, fmt.Errorf("write %s: %w", chainPath, err)
		}
		installed.ChainPath = chainPath
	}
	return installed, nil
}

func withNewline(s string) string {
	if s == "" || s[len(s)-1] == '\n' {
		return s
	}
	return s + "\n"
}
