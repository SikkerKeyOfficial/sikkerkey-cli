// Package auth handles Ed25519 request signing for machine authentication.
//
// Every request to the SikkerKey API is signed with the machine's private key.
// The server verifies the signature using the stored public key. This proves
// the request was created by this specific machine without transmitting any
// shared secret.
package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Signer holds a loaded Ed25519 private key and produces signed request headers.
type Signer struct {
	key       ed25519.PrivateKey
	machineID string
}

// NewSigner loads the private key from disk and returns a Signer.
func NewSigner(keyPath string, machineID string) (*Signer, error) {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", keyPath)
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not Ed25519")
	}

	return &Signer{key: key, machineID: machineID}, nil
}

// Seed returns the 32-byte Ed25519 seed — the input keying material the
// fallback cache derives its encryption key from. It stays within the process
// and is never transmitted; the cache binds itself to this identity so a cache
// file copied off the machine is useless without this key.
func (s *Signer) Seed() []byte {
	return s.key.Seed()
}

// Headers returns the authentication headers for a request.
// The caller must set these on the HTTP request before sending.
func (s *Signer) Headers(method, path string, body []byte) map[string]string {
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	nonce := base64.StdEncoding.EncodeToString(nonceBytes)

	bodyHash := sha256hex(body)

	// Signed payload: method:path:timestamp:nonce:bodyHash
	payload := fmt.Sprintf("%s:%s:%s:%s:%s", method, path, timestamp, nonce, bodyHash)
	sig := ed25519.Sign(s.key, []byte(payload))

	return map[string]string{
		"X-Machine-Id": s.machineID,
		"X-Timestamp":  timestamp,
		"X-Nonce":      nonce,
		"X-Signature":  base64.StdEncoding.EncodeToString(sig),
	}
}

func sha256hex(data []byte) string {
	h := sha256.Sum256(data)
	hex := make([]byte, 64)
	for i, b := range h {
		hex[i*2] = "0123456789abcdef"[b>>4]
		hex[i*2+1] = "0123456789abcdef"[b&0x0f]
	}
	return string(hex)
}
