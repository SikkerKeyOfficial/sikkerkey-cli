// Package sshcert generates the subject keypair for a certificate request and
// installs the signed result where ssh will find it.
//
// The keypair is generated here, per request, and the private half never leaves
// this process except into the local ssh-agent. SikkerKey signs a public key it
// is handed; it never sees or issues a private key.
package sshcert

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Subject is a freshly generated keypair awaiting a certificate.
type Subject struct {
	priv ed25519.PrivateKey
	// PublicKeyLine is the "ssh-ed25519 AAAA..." line sent to SikkerKey.
	PublicKeyLine string
}

// NewSubject generates the keypair whose public half gets signed.
func NewSubject() (*Subject, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("encode public key: %w", err)
	}
	return &Subject{
		priv:          priv,
		PublicKeyLine: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))),
	}, nil
}

// Installed reports where the certificate ended up, so the caller can tell the
// user what to run.
type Installed struct {
	// InAgent is true when ssh will find the certificate without any argument.
	InAgent bool
	// KeyPath is set only when the certificate was written to disk instead.
	KeyPath string
}

// Install parses the signed certificate and loads it into the local ssh-agent,
// falling back to files when no agent is reachable.
//
// The agent is the path that makes a bare `ssh user@host` work: ssh offers keys
// from the agent or from its own default identity filenames, and nothing else.
// A certificate written to a path of ours would be ignored without an -i flag.
func Install(s *Subject, certificateLine string, comment string) (*Installed, error) {
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certificateLine))
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("expected a certificate, got %s", parsed.Type())
	}

	if err := addToAgent(s.priv, cert, comment); err == nil {
		return &Installed{InAgent: true}, nil
	}

	keyPath, err := writeFiles(s.priv, certificateLine, comment)
	if err != nil {
		return nil, err
	}
	return &Installed{KeyPath: keyPath}, nil
}

// addToAgent loads the key and its certificate, expiring them together.
//
// LifetimeSecs is the certificate's own remaining validity, so the agent drops
// the key at the moment the certificate stops being accepted. Without it a dead
// key lingers in the agent and ssh keeps offering it.
func addToAgent(priv ed25519.PrivateKey, cert *ssh.Certificate, comment string) error {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return fmt.Errorf("no ssh-agent")
	}
	// Windows exposes the agent as a named pipe, which net.Dial cannot reach.
	if runtime.GOOS == "windows" {
		return fmt.Errorf("agent unsupported on windows")
	}

	conn, err := net.Dial("unix", sock)
	if err != nil {
		return err
	}
	defer conn.Close()

	remaining := int64(cert.ValidBefore) - time.Now().Unix()
	if remaining <= 0 {
		return fmt.Errorf("certificate already expired")
	}

	return agent.NewClient(conn).Add(agent.AddedKey{
		PrivateKey:   priv,
		Certificate:  cert,
		Comment:      comment,
		LifetimeSecs: uint32(remaining),
	})
}

// writeFiles is the no-agent path: an OpenSSH private key and its certificate,
// named so ssh pairs them when pointed at the key with -i.
func writeFiles(priv ed25519.PrivateKey, certificateLine, comment string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home directory: %w", err)
	}
	dir := filepath.Join(home, ".sikkerkey", "certificates")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create %s: %w", dir, err)
	}

	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return "", fmt.Errorf("encode private key: %w", err)
	}

	keyPath := filepath.Join(dir, comment)
	// Written 0600 before any content reaches it; ssh refuses a key that is
	// readable by anyone else, so a wider mode would fail at use time anyway.
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600); err != nil {
		return "", fmt.Errorf("write %s: %w", keyPath, err)
	}
	// ssh looks for <key>-cert.pub beside the key it was given.
	if err := os.WriteFile(keyPath+"-cert.pub", []byte(certificateLine+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("write certificate: %w", err)
	}
	return keyPath, nil
}
