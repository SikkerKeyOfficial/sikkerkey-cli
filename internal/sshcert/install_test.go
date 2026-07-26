package sshcert

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// signForSubject issues a certificate over the subject's public key, standing in
// for what the server does, so the install path is exercised against a real
// OpenSSH certificate rather than a fixture.
func signForSubject(t *testing.T, s *Subject, validFor time.Duration) string {
	t.Helper()

	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatalf("CA signer: %v", err)
	}

	subjectPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s.PublicKeyLine))
	if err != nil {
		t.Fatalf("parse subject key: %v", err)
	}

	cert := &ssh.Certificate{
		Key:             subjectPub,
		Serial:          1,
		CertType:        ssh.UserCert,
		KeyId:           "sikkerkey:sk_test:tester",
		ValidPrincipals: []string{"deploy"},
		ValidAfter:      uint64(time.Now().Add(-time.Minute).Unix()),
		ValidBefore:     uint64(time.Now().Add(validFor).Unix()),
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatalf("sign cert: %v", err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert)))
}

func TestNewSubjectProducesAnSshPublicKeyLine(t *testing.T) {
	s, err := NewSubject()
	if err != nil {
		t.Fatalf("NewSubject: %v", err)
	}
	if !strings.HasPrefix(s.PublicKeyLine, "ssh-ed25519 ") {
		t.Fatalf("public key line = %q, want an ssh-ed25519 line", s.PublicKeyLine)
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s.PublicKeyLine)); err != nil {
		t.Fatalf("own public key line does not parse: %v", err)
	}
}

// With no agent reachable, Install must leave a usable key + certificate pair on
// disk rather than reporting success with nothing written.
func TestInstallFallsBackToFilesWithoutAnAgent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // os.UserHomeDir on Windows
	t.Setenv("SSH_AUTH_SOCK", "")

	s, err := NewSubject()
	if err != nil {
		t.Fatalf("NewSubject: %v", err)
	}
	line := signForSubject(t, s, time.Hour)

	got, err := Install(s, line, "sikkerkey-sk_test")
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if got.InAgent {
		t.Fatal("reported an agent install with SSH_AUTH_SOCK unset")
	}

	want := filepath.Join(home, ".sikkerkey", "certificates", "sikkerkey-sk_test")
	if got.KeyPath != want {
		t.Fatalf("KeyPath = %q, want %q", got.KeyPath, want)
	}

	info, err := os.Stat(got.KeyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	// ssh refuses a private key any other user can read.
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key mode = %o, want 600", perm)
	}

	keyPem, err := os.ReadFile(got.KeyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if _, err := ssh.ParsePrivateKey(keyPem); err != nil {
		t.Fatalf("written private key does not parse: %v", err)
	}

	certPem, err := os.ReadFile(got.KeyPath + "-cert.pub")
	if err != nil {
		t.Fatalf("read certificate: %v", err)
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey(certPem)
	if err != nil {
		t.Fatalf("written certificate does not parse: %v", err)
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok {
		t.Fatalf("written file is %s, not a certificate", parsed.Type())
	}
	if cert.ValidPrincipals[0] != "deploy" {
		t.Fatalf("principal = %v, want deploy", cert.ValidPrincipals)
	}
}

// A plain public key where a certificate is expected must be refused, not
// written out as if it were one.
func TestInstallRejectsANonCertificate(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SSH_AUTH_SOCK", "")

	s, err := NewSubject()
	if err != nil {
		t.Fatalf("NewSubject: %v", err)
	}
	if _, err := Install(s, s.PublicKeyLine, "sikkerkey-sk_test"); err == nil {
		t.Fatal("accepted a plain public key as a certificate")
	}
}
