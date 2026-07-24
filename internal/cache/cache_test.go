package cache

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/SikkerKeyOfficial/sikkerkey-cli/internal/config"
)

// seed returns a deterministic 32-byte Ed25519 seed for tests.
func seed(b byte) []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = b
	}
	return s
}

func TestStoreLoadRoundTrip(t *testing.T) {
	t.Setenv("SIKKERKEY_HOME", t.TempDir())
	c := New("vault_test", "m_test", seed(1))

	value := `{"host":"db","pass":"x"}`
	fieldNames := "host,pass"
	if err := c.Store("sk_abc", "DB Creds", value, &fieldNames); err != nil {
		t.Fatalf("store: %v", err)
	}

	res, err := c.Load("sk_abc")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if res == nil {
		t.Fatal("expected a hit, got a miss")
	}
	if res.Value != value {
		t.Fatalf("value = %q, want %q", res.Value, value)
	}
	if res.Name != "DB Creds" {
		t.Fatalf("name = %q, want %q", res.Name, "DB Creds")
	}
	if res.FieldNames == nil || *res.FieldNames != fieldNames {
		t.Fatalf("fieldNames = %v, want %q", res.FieldNames, fieldNames)
	}
}

func TestLoadMissReturnsNil(t *testing.T) {
	t.Setenv("SIKKERKEY_HOME", t.TempDir())
	c := New("vault_test", "m_test", seed(1))
	res, err := c.Load("sk_missing")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if res != nil {
		t.Fatal("expected a miss (nil), got a value")
	}
}

// A cache file is bound to the identity that wrote it: a different private key
// (seed) derives a different AES key and must not be able to open the entry.
func TestWrongIdentityRejected(t *testing.T) {
	t.Setenv("SIKKERKEY_HOME", t.TempDir())
	if err := New("vault_test", "m_test", seed(1)).Store("sk_abc", "", "secret-value", nil); err != nil {
		t.Fatalf("store: %v", err)
	}
	if _, err := New("vault_test", "m_test", seed(2)).Load("sk_abc"); err == nil {
		t.Fatal("expected decrypt failure with a different identity, got success")
	}
}

// Editing the cleartext cachedAt breaks the AAD binding, so the AEAD open must
// fail — proving the timestamp is authenticated, not just stored.
func TestTamperedTimestampRejected(t *testing.T) {
	t.Setenv("SIKKERKEY_HOME", t.TempDir())
	c := New("vault_test", "m_test", seed(1))
	if err := c.Store("sk_abc", "", "secret-value", nil); err != nil {
		t.Fatalf("store: %v", err)
	}

	p := filepath.Join(config.CacheDir("vault_test"), "sk_abc"+fileExt)
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	env.CachedAt++ // break the AAD binding without touching the ciphertext
	tampered, _ := json.Marshal(env)
	if err := os.WriteFile(p, tampered, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if _, err := c.Load("sk_abc"); err == nil {
		t.Fatal("expected tampered timestamp to be rejected, got success")
	}
}

// Flipping a ciphertext byte must be caught by the GCM tag.
func TestTamperedCiphertextRejected(t *testing.T) {
	t.Setenv("SIKKERKEY_HOME", t.TempDir())
	c := New("vault_test", "m_test", seed(1))
	if err := c.Store("sk_abc", "", "secret-value", nil); err != nil {
		t.Fatalf("store: %v", err)
	}

	p := filepath.Join(config.CacheDir("vault_test"), "sk_abc"+fileExt)
	data, _ := os.ReadFile(p)
	var env envelope
	json.Unmarshal(data, &env)
	// Flip a bit in the last base64 char of the ciphertext.
	b := []byte(env.CT)
	b[len(b)-1] ^= 0x01
	env.CT = string(b)
	tampered, _ := json.Marshal(env)
	os.WriteFile(p, tampered, 0600)

	if _, err := c.Load("sk_abc"); err == nil {
		t.Fatal("expected tampered ciphertext to be rejected, got success")
	}
}

func TestLoadAllClearAndCount(t *testing.T) {
	t.Setenv("SIKKERKEY_HOME", t.TempDir())
	c := New("vault_test", "m_test", seed(1))
	if err := c.Store("sk_a", "A", "1", nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Store("sk_b", "B", "2", nil); err != nil {
		t.Fatal(err)
	}

	n, err := Count("vault_test")
	if err != nil || n != 2 {
		t.Fatalf("count = %d (err %v), want 2", n, err)
	}

	all, err := c.LoadAll()
	if err != nil {
		t.Fatalf("loadAll: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("loadAll returned %d entries, want 2", len(all))
	}

	if err := Clear("vault_test"); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if n, _ := Count("vault_test"); n != 0 {
		t.Fatalf("after clear count = %d, want 0", n)
	}
}

// Path-traversal guard: an unsafe id is never written and never read.
func TestUnsafeSecretIDRefused(t *testing.T) {
	t.Setenv("SIKKERKEY_HOME", t.TempDir())
	c := New("vault_test", "m_test", seed(1))
	if err := c.Store("../escape", "", "x", nil); err == nil {
		t.Fatal("expected store of an unsafe id to be refused")
	}
	res, err := c.Load("../escape")
	if err != nil || res != nil {
		t.Fatalf("unsafe load = (%v, %v), want (nil, nil)", res, err)
	}
}
