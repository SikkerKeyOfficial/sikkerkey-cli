// Package cache is the on-disk fallback secret cache — the reference
// implementation of the .skc format that the SikkerKey SDKs mirror byte-for-byte.
//
// It is strictly opt-in (see config.GlobalConfig.CacheEnabled) and inert when
// off: nothing here runs unless a caller explicitly constructs a *Cache, which
// only happens when caching is enabled or an --offline read is requested.
//
// # What it is for
//
// When the retrieval plane (machines.sikkerkey.com) is unreachable, a previously
// read secret can still be served from a local, encrypted copy so a workload
// survives a transient outage. It is a resilience cache, never an authority: it
// is consulted ONLY on genuine unreachability, never when the server returns an
// authoritative answer (a 401/403/404 propagates as an error — serving cache
// there would defeat revocation or resurrect a deleted secret).
//
// # Layout
//
// One file per secret at ~/.sikkerkey/vaults/{vaultId}/cache/{secretId}.skc,
// written atomically (temp file + rename). One file per secret means no
// read-modify-write races between processes and isolated corruption.
//
// # Cryptography
//
// The cache is encrypted to the machine's own identity, so a cache file copied
// off the box (a backup, a synced dir, an image layer) is useless without the
// Ed25519 private key. It is exactly as strong as that key — no more, no less.
//
//	key   = HKDF-SHA256(ikm = ed25519_seed, salt = vaultId, info = "sikkerkey-cache-v1")  → 32 bytes
//	entry = AES-256-GCM(key, nonce = random 12B, plaintext = {name,value,fieldNames} JSON,
//	                    aad = "sikkerkey-cache-v1\0{vaultId}\0{machineId}\0{secretId}\0{cachedAt}")
//
// The AAD binds each entry to its vault, machine, secret id, and timestamp, so an
// entry can't be forged, tampered, or swapped between secrets/vaults/machines
// without the key.
package cache

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/SikkerKeyOfficial/sikkerkey-cli/internal/config"
)

const (
	// formatVersion is the .skc envelope version. A reader that sees a version it
	// doesn't understand treats the entry as a miss rather than misparsing it.
	formatVersion = 1
	// kdfInfo is the HKDF info string AND the AAD domain-separation prefix. Bump
	// the suffix if the derivation or format ever changes incompatibly.
	kdfInfo = "sikkerkey-cache-v1"
	fileExt = ".skc"
)

// safeSecretID guards the on-disk filename against path traversal. Real secret
// ids are sk_<alnum>; anything outside this set is treated as non-cacheable.
var safeSecretID = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// Cache is a handle bound to one vault's cache directory and its derived key.
// Construct it only when caching is actually needed — New derives the key, which
// is the one bit of work that must not happen on the disabled read path.
type Cache struct {
	vaultID   string
	machineID string
	key       []byte // 32-byte AES-256 key derived from the Ed25519 seed
}

// New builds a cache handle, deriving the encryption key from the machine's
// Ed25519 seed. Callers gate this behind the enabled/offline check so a disabled
// read never derives a key or touches the filesystem.
func New(vaultID, machineID string, seed []byte) *Cache {
	return &Cache{
		vaultID:   vaultID,
		machineID: machineID,
		key:       deriveKey(seed, vaultID),
	}
}

// Result is a decrypted cache entry.
type Result struct {
	SecretID   string
	Name       string  // secret name (present when cached via export/run --all), else ""
	Value      string  // the secret value
	FieldNames *string // structured-secret field-name list, or nil
	CachedAt   time.Time
}

// payload is the sealed (encrypted) plaintext.
type payload struct {
	Name       string  `json:"name,omitempty"`
	Value      string  `json:"value"`
	FieldNames *string `json:"fieldNames,omitempty"`
}

// envelope is the cleartext .skc file wrapping the sealed payload. Only metadata
// needed to open the payload lives here; the value itself is inside the ciphertext.
type envelope struct {
	Version  int    `json:"v"`
	Nonce    string `json:"nonce"` // base64
	CT       string `json:"ct"`    // base64 ciphertext||tag
	CachedAt int64  `json:"cachedAt"`
}

// Store seals a secret to the cache, replacing any existing entry atomically.
// name/fieldNames are optional (a by-id get supplies only the value).
func (c *Cache) Store(secretID, name, value string, fieldNames *string) error {
	if !safeSecretID.MatchString(secretID) {
		return fmt.Errorf("refusing to cache unsafe secret id %q", secretID)
	}
	cachedAt := time.Now().Unix()
	pt, err := json.Marshal(payload{Name: name, Value: value, FieldNames: fieldNames})
	if err != nil {
		return err
	}
	nonce, ct, err := sealAESGCM(c.key, pt, c.aad(secretID, cachedAt))
	if err != nil {
		return err
	}
	env, err := json.Marshal(envelope{
		Version:  formatVersion,
		Nonce:    base64.StdEncoding.EncodeToString(nonce),
		CT:       base64.StdEncoding.EncodeToString(ct),
		CachedAt: cachedAt,
	})
	if err != nil {
		return err
	}
	return writeAtomic(c.filePath(secretID), env)
}

// Load returns the cached entry for a secret, or (nil, nil) on a miss (no file,
// unknown format, or unsafe id). A decrypt failure is a real error — it means the
// file was tampered with or belongs to a different identity.
func (c *Cache) Load(secretID string) (*Result, error) {
	if !safeSecretID.MatchString(secretID) {
		return nil, nil
	}
	data, err := os.ReadFile(c.filePath(secretID))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return c.decode(secretID, data)
}

// LoadAll returns every cached entry for the vault (used by offline export /
// run --all). Unreadable or foreign entries are skipped, not fatal.
func (c *Cache) LoadAll() ([]Result, error) {
	dir := config.CacheDir(c.vaultID)
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Result
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != fileExt {
			continue
		}
		secretID := e.Name()[:len(e.Name())-len(fileExt)]
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		res, err := c.decode(secretID, data)
		if err != nil || res == nil {
			continue // tampered / foreign / unknown format — skip, don't abort the export
		}
		out = append(out, *res)
	}
	return out, nil
}

func (c *Cache) decode(secretID string, data []byte) (*Result, error) {
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("corrupt cache entry for %s: %w", secretID, err)
	}
	if env.Version != formatVersion {
		return nil, nil // an SDK wrote a newer format; treat as a miss
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, fmt.Errorf("corrupt cache nonce for %s: %w", secretID, err)
	}
	ct, err := base64.StdEncoding.DecodeString(env.CT)
	if err != nil {
		return nil, fmt.Errorf("corrupt cache ciphertext for %s: %w", secretID, err)
	}
	pt, err := openAESGCM(c.key, nonce, ct, c.aad(secretID, env.CachedAt))
	if err != nil {
		return nil, fmt.Errorf("cache entry for %s failed to decrypt (wrong identity or tampered)", secretID)
	}
	var p payload
	if err := json.Unmarshal(pt, &p); err != nil {
		return nil, fmt.Errorf("corrupt cache payload for %s: %w", secretID, err)
	}
	return &Result{
		SecretID:   secretID,
		Name:       p.Name,
		Value:      p.Value,
		FieldNames: p.FieldNames,
		CachedAt:   time.Unix(env.CachedAt, 0),
	}, nil
}

func (c *Cache) filePath(secretID string) string {
	return filepath.Join(config.CacheDir(c.vaultID), secretID+fileExt)
}

// aad binds an entry to its context: domain || vault || machine || secret ||
// timestamp, null-separated (none of the tokens contain a null byte).
func (c *Cache) aad(secretID string, cachedAt int64) []byte {
	return []byte(kdfInfo + "\x00" + c.vaultID + "\x00" + c.machineID + "\x00" + secretID + "\x00" + strconv.FormatInt(cachedAt, 10))
}

// ── Package-level ops (no key needed) ──

// Clear removes the entire cache directory for a vault.
func Clear(vaultID string) error {
	err := os.RemoveAll(config.CacheDir(vaultID))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// Count returns how many secrets are currently cached for a vault.
func Count(vaultID string) (int, error) {
	entries, err := os.ReadDir(config.CacheDir(vaultID))
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == fileExt {
			n++
		}
	}
	return n, nil
}

// ── Crypto ──

func deriveKey(seed []byte, vaultID string) []byte {
	return hkdfSHA256(seed, []byte(vaultID), []byte(kdfInfo), 32)
}

func sealAESGCM(key, plaintext, aad []byte) (nonce, ct []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return nonce, gcm.Seal(nil, nonce, plaintext, aad), nil
}

func openAESGCM(key, nonce, ct, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("bad nonce length")
	}
	return gcm.Open(nil, nonce, ct, aad)
}

// hkdfSHA256 is RFC 5869 HKDF over HMAC-SHA256, hand-rolled to keep the CLI free
// of extra dependencies. The SDK ports use their platform's HKDF (identical output).
func hkdfSHA256(ikm, salt, info []byte, length int) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	// Extract
	ext := hmac.New(sha256.New, salt)
	ext.Write(ikm)
	prk := ext.Sum(nil)
	// Expand
	var out, t []byte
	for i := byte(1); len(out) < length; i++ {
		exp := hmac.New(sha256.New, prk)
		exp.Write(t)
		exp.Write(info)
		exp.Write([]byte{i})
		t = exp.Sum(nil)
		out = append(out, t...)
	}
	return out[:length]
}

// writeAtomic writes data to path via a temp file + rename, so a reader never
// sees a half-written entry and concurrent writers never corrupt each other.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".skc-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once renamed
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
