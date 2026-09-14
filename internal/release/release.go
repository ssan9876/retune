// Package release signs agent builds and verifies those signatures. A build is
// signed once, offline, by whoever cuts the release; the server checks the
// signature when the build is uploaded and every agent checks it again after
// downloading. The key never touches the server, so an admin account -- or
// the server itself -- cannot produce code the fleet will run.
package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrNoTrustedKeys means the verifier was given nothing to trust.
	ErrNoTrustedKeys = errors.New("no trusted release keys")
	// ErrUntrustedKey means the signature names a key that is not trusted.
	ErrUntrustedKey = errors.New("signature is from a key that is not trusted")
	// ErrManifestMismatch means the signature was made over a different
	// version or different bytes than the ones being verified.
	ErrManifestMismatch = errors.New("signature is for a different version or different bytes")
	// ErrBadSignature means the bytes did not verify under the named key.
	ErrBadSignature = errors.New("signature did not verify")
)

// PublicKey is one trusted release key.
type PublicKey struct {
	Raw ed25519.PublicKey
}

// ID is the first eight bytes of the SHA-256 of the raw key, in hex. It lets a
// verifier pick a key out of a list; it carries no security weight of its own.
func (k PublicKey) ID() string {
	sum := sha256.Sum256(k.Raw)
	return hex.EncodeToString(sum[:8])
}

// Encode is the form a key takes in configuration and build flags.
func (k PublicKey) Encode() string { return base64.StdEncoding.EncodeToString(k.Raw) }

// PrivateKey signs builds. It is never stored by the server.
type PrivateKey struct {
	Raw ed25519.PrivateKey
}

// Public derives the matching public key.
func (k PrivateKey) Public() PublicKey {
	return PublicKey{Raw: k.Raw.Public().(ed25519.PublicKey)}
}

// Encode is the base64 of the 32-byte seed, which is all ed25519 needs to
// reconstruct the whole key.
func (k PrivateKey) Encode() string { return base64.StdEncoding.EncodeToString(k.Raw.Seed()) }

// GenerateKey makes a new release key from the system's randomness.
func GenerateKey() (PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return PrivateKey{}, err
	}
	return PrivateKey{Raw: priv}, nil
}

// DecodePrivateKey reads a key written by Encode.
func DecodePrivateKey(s string) (PrivateKey, error) {
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return PrivateKey{}, fmt.Errorf("release key is not base64: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return PrivateKey{}, fmt.Errorf("release key seed is %d bytes, want %d", len(seed), ed25519.SeedSize)
	}
	return PrivateKey{Raw: ed25519.NewKeyFromSeed(seed)}, nil
}

// DecodePublicKey reads a key written by PublicKey.Encode.
func DecodePublicKey(s string) (PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return PublicKey{}, fmt.Errorf("public key is not base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return PublicKey{}, fmt.Errorf("public key is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return PublicKey{Raw: ed25519.PublicKey(raw)}, nil
}

// ParseTrustList reads a comma-separated list of encoded public keys. An empty
// string is an empty list. One unparseable entry fails the whole list: a
// verifier that silently trusts fewer keys than it was told to is a
// misconfiguration nobody would notice until a signed build was refused.
func ParseTrustList(s string) ([]PublicKey, error) {
	var keys []PublicKey
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, err := DecodePublicKey(part)
		if err != nil {
			return nil, fmt.Errorf("trust list entry %q: %w", part, err)
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// EncodeTrustList is the inverse of ParseTrustList.
func EncodeTrustList(keys []PublicKey) string {
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k.Encode())
	}
	return strings.Join(parts, ",")
}

// Manifest is what gets signed: the version a build claims and the hash of
// its bytes, bound together. Signing the bytes alone would leave the version
// an unsigned claim, and a version that does not match the stamp inside the
// binary rolls back on every device it reaches.
type Manifest struct {
	Version string
	SHA256  string
}

// Bytes is the exact form signed. It is fixed text rather than JSON so there is
// no canonicalisation for two implementations to disagree on.
func (m Manifest) Bytes() []byte {
	return []byte("retune-agent-manifest/v1\nversion=" + m.Version + "\nsha256=" + strings.ToLower(m.SHA256) + "\n")
}

// Signature is a signed manifest: what travels beside a build.
type Signature struct {
	Version   string
	SHA256    string
	KeyID     string
	Signature []byte
}

// Sign produces the signature for m under priv.
func Sign(priv PrivateKey, m Manifest) Signature {
	return Signature{
		Version: m.Version, SHA256: strings.ToLower(m.SHA256), KeyID: priv.Public().ID(),
		Signature: ed25519.Sign(priv.Raw, m.Bytes()),
	}
}

// Verify checks sig against m under the trusted keys. The manifest the caller
// computed is compared to the one the signature carries before anything
// cryptographic happens, so the error names the actual disagreement.
func Verify(trusted []PublicKey, m Manifest, sig Signature) error {
	if len(trusted) == 0 {
		return ErrNoTrustedKeys
	}
	if sig.Version != m.Version || !strings.EqualFold(sig.SHA256, m.SHA256) {
		return ErrManifestMismatch
	}
	for _, k := range trusted {
		if k.ID() != sig.KeyID {
			continue
		}
		if ed25519.Verify(k.Raw, m.Bytes(), sig.Signature) {
			return nil
		}
		return ErrBadSignature
	}
	return fmt.Errorf("%w (key %s)", ErrUntrustedKey, sig.KeyID)
}
