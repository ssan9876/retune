// Package opsign signs and checks what an operations key vouches for: the
// scripts an agent runs and the wipes it obeys. It uses the same Ed25519 keys
// as release signing, under a separate trust list, so an organisation can
// require that code reaching its machines was approved offline, where a
// compromised server or admin account can't reach the key.
package opsign

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"retune/internal/release"
)

var (
	// ErrUnsigned is returned when a signature is required and missing.
	ErrUnsigned = errors.New("this is not signed by an operations key")
	// ErrBadSignature is returned for a signature that doesn't match.
	ErrBadSignature = errors.New("the operations signature doesn't match")
	// ErrUntrustedKey is returned for a signature by a key not trusted.
	ErrUntrustedKey = errors.New("signed by a key that isn't a trusted operations key")
	// ErrExpired is returned for a signed order past its expiry.
	ErrExpired = errors.New("the signed order has expired")
	// ErrNoKeys is returned when enforcement is on but no key can be
	// trusted: a malformed trust list refuses everything rather than
	// nothing.
	ErrNoKeys = errors.New("no operations key is trusted, so nothing signed can be accepted")
)

// MaxWipeValidity is the longest a signed wipe order may stay valid.
const MaxWipeValidity = 24 * time.Hour

// Signature is what travels with a signed script or order.
type Signature struct {
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"` // base64
}

// ScriptManifest is the exact text signed for a script: the hashes of its
// body and of its detection script, if any. It isn't bound to a device or a
// command: approved code is approved wherever it runs, and timeouts or
// schedules can't turn it into different code.
//
// Line endings are hashed as LF: a .ps1 saved with CRLF and signed as a file
// must match the same script pasted into a browser, which sends LF.
func ScriptManifest(body, detection string) []byte {
	h := func(s string) string {
		if s == "" {
			return ""
		}
		sum := sha256.Sum256([]byte(strings.ReplaceAll(s, "\r\n", "\n")))
		return hex.EncodeToString(sum[:])
	}
	return []byte("retune-script-manifest/v1\nbody=" + h(body) + "\ndetection=" + h(detection) + "\n")
}

// WipeManifest is the exact text signed for a wipe order: one device, whether
// the wipe is protected, and when the order lapses.
func WipeManifest(deviceID string, protected bool, expires time.Time) []byte {
	return []byte("retune-command-manifest/v1\ntype=wipe\ndevice=" + strings.ToLower(deviceID) +
		"\nprotected=" + strconv.FormatBool(protected) +
		"\nexpires=" + expires.UTC().Format(time.RFC3339) + "\n")
}

// Sign signs manifest with priv.
func Sign(priv release.PrivateKey, manifest []byte) Signature {
	return Signature{
		KeyID:     priv.Public().ID(),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv.Raw, manifest)),
	}
}

// Verify checks sig over manifest against the trusted keys.
func Verify(trusted []release.PublicKey, manifest []byte, sig *Signature) error {
	if len(trusted) == 0 {
		return ErrNoKeys
	}
	if sig == nil || sig.Signature == "" {
		return ErrUnsigned
	}
	raw, err := base64.StdEncoding.DecodeString(sig.Signature)
	if err != nil {
		return fmt.Errorf("%w: not base64", ErrBadSignature)
	}
	for _, k := range trusted {
		if k.ID() != sig.KeyID {
			continue
		}
		if ed25519.Verify(k.Raw, manifest, raw) {
			return nil
		}
		return ErrBadSignature
	}
	return fmt.Errorf("%w (key %s)", ErrUntrustedKey, sig.KeyID)
}

// VerifyWipe checks a wipe order for deviceID at now.
func VerifyWipe(trusted []release.PublicKey, deviceID string, protected bool, expires, now time.Time, sig *Signature) error {
	if expires.IsZero() {
		return ErrUnsigned
	}
	if err := Verify(trusted, WipeManifest(deviceID, protected, expires), sig); err != nil {
		return err
	}
	if !now.Before(expires) {
		return ErrExpired
	}
	return nil
}

// Policy is what an agent was built to require. Enforced with no keys, the
// result of a trust list that didn't parse, refuses everything.
type Policy struct {
	Enforced bool
	Keys     []release.PublicKey
}

// ParsePolicy reads a stamped trust list: empty means not enforced; anything
// else is enforced, with whatever keys parsed — none, if the list is
// malformed, so a typo in the build can't quietly turn enforcement off.
func ParsePolicy(raw string) Policy {
	if strings.TrimSpace(raw) == "" {
		return Policy{}
	}
	keys, err := release.ParseTrustList(raw)
	if err != nil {
		return Policy{Enforced: true}
	}
	return Policy{Enforced: true, Keys: keys}
}
