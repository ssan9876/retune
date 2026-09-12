// Package pki holds certificate helpers shared by server and agent.
package pki

import (
	"crypto/sha256"
	"encoding/hex"
)

// Fingerprint returns "sha256:<hex>" of a DER-encoded certificate.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:])
}
