// Package auth authenticates administrators and manages their sessions.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// ErrWeakPassword marks a password the policy rejects.
var ErrWeakPassword = errors.New("password does not meet the policy")

// Password policy and Argon2id parameters.
const (
	MinPasswordLength = 12
	maxPasswordLength = 1024

	argonMemory  = 64 * 1024 // KiB
	argonTime    = 3
	argonLanes   = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

// HashPassword returns an encoded Argon2id hash.
func HashPassword(password string) (string, error) {
	switch {
	case len(password) < MinPasswordLength:
		return "", fmt.Errorf("%w: at least %d characters are required", ErrWeakPassword, MinPasswordLength)
	case len(password) > maxPasswordLength:
		return "", fmt.Errorf("%w: at most %d characters are allowed", ErrWeakPassword, maxPasswordLength)
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonLanes, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonLanes,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword reports whether password matches the encoded hash. A
// malformed hash simply fails.
func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version, memory, iterations, lanes int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &lanes); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, uint32(iterations), uint32(memory), uint8(lanes), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// GeneratePassword returns a random password that satisfies the policy.
func GeneratePassword() (string, error) {
	b := make([]byte, 15)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
