// Package enroll implements enrollment tokens and device enrollment.
package enroll

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"retune/internal/server/store"
)

var (
	ErrTokenNotFound  = errors.New("enrollment token not found")
	ErrTokenRevoked   = errors.New("enrollment token has been revoked")
	ErrTokenExpired   = errors.New("enrollment token has expired")
	ErrTokenExhausted = errors.New("enrollment token has no uses left")
)

const tokenPrefix = "rt_"

// GenerateToken returns a new random token and its storage hash.
func GenerateToken() (plain string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	plain = tokenPrefix + base64.RawURLEncoding.EncodeToString(b)
	return plain, HashToken(plain), nil
}

// HashToken is the value stored in enrollment_tokens.token_hash.
func HashToken(plain string) []byte {
	sum := sha256.Sum256([]byte(strings.TrimSpace(plain)))
	return sum[:]
}

// CheckUsable reports why a token cannot be used right now, or nil.
func CheckUsable(t store.EnrollmentToken, now time.Time) error {
	switch {
	case t.RevokedAt != nil:
		return ErrTokenRevoked
	case t.ExpiresAt != nil && !now.Before(*t.ExpiresAt):
		return ErrTokenExpired
	case t.MaxUses != nil && t.UseCount >= *t.MaxUses:
		return ErrTokenExhausted
	}
	return nil
}
