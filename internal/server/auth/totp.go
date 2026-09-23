package auth

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"retune/internal/server/secrets"
)

// totpPeriod is the length of one TOTP time step, in seconds.
const totpPeriod = 30

// NewTOTPSecret creates an authenticator secret and its otpauth:// URL.
func NewTOTPSecret(issuer, accountName string) (string, string, error) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: issuer, AccountName: accountName})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

// ValidateTOTP reports whether code is currently valid for secret. It allows
// the usual one-step clock skew on either side.
func ValidateTOTP(secret, code string) bool {
	_, ok := matchTOTP(secret, code, time.Now())
	return ok
}

// matchTOTP finds the time step code belongs to, allowing one step of clock
// skew either side of now. Sign-in keeps the step, so that a code, once used,
// can't be used again.
func matchTOTP(secret, code string, now time.Time) (int64, bool) {
	if secret == "" || len(code) != 6 {
		return 0, false
	}
	step := now.Unix() / totpPeriod
	for _, s := range []int64{step - 1, step, step + 1} {
		want, err := totp.GenerateCodeCustom(secret, time.Unix(s*totpPeriod, 0).UTC(), totp.ValidateOpts{
			Period: totpPeriod, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
		})
		if err == nil && subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return s, true
		}
	}
	return 0, false
}

// sealedPrefix marks a TOTP secret sealed with the server key. What follows is
// the nonce and the ciphertext, each base64, separated by a dot.
const sealedPrefix = "sealed:"

// ErrNoSecretKey is returned when a TOTP secret must be sealed or opened and
// the service has no key to do it with.
var ErrNoSecretKey = errors.New("the server secret key is needed for authenticator secrets")

func totpContext(adminID uuid.UUID) []byte { return []byte("admin-totp:" + adminID.String()) }

// sealTOTP encrypts an authenticator secret for storage. The admin's id is
// bound in, so a sealed secret copied onto another account won't open.
func sealTOTP(key *secrets.Key, adminID uuid.UUID, secret string) (string, error) {
	if key == nil {
		return "", ErrNoSecretKey
	}
	ct, nonce, err := key.Seal([]byte(secret), totpContext(adminID))
	if err != nil {
		return "", err
	}
	enc := base64.RawStdEncoding
	return sealedPrefix + enc.EncodeToString(nonce) + "." + enc.EncodeToString(ct), nil
}

// openTOTP decrypts what sealTOTP stored.
func openTOTP(key *secrets.Key, adminID uuid.UUID, stored string) (string, error) {
	if key == nil {
		return "", ErrNoSecretKey
	}
	body, ok := strings.CutPrefix(stored, sealedPrefix)
	if !ok {
		return "", errors.New("the authenticator secret is not sealed")
	}
	n, c, ok := strings.Cut(body, ".")
	if !ok {
		return "", errors.New("the sealed authenticator secret is malformed")
	}
	enc := base64.RawStdEncoding
	nonce, err := enc.DecodeString(n)
	if err != nil {
		return "", err
	}
	ct, err := enc.DecodeString(c)
	if err != nil {
		return "", err
	}
	plain, err := key.Open(ct, nonce, totpContext(adminID))
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// IsSealedTOTP reports whether a stored secret is already sealed.
func IsSealedTOTP(stored string) bool { return strings.HasPrefix(stored, sealedPrefix) }
