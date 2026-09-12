package auth

import (
	"github.com/pquerna/otp/totp"
)

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
	if secret == "" || code == "" {
		return false
	}
	return totp.Validate(code, secret)
}
