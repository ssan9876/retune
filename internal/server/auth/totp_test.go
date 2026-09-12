package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestTOTP(t *testing.T) {
	secret, url, err := NewTOTPSecret("Retune", "ops@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if secret == "" || !strings.HasPrefix(url, "otpauth://totp/") || !strings.Contains(url, "ops@example.com") {
		t.Fatalf("secret = %q url = %q", secret, url)
	}

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !ValidateTOTP(secret, code) {
		t.Fatal("a current code must validate")
	}
	if ValidateTOTP(secret, "000000") && code != "000000" {
		t.Fatal("a wrong code must not validate")
	}
	if ValidateTOTP("", code) {
		t.Fatal("an empty secret must never validate")
	}
	if ValidateTOTP(secret, "") {
		t.Fatal("an empty code must not validate")
	}
}
