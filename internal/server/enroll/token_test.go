package enroll

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"retune/internal/server/store"
)

func TestGenerateToken(t *testing.T) {
	p1, h1, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	p2, _, _ := GenerateToken()
	if !strings.HasPrefix(p1, "rt_") || len(p1) < 40 {
		t.Fatalf("token %q has wrong shape", p1)
	}
	if p1 == p2 {
		t.Fatal("tokens must be unique")
	}
	if !bytes.Equal(h1, HashToken(p1)) || !bytes.Equal(h1, HashToken("  "+p1+"\n")) {
		t.Fatal("hash must match HashToken and ignore surrounding whitespace")
	}
}

func TestCheckUsable(t *testing.T) {
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Minute), now.Add(time.Minute)
	two := 2
	cases := map[string]struct {
		tok  store.EnrollmentToken
		want error
	}{
		"fresh":             {store.EnrollmentToken{}, nil},
		"not yet expired":   {store.EnrollmentToken{ExpiresAt: &future}, nil},
		"expired":           {store.EnrollmentToken{ExpiresAt: &past}, ErrTokenExpired},
		"expires right now": {store.EnrollmentToken{ExpiresAt: &now}, ErrTokenExpired},
		"revoked":           {store.EnrollmentToken{RevokedAt: &past}, ErrTokenRevoked},
		"uses left":         {store.EnrollmentToken{MaxUses: &two, UseCount: 1}, nil},
		"exhausted":         {store.EnrollmentToken{MaxUses: &two, UseCount: 2}, ErrTokenExhausted},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if err := CheckUsable(tc.tok, now); !errors.Is(err, tc.want) {
				t.Fatalf("CheckUsable = %v, want %v", err, tc.want)
			}
		})
	}
}
