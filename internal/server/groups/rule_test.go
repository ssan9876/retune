package groups_test

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"retune/internal/server/groups"
	"retune/internal/server/store"
)

func TestParseAcceptsRealRules(t *testing.T) {
	for _, rule := range []string{
		`hostname LIKE 'DESKTOP-%'`,
		`ram_gb >= 16 AND os_version = 'Microsoft Windows 11 Pro'`,
		`NOT (manufacturer = 'ASRock' OR model = 'X')`,
		`has_software('7-Zip')`,
		`has_software('Google Chrome', '<', '120.0.0')`,
		`last_seen_days > 7 AND NOT hostname LIKE 'TEST-%'`,
		`HOSTNAME like 'a%'`,
		`hostname = 'it''s'`,
		`ram_gb > -1`,
		`agent_version != '' AND serial != ''`,
	} {
		if _, err := groups.Parse(rule); err != nil {
			t.Errorf("Parse(%q) = %v", rule, err)
		}
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"unknown field":        `nope = 'x'`,
		"LIKE on a number":     `ram_gb LIKE '1%'`,
		"ordering on a string": `hostname > 'a'`,
		"string for a number":  `ram_gb = 'lots'`,
		"number for a string":  `hostname = 5`,
		"unclosed paren":       `(hostname = 'a'`,
		"unterminated string":  `hostname = 'a`,
		"empty":                ``,
		"only spaces":          `   `,
		"trailing junk":        `hostname = 'a' bogus`,
		"bad arity":            `has_software('a', '<')`,
		"unquoted software":    `has_software(7zip)`,
		"LIKE on a version":    `has_software('a', 'LIKE', '1')`,
		"dangling AND":         `hostname = 'a' AND`,
		"operator only":        `=`,
	}
	for name, rule := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := groups.Parse(rule); err == nil {
				t.Fatalf("Parse(%q) should have failed", rule)
			}
		})
	}
}

func TestParseReportsOffset(t *testing.T) {
	_, err := groups.Parse(`hostname = 'a' AND nope = 'b'`)
	var pe groups.ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("want ParseError, got %v", err)
	}
	if pe.Offset != 19 {
		t.Errorf("offset = %d, want 19 (the start of `nope`)", pe.Offset)
	}
	if !strings.Contains(pe.Message, "nope") {
		t.Errorf("the message should name the field, got %q", pe.Message)
	}
}

func TestParseRejectsOversizedRules(t *testing.T) {
	if _, err := groups.Parse(strings.Repeat("a", 2001)); err == nil {
		t.Error("a rule over 2000 characters should be rejected")
	}
	deep := strings.Repeat("(", 25) + "ram_gb = 1" + strings.Repeat(")", 25)
	if _, err := groups.Parse(deep); err == nil {
		t.Error("a rule nested over 20 deep should be rejected")
	}
}

func compile(t *testing.T, rule string) (string, []any) {
	t.Helper()
	n, err := groups.Parse(rule)
	if err != nil {
		t.Fatal(err)
	}
	sql, args, err := groups.Compile(n, store.DefaultTenantID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return sql, args
}

func TestCompileBindsLiterals(t *testing.T) {
	sql, args := compile(t, `hostname LIKE 'DESKTOP-%' AND ram_gb >= 16`)
	if strings.Contains(sql, "DESKTOP-%") {
		t.Fatalf("literals must be bound, not interpolated: %s", sql)
	}
	if !slices.Contains(args, any("DESKTOP-%")) {
		t.Errorf("args %v should carry the pattern", args)
	}
	if !slices.Contains(args, any(16.0)) {
		t.Errorf("args %v should carry the number", args)
	}
}

func TestCompileIsInjectionProof(t *testing.T) {
	sql, args := compile(t, `hostname = 'x''; DROP TABLE devices; --'`)
	if strings.Contains(sql, "DROP TABLE") {
		t.Fatalf("the literal reached the SQL text: %s", sql)
	}
	if !slices.Contains(args, any("x'; DROP TABLE devices; --")) {
		t.Errorf("the literal should be an argument, got %v", args)
	}
}

func TestCompileVersionOrderingUsesIntArrays(t *testing.T) {
	sql, _ := compile(t, `has_software('Chrome', '<', '120.0')`)
	if !strings.Contains(sql, "string_to_array") {
		t.Fatalf("ordering must compare versions numerically, got %s", sql)
	}
	// Equality stays a text comparison.
	eq, _ := compile(t, `has_software('Chrome', '=', '120.0')`)
	if strings.Contains(eq, "string_to_array") {
		t.Fatalf("equality should compare text, got %s", eq)
	}
}

func TestCompileBindsTenantAndClockFirst(t *testing.T) {
	now := time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC)
	n, err := groups.Parse(`last_seen_days > 7`)
	if err != nil {
		t.Fatal(err)
	}
	sql, args, err := groups.Compile(n, store.DefaultTenantID, now)
	if err != nil {
		t.Fatal(err)
	}
	if args[0] != any(store.DefaultTenantID) || args[1] != any(now) {
		t.Fatalf("args should start with the tenant and the clock, got %v", args[:2])
	}
	if strings.Contains(sql, "$CLOCK") {
		t.Fatalf("the clock placeholder was not substituted: %s", sql)
	}
	if !strings.Contains(sql, "$2") {
		t.Fatalf("last_seen_days should reference the bound clock: %s", sql)
	}
}
