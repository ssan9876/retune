package main

import (
	"context"
	"io"
	"regexp"
	"strings"
	"testing"

	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

func TestAdminCLI(t *testing.T) {
	ctx := context.Background()
	url := storetest.DatabaseURL(t)
	e := env(map[string]string{"DATABASE_URL": url})
	if err := run(ctx, []string{"migrate"}, e, io.Discard); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	out := runOut(t, e, "bootstrap-admin", "--email", "ops@example.com")
	if m := regexp.MustCompile(`Password: (\S+)`).FindStringSubmatch(out); m == nil || !strings.Contains(out, "ops@example.com") {
		t.Fatalf("bootstrap-admin = %q", out)
	}
	if err := run(ctx, []string{"bootstrap-admin", "--email", "second@example.com"}, e, io.Discard); err == nil {
		t.Fatal("bootstrap-admin must refuse once an admin exists")
	}

	admin, err := st.Q().GetAdminByEmail(ctx, "ops@example.com")
	if err != nil || admin.Role != store.RoleAdmin {
		t.Fatalf("admin = %+v, err = %v", admin, err)
	}

	if out := runOut(t, e, "admin", "list"); !strings.Contains(out, "ops@example.com") || !strings.Contains(out, "admin") {
		t.Fatalf("admin list = %q", out)
	}
	if out := runOut(t, e, "admin", "create", "--email", "viewer@example.com", "--password", "correct horse battery", "--role", "read_only"); !strings.Contains(out, "viewer@example.com") {
		t.Fatalf("admin create = %q", out)
	}
	if err := run(ctx, []string{"admin", "create", "--email", "weak@example.com", "--password", "short"}, e, io.Discard); err == nil {
		t.Fatal("a weak password must be rejected")
	}

	runOut(t, e, "admin", "password", "--email", "ops@example.com", "--password", "a whole new password")
	updated, _ := st.Q().GetAdminByEmail(ctx, "ops@example.com")
	if updated.PasswordHash == admin.PasswordHash {
		t.Fatal("the password hash must change")
	}

	if out := runOut(t, e, "admin", "totp", "--email", "ops@example.com", "--enable"); !strings.Contains(out, "otpauth://") {
		t.Fatalf("admin totp --enable = %q", out)
	}
	if cur, _ := st.Q().GetAdminByEmail(ctx, "ops@example.com"); cur.TOTPSecret == "" {
		t.Fatal("TOTP secret must be stored")
	}
	runOut(t, e, "admin", "totp", "--email", "ops@example.com", "--disable")
	if cur, _ := st.Q().GetAdminByEmail(ctx, "ops@example.com"); cur.TOTPSecret != "" {
		t.Fatal("TOTP secret must be cleared")
	}
	if err := run(ctx, []string{"admin", "totp", "--email", "ops@example.com"}, e, io.Discard); err == nil {
		t.Fatal("totp needs --enable or --disable")
	}

	runOut(t, e, "admin", "disable", "--email", "viewer@example.com")
	if cur, _ := st.Q().GetAdminByEmail(ctx, "viewer@example.com"); cur.DisabledAt == nil {
		t.Fatal("viewer must be disabled")
	}
	runOut(t, e, "admin", "enable", "--email", "viewer@example.com")
	if cur, _ := st.Q().GetAdminByEmail(ctx, "viewer@example.com"); cur.DisabledAt != nil {
		t.Fatal("viewer must be enabled again")
	}
	if err := run(ctx, []string{"admin", "disable", "--email", "ops@example.com"}, e, io.Discard); err == nil {
		t.Fatal("disabling the last enabled admin must fail")
	}
	if err := run(ctx, []string{"admin", "password", "--email", "nobody@example.com", "--password", "correct horse battery"}, e, io.Discard); err == nil {
		t.Fatal("an unknown email must fail")
	}
}
