package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"retune/internal/pki"
	"retune/internal/server/ca"
	"retune/internal/server/secrets"
	"retune/internal/server/auth"
	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

// TestCommandsReadConfigFile checks that commands other than serve also honour
// the YAML config file, not just environment variables.
func TestCommandsReadConfigFile(t *testing.T) {
	ctx := context.Background()
	url := storetest.DatabaseURL(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "retune-server.yaml")
	body := "database_url: " + url + "\npublic_url: https://localhost:8443\ndata_dir: " +
		filepath.ToSlash(filepath.Join(dir, "data")) + "\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	e := env(map[string]string{"RETUNE_CONFIG": cfg})

	if err := run(ctx, []string{"migrate"}, e, io.Discard); err != nil {
		t.Fatalf("migrate from the config file: %v", err)
	}
	if out := runOut(t, e, "bootstrap-admin", "--email", "ops@example.com"); !strings.Contains(out, "Password: ") {
		t.Fatalf("bootstrap-admin = %q", out)
	}
	if out := runOut(t, e, "admin", "list"); !strings.Contains(out, "ops@example.com") {
		t.Fatalf("admin list = %q", out)
	}
	if out := runOut(t, e, "device", "list"); !strings.Contains(out, "0 device(s)") {
		t.Fatalf("device list = %q", out)
	}
	// The CA is created by the server, not by the ca commands, so make one in
	// the directory the config file names and check the command finds it there.
	authority, err := ca.LoadOrCreate(ctx, ca.FileKeyStore{Dir: filepath.Join(dir, "data", "ca")}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "data", "ca", "ca.crt")); err != nil {
		t.Fatalf("the CA must land in the configured data_dir: %v", err)
	}
	if out := strings.TrimSpace(runOut(t, e, "ca", "fingerprint")); out != pki.Fingerprint(authority.Cert().Raw) {
		t.Fatalf("ca fingerprint = %q, did not read the configured data_dir", out)
	}
}

func TestAdminCLI(t *testing.T) {
	ctx := context.Background()
	url := storetest.DatabaseURL(t)
	dataDir := t.TempDir()
	e := env(map[string]string{"DATABASE_URL": url, "DATA_DIR": dataDir})
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

	admin, err := st.Q().GetAdminByEmail(ctx, store.DefaultTenantID, "ops@example.com")
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
	updated, _ := st.Q().GetAdminByEmail(ctx, store.DefaultTenantID, "ops@example.com")
	if updated.PasswordHash == admin.PasswordHash {
		t.Fatal("the password hash must change")
	}

	// Turning TOTP on seals the secret with the server's key; the command
	// won't make up a key the server doesn't have.
	if err := run(ctx, []string{"admin", "totp", "--email", "ops@example.com", "--enable"}, e, io.Discard); err == nil ||
		!strings.Contains(err.Error(), "DATA_DIR") {
		t.Fatalf("totp --enable with no key = %v", err)
	}
	if _, err := secrets.LoadOrCreateFile(dataDir); err != nil {
		t.Fatal(err)
	}
	if out := runOut(t, e, "admin", "totp", "--email", "ops@example.com", "--enable"); !strings.Contains(out, "otpauth://") {
		t.Fatalf("admin totp --enable = %q", out)
	}
	if cur, _ := st.Q().GetAdminByEmail(ctx, store.DefaultTenantID, "ops@example.com"); !auth.IsSealedTOTP(cur.TOTPSecret) {
		t.Fatalf("TOTP secret must be stored sealed, got %q", cur.TOTPSecret)
	}
	runOut(t, e, "admin", "totp", "--email", "ops@example.com", "--disable")
	if cur, _ := st.Q().GetAdminByEmail(ctx, store.DefaultTenantID, "ops@example.com"); cur.TOTPSecret != "" {
		t.Fatal("TOTP secret must be cleared")
	}
	if err := run(ctx, []string{"admin", "totp", "--email", "ops@example.com"}, e, io.Discard); err == nil {
		t.Fatal("totp needs --enable or --disable")
	}

	runOut(t, e, "admin", "disable", "--email", "viewer@example.com")
	if cur, _ := st.Q().GetAdminByEmail(ctx, store.DefaultTenantID, "viewer@example.com"); cur.DisabledAt == nil {
		t.Fatal("viewer must be disabled")
	}
	runOut(t, e, "admin", "enable", "--email", "viewer@example.com")
	if cur, _ := st.Q().GetAdminByEmail(ctx, store.DefaultTenantID, "viewer@example.com"); cur.DisabledAt != nil {
		t.Fatal("viewer must be enabled again")
	}
	if err := run(ctx, []string{"admin", "disable", "--email", "ops@example.com"}, e, io.Discard); err == nil {
		t.Fatal("disabling the last enabled admin must fail")
	}
	if err := run(ctx, []string{"admin", "password", "--email", "nobody@example.com", "--password", "correct horse battery"}, e, io.Discard); err == nil {
		t.Fatal("an unknown email must fail")
	}
}
