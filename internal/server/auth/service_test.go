package auth_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"

	"retune/internal/server/auth"
	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

func newService(t *testing.T, clock *time.Time) *auth.Service {
	t.Helper()
	st := storetest.New(t)
	return &auth.Service{
		Store: st, Now: func() time.Time { return *clock },
		SessionTTL: 12 * time.Hour,
		Limiter:    auth.NewLimiter(3, 15*time.Minute, func() time.Time { return *clock }),
		Issuer:     "Retune",
	}
}

func TestAuthenticate(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	clock := now
	svc := newService(t, &clock)

	admin, err := svc.CreateAdmin(ctx, auth.CreateAdminOptions{
		Email: "Ops@example.com", Password: "correct horse battery", Role: store.RoleAdmin, Actor: "cli",
	})
	if err != nil {
		t.Fatal(err)
	}
	if admin.PasswordHash == "correct horse battery" || admin.Role != store.RoleAdmin {
		t.Fatalf("admin = %+v", admin)
	}

	got, err := svc.Authenticate(ctx, "ops@EXAMPLE.com", "correct horse battery", "")
	if err != nil || got.ID != admin.ID {
		t.Fatalf("Authenticate = %+v, err = %v", got, err)
	}
	if cur, _ := svc.Store.Q().GetAdmin(ctx, admin.ID); cur.LastLoginAt == nil {
		t.Fatal("a successful login must be recorded")
	}

	if _, err := svc.Authenticate(ctx, "ops@example.com", "wrong", ""); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("wrong password err = %v", err)
	}
	if _, err := svc.Authenticate(ctx, "nobody@example.com", "whatever", ""); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("unknown email err = %v", err)
	}

	for name, opts := range map[string]auth.CreateAdminOptions{
		"weak password": {Email: "a@example.com", Password: "short", Role: store.RoleAdmin},
		"bad email":     {Email: "not-an-email", Password: "correct horse battery", Role: store.RoleAdmin},
		"bad role":      {Email: "b@example.com", Password: "correct horse battery", Role: "wizard"},
	} {
		t.Run(name, func(t *testing.T) {
			opts.Actor = "cli"
			if _, err := svc.CreateAdmin(ctx, opts); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
	if _, err := svc.CreateAdmin(ctx, auth.CreateAdminOptions{
		Email: "OPS@example.com", Password: "correct horse battery", Role: store.RoleAdmin, Actor: "cli",
	}); err == nil {
		t.Fatal("a duplicate email must be rejected")
	}
}

func TestAuthenticateTOTPAndLockout(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	clock := now
	svc := newService(t, &clock)
	admin, err := svc.CreateAdmin(ctx, auth.CreateAdminOptions{
		Email: "ops@example.com", Password: "correct horse battery", Role: store.RoleAdmin, Actor: "cli",
	})
	if err != nil {
		t.Fatal(err)
	}

	secret, url, err := svc.EnableTOTP(ctx, admin.ID, "ops@example.com")
	if err != nil || secret == "" || !strings.Contains(url, "Retune") {
		t.Fatalf("EnableTOTP = %q, %q, %v", secret, url, err)
	}
	if _, err := svc.Authenticate(ctx, "ops@example.com", "correct horse battery", ""); !errors.Is(err, auth.ErrTOTPRequired) {
		t.Fatalf("missing code err = %v", err)
	}
	if _, err := svc.Authenticate(ctx, "ops@example.com", "correct horse battery", "123456"); !errors.Is(err, auth.ErrTOTPInvalid) {
		t.Fatalf("wrong code err = %v", err)
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Authenticate(ctx, "ops@example.com", "correct horse battery", code); err != nil {
		t.Fatalf("valid code err = %v", err)
	}
	if err := svc.DisableTOTP(ctx, admin.ID, "ops@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Authenticate(ctx, "ops@example.com", "correct horse battery", ""); err != nil {
		t.Fatalf("after DisableTOTP err = %v", err)
	}

	for range 3 {
		if _, err := svc.Authenticate(ctx, "ops@example.com", "wrong", ""); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("failure err = %v", err)
		}
	}
	if _, err := svc.Authenticate(ctx, "ops@example.com", "correct horse battery", ""); !errors.Is(err, auth.ErrTooManyAttempts) {
		t.Fatalf("lockout err = %v", err)
	}
	clock = now.Add(16 * time.Minute)
	if _, err := svc.Authenticate(ctx, "ops@example.com", "correct horse battery", ""); err != nil {
		t.Fatalf("after the window err = %v", err)
	}
}

func TestSessions(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	clock := now
	svc := newService(t, &clock)
	admin, err := svc.CreateAdmin(ctx, auth.CreateAdminOptions{
		Email: "ops@example.com", Password: "correct horse battery", Role: store.RoleAdmin, Actor: "cli",
	})
	if err != nil {
		t.Fatal(err)
	}

	info, err := svc.CreateSession(ctx, admin.ID, "curl", "10.0.0.1")
	if err != nil || info.Token == "" || info.CSRFToken == "" || !info.ExpiresAt.Equal(now.Add(12*time.Hour)) {
		t.Fatalf("CreateSession = %+v, err = %v", info, err)
	}

	gotAdmin, gotSession, err := svc.ValidateSession(ctx, info.Token)
	if err != nil || gotAdmin.ID != admin.ID || gotSession.CSRFToken != info.CSRFToken {
		t.Fatalf("ValidateSession = %+v %+v %v", gotAdmin, gotSession, err)
	}
	if _, _, err := svc.ValidateSession(ctx, "not-a-token"); !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatalf("unknown token err = %v", err)
	}

	clock = now.Add(2 * time.Hour)
	if _, gotSession, err = svc.ValidateSession(ctx, info.Token); err != nil || !gotSession.ExpiresAt.Equal(clock.Add(12*time.Hour)) {
		t.Fatalf("session not extended: %+v, %v", gotSession, err)
	}
	clock = clock.Add(13 * time.Hour)
	if _, _, err := svc.ValidateSession(ctx, info.Token); !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatalf("expired session err = %v", err)
	}

	clock = now
	info, err = svc.CreateSession(ctx, admin.ID, "curl", "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateAdmin(ctx, auth.CreateAdminOptions{
		Email: "viewer@example.com", Password: "correct horse battery", Role: store.RoleReadOnly, Actor: "cli",
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetDisabled(ctx, admin.ID, true, "cli"); !errors.Is(err, auth.ErrLastAdmin) {
		t.Fatalf("disabling the only admin must be refused: %v", err)
	}
	second, err := svc.CreateAdmin(ctx, auth.CreateAdminOptions{
		Email: "ops2@example.com", Password: "correct horse battery", Role: store.RoleAdmin, Actor: "cli",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SetDisabled(ctx, admin.ID, true, "cli"); err != nil {
		t.Fatal(err)
	}
	// Disabling an account signs it out immediately.
	if _, _, err := svc.ValidateSession(ctx, info.Token); !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatalf("disabling must revoke sessions, got err = %v", err)
	}
	if _, err := svc.Authenticate(ctx, "ops@example.com", "correct horse battery", ""); !errors.Is(err, auth.ErrAccountDisabled) {
		t.Fatalf("disabled admin login err = %v", err)
	}
	// A session that somehow outlives the account is refused too.
	orphan, err := svc.CreateSession(ctx, admin.ID, "curl", "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.ValidateSession(ctx, orphan.Token); !errors.Is(err, auth.ErrAccountDisabled) {
		t.Fatalf("session for a disabled admin err = %v", err)
	}

	info, err = svc.CreateSession(ctx, second.ID, "curl", "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SetPassword(ctx, second.ID, "a whole new password", "cli"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.ValidateSession(ctx, info.Token); !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatalf("sessions must end on password change: %v", err)
	}
	if _, err := svc.Authenticate(ctx, "ops2@example.com", "a whole new password", ""); err != nil {
		t.Fatalf("the new password must work: %v", err)
	}

	if err := svc.DeleteSession(ctx, "unknown-token"); err != nil {
		t.Fatalf("deleting an unknown session must be harmless: %v", err)
	}
	if err := svc.SetPassword(ctx, uuid.Must(uuid.NewV7()), "a whole new password", "cli"); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("unknown admin err = %v", err)
	}

	list, err := svc.List(ctx)
	if err != nil || len(list) != 3 {
		t.Fatalf("List = %d admins, err = %v", len(list), err)
	}
	if has, err := svc.HasAdmins(ctx); err != nil || !has {
		t.Fatalf("HasAdmins = %v, %v", has, err)
	}

	entries, err := svc.Store.Q().ListAudit(ctx, 200)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, e := range entries {
		seen[e.Action]++
	}
	for _, action := range []string{"admin.created", "admin.login", "admin.disabled", "admin.password_changed"} {
		if seen[action] == 0 {
			t.Errorf("missing audit action %s (saw %v)", action, seen)
		}
	}
}

func TestTOTPChangesAreAudited(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	clock := now
	svc := newService(t, &clock)
	admin, err := svc.CreateAdmin(ctx, auth.CreateAdminOptions{
		Email: "ops@example.com", Password: "correct horse battery", Role: store.RoleAdmin, Actor: "cli",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.EnableTOTP(ctx, admin.ID, "cli"); err != nil {
		t.Fatal(err)
	}
	if err := svc.DisableTOTP(ctx, admin.ID, "cli"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.EnableTOTP(ctx, uuid.Must(uuid.NewV7()), "cli"); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("EnableTOTP for an unknown admin = %v", err)
	}
	if err := svc.DisableTOTP(ctx, uuid.Must(uuid.NewV7()), "cli"); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("DisableTOTP for an unknown admin = %v", err)
	}

	entries, err := svc.Store.Q().ListAudit(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, e := range entries {
		seen[e.Action]++
	}
	if seen["admin.totp_enabled"] != 1 || seen["admin.totp_disabled"] != 1 {
		t.Fatalf("TOTP audit entries = %v", seen)
	}
}
