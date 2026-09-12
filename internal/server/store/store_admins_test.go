package store_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

func newAdmin(t *testing.T, q *store.Queries, email, role string) store.Admin {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	a := store.Admin{
		ID: uuid.Must(uuid.NewV7()), Email: email, PasswordHash: "hash-" + email,
		Role: role, CreatedAt: now,
	}
	if err := q.CreateAdmin(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestAdminQueries(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	q := s.Q()
	now := time.Now().UTC().Truncate(time.Microsecond)

	if n, err := q.CountAdmins(ctx); err != nil || n != 0 {
		t.Fatalf("CountAdmins on empty database = %d, %v", n, err)
	}
	a := newAdmin(t, q, "Ops@example.com", store.RoleAdmin)
	newAdmin(t, q, "viewer@example.com", store.RoleReadOnly)

	if n, _ := q.CountAdmins(ctx); n != 2 {
		t.Fatalf("CountAdmins = %d", n)
	}
	got, err := q.GetAdminByEmail(ctx, "ops@EXAMPLE.com")
	if err != nil || got.ID != a.ID || got.Role != store.RoleAdmin {
		t.Fatalf("GetAdminByEmail (case-insensitive) = %+v, err = %v", got, err)
	}
	if _, err := q.GetAdminByEmail(ctx, "nobody@example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown email err = %v", err)
	}
	if err := q.CreateAdmin(ctx, store.Admin{
		ID: uuid.Must(uuid.NewV7()), Email: "OPS@example.com", PasswordHash: "x", Role: store.RoleAdmin, CreatedAt: now,
	}); err == nil {
		t.Fatal("duplicate email must be rejected regardless of case")
	}

	if err := q.UpdateAdminPassword(ctx, a.ID, "new-hash"); err != nil {
		t.Fatal(err)
	}
	if err := q.UpdateAdminTOTP(ctx, a.ID, "SECRET"); err != nil {
		t.Fatal(err)
	}
	if err := q.RecordAdminLogin(ctx, a.ID, now); err != nil {
		t.Fatal(err)
	}
	cur, err := q.GetAdmin(ctx, a.ID)
	if err != nil || cur.PasswordHash != "new-hash" || cur.TOTPSecret != "SECRET" ||
		cur.LastLoginAt == nil || !cur.LastLoginAt.Equal(now) {
		t.Fatalf("admin = %+v, err = %v", cur, err)
	}

	if err := q.SetAdminDisabled(ctx, a.ID, &now); err != nil {
		t.Fatal(err)
	}
	if cur, _ = q.GetAdmin(ctx, a.ID); cur.DisabledAt == nil {
		t.Fatal("admin must be disabled")
	}
	if err := q.SetAdminDisabled(ctx, a.ID, nil); err != nil {
		t.Fatal(err)
	}
	if cur, _ = q.GetAdmin(ctx, a.ID); cur.DisabledAt != nil {
		t.Fatal("admin must be enabled again")
	}

	list, err := q.ListAdmins(ctx)
	if err != nil || len(list) != 2 || list[0].Email != "Ops@example.com" {
		t.Fatalf("ListAdmins = %+v, err = %v", list, err)
	}
}

func TestSessionQueries(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	q := s.Q()
	now := time.Now().UTC().Truncate(time.Microsecond)
	a := newAdmin(t, q, "ops@example.com", store.RoleAdmin)

	hash := sha256.Sum256([]byte("token-1"))
	sess := store.Session{
		TokenHash: hash[:], AdminID: a.ID, CSRFToken: "csrf-1",
		CreatedAt: now, ExpiresAt: now.Add(12 * time.Hour), LastSeenAt: now,
		UserAgent: "curl", IP: "10.0.0.1",
	}
	if err := q.CreateSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	gotSession, gotAdmin, err := q.GetSessionWithAdmin(ctx, hash[:])
	if err != nil || gotSession.CSRFToken != "csrf-1" || gotAdmin.ID != a.ID || gotSession.UserAgent != "curl" {
		t.Fatalf("session = %+v admin = %+v err = %v", gotSession, gotAdmin, err)
	}
	missing := sha256.Sum256([]byte("nope"))
	if _, _, err := q.GetSessionWithAdmin(ctx, missing[:]); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown session err = %v", err)
	}

	later := now.Add(time.Hour)
	if err := q.TouchSession(ctx, hash[:], later, later.Add(12*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if gotSession, _, _ = q.GetSessionWithAdmin(ctx, hash[:]); !gotSession.LastSeenAt.Equal(later) || !gotSession.ExpiresAt.Equal(later.Add(12*time.Hour)) {
		t.Fatalf("touched session = %+v", gotSession)
	}

	// Expired sessions are swept.
	old := sha256.Sum256([]byte("token-old"))
	stale := sess
	stale.TokenHash = old[:]
	stale.ExpiresAt = now.Add(-time.Minute)
	if err := q.CreateSession(ctx, stale); err != nil {
		t.Fatal(err)
	}
	n, err := q.DeleteExpiredSessions(ctx, now)
	if err != nil || n != 1 {
		t.Fatalf("DeleteExpiredSessions = %d, %v", n, err)
	}

	if err := q.DeleteSession(ctx, hash[:]); err != nil {
		t.Fatal(err)
	}
	if _, _, err := q.GetSessionWithAdmin(ctx, hash[:]); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted session err = %v", err)
	}

	second := sha256.Sum256([]byte("token-2"))
	sess.TokenHash = second[:]
	if err := q.CreateSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	if err := q.DeleteSessionsForAdmin(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := q.GetSessionWithAdmin(ctx, second[:]); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("sessions for admin must be gone: %v", err)
	}
}
