# M3a: Admin API and Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An administrator signs in with a password (and optional TOTP) and manages devices, commands, enrollment tokens, the audit log and other admins through a REST API, with read-only accounts restricted to reading.

**Architecture:** A new `auth` service owns Argon2id password hashing, TOTP, login rate limiting and database-backed sessions; `adminapi` serves `/api/admin/v1` behind session-cookie plus CSRF middleware with per-role access; the server CLI gains `bootstrap-admin` and `admin` commands; configuration can now come from a YAML file as well as the environment.

**Tech Stack:** Go 1.27, PostgreSQL 17, `golang.org/x/crypto/argon2`, `github.com/pquerna/otp` (TOTP), `gopkg.in/yaml.v3`, existing M1/M2 packages.

**Spec:** `docs/superpowers/specs/2026-09-12-core-platform-design.md` (§3 admin authentication and audit, §12 console API surface; roadmap: `docs/superpowers/plans/2026-09-12-roadmap.md`). The React console itself is M3b.

## Global Constraints

- Module path `retune`, Go toolchain 1.27; every table keeps `tenant_id`; IDs are UUIDv7; timestamps `timestamptz`.
- API errors stay JSON `{"code": "...", "message": "..."}`. Admin endpoints live under `/api/admin/v1/`.
- Passwords: Argon2id, 64 MiB memory, 3 iterations, 4 lanes, 32-byte key, 16-byte salt, stored in the standard `$argon2id$v=19$m=...,t=...,p=...$salt$hash` form. Minimum length 12 characters, maximum 1024.
- Login always performs one Argon2id verification, even for an unknown email, so response time does not reveal which accounts exist.
- Sessions: 32 bytes of randomness, sent as cookie `retune_session` (HttpOnly, Secure, SameSite=Strict, Path=/); only the SHA-256 of the token is stored. Absolute lifetime 12 hours, extended on use.
- CSRF: every unsafe method (anything except GET and HEAD) must carry header `X-CSRF-Token` matching the session's token.
- Roles: `admin` may read and write; `read_only` may only use GET. A disabled account cannot sign in and its sessions stop working.
- Login rate limit: 10 failures per email within 15 minutes, then `429 too_many_attempts` until the window passes.
- Every state change is audited with the acting admin's email as the actor.
- Configuration precedence: environment variable > YAML file > default. The YAML path comes from `RETUNE_CONFIG`, or `retune-server.yaml` in the working directory when it exists.
- Postgres tests use testcontainers and need Docker; they skip under `go test -short`. Every task ends with `go vet ./...` and `go test ./...` passing.

## File Structure

```
internal/server/
  store/migrations/0003_admins_sessions.{up,down}.sql   NEW
  store/admins.go        NEW: admin + session models and queries
  store/lists.go         NEW: filtered/paginated device, command, token, audit queries
  auth/password.go       NEW: Argon2id hashing and verification
  auth/totp.go           NEW: TOTP secret creation and validation
  auth/ratelimit.go      NEW: in-memory failed-login limiter
  auth/service.go        NEW: Authenticate, sessions, admin management
  adminapi/handler.go    NEW: routes and middleware (session, CSRF, role)
  adminapi/session.go    NEW: login, logout, me
  adminapi/devices.go    NEW: device list/detail/retire/unenroll/software
  adminapi/commands.go   NEW: command list/queue/detail
  adminapi/tokens.go     NEW: enrollment token list/create/revoke
  adminapi/admins.go     NEW: admin list/create/password/totp/disable
  adminapi/audit.go      NEW: audit log page
  adminapi/json.go       NEW: shared decode/write helpers for this package
  app/app.go             MODIFY: build auth + adminapi, serve both APIs
internal/config/
  server.go              MODIFY: AdminListen, SessionTTL, YAML support
  file.go                NEW: YAML file loading
cmd/retune-server/
  main.go                MODIFY: bootstrap-admin and admin commands
  admins.go              NEW: bootstrap-admin, admin list|password|totp|disable
```

---

### Task 1: Admin and session storage

**Files:**
- Create: `internal/server/store/migrations/0003_admins_sessions.up.sql`, `internal/server/store/migrations/0003_admins_sessions.down.sql`, `internal/server/store/admins.go`, `internal/server/store/store_admins_test.go`

**Interfaces:**
- Consumes: M1/M2 store plumbing (`Queries`, `notFound`, `DefaultTenantID`)
- Produces:
  - `store.RoleAdmin = "admin"`, `store.RoleReadOnly = "read_only"`
  - `store.Admin{ID uuid.UUID; Email, PasswordHash, TOTPSecret, Role string; CreatedAt time.Time; LastLoginAt, DisabledAt *time.Time}`
  - `store.Session{TokenHash []byte; AdminID uuid.UUID; CSRFToken string; CreatedAt, ExpiresAt, LastSeenAt time.Time; UserAgent, IP string}`
  - `*Queries`: `CreateAdmin`, `GetAdmin(ctx, id)`, `GetAdminByEmail(ctx, email)` (case-insensitive), `ListAdmins`, `CountAdmins`, `UpdateAdminPassword`, `UpdateAdminTOTP`, `SetAdminDisabled(ctx, id, at *time.Time)`, `RecordAdminLogin(ctx, id, at)`, `CreateSession`, `GetSessionWithAdmin(ctx, tokenHash) (Session, Admin, error)`, `TouchSession(ctx, tokenHash, seenAt, expiresAt)`, `DeleteSession(ctx, tokenHash)`, `DeleteSessionsForAdmin(ctx, adminID)`, `DeleteExpiredSessions(ctx, now) (int64, error)`

- [ ] **Step 1: Write the migrations**

`internal/server/store/migrations/0003_admins_sessions.up.sql`:

```sql
CREATE TABLE admins (
    id            uuid PRIMARY KEY,
    tenant_id     uuid NOT NULL REFERENCES tenants(id),
    email         text NOT NULL,
    password_hash text NOT NULL,
    totp_secret   text NOT NULL DEFAULT '',
    role          text NOT NULL CHECK (role IN ('admin', 'read_only')),
    created_at    timestamptz NOT NULL,
    last_login_at timestamptz,
    disabled_at   timestamptz
);
CREATE UNIQUE INDEX admins_email ON admins (tenant_id, lower(email));

CREATE TABLE sessions (
    token_hash   bytea PRIMARY KEY,
    tenant_id    uuid NOT NULL REFERENCES tenants(id),
    admin_id     uuid NOT NULL REFERENCES admins(id),
    csrf_token   text NOT NULL,
    created_at   timestamptz NOT NULL,
    expires_at   timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    user_agent   text NOT NULL DEFAULT '',
    ip           text NOT NULL DEFAULT ''
);
CREATE INDEX sessions_admin ON sessions (admin_id);
CREATE INDEX sessions_expiry ON sessions (expires_at);
```

`internal/server/store/migrations/0003_admins_sessions.down.sql`:

```sql
DROP TABLE sessions;
DROP TABLE admins;
```

- [ ] **Step 2: Write the failing test**

`internal/server/store/store_admins_test.go`:

```go
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
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/server/store/ -run 'TestAdminQueries|TestSessionQueries'`
Expected: FAIL — `undefined: store.Admin`.

- [ ] **Step 4: Implement the queries**

`internal/server/store/admins.go`:

```go
package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Admin roles.
const (
	RoleAdmin    = "admin"
	RoleReadOnly = "read_only"
)

// Admin is a console user.
type Admin struct {
	ID           uuid.UUID
	Email        string
	PasswordHash string
	TOTPSecret   string
	Role         string
	CreatedAt    time.Time
	LastLoginAt  *time.Time
	DisabledAt   *time.Time
}

// Session is one signed-in browser. Only the hash of the token is stored.
type Session struct {
	TokenHash  []byte
	AdminID    uuid.UUID
	CSRFToken  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastSeenAt time.Time
	UserAgent  string
	IP         string
}

const adminCols = `id, email, password_hash, totp_secret, role, created_at, last_login_at, disabled_at`

func scanAdmin(row pgx.Row) (Admin, error) {
	var a Admin
	err := row.Scan(&a.ID, &a.Email, &a.PasswordHash, &a.TOTPSecret, &a.Role, &a.CreatedAt, &a.LastLoginAt, &a.DisabledAt)
	return a, notFound(err)
}

func (q *Queries) CreateAdmin(ctx context.Context, a Admin) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO admins (id, tenant_id, email, password_hash, totp_secret, role, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		a.ID, DefaultTenantID, a.Email, a.PasswordHash, a.TOTPSecret, a.Role, a.CreatedAt)
	return err
}

func (q *Queries) GetAdmin(ctx context.Context, id uuid.UUID) (Admin, error) {
	return scanAdmin(q.db.QueryRow(ctx, `SELECT `+adminCols+` FROM admins WHERE id = $1`, id))
}

// GetAdminByEmail looks an admin up case-insensitively.
func (q *Queries) GetAdminByEmail(ctx context.Context, email string) (Admin, error) {
	return scanAdmin(q.db.QueryRow(ctx, `SELECT `+adminCols+` FROM admins WHERE lower(email) = lower($1)`, email))
}

func (q *Queries) ListAdmins(ctx context.Context) ([]Admin, error) {
	rows, err := q.db.Query(ctx, `SELECT `+adminCols+` FROM admins ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Admin
	for rows.Next() {
		a, err := scanAdmin(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (q *Queries) CountAdmins(ctx context.Context) (int, error) {
	var n int
	err := q.db.QueryRow(ctx, `SELECT count(*) FROM admins`).Scan(&n)
	return n, err
}

func (q *Queries) UpdateAdminPassword(ctx context.Context, id uuid.UUID, hash string) error {
	_, err := q.db.Exec(ctx, `UPDATE admins SET password_hash = $2 WHERE id = $1`, id, hash)
	return err
}

// UpdateAdminTOTP stores a new TOTP secret, or "" to turn TOTP off.
func (q *Queries) UpdateAdminTOTP(ctx context.Context, id uuid.UUID, secret string) error {
	_, err := q.db.Exec(ctx, `UPDATE admins SET totp_secret = $2 WHERE id = $1`, id, secret)
	return err
}

// SetAdminDisabled disables an admin, or re-enables it with a nil time.
func (q *Queries) SetAdminDisabled(ctx context.Context, id uuid.UUID, at *time.Time) error {
	_, err := q.db.Exec(ctx, `UPDATE admins SET disabled_at = $2 WHERE id = $1`, id, at)
	return err
}

func (q *Queries) RecordAdminLogin(ctx context.Context, id uuid.UUID, at time.Time) error {
	_, err := q.db.Exec(ctx, `UPDATE admins SET last_login_at = $2 WHERE id = $1`, id, at)
	return err
}

func (q *Queries) CreateSession(ctx context.Context, s Session) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO sessions (token_hash, tenant_id, admin_id, csrf_token, created_at, expires_at, last_seen_at, user_agent, ip)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		s.TokenHash, DefaultTenantID, s.AdminID, s.CSRFToken, s.CreatedAt, s.ExpiresAt, s.LastSeenAt, s.UserAgent, s.IP)
	return err
}

// GetSessionWithAdmin returns a session and its owner in one round trip.
func (q *Queries) GetSessionWithAdmin(ctx context.Context, tokenHash []byte) (Session, Admin, error) {
	var s Session
	var a Admin
	err := q.db.QueryRow(ctx, `
		SELECT s.token_hash, s.admin_id, s.csrf_token, s.created_at, s.expires_at, s.last_seen_at, s.user_agent, s.ip,
		       a.id, a.email, a.password_hash, a.totp_secret, a.role, a.created_at, a.last_login_at, a.disabled_at
		FROM sessions s JOIN admins a ON a.id = s.admin_id
		WHERE s.token_hash = $1`, tokenHash).
		Scan(&s.TokenHash, &s.AdminID, &s.CSRFToken, &s.CreatedAt, &s.ExpiresAt, &s.LastSeenAt, &s.UserAgent, &s.IP,
			&a.ID, &a.Email, &a.PasswordHash, &a.TOTPSecret, &a.Role, &a.CreatedAt, &a.LastLoginAt, &a.DisabledAt)
	if err != nil {
		return Session{}, Admin{}, notFound(err)
	}
	return s, a, nil
}

func (q *Queries) TouchSession(ctx context.Context, tokenHash []byte, seenAt, expiresAt time.Time) error {
	_, err := q.db.Exec(ctx, `
		UPDATE sessions SET last_seen_at = $2, expires_at = $3 WHERE token_hash = $1`, tokenHash, seenAt, expiresAt)
	return err
}

func (q *Queries) DeleteSession(ctx context.Context, tokenHash []byte) error {
	_, err := q.db.Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1`, tokenHash)
	return err
}

func (q *Queries) DeleteSessionsForAdmin(ctx context.Context, adminID uuid.UUID) error {
	_, err := q.db.Exec(ctx, `DELETE FROM sessions WHERE admin_id = $1`, adminID)
	return err
}

func (q *Queries) DeleteExpiredSessions(ctx context.Context, now time.Time) (int64, error) {
	tag, err := q.db.Exec(ctx, `DELETE FROM sessions WHERE expires_at <= $1`, now)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go vet ./internal/server/store/ && go test -count=1 ./internal/server/store/`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/server/store
git commit -m "feat(store): admin accounts and session storage"
```

---

### Task 2: Password hashing, TOTP and login rate limiting

**Files:**
- Create: `internal/server/auth/password.go`, `internal/server/auth/totp.go`, `internal/server/auth/ratelimit.go`, `internal/server/auth/password_test.go`, `internal/server/auth/totp_test.go`, `internal/server/auth/ratelimit_test.go`

**Interfaces:**
- Consumes: nothing from the project (leaf helpers)
- Produces:
  - `auth.HashPassword(password string) (string, error)`, `auth.VerifyPassword(encoded, password string) bool`, `auth.ErrWeakPassword`, `auth.MinPasswordLength = 12`
  - `auth.GeneratePassword() (string, error)` — 20-character random password for `bootstrap-admin`
  - `auth.NewTOTPSecret(issuer, accountName string) (secret, otpauthURL string, err error)`, `auth.ValidateTOTP(secret, code string) bool`
  - `auth.NewLimiter(max int, window time.Duration, now func() time.Time) *auth.Limiter`; `(*Limiter).Allowed(key string) bool`, `(*Limiter).Fail(key string)`, `(*Limiter).Reset(key string)`

- [ ] **Step 1: Add the dependency**

```bash
go get github.com/pquerna/otp@latest
```

- [ ] **Step 2: Write the failing tests**

`internal/server/auth/password_test.go`:

```go
package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestHashAndVerify(t *testing.T) {
	hash, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=65536,t=3,p=4$") {
		t.Fatalf("hash = %q", hash)
	}
	if !VerifyPassword(hash, "correct horse battery") {
		t.Fatal("the right password must verify")
	}
	if VerifyPassword(hash, "wrong horse battery") {
		t.Fatal("the wrong password must not verify")
	}

	other, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if other == hash {
		t.Fatal("each hash must use a fresh salt")
	}

	for _, bad := range []string{"", "$argon2id$broken", "$argon2id$v=19$m=65536,t=3,p=4$notbase64$x"} {
		if VerifyPassword(bad, "correct horse battery") {
			t.Fatalf("malformed hash %q must not verify", bad)
		}
	}
}

func TestPasswordPolicy(t *testing.T) {
	if _, err := HashPassword("short"); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("short password err = %v", err)
	}
	if _, err := HashPassword(strings.Repeat("a", 1025)); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("overlong password err = %v", err)
	}
	if _, err := HashPassword(strings.Repeat("a", MinPasswordLength)); err != nil {
		t.Fatalf("minimum length must be accepted: %v", err)
	}
}

func TestGeneratePassword(t *testing.T) {
	a, err := GeneratePassword()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := GeneratePassword()
	if len(a) < MinPasswordLength || a == b {
		t.Fatalf("generated passwords = %q, %q", a, b)
	}
	if _, err := HashPassword(a); err != nil {
		t.Fatalf("a generated password must satisfy the policy: %v", err)
	}
}
```

`internal/server/auth/totp_test.go`:

```go
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
```

`internal/server/auth/ratelimit_test.go`:

```go
package auth

import (
	"testing"
	"time"
)

func TestLimiter(t *testing.T) {
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	clock := now
	l := NewLimiter(3, 15*time.Minute, func() time.Time { return clock })

	if !l.Allowed("a@example.com") {
		t.Fatal("a fresh key must be allowed")
	}
	for range 3 {
		l.Fail("a@example.com")
	}
	if l.Allowed("a@example.com") {
		t.Fatal("the key must be blocked after reaching the limit")
	}
	if !l.Allowed("b@example.com") {
		t.Fatal("other keys must be unaffected")
	}

	// A success clears the count.
	l.Reset("a@example.com")
	if !l.Allowed("a@example.com") {
		t.Fatal("Reset must clear failures")
	}

	for range 3 {
		l.Fail("a@example.com")
	}
	clock = now.Add(16 * time.Minute)
	if !l.Allowed("a@example.com") {
		t.Fatal("failures must expire with the window")
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/server/auth/`
Expected: FAIL — no such package / `undefined: HashPassword`.

- [ ] **Step 4: Implement the helpers**

`internal/server/auth/password.go`:

```go
// Package auth authenticates administrators and manages their sessions.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// ErrWeakPassword marks a password the policy rejects.
var ErrWeakPassword = errors.New("password does not meet the policy")

// Password policy and Argon2id parameters.
const (
	MinPasswordLength = 12
	maxPasswordLength = 1024

	argonMemory  = 64 * 1024 // KiB
	argonTime    = 3
	argonLanes   = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

// HashPassword returns an encoded Argon2id hash.
func HashPassword(password string) (string, error) {
	switch {
	case len(password) < MinPasswordLength:
		return "", fmt.Errorf("%w: at least %d characters are required", ErrWeakPassword, MinPasswordLength)
	case len(password) > maxPasswordLength:
		return "", fmt.Errorf("%w: at most %d characters are allowed", ErrWeakPassword, maxPasswordLength)
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonLanes, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonLanes,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword reports whether password matches the encoded hash. A
// malformed hash simply fails.
func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version, memory, iterations, lanes int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &lanes); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, uint32(iterations), uint32(memory), uint8(lanes), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// GeneratePassword returns a random password that satisfies the policy.
func GeneratePassword() (string, error) {
	b := make([]byte, 15)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
```

`internal/server/auth/totp.go`:

```go
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
```

`internal/server/auth/ratelimit.go`:

```go
package auth

import (
	"sync"
	"time"
)

// Limiter counts recent failures per key, in memory. A restart forgets them,
// which is acceptable for slowing down password guessing.
type Limiter struct {
	max    int
	window time.Duration
	now    func() time.Time

	mu       sync.Mutex
	failures map[string][]time.Time
}

// NewLimiter allows max failures per key within window.
func NewLimiter(max int, window time.Duration, now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	return &Limiter{max: max, window: window, now: now, failures: map[string][]time.Time{}}
}

// Allowed reports whether the key may attempt again.
func (l *Limiter) Allowed(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recent(key)) < l.max
}

// Fail records one failed attempt.
func (l *Limiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failures[key] = append(l.recent(key), l.now())
}

// Reset clears a key's failures after a success.
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, key)
}

// recent drops expired entries; callers hold the lock.
func (l *Limiter) recent(key string) []time.Time {
	cutoff := l.now().Add(-l.window)
	kept := l.failures[key][:0]
	for _, at := range l.failures[key] {
		if at.After(cutoff) {
			kept = append(kept, at)
		}
	}
	l.failures[key] = kept
	return kept
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go mod tidy && go vet ./internal/server/auth/ && go test ./internal/server/auth/`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/server/auth
git commit -m "feat(auth): Argon2id passwords, TOTP secrets and login rate limiting"
```

---

### Task 3: Auth service

**Files:**
- Create: `internal/server/auth/service.go`, `internal/server/auth/service_test.go`

**Interfaces:**
- Consumes: Task 1 store queries, Task 2 helpers
- Produces:
  - `auth.Service{Store *store.Store; Now func() time.Time; SessionTTL time.Duration; Limiter *Limiter; Issuer string}`
  - `auth.SessionInfo{Token, CSRFToken string; ExpiresAt time.Time}`
  - `(*Service).Authenticate(ctx, email, password, totpCode string) (store.Admin, error)`
  - `(*Service).CreateSession(ctx, adminID uuid.UUID, userAgent, ip string) (SessionInfo, error)`
  - `(*Service).ValidateSession(ctx, token string) (store.Admin, store.Session, error)`
  - `(*Service).DeleteSession(ctx, token string) error`
  - `(*Service).CreateAdmin(ctx, CreateAdminOptions) (store.Admin, error)`; `auth.CreateAdminOptions{Email, Password, Role, Actor string}`
  - `(*Service).SetPassword(ctx, id uuid.UUID, password, actor string) error` (also signs that admin out everywhere)
  - `(*Service).EnableTOTP(ctx, id uuid.UUID, actor string) (secret, url string, err error)`, `(*Service).DisableTOTP(ctx, id uuid.UUID, actor string) error`
  - `(*Service).SetDisabled(ctx, id uuid.UUID, disabled bool, actor string) error`
  - `(*Service).List(ctx) ([]store.Admin, error)`, `(*Service).HasAdmins(ctx) (bool, error)`
  - Errors: `ErrInvalidCredentials`, `ErrTOTPRequired`, `ErrTOTPInvalid`, `ErrAccountDisabled`, `ErrTooManyAttempts`, `ErrInvalidSession`, `ErrNotFound`, `ErrBadRequest`, `ErrLastAdmin`

- [ ] **Step 1: Write the failing test**

`internal/server/auth/service_test.go`:

```go
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

	// Validation.
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

	// Lockout after repeated failures, cleared by the window passing.
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

	// Use extends the session; expiry ends it.
	clock = now.Add(2 * time.Hour)
	if _, gotSession, err = svc.ValidateSession(ctx, info.Token); err != nil || !gotSession.ExpiresAt.Equal(clock.Add(12*time.Hour)) {
		t.Fatalf("session not extended: %+v, %v", gotSession, err)
	}
	clock = clock.Add(13 * time.Hour)
	if _, _, err := svc.ValidateSession(ctx, info.Token); !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatalf("expired session err = %v", err)
	}

	// A disabled admin cannot use an existing session or sign in.
	clock = now
	info, err = svc.CreateSession(ctx, admin.ID, "curl", "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	reader, err := svc.CreateAdmin(ctx, auth.CreateAdminOptions{
		Email: "viewer@example.com", Password: "correct horse battery", Role: store.RoleReadOnly, Actor: "cli",
	})
	if err != nil {
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
	if _, _, err := svc.ValidateSession(ctx, info.Token); !errors.Is(err, auth.ErrAccountDisabled) {
		t.Fatalf("disabled admin session err = %v", err)
	}
	if _, err := svc.Authenticate(ctx, "ops@example.com", "correct horse battery", ""); !errors.Is(err, auth.ErrAccountDisabled) {
		t.Fatalf("disabled admin login err = %v", err)
	}

	// Changing a password signs that admin out.
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
	_ = reader

	entries, err := svc.Store.Q().ListAudit(ctx, 200)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, e := range entries {
		seen[e.Action]++
	}
	for _, action := range []string{"admin.created", "admin.login", "admin.totp_enabled", "admin.totp_disabled", "admin.disabled", "admin.password_changed"} {
		if seen[action] == 0 {
			t.Errorf("missing audit action %s (saw %v)", action, seen)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/server/auth/ -run TestAuthenticate`
Expected: FAIL — `undefined: auth.Service`.

- [ ] **Step 3: Implement the service**

`internal/server/auth/service.go`:

```go
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/store"
)

var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrTOTPRequired       = errors.New("an authenticator code is required")
	ErrTOTPInvalid        = errors.New("invalid authenticator code")
	ErrAccountDisabled    = errors.New("this account is disabled")
	ErrTooManyAttempts    = errors.New("too many failed sign-in attempts")
	ErrInvalidSession     = errors.New("session is invalid or expired")
	ErrNotFound           = errors.New("admin not found")
	ErrBadRequest         = errors.New("bad request")
	ErrLastAdmin          = errors.New("the last enabled admin cannot be disabled")
)

// touchInterval is how stale a session's last_seen may get before the row is
// updated, so a busy console does not write on every request.
const touchInterval = time.Minute

// Service authenticates admins and manages their sessions.
type Service struct {
	Store      *store.Store
	Now        func() time.Time
	SessionTTL time.Duration
	Limiter    *Limiter
	Issuer     string
}

// SessionInfo is a freshly created session.
type SessionInfo struct {
	Token     string
	CSRFToken string
	ExpiresAt time.Time
}

// CreateAdminOptions describe a new admin account.
type CreateAdminOptions struct {
	Email    string
	Password string
	Role     string
	Actor    string
}

// dummyHash lets an unknown email cost the same as a known one.
var dummyHash = sync.OnceValue(func() string {
	h, err := HashPassword("retune-dummy-password-for-timing")
	if err != nil {
		panic(err)
	}
	return h
})

// Authenticate checks an email, password and (when enabled) TOTP code.
func (s *Service) Authenticate(ctx context.Context, email, password, totpCode string) (store.Admin, error) {
	key := strings.ToLower(strings.TrimSpace(email))
	if s.Limiter != nil && !s.Limiter.Allowed(key) {
		return store.Admin{}, ErrTooManyAttempts
	}
	admin, err := s.Store.Q().GetAdminByEmail(ctx, key)
	if errors.Is(err, store.ErrNotFound) {
		VerifyPassword(dummyHash(), password) // keep the timing similar
		s.fail(key)
		return store.Admin{}, ErrInvalidCredentials
	}
	if err != nil {
		return store.Admin{}, err
	}
	if !VerifyPassword(admin.PasswordHash, password) {
		s.fail(key)
		return store.Admin{}, ErrInvalidCredentials
	}
	if admin.DisabledAt != nil {
		return store.Admin{}, ErrAccountDisabled
	}
	if admin.TOTPSecret != "" {
		if totpCode == "" {
			return store.Admin{}, ErrTOTPRequired
		}
		if !ValidateTOTP(admin.TOTPSecret, totpCode) {
			s.fail(key)
			return store.Admin{}, ErrTOTPInvalid
		}
	}
	if s.Limiter != nil {
		s.Limiter.Reset(key)
	}
	now := s.Now()
	err = s.Store.InTx(ctx, func(q *store.Queries) error {
		if err := q.RecordAdminLogin(ctx, admin.ID, now); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: admin.Email, Action: "admin.login", TargetKind: "admin", TargetID: admin.ID.String(),
		})
	})
	if err != nil {
		return store.Admin{}, err
	}
	admin.LastLoginAt = &now
	return admin, nil
}

func (s *Service) fail(key string) {
	if s.Limiter != nil {
		s.Limiter.Fail(key)
	}
}

// CreateSession issues a session token and its CSRF token.
func (s *Service) CreateSession(ctx context.Context, adminID uuid.UUID, userAgent, ip string) (SessionInfo, error) {
	token, err := randomToken()
	if err != nil {
		return SessionInfo{}, err
	}
	csrf, err := randomToken()
	if err != nil {
		return SessionInfo{}, err
	}
	now := s.Now()
	expires := now.Add(s.SessionTTL)
	hash := hashToken(token)
	if err := s.Store.Q().CreateSession(ctx, store.Session{
		TokenHash: hash, AdminID: adminID, CSRFToken: csrf,
		CreatedAt: now, ExpiresAt: expires, LastSeenAt: now,
		UserAgent: trim(userAgent, 256), IP: trim(ip, 64),
	}); err != nil {
		return SessionInfo{}, err
	}
	return SessionInfo{Token: token, CSRFToken: csrf, ExpiresAt: expires}, nil
}

// ValidateSession returns the signed-in admin, extending the session's life.
func (s *Service) ValidateSession(ctx context.Context, token string) (store.Admin, store.Session, error) {
	hash := hashToken(token)
	q := s.Store.Q()
	session, admin, err := q.GetSessionWithAdmin(ctx, hash)
	if errors.Is(err, store.ErrNotFound) {
		return store.Admin{}, store.Session{}, ErrInvalidSession
	}
	if err != nil {
		return store.Admin{}, store.Session{}, err
	}
	now := s.Now()
	if !now.Before(session.ExpiresAt) {
		if err := q.DeleteSession(ctx, hash); err != nil {
			return store.Admin{}, store.Session{}, err
		}
		return store.Admin{}, store.Session{}, ErrInvalidSession
	}
	if admin.DisabledAt != nil {
		if err := q.DeleteSessionsForAdmin(ctx, admin.ID); err != nil {
			return store.Admin{}, store.Session{}, err
		}
		return store.Admin{}, store.Session{}, ErrAccountDisabled
	}
	if now.Sub(session.LastSeenAt) >= touchInterval {
		expires := now.Add(s.SessionTTL)
		if err := q.TouchSession(ctx, hash, now, expires); err != nil {
			return store.Admin{}, store.Session{}, err
		}
		session.LastSeenAt, session.ExpiresAt = now, expires
	}
	return admin, session, nil
}

// DeleteSession signs one browser out. An unknown token is not an error.
func (s *Service) DeleteSession(ctx context.Context, token string) error {
	return s.Store.Q().DeleteSession(ctx, hashToken(token))
}

// CreateAdmin adds an account.
func (s *Service) CreateAdmin(ctx context.Context, o CreateAdminOptions) (store.Admin, error) {
	email := strings.TrimSpace(o.Email)
	if !validEmail(email) {
		return store.Admin{}, fmt.Errorf("%w: %q is not a valid email address", ErrBadRequest, o.Email)
	}
	if o.Role != store.RoleAdmin && o.Role != store.RoleReadOnly {
		return store.Admin{}, fmt.Errorf("%w: role must be %s or %s", ErrBadRequest, store.RoleAdmin, store.RoleReadOnly)
	}
	hash, err := HashPassword(o.Password)
	if err != nil {
		return store.Admin{}, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return store.Admin{}, err
	}
	admin := store.Admin{ID: id, Email: email, PasswordHash: hash, Role: o.Role, CreatedAt: s.Now()}
	err = s.Store.InTx(ctx, func(q *store.Queries) error {
		if err := q.CreateAdmin(ctx, admin); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: o.Actor, Action: "admin.created", TargetKind: "admin", TargetID: id.String(),
			Details: map[string]any{"email": email, "role": o.Role},
		})
	})
	if err != nil {
		return store.Admin{}, err
	}
	return admin, nil
}

// SetPassword replaces a password and signs that admin out everywhere.
func (s *Service) SetPassword(ctx context.Context, id uuid.UUID, password, actor string) error {
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	return s.Store.InTx(ctx, func(q *store.Queries) error {
		admin, err := q.GetAdmin(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("%w: %s", ErrNotFound, id)
		}
		if err != nil {
			return err
		}
		if err := q.UpdateAdminPassword(ctx, id, hash); err != nil {
			return err
		}
		if err := q.DeleteSessionsForAdmin(ctx, id); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: actor, Action: "admin.password_changed", TargetKind: "admin", TargetID: id.String(),
			Details: map[string]any{"email": admin.Email},
		})
	})
}

// EnableTOTP generates a secret and returns it with its otpauth URL.
func (s *Service) EnableTOTP(ctx context.Context, id uuid.UUID, actor string) (string, string, error) {
	var secret, url string
	err := s.Store.InTx(ctx, func(q *store.Queries) error {
		admin, err := q.GetAdmin(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("%w: %s", ErrNotFound, id)
		}
		if err != nil {
			return err
		}
		if secret, url, err = NewTOTPSecret(s.Issuer, admin.Email); err != nil {
			return err
		}
		if err := q.UpdateAdminTOTP(ctx, id, secret); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: actor, Action: "admin.totp_enabled", TargetKind: "admin", TargetID: id.String(),
		})
	})
	if err != nil {
		return "", "", err
	}
	return secret, url, nil
}

// DisableTOTP turns two-factor authentication off for an admin.
func (s *Service) DisableTOTP(ctx context.Context, id uuid.UUID, actor string) error {
	return s.Store.InTx(ctx, func(q *store.Queries) error {
		if _, err := q.GetAdmin(ctx, id); errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("%w: %s", ErrNotFound, id)
		} else if err != nil {
			return err
		}
		if err := q.UpdateAdminTOTP(ctx, id, ""); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: actor, Action: "admin.totp_disabled", TargetKind: "admin", TargetID: id.String(),
		})
	})
}

// SetDisabled disables or re-enables an account. The last enabled admin
// cannot be disabled, so nobody can lock everyone out.
func (s *Service) SetDisabled(ctx context.Context, id uuid.UUID, disabled bool, actor string) error {
	now := s.Now()
	return s.Store.InTx(ctx, func(q *store.Queries) error {
		admin, err := q.GetAdmin(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("%w: %s", ErrNotFound, id)
		}
		if err != nil {
			return err
		}
		if disabled {
			others, err := q.ListAdmins(ctx)
			if err != nil {
				return err
			}
			enabled := 0
			for _, a := range others {
				if a.Role == store.RoleAdmin && a.DisabledAt == nil && a.ID != id {
					enabled++
				}
			}
			if admin.Role == store.RoleAdmin && enabled == 0 {
				return ErrLastAdmin
			}
		}
		var at *time.Time
		action := "admin.enabled"
		if disabled {
			at, action = &now, "admin.disabled"
		}
		if err := q.SetAdminDisabled(ctx, id, at); err != nil {
			return err
		}
		if disabled {
			if err := q.DeleteSessionsForAdmin(ctx, id); err != nil {
				return err
			}
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: actor, Action: action, TargetKind: "admin", TargetID: id.String(),
			Details: map[string]any{"email": admin.Email},
		})
	})
}

// List returns every admin account.
func (s *Service) List(ctx context.Context) ([]store.Admin, error) {
	return s.Store.Q().ListAdmins(ctx)
}

// HasAdmins reports whether any account exists yet.
func (s *Service) HasAdmins(ctx context.Context) (bool, error) {
	n, err := s.Store.Q().CountAdmins(ctx)
	return n > 0, err
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// validEmail is deliberately permissive: one @ with text either side.
func validEmail(email string) bool {
	at := strings.IndexByte(email, '@')
	return at > 0 && at < len(email)-1 && len(email) <= 320 &&
		!strings.ContainsAny(email, " \t\r\n") && strings.Count(email, "@") == 1
}

func trim(s string, max int) string {
	if len(s) > max {
		return s[:max]
	}
	return s
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go vet ./internal/server/auth/ && go test -count=1 ./internal/server/auth/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/server/auth
git commit -m "feat(auth): sessions, admin management and audited sign-in"
```

---

### Task 4: Filtered list queries

**Files:**
- Create: `internal/server/store/lists.go`, `internal/server/store/store_lists_test.go`

**Interfaces:**
- Consumes: M1/M2 store
- Produces:
  - `store.Page{Limit, Offset int}` with `(Page).Normalized() Page` (limit 1–200, default 50)
  - `store.DeviceFilter{Search, Status string; Page}`; `(*Queries).ListDevicesPage(ctx, DeviceFilter) ([]Device, int, error)` — returns the rows and the total before paging
  - `store.CommandFilter{DeviceID *uuid.UUID; Status string; Page}`; `(*Queries).ListCommandsPage(ctx, CommandFilter) ([]Command, int, error)`
  - `(*Queries).ListEnrollmentTokens(ctx) ([]EnrollmentToken, error)`
  - `(*Queries).ListAuditPage(ctx, Page) ([]AuditEntry, int, error)`

- [ ] **Step 1: Write the failing test**

`internal/server/store/store_lists_test.go`:

```go
package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

func TestListDevicesPage(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	q := s.Q()
	now := time.Now().UTC().Truncate(time.Microsecond)

	mk := func(hostname, serial, status string) store.Device {
		d := store.Device{
			ID: uuid.Must(uuid.NewV7()), Hostname: hostname, Serial: serial, Status: status,
			CertSerial: "c1", CertExpiresAt: now.Add(time.Hour), EnrolledAt: now,
		}
		if err := q.CreateDevice(ctx, d); err != nil {
			t.Fatal(err)
		}
		return d
	}
	mk("PC-ALPHA", "SN-100", store.DeviceActive)
	mk("PC-BETA", "SN-200", store.DeviceActive)
	mk("PC-GAMMA", "SN-300", store.DeviceRetired)
	if err := q.UpdateDeviceHardware(ctx, mk("PC-DELTA", "SN-400", store.DeviceActive).ID,
		store.HardwareInfo{Model: "Latitude 7440"}); err != nil {
		t.Fatal(err)
	}

	all, total, err := q.ListDevicesPage(ctx, store.DeviceFilter{})
	if err != nil || len(all) != 4 || total != 4 {
		t.Fatalf("all = %d rows, total = %d, err = %v", len(all), total, err)
	}

	active, total, err := q.ListDevicesPage(ctx, store.DeviceFilter{Status: store.DeviceActive})
	if err != nil || len(active) != 3 || total != 3 {
		t.Fatalf("active = %d rows, total = %d, err = %v", len(active), total, err)
	}

	byHost, _, err := q.ListDevicesPage(ctx, store.DeviceFilter{Search: "beta"})
	if err != nil || len(byHost) != 1 || byHost[0].Hostname != "PC-BETA" {
		t.Fatalf("hostname search = %+v, err = %v", byHost, err)
	}
	bySerial, _, err := q.ListDevicesPage(ctx, store.DeviceFilter{Search: "SN-300"})
	if err != nil || len(bySerial) != 1 || bySerial[0].Hostname != "PC-GAMMA" {
		t.Fatalf("serial search = %+v, err = %v", bySerial, err)
	}
	byModel, _, err := q.ListDevicesPage(ctx, store.DeviceFilter{Search: "latitude"})
	if err != nil || len(byModel) != 1 || byModel[0].Hostname != "PC-DELTA" {
		t.Fatalf("model search = %+v, err = %v", byModel, err)
	}
	if none, total, _ := q.ListDevicesPage(ctx, store.DeviceFilter{Search: "nothing"}); len(none) != 0 || total != 0 {
		t.Fatalf("no matches = %d rows, total %d", len(none), total)
	}

	// Paging reports the unpaged total.
	page1, total, err := q.ListDevicesPage(ctx, store.DeviceFilter{Page: store.Page{Limit: 2}})
	if err != nil || len(page1) != 2 || total != 4 {
		t.Fatalf("page 1 = %d rows, total = %d, err = %v", len(page1), total, err)
	}
	page2, _, err := q.ListDevicesPage(ctx, store.DeviceFilter{Page: store.Page{Limit: 2, Offset: 2}})
	if err != nil || len(page2) != 2 || page2[0].ID == page1[0].ID {
		t.Fatalf("page 2 = %+v, err = %v", page2, err)
	}
}

func TestListCommandsAndTokensAndAudit(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	q := s.Q()
	now := time.Now().UTC().Truncate(time.Microsecond)
	d1 := newDevice(t, q, "PC-1")
	d2 := newDevice(t, q, "PC-2")

	mkCmd := func(device uuid.UUID, status string) store.Command {
		c := store.Command{
			ID: uuid.Must(uuid.NewV7()), DeviceID: device, Type: "refresh_inventory",
			Payload: []byte(`{}`), Status: status, CreatedBy: "test", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		}
		if err := q.CreateCommand(ctx, c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	mkCmd(d1.ID, store.CommandQueued)
	mkCmd(d1.ID, store.CommandSucceeded)
	mkCmd(d2.ID, store.CommandQueued)

	all, total, err := q.ListCommandsPage(ctx, store.CommandFilter{})
	if err != nil || len(all) != 3 || total != 3 {
		t.Fatalf("all commands = %d, total = %d, err = %v", len(all), total, err)
	}
	forDevice, total, err := q.ListCommandsPage(ctx, store.CommandFilter{DeviceID: &d1.ID})
	if err != nil || len(forDevice) != 2 || total != 2 {
		t.Fatalf("device commands = %d, total = %d, err = %v", len(forDevice), total, err)
	}
	queued, _, err := q.ListCommandsPage(ctx, store.CommandFilter{Status: store.CommandQueued})
	if err != nil || len(queued) != 2 {
		t.Fatalf("queued commands = %d, err = %v", len(queued), err)
	}

	for _, label := range []string{"t1", "t2"} {
		if err := q.CreateEnrollmentToken(ctx, store.EnrollmentToken{
			ID: uuid.Must(uuid.NewV7()), TokenHash: []byte("hash-" + label), Label: label, CreatedBy: "test",
		}); err != nil {
			t.Fatal(err)
		}
	}
	tokens, err := q.ListEnrollmentTokens(ctx)
	if err != nil || len(tokens) != 2 {
		t.Fatalf("tokens = %+v, err = %v", tokens, err)
	}

	for _, action := range []string{"a.one", "a.two", "a.three"} {
		if err := q.InsertAudit(ctx, store.AuditEntry{Actor: "test", Action: action, TargetKind: "device", TargetID: d1.ID.String()}); err != nil {
			t.Fatal(err)
		}
	}
	page, total, err := q.ListAuditPage(ctx, store.Page{Limit: 2})
	if err != nil || len(page) != 2 || total != 3 {
		t.Fatalf("audit page = %d rows, total = %d, err = %v", len(page), total, err)
	}
	if page[0].Action != "a.three" {
		t.Fatalf("audit must be newest first, got %s", page[0].Action)
	}
}

func TestPageNormalized(t *testing.T) {
	cases := map[store.Page]store.Page{
		{}:                      {Limit: 50},
		{Limit: 10, Offset: 20}: {Limit: 10, Offset: 20},
		{Limit: 5000}:           {Limit: 200},
		{Limit: -3, Offset: -9}: {Limit: 50},
	}
	for in, want := range cases {
		if got := in.Normalized(); got != want {
			t.Errorf("%+v.Normalized() = %+v, want %+v", in, got, want)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/server/store/ -run 'TestList|TestPage'`
Expected: FAIL — `undefined: store.Page`.

- [ ] **Step 3: Implement the queries**

`internal/server/store/lists.go`:

```go
package store

import (
	"context"

	"github.com/google/uuid"
)

// Paging defaults.
const (
	DefaultPageLimit = 50
	MaxPageLimit     = 200
)

// Page is a limit/offset window.
type Page struct {
	Limit  int
	Offset int
}

// Normalized clamps a page into the supported range.
func (p Page) Normalized() Page {
	if p.Limit <= 0 {
		p.Limit = DefaultPageLimit
	}
	if p.Limit > MaxPageLimit {
		p.Limit = MaxPageLimit
	}
	if p.Offset < 0 {
		p.Offset = 0
	}
	return p
}

// DeviceFilter narrows a device listing. Search matches hostname, serial,
// SMBIOS UUID, manufacturer and model.
type DeviceFilter struct {
	Search string
	Status string
	Page   Page
}

// ListDevicesPage returns one page of devices and the total number of matches.
func (q *Queries) ListDevicesPage(ctx context.Context, f DeviceFilter) ([]Device, int, error) {
	p := f.Page.Normalized()
	rows, err := q.db.Query(ctx, `
		SELECT `+deviceCols+`, count(*) OVER () AS total FROM devices
		WHERE ($1 = '' OR status = $1)
		  AND ($2 = '' OR hostname ILIKE '%' || $2 || '%' OR serial ILIKE '%' || $2 || '%'
		       OR smbios_uuid ILIKE '%' || $2 || '%' OR manufacturer ILIKE '%' || $2 || '%'
		       OR model ILIKE '%' || $2 || '%')
		ORDER BY lower(hostname), enrolled_at
		LIMIT $3 OFFSET $4`, f.Status, f.Search, p.Limit, p.Offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Device
	total := 0
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.Hostname, &d.Serial, &d.SMBIOSUUID, &d.OSVersion, &d.Status, &d.CertSerial,
			&d.CertExpiresAt, &d.LastSeenAt, &d.AgentVersion, &d.EnrolledAt, &d.ReplacedBy,
			&d.PrevCertSerial, &d.OSBuild, &d.Manufacturer, &d.Model, &total); err != nil {
			return nil, 0, err
		}
		out = append(out, d)
	}
	return out, total, rows.Err()
}

// CommandFilter narrows a command listing.
type CommandFilter struct {
	DeviceID *uuid.UUID
	Status   string
	Page     Page
}

// ListCommandsPage returns one page of commands, newest first, and the total.
func (q *Queries) ListCommandsPage(ctx context.Context, f CommandFilter) ([]Command, int, error) {
	p := f.Page.Normalized()
	rows, err := q.db.Query(ctx, `
		SELECT `+commandCols+`, count(*) OVER () AS total FROM commands
		WHERE ($1::uuid IS NULL OR device_id = $1)
		  AND ($2 = '' OR status = $2)
		ORDER BY created_at DESC, id DESC
		LIMIT $3 OFFSET $4`, f.DeviceID, f.Status, p.Limit, p.Offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Command
	total := 0
	for rows.Next() {
		var c Command
		if err := rows.Scan(&c.ID, &c.DeviceID, &c.Type, &c.Payload, &c.Status, &c.CreatedBy, &c.CreatedAt,
			&c.DeliveredAt, &c.StartedAt, &c.CompletedAt, &c.ExpiresAt, &total); err != nil {
			return nil, 0, err
		}
		out = append(out, c)
	}
	return out, total, rows.Err()
}

// ListEnrollmentTokens returns every token, newest first.
func (q *Queries) ListEnrollmentTokens(ctx context.Context) ([]EnrollmentToken, error) {
	rows, err := q.db.Query(ctx, `SELECT `+tokenCols+` FROM enrollment_tokens ORDER BY created_at DESC, id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EnrollmentToken
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ListAuditPage returns one page of audit entries, newest first, and the total.
func (q *Queries) ListAuditPage(ctx context.Context, page Page) ([]AuditEntry, int, error) {
	p := page.Normalized()
	rows, err := q.db.Query(ctx, `
		SELECT actor, action, target_kind, target_id, details, at, count(*) OVER () AS total
		FROM audit_log ORDER BY at DESC, id DESC LIMIT $1 OFFSET $2`, p.Limit, p.Offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []AuditEntry
	total := 0
	for rows.Next() {
		var a AuditEntry
		var raw []byte
		if err := rows.Scan(&a.Actor, &a.Action, &a.TargetKind, &a.TargetID, &raw, &a.At, &total); err != nil {
			return nil, 0, err
		}
		if err := unmarshalDetails(raw, &a); err != nil {
			return nil, 0, err
		}
		out = append(out, a)
	}
	return out, total, rows.Err()
}
```

Add the shared helper to `internal/server/store/audit.go` and use it in `ListAudit` too:

```go
func unmarshalDetails(raw []byte, a *AuditEntry) error {
	if err := json.Unmarshal(raw, &a.Details); err != nil {
		return fmt.Errorf("unmarshal audit details: %w", err)
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go vet ./internal/server/store/ && go test -count=1 ./internal/server/store/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/server/store
git commit -m "feat(store): filtered, paginated listings for the admin API"
```

---

### Task 5: Configuration file and session TTL

**Files:**
- Create: `internal/config/file.go`, `internal/config/file_test.go`
- Modify: `internal/config/server.go`, `internal/config/server_test.go`, `docs/superpowers/specs/2026-09-12-core-platform-design.md`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `config.Server` gains `SessionTTL time.Duration` (env `SESSION_TTL_HOURS`, default 12, range 1–168)
  - `LoadServer` now reads a YAML file when `RETUNE_CONFIG` names one, or `retune-server.yaml` exists in the working directory; environment variables win over file values
  - YAML keys: `database_url`, `public_url`, `agent_api_listen`, `tls_mode`, `tls_cert_file`, `tls_key_file`, `data_dir`, `checkin_interval_seconds`, `session_ttl_hours`. Unknown keys are an error.

**Spec note:** the admin API and console share the agent listener, so there is no separate `ADMIN_API_LISTEN`. Update the spec's config list in §2 accordingly as part of this task.

- [ ] **Step 1: Write the failing tests**

`internal/config/file_test.go`:

```go
package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "retune-server.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadServerFromFile(t *testing.T) {
	path := writeFile(t, `
database_url: postgres://file/retune
public_url: https://mdm.file.example
agent_api_listen: 127.0.0.1:9443
data_dir: /var/lib/retune
checkin_interval_seconds: 120
session_ttl_hours: 24
`)
	c, err := LoadServer(env(map[string]string{"RETUNE_CONFIG": path}))
	if err != nil {
		t.Fatal(err)
	}
	if c.DatabaseURL != "postgres://file/retune" || c.PublicURL != "https://mdm.file.example" ||
		c.AgentListen != "127.0.0.1:9443" || c.DataDir != "/var/lib/retune" ||
		c.CheckinInterval != 2*time.Minute || c.SessionTTL != 24*time.Hour {
		t.Fatalf("config = %+v", c)
	}
}

func TestEnvironmentBeatsFile(t *testing.T) {
	path := writeFile(t, "database_url: postgres://file/retune\npublic_url: https://file.example\n")
	c, err := LoadServer(env(map[string]string{
		"RETUNE_CONFIG": path,
		"PUBLIC_URL":    "https://env.example",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.PublicURL != "https://env.example" || c.DatabaseURL != "postgres://file/retune" {
		t.Fatalf("config = %+v", c)
	}
}

func TestConfigFileErrors(t *testing.T) {
	if _, err := LoadServer(env(map[string]string{"RETUNE_CONFIG": "does-not-exist.yaml"})); err == nil {
		t.Fatal("a named config file that is missing must be an error")
	}
	bad := writeFile(t, "database_url: postgres://x\npublic_url: https://h\nnonsense_key: 1\n")
	_, err := LoadServer(env(map[string]string{"RETUNE_CONFIG": bad}))
	if err == nil || !strings.Contains(err.Error(), "nonsense_key") {
		t.Fatalf("unknown key err = %v", err)
	}
	broken := writeFile(t, "database_url: [unclosed\n")
	if _, err := LoadServer(env(map[string]string{"RETUNE_CONFIG": broken})); err == nil {
		t.Fatal("malformed YAML must be an error")
	}
}
```

Append to `internal/config/server_test.go`:

```go
func TestSessionTTL(t *testing.T) {
	base := map[string]string{"DATABASE_URL": "postgres://x", "PUBLIC_URL": "https://h"}
	c, err := LoadServer(env(base))
	if err != nil || c.SessionTTL != 12*time.Hour {
		t.Fatalf("default SessionTTL = %s, err = %v", c.SessionTTL, err)
	}
	base["SESSION_TTL_HOURS"] = "36"
	if c, err = LoadServer(env(base)); err != nil || c.SessionTTL != 36*time.Hour {
		t.Fatalf("SessionTTL = %s, err = %v", c.SessionTTL, err)
	}
	for _, bad := range []string{"0", "-1", "200", "abc"} {
		base["SESSION_TTL_HOURS"] = bad
		if _, err := LoadServer(env(base)); err == nil {
			t.Errorf("SESSION_TTL_HOURS=%s must be rejected", bad)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/config/`
Expected: FAIL — `c.SessionTTL undefined`.

- [ ] **Step 3: Implement file loading**

`internal/config/file.go`:

```go
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

// DefaultConfigFile is read when it exists and RETUNE_CONFIG is unset.
const DefaultConfigFile = "retune-server.yaml"

// fileConfig mirrors the environment variables in YAML form.
type fileConfig struct {
	DatabaseURL            string `yaml:"database_url"`
	PublicURL              string `yaml:"public_url"`
	AgentAPIListen         string `yaml:"agent_api_listen"`
	TLSMode                string `yaml:"tls_mode"`
	TLSCertFile            string `yaml:"tls_cert_file"`
	TLSKeyFile             string `yaml:"tls_key_file"`
	DataDir                string `yaml:"data_dir"`
	CheckinIntervalSeconds int    `yaml:"checkin_interval_seconds"`
	SessionTTLHours        int    `yaml:"session_ttl_hours"`
}

// loadConfigFile turns the YAML file, if any, into environment-style values.
func loadConfigFile(getenv func(string) string) (map[string]string, error) {
	path := getenv("RETUNE_CONFIG")
	named := path != ""
	if !named {
		path = DefaultConfigFile
	}
	body, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist) && !named:
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("read config file %s: %w", path, err)
	}

	var f fileConfig
	dec := yaml.NewDecoder(newReader(body))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("parse config file %s: %w", path, err)
	}
	out := map[string]string{}
	set := func(key, value string) {
		if value != "" {
			out[key] = value
		}
	}
	set("DATABASE_URL", f.DatabaseURL)
	set("PUBLIC_URL", f.PublicURL)
	set("AGENT_API_LISTEN", f.AgentAPIListen)
	set("TLS_MODE", f.TLSMode)
	set("TLS_CERT_FILE", f.TLSCertFile)
	set("TLS_KEY_FILE", f.TLSKeyFile)
	set("DATA_DIR", f.DataDir)
	if f.CheckinIntervalSeconds != 0 {
		set("CHECKIN_INTERVAL_SECONDS", strconv.Itoa(f.CheckinIntervalSeconds))
	}
	if f.SessionTTLHours != 0 {
		set("SESSION_TTL_HOURS", strconv.Itoa(f.SessionTTLHours))
	}
	return out, nil
}
```

Add the tiny reader helper at the bottom of the same file:

```go
type bytesReader struct {
	body []byte
	pos  int
}

func newReader(body []byte) *bytesReader { return &bytesReader{body: body} }

func (r *bytesReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.body) {
		return 0, io.EOF
	}
	n := copy(p, r.body[r.pos:])
	r.pos += n
	return n, nil
}
```

Add `"io"` to that file's imports. (A `bytes.Reader` would do the same; this avoids importing `bytes` only for one call — either is fine, so if you prefer, use `bytes.NewReader` and drop this helper.)

- [ ] **Step 4: Wire the file and session TTL into LoadServer**

In `internal/config/server.go`, add the field to `Server`:

```go
	SessionTTL      time.Duration
```

and replace the first lines of `LoadServer` so values fall back to the file:

```go
func LoadServer(getenv func(string) string) (Server, error) {
	fileValues, err := loadConfigFile(getenv)
	if err != nil {
		return Server{}, err
	}
	lookup := func(key string) string {
		if v := getenv(key); v != "" {
			return v
		}
		return fileValues[key]
	}
	c := Server{
		DatabaseURL:     lookup("DATABASE_URL"),
		PublicURL:       lookup("PUBLIC_URL"),
		AgentListen:     or(lookup("AGENT_API_LISTEN"), ":8443"),
		TLSMode:         or(lookup("TLS_MODE"), "self-signed"),
		TLSCertFile:     lookup("TLS_CERT_FILE"),
		TLSKeyFile:      lookup("TLS_KEY_FILE"),
		DataDir:         or(lookup("DATA_DIR"), "data"),
		CheckinInterval: 5 * time.Minute,
		SessionTTL:      12 * time.Hour,
	}
	if v := lookup("CHECKIN_INTERVAL_SECONDS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 30 {
			return Server{}, errors.New("CHECKIN_INTERVAL_SECONDS must be an integer >= 30")
		}
		c.CheckinInterval = time.Duration(n) * time.Second
	}
	if v := lookup("SESSION_TTL_HOURS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 168 {
			return Server{}, errors.New("SESSION_TTL_HOURS must be an integer between 1 and 168")
		}
		c.SessionTTL = time.Duration(n) * time.Hour
	}
```

The rest of `LoadServer` (the `DATABASE_URL`, `PUBLIC_URL` and `TLS_MODE` validation) stays as it is.

- [ ] **Step 5: Update the spec's configuration list**

In `docs/superpowers/specs/2026-09-12-core-platform-design.md` §2, replace the config-precedence line with:

```markdown
Config precedence: environment variables > `retune-server.yaml` (or the file named by `RETUNE_CONFIG`) > defaults. Key settings: `DATABASE_URL`, `PUBLIC_URL`, `TLS_MODE` (`self-signed` | `provided` | `behind-proxy`), `TLS_CERT_FILE`, `TLS_KEY_FILE`, `CA_KEY_SOURCE`, `AGENT_API_LISTEN`, `DATA_DIR`, `CHECKIN_INTERVAL_SECONDS`, `SESSION_TTL_HOURS`. The admin API and console are served on the same listener as the agent API.
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `go mod tidy && go vet ./internal/config/ && go test ./internal/config/`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add go.mod go.sum internal/config docs/superpowers/specs
git commit -m "feat(config): YAML config file and session TTL"
```

---

### Task 6: Admin API core — sessions, CSRF and roles

**Files:**
- Create: `internal/server/adminapi/json.go`, `internal/server/adminapi/handler.go`, `internal/server/adminapi/session.go`, `internal/server/app/app_admin_test.go`, `internal/server/app/admin_helpers_test.go`
- Modify: `internal/server/app/app.go`

**Interfaces:**
- Consumes: Tasks 1–5
- Produces:
  - `adminapi.Handler{Auth *auth.Service; Store *store.Store; Commands *commands.Service; Devices *devices.Service; Enroll *enroll.Service; Now func() time.Time; Log *slog.Logger}` with `Routes() *http.ServeMux`
  - `adminapi.SessionCookie = "retune_session"`, `adminapi.CSRFHeader = "X-CSRF-Token"`
  - Endpoints: `GET /api/admin/v1/setup` (unauthenticated, `{"needs_setup":bool}`), `POST /api/admin/v1/session` (login), `GET /api/admin/v1/session` (current admin), `DELETE /api/admin/v1/session` (logout)
  - Error codes: `invalid_credentials` (401), `totp_required` (401), `totp_invalid` (401), `account_disabled` (403), `too_many_attempts` (429), `unauthenticated` (401), `csrf_invalid` (403), `forbidden` (403), `not_found` (404), `bad_request` (400)
  - `app.App` gains `Auth *auth.Service`; `App.Handler` now serves both `/api/agent/v1/` and `/api/admin/v1/`

- [ ] **Step 1: Write the failing test**

`internal/server/app/admin_helpers_test.go`:

```go
package app_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"

	"retune/internal/server/adminapi"
	"retune/internal/server/app"
	"retune/internal/server/auth"
	"retune/internal/server/store"
)

// adminClient is a browser-like client: it keeps cookies and sends CSRF.
type adminClient struct {
	t    *testing.T
	http *http.Client
	base string
	csrf string
}

func newAdminClient(t *testing.T, a *app.App, srv *httptest.Server) *adminClient {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &adminClient{
		t: t, base: srv.URL + "/api/admin/v1",
		http: &http.Client{
			Jar:       jar,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: a.CA.Pool()}},
		},
	}
}

func (c *adminClient) do(method, path string, body any) (int, []byte) {
	c.t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			c.t.Fatal(err)
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, c.base+path, r)
	if err != nil {
		c.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.csrf != "" {
		req.Header.Set(adminapi.CSRFHeader, c.csrf)
	}
	res, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, out
}

// login signs in and remembers the CSRF token.
func (c *adminClient) login(email, password, code string) (int, []byte) {
	c.t.Helper()
	status, body := c.do(http.MethodPost, "/session", map[string]string{
		"email": email, "password": password, "totp_code": code,
	})
	if status == http.StatusOK {
		var resp struct {
			CSRFToken string `json:"csrf_token"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			c.t.Fatal(err)
		}
		c.csrf = resp.CSRFToken
	}
	return status, body
}

func (c *adminClient) sessionCookie(srv *httptest.Server) *http.Cookie {
	c.t.Helper()
	u, _ := url.Parse(srv.URL)
	for _, ck := range c.http.Jar.Cookies(u) {
		if ck.Name == adminapi.SessionCookie {
			return ck
		}
	}
	return nil
}

// seedAdmin creates an account directly through the service.
func seedAdmin(t *testing.T, a *app.App, email, password, role string) store.Admin {
	t.Helper()
	admin, err := a.Auth.CreateAdmin(context.Background(), auth.CreateAdminOptions{
		Email: email, Password: password, Role: role, Actor: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	return admin
}
```

`internal/server/app/app_admin_test.go`:

```go
package app_test

import (
	"bytes"
	"context"
	"net/http"
	"testing"

	"retune/internal/server/adminapi"
	"retune/internal/server/store"
)

const testPassword = "correct horse battery"

func TestSetupAndLogin(t *testing.T) {
	a, srv := newTestApp(t)
	c := newAdminClient(t, a, srv)

	status, body := c.do(http.MethodGet, "/setup", nil)
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"needs_setup":true`)) {
		t.Fatalf("setup before any admin: %d %s", status, body)
	}
	seedAdmin(t, a, "ops@example.com", testPassword, store.RoleAdmin)
	if _, body = c.do(http.MethodGet, "/setup", nil); !bytes.Contains(body, []byte(`"needs_setup":false`)) {
		t.Fatalf("setup after seeding: %s", body)
	}

	if status, body = c.do(http.MethodGet, "/session", nil); status != http.StatusUnauthorized {
		t.Fatalf("session without login: %d %s", status, body)
	}
	if status, body = c.login("ops@example.com", "wrong password", ""); status != http.StatusUnauthorized ||
		!bytes.Contains(body, []byte("invalid_credentials")) {
		t.Fatalf("bad password: %d %s", status, body)
	}
	status, body = c.login("ops@example.com", testPassword, "")
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"email":"ops@example.com"`)) {
		t.Fatalf("login: %d %s", status, body)
	}
	if c.csrf == "" {
		t.Fatal("login must return a CSRF token")
	}
	cookie := c.sessionCookie(srv)
	if cookie == nil || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode {
			t.Fatalf("session cookie = %+v", cookie)
	}

	if status, body = c.do(http.MethodGet, "/session", nil); status != http.StatusOK ||
		!bytes.Contains(body, []byte(`"role":"admin"`)) {
		t.Fatalf("session after login: %d %s", status, body)
	}

	// CSRF is required for unsafe methods.
	saved := c.csrf
	c.csrf = ""
	if status, body = c.do(http.MethodDelete, "/session", nil); status != http.StatusForbidden ||
		!bytes.Contains(body, []byte("csrf_invalid")) {
		t.Fatalf("logout without CSRF: %d %s", status, body)
	}
	c.csrf = "wrong-token"
	if status, _ = c.do(http.MethodDelete, "/session", nil); status != http.StatusForbidden {
		t.Fatalf("logout with a wrong CSRF token: %d", status)
	}
	c.csrf = saved

	if status, body = c.do(http.MethodDelete, "/session", nil); status != http.StatusNoContent {
		t.Fatalf("logout: %d %s", status, body)
	}
	if status, _ = c.do(http.MethodGet, "/session", nil); status != http.StatusUnauthorized {
		t.Fatalf("session after logout: %d", status)
	}
}

func TestLockoutAndDisabledAccount(t *testing.T) {
	ctx := context.Background()
	a, srv := newTestApp(t)
	admin := seedAdmin(t, a, "ops@example.com", testPassword, store.RoleAdmin)
	seedAdmin(t, a, "ops2@example.com", testPassword, store.RoleAdmin)
	c := newAdminClient(t, a, srv)

	for range 10 {
		if status, _ := c.login("ops@example.com", "wrong password", ""); status != http.StatusUnauthorized {
			t.Fatalf("expected 401 while failing")
		}
	}
	status, body := c.login("ops@example.com", testPassword, "")
	if status != http.StatusTooManyRequests || !bytes.Contains(body, []byte("too_many_attempts")) {
		t.Fatalf("lockout: %d %s", status, body)
	}

	other := newAdminClient(t, a, srv)
	if status, _ := other.login("ops2@example.com", testPassword, ""); status != http.StatusOK {
		t.Fatal("a different account must not be locked out")
	}
	if err := a.Auth.SetDisabled(ctx, admin.ID, true, "test"); err != nil {
		t.Fatal(err)
	}
	disabled := newAdminClient(t, a, srv)
	if status, body := disabled.login("ops@example.com", testPassword, ""); status != http.StatusForbidden ||
		!bytes.Contains(body, []byte("account_disabled")) {
		t.Fatalf("disabled login: %d %s", status, body)
	}
}

func TestReadOnlyRole(t *testing.T) {
	a, srv := newTestApp(t)
	seedAdmin(t, a, "viewer@example.com", testPassword, store.RoleReadOnly)
	c := newAdminClient(t, a, srv)
	if status, _ := c.login("viewer@example.com", testPassword, ""); status != http.StatusOK {
		t.Fatal("a read-only admin must be able to sign in")
	}
	if status, _ := c.do(http.MethodGet, "/session", nil); status != http.StatusOK {
		t.Fatal("a read-only admin must be able to read")
	}
	// Logging out is allowed for any role; writing device state is not (Task 7
	// adds those endpoints, so here we only check the role gate on tokens).
	status, body := c.do(http.MethodPost, "/tokens", map[string]any{"label": "nope"})
	if status != http.StatusForbidden || !bytes.Contains(body, []byte("forbidden")) {
		t.Fatalf("read-only write: %d %s", status, body)
	}
}

func TestExpiredSessionCookieIsRejected(t *testing.T) {
	a, srv := newTestApp(t)
	seedAdmin(t, a, "ops@example.com", testPassword, store.RoleAdmin)
	c := newAdminClient(t, a, srv)
	if status, _ := c.login("ops@example.com", testPassword, ""); status != http.StatusOK {
		t.Fatal("login failed")
	}
	cookie := c.sessionCookie(srv)
	if err := a.Auth.DeleteSession(context.Background(), cookie.Value); err != nil {
		t.Fatal(err)
	}
	if status, body := c.do(http.MethodGet, "/session", nil); status != http.StatusUnauthorized ||
		!bytes.Contains(body, []byte("unauthenticated")) {
		t.Fatalf("deleted session: %d %s", status, body)
	}
	_ = adminapi.SessionCookie
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/server/app/ -run TestSetupAndLogin`
Expected: FAIL — no `adminapi` package, `a.Auth` undefined.

- [ ] **Step 3: Write the JSON helpers**

`internal/server/adminapi/json.go`:

```go
package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"retune/internal/protocol"
	"retune/internal/server/store"
)

// maxBody is generous enough for a script payload but not unbounded.
const maxBody = 4 << 20

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	err := json.NewDecoder(r.Body).Decode(v)
	if err == nil {
		return true
	}
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body is too large")
		return false
	}
	writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
	return false
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeNoContent(w http.ResponseWriter) { w.WriteHeader(http.StatusNoContent) }

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, protocol.Error{Code: code, Message: msg})
}

// pageFrom reads limit/offset query parameters.
func pageFrom(r *http.Request) store.Page {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	return store.Page{Limit: limit, Offset: offset}.Normalized()
}

// listResponse is the shape every listing returns.
type listResponse[T any] struct {
	Items  []T `json:"items"`
	Total  int `json:"total"`
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

func newListResponse[T any](items []T, total int, page store.Page) listResponse[T] {
	if items == nil {
		items = []T{}
	}
	return listResponse[T]{Items: items, Total: total, Limit: page.Limit, Offset: page.Offset}
}
```

- [ ] **Step 4: Write the handler, middleware and session endpoints**

`internal/server/adminapi/handler.go`:

```go
// Package adminapi serves the console's REST API.
package adminapi

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"retune/internal/server/auth"
	"retune/internal/server/commands"
	"retune/internal/server/devices"
	"retune/internal/server/enroll"
	"retune/internal/server/store"
)

// SessionCookie holds the session token; CSRFHeader carries its CSRF token.
const (
	SessionCookie = "retune_session"
	CSRFHeader    = "X-CSRF-Token"
)

// Handler serves /api/admin/v1.
type Handler struct {
	Auth     *auth.Service
	Store    *store.Store
	Commands *commands.Service
	Devices  *devices.Service
	Enroll   *enroll.Service
	Now      func() time.Time
	Log      *slog.Logger
}

type authKey struct{}

// authContext is the signed-in admin for this request.
type authContext struct {
	Admin   store.Admin
	Session store.Session
}

func caller(r *http.Request) authContext { return r.Context().Value(authKey{}).(authContext) }

// Routes returns the admin API mux.
func (h *Handler) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	const base = "/api/admin/v1"

	mux.HandleFunc("GET "+base+"/setup", h.setup)
	mux.HandleFunc("POST "+base+"/session", h.login)
	mux.Handle("GET "+base+"/session", h.read(h.currentSession))
	mux.Handle("DELETE "+base+"/session", h.anyRole(h.logout))

	h.mountResources(mux, base)
	return mux
}

// read allows both roles; write requires the admin role. anyRole is for
// actions every signed-in admin may take on themselves, such as logging out.
func (h *Handler) read(next http.HandlerFunc) http.Handler  { return h.protect(next, false) }
func (h *Handler) write(next http.HandlerFunc) http.Handler { return h.protect(next, true) }
func (h *Handler) anyRole(next http.HandlerFunc) http.Handler {
	return h.protect(next, false)
}

// protect authenticates the session cookie, enforces CSRF on unsafe methods
// and checks the role.
func (h *Handler) protect(next http.HandlerFunc, needsAdmin bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(SessionCookie)
		if err != nil || cookie.Value == "" {
			writeError(w, http.StatusUnauthorized, "unauthenticated", "sign in to continue")
			return
		}
		admin, session, err := h.Auth.ValidateSession(r.Context(), cookie.Value)
		switch {
		case errors.Is(err, auth.ErrInvalidSession):
			h.clearCookie(w)
			writeError(w, http.StatusUnauthorized, "unauthenticated", "sign in to continue")
			return
		case errors.Is(err, auth.ErrAccountDisabled):
			h.clearCookie(w)
			writeError(w, http.StatusForbidden, "account_disabled", "this account is disabled")
			return
		case err != nil:
			h.Log.Error("validate session", "error", err)
			writeError(w, http.StatusInternalServerError, "internal", "internal server error")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			sent := r.Header.Get(CSRFHeader)
			if subtle.ConstantTimeCompare([]byte(sent), []byte(session.CSRFToken)) != 1 {
				writeError(w, http.StatusForbidden, "csrf_invalid", "missing or invalid CSRF token")
				return
			}
		}
		if needsAdmin && admin.Role != store.RoleAdmin {
			writeError(w, http.StatusForbidden, "forbidden", "this account may only read")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), authKey{}, authContext{Admin: admin, Session: session})))
	})
}

func (h *Handler) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
}

func (h *Handler) internal(w http.ResponseWriter, msg string, err error, args ...any) {
	h.Log.Error(msg, append([]any{"error", err}, args...)...)
	writeError(w, http.StatusInternalServerError, "internal", "internal server error")
}
```

`internal/server/adminapi/session.go`:

```go
package adminapi

import (
	"errors"
	"net"
	"net/http"
	"time"

	"retune/internal/server/auth"
	"retune/internal/server/store"
)

// adminJSON is how an account appears in the API.
type adminJSON struct {
	ID          string     `json:"id"`
	Email       string     `json:"email"`
	Role        string     `json:"role"`
	TOTPEnabled bool       `json:"totp_enabled"`
	Disabled    bool       `json:"disabled"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
}

func newAdminJSON(a store.Admin) adminJSON {
	return adminJSON{
		ID: a.ID.String(), Email: a.Email, Role: a.Role,
		TOTPEnabled: a.TOTPSecret != "", Disabled: a.DisabledAt != nil,
		CreatedAt: a.CreatedAt, LastLoginAt: a.LastLoginAt,
	}
}

type sessionResponse struct {
	Admin     adminJSON `json:"admin"`
	CSRFToken string    `json:"csrf_token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// setup tells the console whether the first admin still has to be created.
func (h *Handler) setup(w http.ResponseWriter, r *http.Request) {
	has, err := h.Auth.HasAdmins(r.Context())
	if err != nil {
		h.internal(w, "count admins", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"needs_setup": !has})
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		TOTPCode string `json:"totp_code"`
	}
	if !decode(w, r, &req) {
		return
	}
	admin, err := h.Auth.Authenticate(r.Context(), req.Email, req.Password, req.TOTPCode)
	switch {
	case err == nil:
	case errors.Is(err, auth.ErrInvalidCredentials):
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "invalid email or password")
		return
	case errors.Is(err, auth.ErrTOTPRequired):
		writeError(w, http.StatusUnauthorized, "totp_required", "enter your authenticator code")
		return
	case errors.Is(err, auth.ErrTOTPInvalid):
		writeError(w, http.StatusUnauthorized, "totp_invalid", "invalid authenticator code")
		return
	case errors.Is(err, auth.ErrAccountDisabled):
		writeError(w, http.StatusForbidden, "account_disabled", "this account is disabled")
		return
	case errors.Is(err, auth.ErrTooManyAttempts):
		writeError(w, http.StatusTooManyRequests, "too_many_attempts", "too many failed attempts; try again later")
		return
	default:
		h.internal(w, "authenticate", err)
		return
	}

	info, err := h.Auth.CreateSession(r.Context(), admin.ID, r.UserAgent(), clientIP(r))
	if err != nil {
		h.internal(w, "create session", err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: info.Token, Path: "/",
		Expires: info.ExpiresAt, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, sessionResponse{
		Admin: newAdminJSON(admin), CSRFToken: info.CSRFToken, ExpiresAt: info.ExpiresAt,
	})
}

func (h *Handler) currentSession(w http.ResponseWriter, r *http.Request) {
	c := caller(r)
	writeJSON(w, http.StatusOK, sessionResponse{
		Admin: newAdminJSON(c.Admin), CSRFToken: c.Session.CSRFToken, ExpiresAt: c.Session.ExpiresAt,
	})
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(SessionCookie)
	if err == nil {
		if err := h.Auth.DeleteSession(r.Context(), cookie.Value); err != nil {
			h.internal(w, "delete session", err)
			return
		}
	}
	h.clearCookie(w)
	writeNoContent(w)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
```

- [ ] **Step 5: Add the resource stub so the package compiles**

Task 7 fills this in; for now `internal/server/adminapi/resources.go`:

```go
package adminapi

import "net/http"

// mountResources registers the device, command, token, admin and audit routes.
func (h *Handler) mountResources(mux *http.ServeMux, base string) {
	mux.Handle("POST "+base+"/tokens", h.write(h.createToken))
}
```

and the one endpoint the role test needs, in `internal/server/adminapi/tokens.go`:

```go
package adminapi

import (
	"errors"
	"net/http"
	"time"

	"retune/internal/server/enroll"
)

type createTokenRequest struct {
	Label      string `json:"label"`
	MaxUses    *int   `json:"max_uses"`
	ExpiresInH int    `json:"expires_in_hours"`
}

func (h *Handler) createToken(w http.ResponseWriter, r *http.Request) {
	var req createTokenRequest
	if !decode(w, r, &req) {
		return
	}
	opts := enroll.TokenOptions{Label: req.Label, MaxUses: req.MaxUses, CreatedBy: caller(r).Admin.Email}
	if req.ExpiresInH > 0 {
		exp := h.Now().Add(time.Duration(req.ExpiresInH) * time.Hour)
		opts.ExpiresAt = &exp
	}
	plain, tok, err := h.Enroll.CreateToken(r.Context(), opts)
	switch {
	case err == nil:
	case errors.Is(err, enroll.ErrBadRequest):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	default:
		h.internal(w, "create enrollment token", err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": tok.ID.String(), "token": plain, "label": tok.Label,
		"max_uses": tok.MaxUses, "expires_at": tok.ExpiresAt, "created_at": tok.CreatedAt,
	})
}
```

- [ ] **Step 6: Wire the admin API into the app**

In `internal/server/app/app.go`, add imports for `adminapi` and `auth`, add the field:

```go
	Auth *auth.Service
```

and replace the handler construction with a root mux that serves both APIs:

```go
	authSvc := &auth.Service{
		Store: st, Now: time.Now, SessionTTL: cfg.SessionTTL,
		Limiter: auth.NewLimiter(10, 15*time.Minute, time.Now), Issuer: "Retune",
	}
	agent := &agentapi.Handler{
		Enroll: svc, Inventory: inv, Commands: cmd, Store: st,
		Now: time.Now, CheckinInterval: cfg.CheckinInterval, Log: log,
	}
	admin := &adminapi.Handler{
		Auth: authSvc, Store: st, Commands: cmd, Devices: dev, Enroll: svc,
		Now: time.Now, Log: log,
	}
	root := http.NewServeMux()
	root.Handle("/api/agent/v1/", agent.Routes())
	root.Handle("/api/admin/v1/", admin.Routes())

	return &App{
		Store:     st,
		CA:        authority,
		Enroll:    svc,
		Inventory: inv,
		Commands:  cmd,
		Devices:   dev,
		Auth:      authSvc,
		Handler:   root,
		TLSConfig: ...unchanged...,
	}, nil
```

`config.Server` in tests must now set `SessionTTL`; update `newTestApp` in `internal/server/app/app_test.go` to include `SessionTTL: 12 * time.Hour`.

- [ ] **Step 7: Run tests to verify they pass**

Run: `go vet ./internal/server/... && go test -count=1 ./internal/server/app/`
Expected: PASS, including the M1/M2 agent tests through the new root mux.

- [ ] **Step 8: Commit**

```bash
git add internal/server/adminapi internal/server/app
git commit -m "feat(adminapi): session login, CSRF protection and role checks"
```

---

### Task 7: Admin API resources

**Files:**
- Create: `internal/server/adminapi/devices.go`, `internal/server/adminapi/commands.go`, `internal/server/adminapi/admins.go`, `internal/server/adminapi/audit.go`, `internal/server/app/app_admin_resources_test.go`
- Modify: `internal/server/adminapi/resources.go`, `internal/server/adminapi/tokens.go`, `internal/server/enroll/service.go` (add `RevokeToken`)

**Interfaces:**
- Consumes: Tasks 1–6, plus M2's `commands`, `devices`, `inventory` services
- Produces:
  - `GET /devices` (search, status, limit, offset), `GET /devices/{id}`, `GET /devices/{id}/software`, `POST /devices/{id}/retire`, `POST /devices/{id}/unenroll`
  - `GET /commands` (device_id, status, limit, offset), `POST /commands` (one or more `device_ids`), `GET /commands/{id}`
  - `GET /tokens`, `POST /tokens/{id}/revoke`
  - `GET /admins`, `POST /admins`, `POST /admins/{id}/password`, `POST /admins/{id}/totp`, `POST /admins/{id}/disabled`
  - `GET /audit` (limit, offset)
  - `(*enroll.Service).RevokeToken(ctx, id uuid.UUID, actor string) error` with `enroll.ErrTokenNotFound` for unknown IDs
  - Writes require the `admin` role; reads work for `read_only` too

- [ ] **Step 1: Write the failing test**

`internal/server/app/app_admin_resources_test.go`:

```go
package app_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/store"
)

// signedIn seeds an account with the given role and returns a logged-in client.
// Put this helper in admin_helpers_test.go alongside the others.
func signedIn(t *testing.T, a *app.App, srv *httptest.Server, role string) *adminClient {
	t.Helper()
	email := "ops@example.com"
	if role == store.RoleReadOnly {
		email = "viewer@example.com"
	}
	seedAdmin(t, a, email, testPassword, role)
	c := newAdminClient(t, a, srv)
	if status, body := c.login(email, testPassword, ""); status != http.StatusOK {
		t.Fatalf("login: %d %s", status, body)
	}
	return c
}

func TestDeviceEndpoints(t *testing.T) {
	ctx := context.Background()
	a, srv := newTestApp(t)
	id, mtls := enrollDevice(t, a, srv, "PC-ADMIN")
	// Give the device inventory so the detail view has something to show.
	inv := protocol.Inventory{
		Hostname: "PC-ADMIN",
		OS:       protocol.OSInfo{Name: "Microsoft Windows 11 Pro", Version: "10.0.26200", Build: "26200"},
		Hardware: protocol.Hardware{Manufacturer: "Contoso", Model: "Book 9", RAMBytes: 8 << 30},
		Disks:    []protocol.Disk{{Name: "C:", FreeBytes: 100 << 30}},
		Software: []protocol.Software{{Name: "7-Zip", Version: "24.08", Scope: "machine"}},
	}
	if status, body := send(t, mtls, http.MethodPut, srv.URL+"/api/agent/v1/inventory", inv); status != http.StatusOK {
		t.Fatalf("seed inventory: %d %s", status, body)
	}
	c := signedIn(t, a, srv, store.RoleAdmin)

	status, body := c.do(http.MethodGet, "/devices", nil)
	if status != http.StatusOK || !bytes.Contains(body, []byte("PC-ADMIN")) || !bytes.Contains(body, []byte(`"total":1`)) {
		t.Fatalf("device list: %d %s", status, body)
	}
	if _, body = c.do(http.MethodGet, "/devices?search=nothing", nil); !bytes.Contains(body, []byte(`"total":0`)) {
		t.Fatalf("filtered list: %s", body)
	}
	if _, body = c.do(http.MethodGet, "/devices?status=retired", nil); !bytes.Contains(body, []byte(`"total":0`)) {
		t.Fatalf("status filter: %s", body)
	}

	status, body = c.do(http.MethodGet, "/devices/"+id.String(), nil)
	if status != http.StatusOK || !bytes.Contains(body, []byte("Contoso")) ||
		!bytes.Contains(body, []byte("7-Zip")) || !bytes.Contains(body, []byte(`"ram_gb":8`)) {
		t.Fatalf("device detail: %d %s", status, body)
	}
	if status, _ = c.do(http.MethodGet, "/devices/"+uuid.Must(uuid.NewV7()).String(), nil); status != http.StatusNotFound {
		t.Fatalf("unknown device: %d", status)
	}
	if status, _ = c.do(http.MethodGet, "/devices/not-a-uuid", nil); status != http.StatusNotFound {
		t.Fatalf("malformed device id: %d", status)
	}

	status, body = c.do(http.MethodGet, "/devices/"+id.String()+"/software", nil)
	if status != http.StatusOK || !bytes.Contains(body, []byte("7-Zip")) {
		t.Fatalf("software list: %d %s", status, body)
	}

	if status, body = c.do(http.MethodPost, "/devices/"+id.String()+"/retire", nil); status != http.StatusNoContent {
		t.Fatalf("retire: %d %s", status, body)
	}
	if d, _ := a.Store.Q().GetDevice(ctx, id); d.Status != store.DeviceRetired {
		t.Fatalf("status after retire = %s", d.Status)
	}
	if status, body = c.do(http.MethodPost, "/devices/"+id.String()+"/retire", nil); status != http.StatusConflict {
		t.Fatalf("retiring twice: %d %s", status, body)
	}
	if status, body = c.do(http.MethodPost, "/devices/"+id.String()+"/unenroll", nil); status != http.StatusNoContent {
		t.Fatalf("unenroll: %d %s", status, body)
	}
	if d, _ := a.Store.Q().GetDevice(ctx, id); d.Status != store.DeviceUnenrolled {
		t.Fatalf("status after unenroll = %s", d.Status)
	}
}

func TestCommandEndpointsAdmin(t *testing.T) {
	ctx := context.Background()
	a, srv := newTestApp(t)
	first, _ := enrollDevice(t, a, srv, "PC-1")
	second, _ := enrollDevice(t, a, srv, "PC-2")
	c := signedIn(t, a, srv, store.RoleAdmin)

	// One request queues the same command on two devices.
	status, body := c.do(http.MethodPost, "/commands", map[string]any{
		"device_ids": []string{first.String(), second.String()},
		"type":       protocol.CommandRunPowerShell,
		"script":     "Get-Date",
		"timeout_seconds": 60,
	})
	if status != http.StatusCreated {
		t.Fatalf("queue: %d %s", status, body)
	}
	var queued struct {
		Commands []struct {
			ID       string `json:"id"`
			DeviceID string `json:"device_id"`
		} `json:"commands"`
	}
	if err := json.Unmarshal(body, &queued); err != nil || len(queued.Commands) != 2 {
		t.Fatalf("queue response = %s, err = %v", body, err)
	}

	if status, body = c.do(http.MethodPost, "/commands", map[string]any{
		"device_ids": []string{first.String()}, "type": "nonsense",
	}); status != http.StatusBadRequest {
		t.Fatalf("bad type: %d %s", status, body)
	}
	if status, _ = c.do(http.MethodPost, "/commands", map[string]any{
		"device_ids": []string{}, "type": protocol.CommandRefreshInventory,
	}); status != http.StatusBadRequest {
		t.Fatalf("no devices: %d", status)
	}

	if _, body = c.do(http.MethodGet, "/commands", nil); !bytes.Contains(body, []byte(`"total":2`)) {
		t.Fatalf("command list: %s", body)
	}
	if _, body = c.do(http.MethodGet, "/commands?device_id="+first.String(), nil); !bytes.Contains(body, []byte(`"total":1`)) {
		t.Fatalf("device filter: %s", body)
	}
	if _, body = c.do(http.MethodGet, "/commands?status=queued", nil); !bytes.Contains(body, []byte(`"total":2`)) {
		t.Fatalf("status filter: %s", body)
	}

	cmdID := uuid.MustParse(queued.Commands[0].ID)
	if err := a.Commands.Complete(ctx, first, cmdID, protocol.CommandResult{
		Status: protocol.ResultSucceeded, Stdout: "ran", StartedAt: time.Now(), FinishedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	status, body = c.do(http.MethodGet, "/commands/"+cmdID.String(), nil)
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"stdout":"ran"`)) {
		t.Fatalf("command detail: %d %s", status, body)
	}
	if status, _ = c.do(http.MethodGet, "/commands/"+uuid.Must(uuid.NewV7()).String(), nil); status != http.StatusNotFound {
		t.Fatalf("unknown command: %d", status)
	}
}

func TestTokenAuditAndAdminEndpoints(t *testing.T) {
	ctx := context.Background()
	a, srv := newTestApp(t)
	c := signedIn(t, a, srv, store.RoleAdmin)

	status, body := c.do(http.MethodPost, "/tokens", map[string]any{"label": "office", "max_uses": 5, "expires_in_hours": 24})
	if status != http.StatusCreated || !bytes.Contains(body, []byte(`"token":"rt_`)) {
		t.Fatalf("create token: %d %s", status, body)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if _, body = c.do(http.MethodGet, "/tokens", nil); !bytes.Contains(body, []byte("office")) || bytes.Contains(body, []byte("rt_")) {
		t.Fatalf("token list must not contain plaintext tokens: %s", body)
	}
	if status, body = c.do(http.MethodPost, "/tokens/"+created.ID+"/revoke", nil); status != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", status, body)
	}
	if _, body = c.do(http.MethodGet, "/tokens", nil); !bytes.Contains(body, []byte(`"revoked_at"`)) {
		t.Fatalf("revoked token must show its time: %s", body)
	}
	if status, _ = c.do(http.MethodPost, "/tokens/"+uuid.Must(uuid.NewV7()).String()+"/revoke", nil); status != http.StatusNotFound {
		t.Fatalf("revoking an unknown token: %d", status)
	}

	// Admin management.
	status, body = c.do(http.MethodPost, "/admins", map[string]any{
		"email": "second@example.com", "password": testPassword, "role": store.RoleReadOnly,
	})
	if status != http.StatusCreated || !bytes.Contains(body, []byte("second@example.com")) {
		t.Fatalf("create admin: %d %s", status, body)
	}
	var newAdmin struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &newAdmin); err != nil {
		t.Fatal(err)
	}
	if status, body = c.do(http.MethodPost, "/admins", map[string]any{
		"email": "weak@example.com", "password": "short", "role": store.RoleAdmin,
	}); status != http.StatusBadRequest {
		t.Fatalf("weak password: %d %s", status, body)
	}
	if _, body = c.do(http.MethodGet, "/admins", nil); !bytes.Contains(body, []byte("ops@example.com")) ||
		bytes.Contains(body, []byte("password_hash")) || bytes.Contains(body, []byte("totp_secret")) {
		t.Fatalf("admin list must not leak secrets: %s", body)
	}

	if status, body = c.do(http.MethodPost, "/admins/"+newAdmin.ID+"/password", map[string]any{"password": "another good password"}); status != http.StatusNoContent {
		t.Fatalf("set password: %d %s", status, body)
	}
	status, body = c.do(http.MethodPost, "/admins/"+newAdmin.ID+"/totp", map[string]any{"enabled": true})
	if status != http.StatusOK || !bytes.Contains(body, []byte("otpauth://")) {
		t.Fatalf("enable TOTP: %d %s", status, body)
	}
	if status, _ = c.do(http.MethodPost, "/admins/"+newAdmin.ID+"/totp", map[string]any{"enabled": false}); status != http.StatusNoContent {
		t.Fatalf("disable TOTP: %d", status)
	}
	if status, body = c.do(http.MethodPost, "/admins/"+newAdmin.ID+"/disabled", map[string]any{"disabled": true}); status != http.StatusNoContent {
		t.Fatalf("disable admin: %d %s", status, body)
	}
	if cur, _ := a.Store.Q().GetAdmin(ctx, uuid.MustParse(newAdmin.ID)); cur.DisabledAt == nil {
		t.Fatal("admin must be disabled")
	}
	// The signed-in admin is the only enabled admin, so disabling them fails.
	me, _ := a.Store.Q().GetAdminByEmail(ctx, "ops@example.com")
	if status, body = c.do(http.MethodPost, "/admins/"+me.ID.String()+"/disabled", map[string]any{"disabled": true}); status != http.StatusConflict {
		t.Fatalf("disabling the last admin: %d %s", status, body)
	}

	if _, body = c.do(http.MethodGet, "/audit", nil); !bytes.Contains(body, []byte("admin.login")) ||
		!bytes.Contains(body, []byte("enrollment_token.created")) {
		t.Fatalf("audit: %s", body)
	}
}

func TestReadOnlyCannotWrite(t *testing.T) {
	a, srv := newTestApp(t)
	id, _ := enrollDevice(t, a, srv, "PC-RO")
	seedAdmin(t, a, "ops@example.com", testPassword, store.RoleAdmin) // so reads have data
	c := signedIn(t, a, srv, store.RoleReadOnly)

	if status, _ := c.do(http.MethodGet, "/devices", nil); status != http.StatusOK {
		t.Fatal("read-only must be able to list devices")
	}
	writes := []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, "/devices/" + id.String() + "/retire", nil},
		{http.MethodPost, "/devices/" + id.String() + "/unenroll", nil},
		{http.MethodPost, "/commands", map[string]any{"device_ids": []string{id.String()}, "type": protocol.CommandRefreshInventory}},
		{http.MethodPost, "/tokens", map[string]any{"label": "x"}},
		{http.MethodPost, "/admins", map[string]any{"email": "x@example.com", "password": testPassword, "role": store.RoleAdmin}},
	}
	for _, w := range writes {
		if status, body := c.do(w.method, w.path, w.body); status != http.StatusForbidden {
			t.Errorf("%s %s = %d %s, want 403", w.method, w.path, status, body)
		}
	}
}
```

Note: the resource tests reuse `newTestApp`, `enrollDevice` and `send` from the M1/M2 test files in this package.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/server/app/ -run TestDeviceEndpoints`
Expected: FAIL — 404 from the unmounted routes (and a compile error until the helper types are right).

- [ ] **Step 3: Add token revocation to the enroll service**

Append to `internal/server/enroll/service.go`:

```go
// RevokeToken stops a token from being used again.
func (s *Service) RevokeToken(ctx context.Context, id uuid.UUID, actor string) error {
	now := s.Now()
	return s.Store.InTx(ctx, func(q *store.Queries) error {
		tok, err := q.GetEnrollmentToken(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("%w: %s", ErrTokenNotFound, id)
		}
		if err != nil {
			return err
		}
		if err := q.RevokeEnrollmentToken(ctx, id, now); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: actor, Action: "enrollment_token.revoked",
			TargetKind: "enrollment_token", TargetID: id.String(),
			Details: map[string]any{"label": tok.Label},
		})
	})
}
```

- [ ] **Step 4: Write the device endpoints**

`internal/server/adminapi/devices.go`:

```go
package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/devices"
	"retune/internal/server/store"
)

// staleAfter is how long a device may go unseen before the console flags it.
const staleAfter = 7 * 24 * time.Hour

type deviceJSON struct {
	ID            string     `json:"id"`
	Hostname      string     `json:"hostname"`
	Status        string     `json:"status"`
	OSVersion     string     `json:"os_version"`
	OSBuild       string     `json:"os_build"`
	Manufacturer  string     `json:"manufacturer"`
	Model         string     `json:"model"`
	Serial        string     `json:"serial"`
	SMBIOSUUID    string     `json:"smbios_uuid"`
	AgentVersion  string     `json:"agent_version"`
	EnrolledAt    time.Time  `json:"enrolled_at"`
	LastSeenAt    *time.Time `json:"last_seen_at,omitempty"`
	CertExpiresAt time.Time  `json:"cert_expires_at"`
	Stale         bool       `json:"stale"`
}

func (h *Handler) newDeviceJSON(d store.Device) deviceJSON {
	stale := d.LastSeenAt == nil || h.Now().Sub(*d.LastSeenAt) > staleAfter
	return deviceJSON{
		ID: d.ID.String(), Hostname: d.Hostname, Status: d.Status,
		OSVersion: d.OSVersion, OSBuild: d.OSBuild, Manufacturer: d.Manufacturer, Model: d.Model,
		Serial: d.Serial, SMBIOSUUID: d.SMBIOSUUID, AgentVersion: d.AgentVersion,
		EnrolledAt: d.EnrolledAt, LastSeenAt: d.LastSeenAt, CertExpiresAt: d.CertExpiresAt,
		Stale: stale && d.Status == store.DeviceActive,
	}
}

type softwareJSON struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Publisher   string `json:"publisher"`
	InstallDate string `json:"install_date"`
	Scope       string `json:"scope"`
}

type inventoryJSON struct {
	CollectedAt time.Time       `json:"collected_at"`
	ReceivedAt  time.Time       `json:"received_at"`
	RAMGB       float64         `json:"ram_gb"`
	DiskFreeGB  float64         `json:"disk_free_gb"`
	Document    json.RawMessage `json:"document"`
}

type deviceDetailJSON struct {
	Device    deviceJSON     `json:"device"`
	Inventory *inventoryJSON `json:"inventory"`
	Software  []softwareJSON `json:"software"`
	Commands  []commandJSON  `json:"commands"`
}

func (h *Handler) listDevices(w http.ResponseWriter, r *http.Request) {
	page := pageFrom(r)
	q := r.URL.Query()
	rows, total, err := h.Store.Q().ListDevicesPage(r.Context(), store.DeviceFilter{
		Search: q.Get("search"), Status: q.Get("status"), Page: page,
	})
	if err != nil {
		h.internal(w, "list devices", err)
		return
	}
	items := make([]deviceJSON, 0, len(rows))
	for _, d := range rows {
		items = append(items, h.newDeviceJSON(d))
	}
	writeJSON(w, http.StatusOK, newListResponse(items, total, page))
}

func (h *Handler) getDevice(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "not found")
	if !ok {
		return
	}
	ctx := r.Context()
	q := h.Store.Q()
	d, err := q.GetDevice(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "no such device")
		return
	}
	if err != nil {
		h.internal(w, "get device", err)
		return
	}
	detail := deviceDetailJSON{Device: h.newDeviceJSON(d), Software: []softwareJSON{}, Commands: []commandJSON{}}

	inv, err := q.GetInventory(ctx, id)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		h.internal(w, "get inventory", err)
		return
	default:
		detail.Inventory = &inventoryJSON{
			CollectedAt: inv.CollectedAt, ReceivedAt: inv.ReceivedAt,
			RAMGB: inv.RAMGB, DiskFreeGB: inv.DiskFreeGB, Document: json.RawMessage(inv.Data),
		}
	}

	sw, err := q.ListSoftware(ctx, id)
	if err != nil {
		h.internal(w, "list software", err)
		return
	}
	for _, s := range sw {
		detail.Software = append(detail.Software, softwareJSON(s))
	}

	cmds, err := q.ListCommands(ctx, id, 20)
	if err != nil {
		h.internal(w, "list commands", err)
		return
	}
	for _, c := range cmds {
		detail.Commands = append(detail.Commands, newCommandJSON(c))
	}
	writeJSON(w, http.StatusOK, detail)
}

func (h *Handler) listDeviceSoftware(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "not found")
	if !ok {
		return
	}
	sw, err := h.Store.Q().ListSoftware(r.Context(), id)
	if err != nil {
		h.internal(w, "list software", err)
		return
	}
	items := make([]softwareJSON, 0, len(sw))
	for _, s := range sw {
		items = append(items, softwareJSON(s))
	}
	writeJSON(w, http.StatusOK, newListResponse(items, len(items), store.Page{Limit: len(items)}))
}

func (h *Handler) retireDevice(w http.ResponseWriter, r *http.Request) {
	h.changeDeviceStatus(w, r, false)
}

func (h *Handler) unenrollDevice(w http.ResponseWriter, r *http.Request) {
	h.changeDeviceStatus(w, r, true)
}

func (h *Handler) changeDeviceStatus(w http.ResponseWriter, r *http.Request, unenroll bool) {
	id, ok := pathUUID(w, r, "not found")
	if !ok {
		return
	}
	actor := caller(r).Admin.Email
	var err error
	if unenroll {
		err = h.Devices.Unenroll(r.Context(), id, actor)
	} else {
		err = h.Devices.Retire(r.Context(), id, actor)
	}
	switch {
	case err == nil:
		writeNoContent(w)
	case errors.Is(err, devices.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such device")
	case errors.Is(err, devices.ErrInvalidTransition):
		writeError(w, http.StatusConflict, "invalid_transition", err.Error())
	default:
		h.internal(w, "change device status", err, "device_id", id)
	}
}

// pathUUID reads the {id} path value.
func pathUUID(w http.ResponseWriter, r *http.Request, message string) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", message)
		return uuid.UUID{}, false
	}
	return id, true
}
```

- [ ] **Step 5: Write the command endpoints**

`internal/server/adminapi/commands.go`:

```go
package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/commands"
	"retune/internal/server/store"
)

type commandJSON struct {
	ID          string          `json:"id"`
	DeviceID    string          `json:"device_id"`
	Type        string          `json:"type"`
	Status      string          `json:"status"`
	Payload     json.RawMessage `json:"payload"`
	CreatedBy   string          `json:"created_by"`
	CreatedAt   time.Time       `json:"created_at"`
	DeliveredAt *time.Time      `json:"delivered_at,omitempty"`
	StartedAt   *time.Time      `json:"started_at,omitempty"`
	CompletedAt *time.Time      `json:"completed_at,omitempty"`
	ExpiresAt   time.Time       `json:"expires_at"`
}

func newCommandJSON(c store.Command) commandJSON {
	return commandJSON{
		ID: c.ID.String(), DeviceID: c.DeviceID.String(), Type: c.Type, Status: c.Status,
		Payload: json.RawMessage(c.Payload), CreatedBy: c.CreatedBy, CreatedAt: c.CreatedAt,
		DeliveredAt: c.DeliveredAt, StartedAt: c.StartedAt, CompletedAt: c.CompletedAt, ExpiresAt: c.ExpiresAt,
	}
}

type resultJSON struct {
	ExitCode        int       `json:"exit_code"`
	Stdout          string    `json:"stdout"`
	Stderr          string    `json:"stderr"`
	StdoutTruncated bool      `json:"stdout_truncated"`
	StderrTruncated bool      `json:"stderr_truncated"`
	Error           string    `json:"error"`
	StartedAt       time.Time `json:"started_at"`
	FinishedAt      time.Time `json:"finished_at"`
}

type queueRequest struct {
	DeviceIDs      []string `json:"device_ids"`
	Type           string   `json:"type"`
	Script         string   `json:"script"`
	TimeoutSeconds int      `json:"timeout_seconds"`
	DelaySeconds   int      `json:"delay_seconds"`
	Message        string   `json:"message"`
	TTLHours       int      `json:"ttl_hours"`
}

func (h *Handler) listCommands(w http.ResponseWriter, r *http.Request) {
	page := pageFrom(r)
	filter := store.CommandFilter{Status: r.URL.Query().Get("status"), Page: page}
	if raw := r.URL.Query().Get("device_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "device_id must be a device ID")
			return
		}
		filter.DeviceID = &id
	}
	rows, total, err := h.Store.Q().ListCommandsPage(r.Context(), filter)
	if err != nil {
		h.internal(w, "list commands", err)
		return
	}
	items := make([]commandJSON, 0, len(rows))
	for _, c := range rows {
		items = append(items, newCommandJSON(c))
	}
	writeJSON(w, http.StatusOK, newListResponse(items, total, page))
}

func (h *Handler) queueCommand(w http.ResponseWriter, r *http.Request) {
	var req queueRequest
	if !decode(w, r, &req) {
		return
	}
	if len(req.DeviceIDs) == 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "device_ids must name at least one device")
		return
	}
	payload, err := payloadFor(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	actor := caller(r).Admin.Email
	type queued struct {
		ID       string `json:"id"`
		DeviceID string `json:"device_id"`
	}
	out := make([]queued, 0, len(req.DeviceIDs))
	for _, raw := range req.DeviceIDs {
		deviceID, err := uuid.Parse(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "device_ids must contain device IDs")
			return
		}
		c, err := h.Commands.Queue(r.Context(), commands.QueueOptions{
			DeviceID: deviceID, Type: req.Type, Payload: payload, CreatedBy: actor,
			TTL: time.Duration(req.TTLHours) * time.Hour,
		})
		switch {
		case err == nil:
			out = append(out, queued{ID: c.ID.String(), DeviceID: deviceID.String()})
		case errors.Is(err, commands.ErrBadRequest):
			writeError(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		case errors.Is(err, commands.ErrNotFound):
			writeError(w, http.StatusNotFound, "not_found", err.Error())
			return
		case errors.Is(err, commands.ErrDeviceNotActive):
			writeError(w, http.StatusConflict, "device_not_active", err.Error())
			return
		default:
			h.internal(w, "queue command", err)
			return
		}
	}
	writeJSON(w, http.StatusCreated, map[string]any{"commands": out})
}

// payloadFor builds the typed payload the command service expects.
func payloadFor(req queueRequest) (json.RawMessage, error) {
	switch req.Type {
	case protocol.CommandRunPowerShell:
		return json.Marshal(protocol.RunPowerShellPayload{Script: req.Script, TimeoutSeconds: req.TimeoutSeconds})
	case protocol.CommandRestart:
		return json.Marshal(protocol.RestartPayload{DelaySeconds: req.DelaySeconds, Message: req.Message})
	case protocol.CommandRefreshInventory:
		return nil, nil
	default:
		return nil, errors.New("type must be run_powershell, restart or refresh_inventory")
	}
}

func (h *Handler) getCommand(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such command")
	if !ok {
		return
	}
	c, res, err := h.Commands.Get(r.Context(), id)
	switch {
	case err == nil:
	case errors.Is(err, commands.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such command")
		return
	default:
		h.internal(w, "get command", err)
		return
	}
	body := map[string]any{"command": newCommandJSON(c)}
	if res != nil {
		body["result"] = resultJSON{
			ExitCode: res.ExitCode, Stdout: res.Stdout, Stderr: res.Stderr,
			StdoutTruncated: res.StdoutTruncated, StderrTruncated: res.StderrTruncated,
			Error: res.Error, StartedAt: res.StartedAt, FinishedAt: res.FinishedAt,
		}
	}
	writeJSON(w, http.StatusOK, body)
}
```

- [ ] **Step 6: Write the token, admin and audit endpoints**

Append to `internal/server/adminapi/tokens.go`:

```go
type tokenJSON struct {
	ID        string     `json:"id"`
	Label     string     `json:"label"`
	MaxUses   *int       `json:"max_uses,omitempty"`
	UseCount  int        `json:"use_count"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
}

func (h *Handler) listTokens(w http.ResponseWriter, r *http.Request) {
	rows, err := h.Store.Q().ListEnrollmentTokens(r.Context())
	if err != nil {
		h.internal(w, "list enrollment tokens", err)
		return
	}
	items := make([]tokenJSON, 0, len(rows))
	for _, t := range rows {
		items = append(items, tokenJSON{
			ID: t.ID.String(), Label: t.Label, MaxUses: t.MaxUses, UseCount: t.UseCount,
			ExpiresAt: t.ExpiresAt, RevokedAt: t.RevokedAt, CreatedBy: t.CreatedBy, CreatedAt: t.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, newListResponse(items, len(items), store.Page{Limit: len(items)}))
}

func (h *Handler) revokeToken(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such token")
	if !ok {
		return
	}
	err := h.Enroll.RevokeToken(r.Context(), id, caller(r).Admin.Email)
	switch {
	case err == nil:
		writeNoContent(w)
	case errors.Is(err, enroll.ErrTokenNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such token")
	default:
		h.internal(w, "revoke enrollment token", err, "token_id", id)
	}
}
```

Add `"retune/internal/server/store"` to that file's imports.

`internal/server/adminapi/admins.go`:

```go
package adminapi

import (
	"errors"
	"net/http"

	"retune/internal/server/auth"
	"retune/internal/server/store"
)

func (h *Handler) listAdmins(w http.ResponseWriter, r *http.Request) {
	rows, err := h.Auth.List(r.Context())
	if err != nil {
		h.internal(w, "list admins", err)
		return
	}
	items := make([]adminJSON, 0, len(rows))
	for _, a := range rows {
		items = append(items, newAdminJSON(a))
	}
	writeJSON(w, http.StatusOK, newListResponse(items, len(items), store.Page{Limit: len(items)}))
}

func (h *Handler) createAdmin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if !decode(w, r, &req) {
		return
	}
	admin, err := h.Auth.CreateAdmin(r.Context(), auth.CreateAdminOptions{
		Email: req.Email, Password: req.Password, Role: req.Role, Actor: caller(r).Admin.Email,
	})
	switch {
	case err == nil:
		writeJSON(w, http.StatusCreated, newAdminJSON(admin))
	case errors.Is(err, auth.ErrBadRequest), errors.Is(err, auth.ErrWeakPassword):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	default:
		// A duplicate email trips the unique index.
		h.Log.Warn("create admin failed", "error", err)
		writeError(w, http.StatusBadRequest, "bad_request", "could not create this admin; the email may already be in use")
	}
}

func (h *Handler) setAdminPassword(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such admin")
	if !ok {
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &req) {
		return
	}
	err := h.Auth.SetPassword(r.Context(), id, req.Password, caller(r).Admin.Email)
	switch {
	case err == nil:
		writeNoContent(w)
	case errors.Is(err, auth.ErrWeakPassword):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	case errors.Is(err, auth.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such admin")
	default:
		h.internal(w, "set admin password", err, "admin_id", id)
	}
}

func (h *Handler) setAdminTOTP(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such admin")
	if !ok {
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if !decode(w, r, &req) {
		return
	}
	actor := caller(r).Admin.Email
	if !req.Enabled {
		switch err := h.Auth.DisableTOTP(r.Context(), id, actor); {
		case err == nil:
			writeNoContent(w)
		case errors.Is(err, auth.ErrNotFound):
			writeError(w, http.StatusNotFound, "not_found", "no such admin")
		default:
			h.internal(w, "disable TOTP", err, "admin_id", id)
		}
		return
	}
	secret, url, err := h.Auth.EnableTOTP(r.Context(), id, actor)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]string{"secret": secret, "otpauth_url": url})
	case errors.Is(err, auth.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such admin")
	default:
		h.internal(w, "enable TOTP", err, "admin_id", id)
	}
}

func (h *Handler) setAdminDisabled(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such admin")
	if !ok {
		return
	}
	var req struct {
		Disabled bool `json:"disabled"`
	}
	if !decode(w, r, &req) {
		return
	}
	err := h.Auth.SetDisabled(r.Context(), id, req.Disabled, caller(r).Admin.Email)
	switch {
	case err == nil:
		writeNoContent(w)
	case errors.Is(err, auth.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such admin")
	case errors.Is(err, auth.ErrLastAdmin):
		writeError(w, http.StatusConflict, "last_admin", err.Error())
	default:
		h.internal(w, "set admin disabled", err, "admin_id", id)
	}
}
```

`internal/server/adminapi/audit.go`:

```go
package adminapi

import (
	"net/http"
	"time"
)

type auditJSON struct {
	Actor      string         `json:"actor"`
	Action     string         `json:"action"`
	TargetKind string         `json:"target_kind"`
	TargetID   string         `json:"target_id"`
	Details    map[string]any `json:"details"`
	At         time.Time      `json:"at"`
}

func (h *Handler) listAudit(w http.ResponseWriter, r *http.Request) {
	page := pageFrom(r)
	rows, total, err := h.Store.Q().ListAuditPage(r.Context(), page)
	if err != nil {
		h.internal(w, "list audit log", err)
		return
	}
	items := make([]auditJSON, 0, len(rows))
	for _, e := range rows {
		items = append(items, auditJSON{
			Actor: e.Actor, Action: e.Action, TargetKind: e.TargetKind,
			TargetID: e.TargetID, Details: e.Details, At: e.At,
		})
	}
	writeJSON(w, http.StatusOK, newListResponse(items, total, page))
}
```

- [ ] **Step 7: Mount every route**

Replace `internal/server/adminapi/resources.go` with:

```go
package adminapi

import "net/http"

// mountResources registers the device, command, token, admin and audit routes.
func (h *Handler) mountResources(mux *http.ServeMux, base string) {
	mux.Handle("GET "+base+"/devices", h.read(h.listDevices))
	mux.Handle("GET "+base+"/devices/{id}", h.read(h.getDevice))
	mux.Handle("GET "+base+"/devices/{id}/software", h.read(h.listDeviceSoftware))
	mux.Handle("POST "+base+"/devices/{id}/retire", h.write(h.retireDevice))
	mux.Handle("POST "+base+"/devices/{id}/unenroll", h.write(h.unenrollDevice))

	mux.Handle("GET "+base+"/commands", h.read(h.listCommands))
	mux.Handle("POST "+base+"/commands", h.write(h.queueCommand))
	mux.Handle("GET "+base+"/commands/{id}", h.read(h.getCommand))

	mux.Handle("GET "+base+"/tokens", h.read(h.listTokens))
	mux.Handle("POST "+base+"/tokens", h.write(h.createToken))
	mux.Handle("POST "+base+"/tokens/{id}/revoke", h.write(h.revokeToken))

	mux.Handle("GET "+base+"/admins", h.read(h.listAdmins))
	mux.Handle("POST "+base+"/admins", h.write(h.createAdmin))
	mux.Handle("POST "+base+"/admins/{id}/password", h.write(h.setAdminPassword))
	mux.Handle("POST "+base+"/admins/{id}/totp", h.write(h.setAdminTOTP))
	mux.Handle("POST "+base+"/admins/{id}/disabled", h.write(h.setAdminDisabled))

	mux.Handle("GET "+base+"/audit", h.read(h.listAudit))
}
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `go vet ./internal/server/... && go test -count=1 ./internal/server/...`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add internal/server/adminapi internal/server/app internal/server/enroll
git commit -m "feat(adminapi): device, command, token, admin and audit endpoints"
```

---

### Task 8: Admin CLI commands

**Files:**
- Create: `cmd/retune-server/admins.go`, `cmd/retune-server/cli_m3_test.go`
- Modify: `cmd/retune-server/main.go` (usage plus `bootstrap-admin` and `admin` cases)

**Interfaces:**
- Consumes: Task 3 auth service, `openStore`
- Produces:
  - `retune-server bootstrap-admin --email E [--password P] [--role admin|read_only]` — creates the very first account and prints a generated password when none is given; refuses once any account exists
  - `retune-server admin list | create --email E [--password P] [--role R] | password --email E [--password P] | totp --email E (--enable|--disable) | disable --email E | enable --email E`

- [ ] **Step 1: Write the failing test**

`cmd/retune-server/cli_m3_test.go`:

```go
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
	m := regexp.MustCompile(`Password: (\S+)`).FindStringSubmatch(out)
	if m == nil || !strings.Contains(out, "ops@example.com") {
		t.Fatalf("bootstrap-admin = %q", out)
	}
	generated := m[1]
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
	_ = generated

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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/retune-server/ -run TestAdminCLI`
Expected: FAIL — `unknown command "bootstrap-admin"`.

- [ ] **Step 3: Write the commands**

`cmd/retune-server/admins.go`:

```go
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"retune/internal/server/auth"
	"retune/internal/server/store"
)

const adminUsage = `usage: retune-server admin list | create | password | totp | disable | enable [flags]

flags:
  --email E       the account to act on (required except for list)
  --password P    new password; generated and printed when omitted
  --role R        admin (default) or read_only, for create
  --enable        turn TOTP on, for totp
  --disable       turn TOTP off, for totp`

func authService(st *store.Store) *auth.Service {
	return &auth.Service{Store: st, Now: time.Now, SessionTTL: 12 * time.Hour, Issuer: "Retune"}
}

// bootstrapAdminCmd creates the first account.
func bootstrapAdminCmd(ctx context.Context, args []string, getenv func(string) string, out io.Writer) error {
	fs := flag.NewFlagSet("bootstrap-admin", flag.ContinueOnError)
	email := fs.String("email", "", "email address to sign in with")
	password := fs.String("password", "", "password; generated when omitted")
	role := fs.String("role", store.RoleAdmin, "admin or read_only")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *email == "" {
		return errors.New("--email is required")
	}
	st, err := openStore(ctx, getenv)
	if err != nil {
		return err
	}
	defer st.Close()

	svc := authService(st)
	has, err := svc.HasAdmins(ctx)
	if err != nil {
		return err
	}
	if has {
		return errors.New("an admin already exists; use `retune-server admin create` instead")
	}
	return createAdmin(ctx, svc, *email, *password, *role, out)
}

func adminCmd(ctx context.Context, args []string, getenv func(string) string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(adminUsage)
	}
	fs := flag.NewFlagSet("admin "+args[0], flag.ContinueOnError)
	email := fs.String("email", "", "the account to act on")
	password := fs.String("password", "", "new password; generated when omitted")
	role := fs.String("role", store.RoleAdmin, "admin or read_only")
	enable := fs.Bool("enable", false, "turn TOTP on")
	disable := fs.Bool("disable", false, "turn TOTP off")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if args[0] != "list" && *email == "" {
		return errors.New("--email is required")
	}

	st, err := openStore(ctx, getenv)
	if err != nil {
		return err
	}
	defer st.Close()
	svc := authService(st)

	if args[0] == "list" {
		admins, err := svc.List(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "EMAIL\tROLE\tTOTP\tSTATUS\tLAST LOGIN")
		for _, a := range admins {
			status := "enabled"
			if a.DisabledAt != nil {
				status = "disabled"
			}
			totp := "off"
			if a.TOTPSecret != "" {
				totp = "on"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", a.Email, a.Role, totp, status, timeOrNever(a.LastLoginAt))
		}
		return tw.Flush()
	}
	if args[0] == "create" {
		return createAdmin(ctx, svc, *email, *password, *role, out)
	}

	admin, err := st.Q().GetAdminByEmail(ctx, *email)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("no admin with email %s", *email)
	}
	if err != nil {
		return err
	}

	switch args[0] {
	case "password":
		pw := *password
		if pw == "" {
			if pw, err = auth.GeneratePassword(); err != nil {
				return err
			}
			fmt.Fprintf(out, "Password: %s\n", pw)
		}
		if err := svc.SetPassword(ctx, admin.ID, pw, "cli"); err != nil {
			return err
		}
		fmt.Fprintf(out, "Password changed for %s; existing sessions were signed out.\n", admin.Email)
		return nil
	case "totp":
		switch {
		case *enable == *disable:
			return errors.New("pass exactly one of --enable or --disable")
		case *enable:
			secret, url, err := svc.EnableTOTP(ctx, admin.ID, "cli")
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "Secret: %s\nURL:    %s\n", secret, url)
			return nil
		default:
			if err := svc.DisableTOTP(ctx, admin.ID, "cli"); err != nil {
				return err
			}
			fmt.Fprintf(out, "TOTP disabled for %s.\n", admin.Email)
			return nil
		}
	case "disable", "enable":
		off := args[0] == "disable"
		if err := svc.SetDisabled(ctx, admin.ID, off, "cli"); err != nil {
			return err
		}
		fmt.Fprintf(out, "Admin %s %sd.\n", admin.Email, args[0])
		return nil
	default:
		return errors.New(adminUsage)
	}
}

func createAdmin(ctx context.Context, svc *auth.Service, email, password, role string, out io.Writer) error {
	generated := password == ""
	if generated {
		var err error
		if password, err = auth.GeneratePassword(); err != nil {
			return err
		}
	}
	admin, err := svc.CreateAdmin(ctx, auth.CreateAdminOptions{
		Email: email, Password: password, Role: role, Actor: "cli",
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Created %s (%s).\n", admin.Email, admin.Role)
	if generated {
		fmt.Fprintf(out, "Password: %s\n(The password is shown only once.)\n", password)
	}
	return nil
}
```

- [ ] **Step 4: Register the commands**

In `cmd/retune-server/main.go`, extend `usage`:

```go
  bootstrap-admin        create the first console account (--email, --password, --role)
  admin <subcommand>     manage console accounts (list, create, password, totp, disable, enable)
```

and add to the `switch` in `run`:

```go
	case "bootstrap-admin":
		return bootstrapAdminCmd(ctx, args[1:], getenv, out)
	case "admin":
		return adminCmd(ctx, args[1:], getenv, out)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go vet ./cmd/... && go test -count=1 ./cmd/retune-server/`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add cmd/retune-server
git commit -m "feat(server): bootstrap-admin and admin management commands"
```

---

### Task 9: Verification and manual smoke test

**Files:** none (verification only)

- [ ] **Step 1: Full verification**

Run: `go vet ./... && go test -count=1 ./... && go build -o bin/ ./cmd/...`
Expected: every package passes and both binaries build.

- [ ] **Step 2: Start a server with a YAML config file**

```powershell
docker run -d --name retune-m3-pg -e POSTGRES_USER=retune -e POSTGRES_PASSWORD=retune -e POSTGRES_DB=retune -p 127.0.0.1::5432 postgres:17-alpine
$port = ((docker port retune-m3-pg 5432) -split ':')[-1]
@"
database_url: postgres://retune:retune@127.0.0.1:$port/retune?sslmode=disable
public_url: https://localhost:18443
agent_api_listen: 127.0.0.1:18443
data_dir: ./data
session_ttl_hours: 4
"@ | Set-Content retune-server.yaml
.\bin\retune-server.exe migrate
.\bin\retune-server.exe bootstrap-admin --email ops@example.com
# in a second terminal:
.\bin\retune-server.exe serve
```

Expected: `migrate` and `bootstrap-admin` work with no environment variables set, proving the YAML file is read, and `bootstrap-admin` prints a generated password.

- [ ] **Step 3: Exercise the API as an admin**

```powershell
$pw = '<the generated password>'
$s = Invoke-WebRequest -Uri https://localhost:18443/api/admin/v1/session -Method Post -SkipCertificateCheck `
  -ContentType application/json -SessionVariable sess `
  -Body (@{email='ops@example.com'; password=$pw} | ConvertTo-Json)
$csrf = ($s.Content | ConvertFrom-Json).csrf_token
Invoke-WebRequest -Uri https://localhost:18443/api/admin/v1/devices -SkipCertificateCheck -WebSession $sess | Select-Object -ExpandProperty Content
Invoke-WebRequest -Uri https://localhost:18443/api/admin/v1/tokens -Method Post -SkipCertificateCheck -WebSession $sess `
  -Headers @{'X-CSRF-Token' = $csrf} -ContentType application/json -Body '{"label":"smoke","max_uses":1}' |
  Select-Object -ExpandProperty Content
# CSRF is enforced:
try { Invoke-WebRequest -Uri https://localhost:18443/api/admin/v1/tokens -Method Post -SkipCertificateCheck -WebSession $sess -ContentType application/json -Body '{"label":"no-csrf"}' } catch { $_.Exception.Response.StatusCode }
Invoke-WebRequest -Uri https://localhost:18443/api/admin/v1/audit -SkipCertificateCheck -WebSession $sess | Select-Object -ExpandProperty Content
```

Expected: login returns the admin and a CSRF token, the device list is empty with `"total":0`, creating a token returns a `rt_…` value once, the request without the CSRF header fails with 403, and the audit log shows `admin.login` and `enrollment_token.created`.

- [ ] **Step 4: Enroll a device and see it through the API**

```powershell
.\bin\retune-agent.exe enroll --server https://localhost:18443 --token <TOKEN> --pin (.\bin\retune-server.exe ca fingerprint) --data-dir .\agent-data
.\bin\retune-agent.exe run --once --data-dir .\agent-data
Invoke-WebRequest -Uri https://localhost:18443/api/admin/v1/devices -SkipCertificateCheck -WebSession $sess | Select-Object -ExpandProperty Content
```

Expected: the device appears with its real hostname, and its detail endpoint shows inventory and software.

- [ ] **Step 5: Clean up**

```powershell
docker rm -f retune-m3-pg
Remove-Item -Recurse -Force .\data, .\agent-data, .\retune-server.yaml
```

- [ ] **Step 6: Commit any fixes the smoke test uncovered**

```bash
git add -A
git commit -m "fix: address issues found during the M3a smoke test"
```
