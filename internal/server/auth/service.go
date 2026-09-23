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
	// ErrLocalLoginDisabled is password sign-in refused because SSO is the
	// only way in.
	ErrLocalLoginDisabled = errors.New("password sign-in is turned off; sign in with SSO")
)

// ssoOwned is the reason a password or authenticator change is refused for an
// account that signs in through the identity provider: both belong there.
const ssoOwned = "this account signs in through SSO; its password and MFA belong to the identity provider"

// touchInterval is how stale a session's last_seen may get before the row is
// updated, so a busy console does not write on every request.
const touchInterval = time.Minute

// maxEmailLength is the longest address sign-in will even look at (RFC 5321's
// limit). Anything longer is refused before it costs a hash or a limiter slot.
const maxEmailLength = 320

// hashSlots bounds how many password checks run at once. Each Argon2id check
// takes 64 MiB, and sign-in is reachable without an account, so without a
// bound a burst of requests - for unknown addresses too, which cost a dummy
// check to keep the timing honest - could take the server's memory with it.
// Four at a time is 256 MiB at most; a check that cannot get a slot within
// hashWait is refused as too many attempts.
var hashSlots = make(chan struct{}, 4)

const hashWait = 5 * time.Second

// verifyPassword is VerifyPassword under the hashSlots bound.
func verifyPassword(ctx context.Context, encoded, password string) (bool, error) {
	timer := time.NewTimer(hashWait)
	defer timer.Stop()
	select {
	case hashSlots <- struct{}{}:
	case <-timer.C:
		return false, ErrTooManyAttempts
	case <-ctx.Done():
		return false, ctx.Err()
	}
	defer func() { <-hashSlots }()
	return VerifyPassword(encoded, password), nil
}

// Service authenticates admins and manages their sessions.
type Service struct {
	Store      *store.Store
	Now        func() time.Time
	SessionTTL time.Duration
	Limiter    *Limiter
	Issuer     string
	// LocalLoginDisabled refuses every password sign-in.
	LocalLoginDisabled bool
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
	if s.LocalLoginDisabled {
		return store.Admin{}, ErrLocalLoginDisabled
	}
	key := strings.ToLower(strings.TrimSpace(email))
	if len(key) > maxEmailLength || len(password) > maxPasswordLength {
		return store.Admin{}, ErrInvalidCredentials
	}
	if s.Limiter != nil && !s.Limiter.Allowed(key) {
		return store.Admin{}, ErrTooManyAttempts
	}
	admin, err := s.Store.Q().GetAdminByEmail(ctx, store.DefaultTenantID, key)
	if errors.Is(err, store.ErrNotFound) {
		if _, err := verifyPassword(ctx, dummyHash(), password); err != nil { // keep the timing similar
			return store.Admin{}, err
		}
		s.fail(key)
		return store.Admin{}, ErrInvalidCredentials
	}
	if err != nil {
		return store.Admin{}, err
	}
	if admin.AuthSource == store.AuthOIDC {
		// An SSO account has no password, and checking against an empty
		// hash returns at once: without the dummy check, the timing alone
		// would say which addresses belong to SSO accounts.
		if _, err := verifyPassword(ctx, dummyHash(), password); err != nil {
			return store.Admin{}, err
		}
		s.fail(key)
		return store.Admin{}, ErrInvalidCredentials
	}
	ok, err := verifyPassword(ctx, admin.PasswordHash, password)
	if err != nil {
		return store.Admin{}, err
	}
	if !ok {
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
		if err := q.RecordAdminLogin(ctx, store.DefaultTenantID, admin.ID, now); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: admin.Email, Action: "admin.login", TargetKind: "admin", TargetID: admin.ID.String(),
			Details: map[string]any{"method": store.AuthLocal},
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
		admin, err := q.GetAdmin(ctx, store.DefaultTenantID, id)
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("%w: %s", ErrNotFound, id)
		}
		if err != nil {
			return err
		}
		if admin.AuthSource == store.AuthOIDC {
			return fmt.Errorf("%w: %s", ErrBadRequest, ssoOwned)
		}
		if err := q.UpdateAdminPassword(ctx, store.DefaultTenantID, id, hash); err != nil {
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
		admin, err := q.GetAdmin(ctx, store.DefaultTenantID, id)
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("%w: %s", ErrNotFound, id)
		}
		if err != nil {
			return err
		}
		if admin.AuthSource == store.AuthOIDC {
			return fmt.Errorf("%w: %s", ErrBadRequest, ssoOwned)
		}
		if secret, url, err = NewTOTPSecret(s.Issuer, admin.Email); err != nil {
			return err
		}
		if err := q.UpdateAdminTOTP(ctx, store.DefaultTenantID, id, secret); err != nil {
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
		admin, err := q.GetAdmin(ctx, store.DefaultTenantID, id)
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("%w: %s", ErrNotFound, id)
		} else if err != nil {
			return err
		}
		if admin.AuthSource == store.AuthOIDC {
			return fmt.Errorf("%w: %s", ErrBadRequest, ssoOwned)
		}
		if err := q.UpdateAdminTOTP(ctx, store.DefaultTenantID, id, ""); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: actor, Action: "admin.totp_disabled", TargetKind: "admin", TargetID: id.String(),
		})
	})
}

// SetDisabled disables or re-enables an account. The last enabled admin cannot
// be disabled, so nobody can lock everyone out.
func (s *Service) SetDisabled(ctx context.Context, id uuid.UUID, disabled bool, actor string) error {
	now := s.Now()
	return s.Store.InTx(ctx, func(q *store.Queries) error {
		admin, err := q.GetAdmin(ctx, store.DefaultTenantID, id)
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
		if err := q.SetAdminDisabled(ctx, store.DefaultTenantID, id, at); err != nil {
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
