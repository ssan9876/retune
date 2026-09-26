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

	"retune/internal/server/secrets"
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
	ErrLastAdmin          = errors.New("the last enabled, unscoped admin cannot be disabled or scoped")
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
	// MaxSessionLifetime caps a session however busy it is, counted from
	// sign-in. Without it a session kept in use never ends, and neither does
	// the access of someone the identity provider has since removed. Zero
	// means no cap.
	MaxSessionLifetime time.Duration
	Limiter    *Limiter
	Issuer     string
	// Throttle counts failed sign-ins in the database, shared by every server
	// behind a load balancer. When it is nil, Limiter counts them in this
	// server's memory instead.
	Throttle Throttle
	// IPThrottle counts failed sign-ins per client address, across every
	// account, so one address cannot try a common password against each
	// account in turn. Nil turns it off.
	IPThrottle Throttle
	// LocalLoginDisabled refuses every password sign-in.
	LocalLoginDisabled bool
	// SSOScopesManaged says the identity provider sets SSO accounts'
	// device scopes at each sign-in, so they can't be edited here.
	SSOScopesManaged bool
	// Key seals authenticator secrets at rest. Turning TOTP on, and signing in
	// with it, need it.
	Key *secrets.Key
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
	return s.AuthenticateFrom(ctx, "", email, password, totpCode)
}

// AuthenticateFrom is Authenticate for a request from ip, which IPThrottle
// also counts. An empty ip is counted against the account alone.
func (s *Service) AuthenticateFrom(ctx context.Context, ip, email, password, totpCode string) (store.Admin, error) {
	if s.LocalLoginDisabled {
		return store.Admin{}, ErrLocalLoginDisabled
	}
	key := strings.ToLower(strings.TrimSpace(email))
	if len(key) > maxEmailLength || len(password) > maxPasswordLength {
		return store.Admin{}, ErrInvalidCredentials
	}
	if t := s.throttle(); t != nil {
		allowed, err := t.Allowed(ctx, key)
		if err != nil {
			return store.Admin{}, err
		}
		if !allowed {
			return store.Admin{}, ErrTooManyAttempts
		}
	}
	if s.IPThrottle != nil && ip != "" {
		allowed, err := s.IPThrottle.Allowed(ctx, ipKey(ip))
		if err != nil {
			return store.Admin{}, err
		}
		if !allowed {
			return store.Admin{}, ErrTooManyAttempts
		}
	}
	admin, err := s.Store.Q().GetAdminByEmail(ctx, store.DefaultTenantID, key)
	if errors.Is(err, store.ErrNotFound) {
		if _, err := verifyPassword(ctx, dummyHash(), password); err != nil { // keep the timing similar
			return store.Admin{}, err
		}
		s.fail(ctx, key, ip)
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
		s.fail(ctx, key, ip)
		return store.Admin{}, ErrInvalidCredentials
	}
	ok, err := verifyPassword(ctx, admin.PasswordHash, password)
	if err != nil {
		return store.Admin{}, err
	}
	if !ok {
		s.fail(ctx, key, ip)
		return store.Admin{}, ErrInvalidCredentials
	}
	if admin.DisabledAt != nil {
		return store.Admin{}, ErrAccountDisabled
	}
	if admin.TOTPSecret != "" {
		if totpCode == "" {
			return store.Admin{}, ErrTOTPRequired
		}
		secret, err := openTOTP(s.Key, admin.ID, admin.TOTPSecret)
		if err != nil {
			return store.Admin{}, fmt.Errorf("open the authenticator secret for %s: %w", admin.Email, err)
		}
		step, ok := matchTOTP(secret, totpCode, s.Now())
		if !ok {
			s.fail(ctx, key, ip)
			return store.Admin{}, ErrTOTPInvalid
		}
		// A code is good for a minute or so; whoever watched it being typed
		// mustn't be able to use it too.
		fresh, err := s.Store.Q().ClaimTOTPStep(ctx, store.DefaultTenantID, admin.ID, step)
		if err != nil {
			return store.Admin{}, err
		}
		if !fresh {
			s.fail(ctx, key, ip)
			return store.Admin{}, ErrTOTPInvalid
		}
	}
	if t := s.throttle(); t != nil {
		// Best effort: a sign-in that worked isn't refused because its
		// failures couldn't be cleared.
		_ = t.Reset(ctx, key)
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

// throttle is Throttle when set, shared by every server; else the in-memory
// Limiter; else none.
func (s *Service) throttle() Throttle {
	switch {
	case s.Throttle != nil:
		return s.Throttle
	case s.Limiter != nil:
		return memoryThrottle{s.Limiter}
	}
	return nil
}

func (s *Service) fail(ctx context.Context, key, ip string) {
	// Best effort, like Reset: if the database can't be written, the
	// sign-in fails anyway.
	if t := s.throttle(); t != nil {
		_ = t.Fail(ctx, key)
	}
	// An address's failures are not cleared by a sign-in that works: one
	// account of the attacker's own would otherwise reset the count.
	if s.IPThrottle != nil && ip != "" {
		_ = s.IPThrottle.Fail(ctx, ipKey(ip))
	}
}

// ipKey keeps address keys apart from account keys, which are email
// addresses and so never contain a space.
func ipKey(ip string) string { return "ip " + ip }

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
	expires := s.capped(now, now.Add(s.SessionTTL))
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
		expires := s.capped(session.CreatedAt, now.Add(s.SessionTTL))
		if err := q.TouchSession(ctx, hash, now, expires); err != nil {
			return store.Admin{}, store.Session{}, err
		}
		session.LastSeenAt, session.ExpiresAt = now, expires
	}
	return admin, session, nil
}

// capped keeps an expiry within MaxSessionLifetime of when the session began.
func (s *Service) capped(createdAt, expires time.Time) time.Time {
	if s.MaxSessionLifetime <= 0 {
		return expires
	}
	if limit := createdAt.Add(s.MaxSessionLifetime); expires.After(limit) {
		return limit
	}
	return expires
}

// DeleteSession signs one browser out. An unknown token is not an error.
func (s *Service) DeleteSession(ctx context.Context, token string) error {
	return s.Store.Q().DeleteSession(ctx, hashToken(token))
}

// isFleetAdmin is an admin who can manage the whole fleet: the admin role,
// enabled, and not limited to some device groups. There must always be one,
// or nobody could manage admins, groups or anything else fleet-wide again.
func isFleetAdmin(a store.Admin) bool {
	return a.Role == store.RoleAdmin && a.DisabledAt == nil && !a.Scoped
}

func fleetAdminsBesides(admins []store.Admin, id uuid.UUID) int {
	n := 0
	for _, a := range admins {
		if a.ID != id && isFleetAdmin(a) {
			n++
		}
	}
	return n
}

// SetScope limits an admin to device groups, or with nil lifts the limit. An
// empty, non-nil list limits them to nothing at all. It refuses to scope the
// last admin who can manage the whole fleet.
func (s *Service) SetScope(ctx context.Context, id uuid.UUID, groups []uuid.UUID, actor string) error {
	return s.Store.InTx(ctx, func(q *store.Queries) error {
		admin, err := q.GetAdmin(ctx, store.DefaultTenantID, id)
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("%w: %s", ErrNotFound, id)
		}
		if err != nil {
			return err
		}
		if s.SSOScopesManaged && admin.AuthSource == store.AuthOIDC {
			return fmt.Errorf("%w: this account's devices come from its groups in the identity provider", ErrBadRequest)
		}
		if groups != nil && isFleetAdmin(admin) {
			all, err := q.ListAdmins(ctx)
			if err != nil {
				return err
			}
			if fleetAdminsBesides(all, id) == 0 {
				return ErrLastAdmin
			}
		}
		names := make([]string, 0, len(groups))
		for _, g := range groups {
			group, err := q.GetGroup(ctx, store.DefaultTenantID, g)
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("%w: there is no group %s", ErrBadRequest, g)
			}
			if err != nil {
				return err
			}
			names = append(names, group.Name)
		}
		if err := q.SetAdminScope(ctx, store.DefaultTenantID, id, store.DeviceScope(groups)); err != nil {
			return err
		}
		details := map[string]any{"email": admin.Email, "scoped": groups != nil}
		if groups != nil {
			details["groups"] = names
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: actor, Action: "admin.scope_changed", TargetKind: "admin", TargetID: id.String(),
			Details: details,
		})
	})
}

// CreateAdmin adds an account.
func (s *Service) CreateAdmin(ctx context.Context, o CreateAdminOptions) (store.Admin, error) {
	email := strings.TrimSpace(o.Email)
	if !validEmail(email) {
		return store.Admin{}, fmt.Errorf("%w: %q is not a valid email address", ErrBadRequest, o.Email)
	}
	if !store.ValidRole(o.Role) {
		return store.Admin{}, fmt.Errorf("%w: role must be %s, %s or %s", ErrBadRequest,
			store.RoleAdmin, store.RoleHelpdesk, store.RoleReadOnly)
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
		sealed, err := sealTOTP(s.Key, id, secret)
		if err != nil {
			return err
		}
		if err := q.UpdateAdminTOTP(ctx, store.DefaultTenantID, id, sealed); err != nil {
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

// SealTOTPSecrets seals any authenticator secret stored in the clear by an
// earlier version, and reports how many it sealed. The server runs it at
// startup.
func (s *Service) SealTOTPSecrets(ctx context.Context) (int, error) {
	plain, err := s.Store.Q().ListPlainTOTPSecrets(ctx)
	if err != nil || len(plain) == 0 {
		return 0, err
	}
	for i, p := range plain {
		sealed, err := sealTOTP(s.Key, p.AdminID, p.Secret)
		if err != nil {
			return i, err
		}
		if err := s.Store.Q().ReplaceTOTPSecret(ctx, p.TenantID, p.AdminID, p.Secret, sealed); err != nil {
			return i, err
		}
	}
	return len(plain), nil
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
			if isFleetAdmin(admin) && fleetAdminsBesides(others, id) == 0 {
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
