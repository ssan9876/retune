package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/store"
)

// APITokenPrefix starts every API token, so one found in a log, a paste or a
// repository is recognisable for what it is, and a secret scanner can match
// it.
const APITokenPrefix = "rtk_"

// API token lifetimes, in days. Every token expires: a credential that lives
// in a script's config tends to outlive the reason it was made.
const (
	DefaultAPITokenDays = 90
	MaxAPITokenDays     = 365
	maxAPITokenName     = 100
)

var (
	// ErrInvalidToken is an API token that is unknown, revoked, expired, or
	// made by an admin who is now disabled. The caller is not told which.
	ErrInvalidToken = errors.New("the API token is invalid, expired or revoked")
	// ErrDuplicateToken is a live token that already has the name.
	ErrDuplicateToken = errors.New("a live API token already has that name")
)

// NewAPIToken describes a token to create.
type NewAPIToken struct {
	Name string
	Role string
	// Days is the lifetime, 1 to MaxAPITokenDays; 0 means the default.
	Days int
	// Creator is the admin making the token. The token dies with them: it
	// stops working when they are disabled, and it can never have a role
	// they do not have.
	Creator store.Admin
}

// CreateAPIToken makes a token and returns it in plain text, the only time it
// is ever available.
func (s *Service) CreateAPIToken(ctx context.Context, n NewAPIToken) (string, store.APIToken, error) {
	name := strings.TrimSpace(n.Name)
	if name == "" || len(name) > maxAPITokenName {
		return "", store.APIToken{}, fmt.Errorf("%w: a token needs a name of at most %d characters", ErrBadRequest, maxAPITokenName)
	}
	if !store.ValidRole(n.Role) {
		return "", store.APIToken{}, fmt.Errorf("%w: role must be %s, %s or %s", ErrBadRequest,
			store.RoleAdmin, store.RoleHelpdesk, store.RoleReadOnly)
	}
	if store.RoleRank(n.Role) > store.RoleRank(n.Creator.Role) {
		return "", store.APIToken{}, fmt.Errorf("%w: a token cannot have more access than the admin who makes it", ErrBadRequest)
	}
	days := n.Days
	if days == 0 {
		days = DefaultAPITokenDays
	}
	if days < 1 || days > MaxAPITokenDays {
		return "", store.APIToken{}, fmt.Errorf("%w: a token must expire in 1 to %d days", ErrBadRequest, MaxAPITokenDays)
	}
	secret, err := randomToken()
	if err != nil {
		return "", store.APIToken{}, err
	}
	plain := APITokenPrefix + secret
	id, err := uuid.NewV7()
	if err != nil {
		return "", store.APIToken{}, err
	}
	now := s.Now()
	tok := store.APIToken{
		ID: id, Name: name, TokenHash: hashToken(plain), Role: n.Role,
		CreatedByID: n.Creator.ID, CreatedBy: n.Creator.Email,
		CreatedAt: now, ExpiresAt: now.Add(time.Duration(days) * 24 * time.Hour),
	}
	err = s.Store.InTx(ctx, func(q *store.Queries) error {
		if err := q.CreateAPIToken(ctx, tok); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: n.Creator.Email, Action: "api_token.created", TargetKind: "api_token", TargetID: id.String(),
			Details: map[string]any{"name": name, "role": n.Role, "expires_at": tok.ExpiresAt},
		})
	})
	if errors.Is(err, store.ErrDuplicate) {
		return "", store.APIToken{}, ErrDuplicateToken
	}
	if err != nil {
		return "", store.APIToken{}, err
	}
	return plain, tok, nil
}

// AuthenticateAPIToken returns the token a request presented, if it is one
// that should still work.
func (s *Service) AuthenticateAPIToken(ctx context.Context, plain string) (store.APIToken, error) {
	if !strings.HasPrefix(plain, APITokenPrefix) {
		return store.APIToken{}, ErrInvalidToken
	}
	now := s.Now()
	q := s.Store.Q()
	tok, err := q.GetUsableAPIToken(ctx, hashToken(plain), now)
	if errors.Is(err, store.ErrNotFound) {
		return store.APIToken{}, ErrInvalidToken
	}
	if err != nil {
		return store.APIToken{}, err
	}
	// The same rule sessions follow: a busy integration does not write on
	// every request, but "last used" is never more than a minute stale.
	if tok.LastUsedAt == nil || now.Sub(*tok.LastUsedAt) >= touchInterval {
		if err := q.TouchAPIToken(ctx, store.DefaultTenantID, tok.ID, now); err != nil {
			return store.APIToken{}, err
		}
		tok.LastUsedAt = &now
	}
	return tok, nil
}

// ListAPITokens returns every token, revoked ones included, never the secrets.
func (s *Service) ListAPITokens(ctx context.Context) ([]store.APIToken, error) {
	return s.Store.Q().ListAPITokens(ctx)
}

// RevokeAPIToken stops a token working, at once.
func (s *Service) RevokeAPIToken(ctx context.Context, id uuid.UUID, actor string) error {
	return s.Store.InTx(ctx, func(q *store.Queries) error {
		tok, err := q.GetAPIToken(ctx, store.DefaultTenantID, id)
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("%w: %s", ErrNotFound, id)
		}
		if err != nil {
			return err
		}
		revoked, err := q.RevokeAPIToken(ctx, store.DefaultTenantID, id, s.Now())
		if err != nil || !revoked {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: actor, Action: "api_token.revoked", TargetKind: "api_token", TargetID: id.String(),
			Details: map[string]any{"name": tok.Name},
		})
	})
}
