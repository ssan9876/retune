package executor

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"

	"retune/internal/protocol"
)

// PasswordSetter changes local account passwords.
type PasswordSetter interface {
	// BuiltinAdmin names the built-in Administrator account (RID 500),
	// whatever it has been renamed to.
	BuiltinAdmin(ctx context.Context) (string, error)
	SetPassword(ctx context.Context, account, password string) error
}

// PasswordEscrower hands a password to the server before it is set.
type PasswordEscrower interface {
	EscrowAdminPassword(ctx context.Context, req protocol.AdminPasswordEscrowRequest) error
}

// passwordAlphabets leave out characters that are easy to misread when a
// password is read off a screen and typed at a login prompt: 0/O, 1/l/I, and
// quotes and backticks.
var passwordAlphabets = []string{
	"ABCDEFGHJKLMNPQRSTUVWXYZ",
	"abcdefghijkmnopqrstuvwxyz",
	"23456789",
	"!#$%&*+-=?@^_~",
}

// GeneratePassword makes a password of length characters with at least one
// from each alphabet, which every Windows complexity policy accepts.
func GeneratePassword(length int) (string, error) {
	if length < len(passwordAlphabets) {
		return "", fmt.Errorf("a password needs at least %d characters", len(passwordAlphabets))
	}
	all := ""
	for _, a := range passwordAlphabets {
		all += a
	}
	out := make([]byte, length)
	for i := range out {
		set := all
		if i < len(passwordAlphabets) {
			set = passwordAlphabets[i]
		}
		c, err := pick(set)
		if err != nil {
			return "", err
		}
		out[i] = c
	}
	// Shuffle, so the guaranteed characters aren't always first.
	for i := len(out) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return "", err
		}
		out[i], out[j.Int64()] = out[j.Int64()], out[i]
	}
	return string(out), nil
}

func pick(set string) (byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
	if err != nil {
		return 0, err
	}
	return set[n.Int64()], nil
}

// rotateAdminPassword escrows a new password with the server and only then
// sets it: a password set but never escrowed is one nobody knows. The result
// names the account, never the password.
func (e *Executor) rotateAdminPassword(ctx context.Context, c protocol.Command, res *protocol.CommandResult) {
	p := protocol.RotateAdminPasswordPayload{Length: protocol.DefaultAdminPasswordLength}
	if len(c.Payload) > 0 && string(c.Payload) != "null" {
		if err := json.Unmarshal(c.Payload, &p); err != nil {
			fail(res, fmt.Sprintf("invalid rotate_local_admin_password payload: %v", err))
			return
		}
	}
	if p.Length < protocol.MinAdminPasswordLength || p.Length > protocol.MaxAdminPasswordLength {
		fail(res, fmt.Sprintf("length must be between %d and %d", protocol.MinAdminPasswordLength, protocol.MaxAdminPasswordLength))
		return
	}
	if e.Passwords == nil || e.Escrower == nil {
		fail(res, "rotating passwords "+errUnavailable.Error())
		return
	}
	account := p.Account
	if account == "" {
		name, err := e.Passwords.BuiltinAdmin(ctx)
		if err != nil {
			fail(res, fmt.Sprintf("finding the built-in Administrator account: %v", err))
			return
		}
		account = name
	}
	password, err := GeneratePassword(p.Length)
	if err != nil {
		fail(res, fmt.Sprintf("generating a password: %v", err))
		return
	}
	if err := e.Escrower.EscrowAdminPassword(ctx, protocol.AdminPasswordEscrowRequest{
		CommandID: c.ID, Account: account, Password: password,
	}); err != nil {
		fail(res, fmt.Sprintf("the server didn't store the new password, so it wasn't set: %v", err))
		return
	}
	if err := e.Passwords.SetPassword(ctx, account, password); err != nil {
		fail(res, fmt.Sprintf("setting the password for %s: %v", account, err))
		return
	}
	res.Stdout = fmt.Sprintf("set a new password for %s; it is escrowed with the server", account)
}
