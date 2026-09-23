// Package rekey re-seals every secret the server stores from one server key
// to another, so a key suspected of exposure can be retired.
package rekey

import (
	"context"
	"errors"
	"fmt"

	"retune/internal/server/alerts"
	"retune/internal/server/auth"
	"retune/internal/server/bitlocker"
	"retune/internal/server/laps"
	"retune/internal/server/profiles"
	"retune/internal/server/secrets"
	"retune/internal/server/store"
)

// Counts says how many values of each kind were re-sealed.
type Counts struct {
	AuthenticatorSecrets int
	BitLockerKeys        int
	AdminPasswords       int
	ChannelSecrets       int
	ProfileVersions      int
}

// Total is every value re-sealed.
func (c Counts) Total() int {
	return c.AuthenticatorSecrets + c.BitLockerKeys + c.AdminPasswords + c.ChannelSecrets + c.ProfileVersions
}

// Rotate re-seals everything sealed under from so it is sealed under to, in
// one transaction: either every value moves to the new key or none does. It
// refuses to run while any server is running against the database, and
// fails without changing anything if a value doesn't open with from - the
// sign of being given the wrong key. A dry run does all of it and then rolls
// back, to prove the current key opens everything.
func Rotate(ctx context.Context, st *store.Store, from, to *secrets.Key, dryRun bool) (Counts, error) {
	var c Counts
	err := st.WithServersStopped(ctx, func(q *store.Queries) error {
		c = Counts{}
		totps, err := q.SealedTOTPSecrets(ctx)
		if err != nil {
			return err
		}
		for _, t := range totps {
			if !auth.IsSealedTOTP(t.Stored) {
				continue // sealed by the server when it next starts
			}
			resealed, err := auth.ResealTOTP(from, to, t.AdminID, t.Stored)
			if err != nil {
				return fmt.Errorf("authenticator secret of admin %s: %w", t.AdminID, err)
			}
			if err := q.SetTOTPSealed(ctx, t.AdminID, resealed); err != nil {
				return err
			}
			c.AuthenticatorSecrets++
		}

		type kind struct {
			what    string
			list    func(context.Context) ([]store.SealedValue, error)
			context func(store.SealedValue) []byte
			set     func(context.Context, store.SealedValue, []byte, []byte) error
			count   *int
		}
		kinds := []kind{
			{"BitLocker recovery key", q.SealedBitLockerKeys,
				func(v store.SealedValue) []byte { return bitlocker.EscrowContext(v.DeviceID, v.Name) },
				func(ctx context.Context, v store.SealedValue, ct, n []byte) error {
					return q.SetBitLockerKeySealed(ctx, v.ID, ct, n)
				},
				&c.BitLockerKeys},
			{"local admin password", q.SealedAdminPasswords,
				func(v store.SealedValue) []byte { return laps.SealContext(v.DeviceID, v.Name) },
				func(ctx context.Context, v store.SealedValue, ct, n []byte) error {
					return q.SetAdminPasswordSealed(ctx, v.ID, ct, n)
				},
				&c.AdminPasswords},
			{"notification channel secret", q.SealedChannelSecrets,
				func(v store.SealedValue) []byte { return alerts.SecretContext(v.ID) },
				func(ctx context.Context, v store.SealedValue, ct, n []byte) error {
					return q.SetChannelSecretSealed(ctx, v.ID, ct, n)
				},
				&c.ChannelSecrets},
		}
		for _, k := range kinds {
			values, err := k.list(ctx)
			if err != nil {
				return err
			}
			for _, v := range values {
				plain, err := from.Open(v.Ciphertext, v.Nonce, k.context(v))
				if err != nil {
					return fmt.Errorf("%s %s: %w", k.what, v.ID, err)
				}
				ct, nonce, err := to.Seal(plain, k.context(v))
				if err != nil {
					return err
				}
				if err := k.set(ctx, v, ct, nonce); err != nil {
					return err
				}
				*k.count++
			}
		}

		versions, err := q.ProfileVersionsWithSecrets(ctx)
		if err != nil {
			return err
		}
		for _, v := range versions {
			settings, hash, changed, err := profiles.ResealSettings(from, to, v.ProfileID, v.Settings)
			if err != nil {
				return fmt.Errorf("profile %s version %d: %w", v.ProfileID, v.Version, err)
			}
			if !changed {
				continue
			}
			if err := q.SetProfileVersionSettings(ctx, v.ProfileID, v.Version, settings, hash); err != nil {
				return err
			}
			c.ProfileVersions++
		}

		if dryRun {
			return errDryRun
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: "retune-server rotate-secret-key", Action: "secret_key.rotated", TargetKind: "server",
			Details: map[string]any{
				"authenticator_secrets": c.AuthenticatorSecrets, "bitlocker_keys": c.BitLockerKeys,
				"admin_passwords": c.AdminPasswords, "channel_secrets": c.ChannelSecrets,
				"profile_versions": c.ProfileVersions,
			},
		})
	})
	if dryRun && errors.Is(err, errDryRun) {
		err = nil
	}
	return c, err
}

var errDryRun = errors.New("dry run")
