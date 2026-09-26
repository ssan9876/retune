package rekey_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/bitlocker"
	"retune/internal/server/laps"
	"retune/internal/server/rekey"
	"retune/internal/server/secrets"
	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

func newKey(t *testing.T) *secrets.Key {
	t.Helper()
	k, _, err := secrets.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestRotateIsAllOrNothing: when one value won't open - here a password
// sealed under some other key - values already re-sealed earlier in the same
// run are rolled back, and the error names the one that failed. The same
// data without the stray value then rotates, and a dry run beforehand counts
// it all but changes nothing.
func TestRotateIsAllOrNothing(t *testing.T) {
	ctx := context.Background()
	st := storetest.New(t)
	q := st.Q()
	from, to, stray := newKey(t), newKey(t), newKey(t)
	now := time.Now().UTC()

	device := store.Device{
		ID: uuid.Must(uuid.NewV7()), Hostname: "PC-KEY", Status: store.DeviceActive,
		CertSerial: "c", CertExpiresAt: now.Add(time.Hour), EnrolledAt: now,
	}
	if err := q.CreateDevice(ctx, device); err != nil {
		t.Fatal(err)
	}
	// BitLocker keys are re-sealed before admin passwords.
	for _, vol := range []string{"C:", "D:"} {
		if err := (&bitlocker.Service{Store: st, Key: from}).Escrow(ctx, device.ID, vol, "XtsAes256", "111111-"+vol); err != nil {
			t.Fatal(err)
		}
	}
	bitlockerSealed := func() map[uuid.UUID][]byte {
		keys, err := q.ListBitLockerKeys(ctx, device.ID)
		if err != nil {
			t.Fatal(err)
		}
		out := map[uuid.UUID][]byte{}
		for _, k := range keys {
			full, err := q.GetBitLockerKey(ctx, store.DefaultTenantID, k.ID)
			if err != nil {
				t.Fatal(err)
			}
			out[k.ID] = full.Ciphertext
		}
		return out
	}
	before := bitlockerSealed()

	ct, nonce, err := stray.Seal([]byte("local-admin-pw"), laps.SealContext(device.ID, "Administrator"))
	if err != nil {
		t.Fatal(err)
	}
	strayID := uuid.Must(uuid.NewV7())
	if err := q.UpsertPendingAdminPassword(ctx, store.AdminPassword{
		ID: strayID, DeviceID: device.ID, Account: "Administrator",
		Ciphertext: ct, Nonce: nonce, CommandID: uuid.New(), CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	_, err = rekey.Rotate(ctx, st, from, to, false)
	if err == nil || !strings.Contains(err.Error(), "local admin password") || !strings.Contains(err.Error(), strayID.String()) {
		t.Fatalf("rotate with a stray value: %v", err)
	}
	after := bitlockerSealed()
	for id, sealed := range before {
		if !bytes.Equal(after[id], sealed) {
			t.Fatal("a failed rotation kept the BitLocker keys it re-sealed before failing")
		}
	}

	// Re-seal the stray value under from, and the rotation goes through.
	ct, nonce, err = from.Seal([]byte("local-admin-pw"), laps.SealContext(device.ID, "Administrator"))
	if err != nil {
		t.Fatal(err)
	}
	if err := q.SetAdminPasswordSealed(ctx, strayID, ct, nonce); err != nil {
		t.Fatal(err)
	}

	counts, err := rekey.Rotate(ctx, st, from, to, true)
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if counts.BitLockerKeys != 2 || counts.AdminPasswords != 1 || counts.Total() != 3 {
		t.Fatalf("dry run counts = %+v", counts)
	}
	for id, sealed := range bitlockerSealed() {
		if !bytes.Equal(before[id], sealed) {
			t.Fatal("a dry run changed a stored secret")
		}
	}

	counts, err = rekey.Rotate(ctx, st, from, to, false)
	if err != nil || counts.Total() != 3 {
		t.Fatalf("rotate: %+v %v", counts, err)
	}
	for id := range before {
		full, err := q.GetBitLockerKey(ctx, store.DefaultTenantID, id)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := to.Open(full.Ciphertext, full.Nonce, bitlocker.EscrowContext(device.ID, full.VolumeID)); err != nil {
			t.Errorf("BitLocker key %s does not open with the new key: %v", full.VolumeID, err)
		}
	}
	p, err := q.GetAdminPassword(ctx, strayID)
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := to.Open(p.Ciphertext, p.Nonce, laps.SealContext(device.ID, "Administrator")); err != nil || string(plain) != "local-admin-pw" {
		t.Errorf("the admin password under the new key: %q %v", plain, err)
	}

	// A second run with the old key finds nothing it can open.
	if _, err := rekey.Rotate(ctx, st, from, to, true); err == nil {
		t.Error("the old key still opens something after rotating")
	}

	// Not while a server is running.
	release, err := st.HoldRunningLock(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := rekey.Rotate(ctx, st, to, from, true); !errors.Is(err, store.ErrServerRunning) {
		t.Errorf("beside a running server: %v", err)
	}
}
