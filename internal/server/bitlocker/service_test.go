package bitlocker_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/bitlocker"
	"retune/internal/server/secrets"
	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

func service(t *testing.T, st *store.Store) *bitlocker.Service {
	t.Helper()
	key, err := secrets.LoadOrCreateFile(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &bitlocker.Service{Store: st, Key: key, Now: time.Now}
}

func device(t *testing.T, st *store.Store, hostname string) store.Device {
	t.Helper()
	now := time.Now()
	d := store.Device{
		ID: uuid.Must(uuid.NewV7()), Hostname: hostname, Status: store.DeviceActive,
		CertSerial: hostname, CertExpiresAt: now.Add(time.Hour), EnrolledAt: now,
	}
	if err := st.Q().CreateDevice(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	return d
}

const password = "123456-234567-345678-456789-567890-678901-789012-890123"

func TestEscrowAndReveal(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(t, st)
	d := device(t, st, "LAPTOP")

	if has, err := svc.Has(ctx, d.ID, "C:"); err != nil || has {
		t.Fatalf("nothing is escrowed yet: %v %v", has, err)
	}
	if err := svc.Escrow(ctx, d.ID, "C:", "XtsAes256", password); err != nil {
		t.Fatal(err)
	}
	if has, err := svc.Has(ctx, d.ID, "C:"); err != nil || !has {
		t.Fatalf("the key should be escrowed: %v %v", has, err)
	}

	// A listing never carries the key.
	keys, err := svc.List(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].VolumeID != "C:" || keys[0].Method != "XtsAes256" {
		t.Fatalf("keys = %+v", keys)
	}
	if len(keys[0].Ciphertext) != 0 {
		t.Error("a listing must not carry the encrypted key either")
	}

	got, plaintext, err := svc.Reveal(ctx, keys[0].ID, "ops@example.com", "help desk call 1234")
	if err != nil {
		t.Fatal(err)
	}
	if plaintext != password {
		t.Fatalf("revealed %q", plaintext)
	}
	if got.Hostname != "LAPTOP" {
		t.Errorf("the reveal should say which machine, got %q", got.Hostname)
	}
}

// The recovery key is never stored in a form the database alone can read.
func TestTheStoredKeyIsEncrypted(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(t, st)
	d := device(t, st, "LAPTOP")

	if err := svc.Escrow(ctx, d.ID, "C:", "XtsAes256", password); err != nil {
		t.Fatal(err)
	}
	keys, err := svc.List(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := st.Q().GetBitLockerKey(ctx, keys[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stored.Ciphertext), "123456") {
		t.Fatal("the recovery key is readable in the database")
	}
	if len(stored.Nonce) == 0 {
		t.Error("a nonce should be stored alongside it")
	}
}

// Every reveal is audited; that is why it is a separate act.
func TestRevealIsAudited(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(t, st)
	d := device(t, st, "LAPTOP")

	if err := svc.Escrow(ctx, d.ID, "C:", "XtsAes256", password); err != nil {
		t.Fatal(err)
	}
	keys, _ := svc.List(ctx, d.ID)
	if _, _, err := svc.Reveal(ctx, keys[0].ID, "ops@example.com", "help desk call 1234"); err != nil {
		t.Fatal(err)
	}

	entries, err := st.Q().ListAudit(ctx, 20)
	if err != nil {
		t.Fatal(err)
	}
	var viewed *store.AuditEntry
	for i := range entries {
		if entries[i].Action == "bitlocker_key.viewed" {
			viewed = &entries[i]
		}
	}
	if viewed == nil {
		t.Fatal("revealing a recovery key must be recorded")
	}
	if viewed.Actor != "ops@example.com" || viewed.TargetID != d.ID.String() {
		t.Fatalf("the entry should name who and which device, got %+v", viewed)
	}
	if viewed.Details["reason"] != "help desk call 1234" {
		t.Errorf("the reason should be recorded, got %v", viewed.Details)
	}
	// The key itself must never be in the audit log.
	for _, e := range entries {
		for _, v := range e.Details {
			if s, ok := v.(string); ok && strings.Contains(s, "123456") {
				t.Fatalf("the recovery key leaked into the audit log: %+v", e)
			}
		}
	}
}

// Re-encrypting a volume produces a new recovery password; the old one is
// useless, so it is replaced rather than accumulating.
func TestEscrowReplacesTheVolumesKey(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(t, st)
	d := device(t, st, "LAPTOP")

	if err := svc.Escrow(ctx, d.ID, "C:", "XtsAes256", password); err != nil {
		t.Fatal(err)
	}
	const replacement = "999999-888888-777777-666666-555555-444444-333333-222222"
	if err := svc.Escrow(ctx, d.ID, "C:", "XtsAes256", replacement); err != nil {
		t.Fatal(err)
	}
	keys, err := svc.List(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("a volume should have one key, got %d", len(keys))
	}
	_, plaintext, err := svc.Reveal(ctx, keys[0].ID, "ops@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if plaintext != replacement {
		t.Fatalf("the newest key should be held, got %q", plaintext)
	}
}

func TestEscrowRejectsNonsense(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(t, st)
	d := device(t, st, "LAPTOP")

	if err := svc.Escrow(ctx, d.ID, "", "XtsAes256", password); !errors.Is(err, bitlocker.ErrBadRequest) {
		t.Errorf("a key with no volume should be refused, got %v", err)
	}
	if err := svc.Escrow(ctx, d.ID, "C:", "XtsAes256", "  "); !errors.Is(err, bitlocker.ErrBadRequest) {
		t.Errorf("an empty key should be refused, got %v", err)
	}
	big := strings.Repeat("x", bitlocker.MaxRecoveryPasswordBytes+1)
	if err := svc.Escrow(ctx, d.ID, "C:", "XtsAes256", big); !errors.Is(err, bitlocker.ErrBadRequest) {
		t.Errorf("an oversized key should be refused, got %v", err)
	}
}

func TestRevealMissingKey(t *testing.T) {
	st := storetest.New(t)
	svc := service(t, st)
	if _, _, err := svc.Reveal(context.Background(), uuid.Must(uuid.NewV7()), "ops", ""); !errors.Is(err, bitlocker.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

// A row copied to another device does not decrypt, because the device and
// volume are authenticated with the ciphertext.
func TestAKeyCannotBeMovedBetweenDevices(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(t, st)
	a := device(t, st, "LAPTOP-A")
	b := device(t, st, "LAPTOP-B")

	if err := svc.Escrow(ctx, a.ID, "C:", "XtsAes256", password); err != nil {
		t.Fatal(err)
	}
	keys, _ := svc.List(ctx, a.ID)
	stolen, err := st.Q().GetBitLockerKey(ctx, keys[0].ID)
	if err != nil {
		t.Fatal(err)
	}

	// Re-file the same ciphertext under another device, as a tampering
	// database user might.
	stolen.ID = uuid.Must(uuid.NewV7())
	stolen.DeviceID = b.ID
	stolen.CreatedAt = time.Now()
	if err := st.Q().UpsertBitLockerKey(ctx, stolen); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Reveal(ctx, stolen.ID, "ops", ""); err == nil {
		t.Fatal("a key re-filed under another device must not decrypt")
	}
}
