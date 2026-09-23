package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/alerts"
	"retune/internal/server/auth"
	"retune/internal/server/bitlocker"
	"retune/internal/server/laps"
	"retune/internal/server/profiles"
	"retune/internal/server/secrets"
	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

// TestRotateSecretKey: every kind of stored secret moves to a new key, the
// old key opens none of them afterwards, and the command won't run beside a
// server or with the wrong key.
func TestRotateSecretKey(t *testing.T) {
	ctx := context.Background()
	url := storetest.DatabaseURL(t)
	dataDir := t.TempDir()
	e := env(map[string]string{"DATABASE_URL": url, "DATA_DIR": dataDir})
	if err := run(ctx, []string{"migrate"}, e, io.Discard); err != nil {
		t.Fatal(err)
	}
	oldKey, err := secrets.LoadOrCreateFile(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dataDir, secrets.FileName)
	oldKeyFile, _ := os.ReadFile(keyPath)
	st, err := store.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	q := st.Q()

	// One of everything that is sealed.
	runOut(t, e, "bootstrap-admin", "--email", "ops@example.com")
	runOut(t, e, "admin", "totp", "--email", "ops@example.com", "--enable")
	admin, err := q.GetAdminByEmail(ctx, store.DefaultTenantID, "ops@example.com")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	device := store.Device{
		ID: uuid.Must(uuid.NewV7()), Hostname: "PC-KEY", Serial: "S", SMBIOSUUID: "U",
		Status: store.DeviceActive, CertSerial: "c", CertExpiresAt: now.Add(time.Hour), EnrolledAt: now,
	}
	if err := q.CreateDevice(ctx, device); err != nil {
		t.Fatal(err)
	}
	if err := (&bitlocker.Service{Store: st, Key: oldKey, Now: time.Now}).Escrow(ctx, device.ID, "C:", "XtsAes256", "111111-222222"); err != nil {
		t.Fatal(err)
	}
	pwCT, pwNonce, _ := oldKey.Seal([]byte("local-admin-pw"), laps.SealContext(device.ID, "Administrator"))
	password := store.AdminPassword{ID: uuid.Must(uuid.NewV7()), DeviceID: device.ID, Account: "Administrator",
		Ciphertext: pwCT, Nonce: pwNonce, State: "pending", CommandID: uuid.New(), CreatedAt: now}
	if err := q.UpsertPendingAdminPassword(ctx, password); err != nil {
		t.Fatal(err)
	}
	channelID := uuid.Must(uuid.NewV7())
	chCT, chNonce, _ := oldKey.Seal([]byte("hook-secret"), alerts.SecretContext(channelID))
	if err := q.CreateNotificationChannel(ctx, store.NotificationChannel{ID: channelID, Name: "Hook", Kind: "webhook",
		Config: []byte(`{"url":"https://example.com/hook"}`), SecretCiphertext: chCT, SecretNonce: chNonce,
		Enabled: true, CreatedAt: now, UpdatedAt: now, CreatedBy: "t"}); err != nil {
		t.Fatal(err)
	}
	prof, err := (&profiles.Service{Store: st, Key: oldKey}).Create(ctx, profiles.NewProfile{Name: "Wi-Fi", Actor: "t",
		Settings: []protocol.Setting{{Kind: "wifi", SSID: "Corp", Security: "wpa2_personal", Passphrase: "wifi-passphrase"}}})
	if err != nil {
		t.Fatal(err)
	}
	pwAfter := func() store.AdminPassword {
		p, err := q.GetAdminPassword(ctx, password.ID)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}

	// Not while a server runs.
	release, err := st.HoldRunningLock(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := run(ctx, []string{"rotate-secret-key"}, e, io.Discard); err == nil || !strings.Contains(err.Error(), "stop every server") {
		t.Fatalf("beside a running server: %v", err)
	}
	release()
	if _, err := os.Stat(keyPath + ".new"); !os.IsNotExist(err) {
		t.Fatal("a refused rotation must not leave a new key behind")
	}

	// A dry run proves the key and changes nothing.
	if out := runOut(t, e, "rotate-secret-key", "--dry-run"); !strings.Contains(out, "opens all 5 stored secrets") {
		t.Fatalf("dry run = %q", out)
	}
	if got := pwAfter(); string(got.Ciphertext) != string(pwCT) {
		t.Fatal("a dry run changed a stored secret")
	}

	out := runOut(t, e, "rotate-secret-key")
	if !strings.Contains(out, "Re-sealed 5 secrets") {
		t.Fatalf("rotate = %q", out)
	}
	newKey, err := secrets.LoadFile(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	olds, _ := filepath.Glob(keyPath + ".old-*")
	if len(olds) != 1 {
		t.Fatalf("old keys kept: %v", olds)
	}
	if kept, _ := os.ReadFile(olds[0]); string(kept) != string(oldKeyFile) {
		t.Fatal("the old key must be kept aside unchanged")
	}

	// Everything opens with the new key, and nothing with the old one.
	opens := func(k *secrets.Key) map[string]bool {
		got := map[string]bool{}
		cur, _ := q.GetAdminByEmail(ctx, store.DefaultTenantID, "ops@example.com")
		_, err := auth.ResealTOTP(k, k, admin.ID, cur.TOTPSecret)
		got["totp"] = err == nil
		keys, _ := (&bitlocker.Service{Store: st, Key: k}).List(ctx, device.ID)
		if len(keys) == 1 {
			full, _ := q.GetBitLockerKey(ctx, store.DefaultTenantID, keys[0].ID)
			plain, err := k.Open(full.Ciphertext, full.Nonce, bitlocker.EscrowContext(device.ID, "C:"))
			got["bitlocker"] = err == nil && string(plain) == "111111-222222"
		}
		p := pwAfter()
		plain, err := k.Open(p.Ciphertext, p.Nonce, laps.SealContext(device.ID, "Administrator"))
		got["laps"] = err == nil && string(plain) == "local-admin-pw"
		ch, _ := q.GetNotificationChannel(ctx, store.DefaultTenantID, channelID)
		plain, err = k.Open(ch.SecretCiphertext, ch.SecretNonce, alerts.SecretContext(channelID))
		got["channel"] = err == nil && string(plain) == "hook-secret"
		v, _ := q.GetProfileVersion(ctx, store.DefaultTenantID, prof.ID, 1)
		settings, err := (&profiles.Service{Key: k}).ForAgent(prof.ID, decodeSettings(t, v.Settings))
		got["wifi"] = err == nil && settings[0].Passphrase == "wifi-passphrase"
		return got
	}
	for what, ok := range opens(newKey) {
		if !ok {
			t.Errorf("%s does not open with the new key", what)
		}
	}
	for what, ok := range opens(oldKey) {
		if ok {
			t.Errorf("%s still opens with the old key", what)
		}
	}

	// Run with the wrong key, it fails and changes nothing.
	if err := os.WriteFile(keyPath, oldKeyFile, 0o600); err != nil {
		t.Fatal(err)
	}
	before := pwAfter()
	if err := run(ctx, []string{"rotate-secret-key"}, e, io.Discard); err == nil || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("with the wrong key: %v", err)
	}
	if string(pwAfter().Ciphertext) != string(before.Ciphertext) {
		t.Fatal("a failed rotation changed a stored secret")
	}
	if _, err := os.Stat(keyPath + ".new"); !os.IsNotExist(err) {
		t.Fatal("a failed rotation must remove the key it made")
	}
}

func decodeSettings(t *testing.T, raw []byte) []protocol.Setting {
	t.Helper()
	var s []protocol.Setting
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	return s
}
