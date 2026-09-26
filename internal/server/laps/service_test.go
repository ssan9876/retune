package laps_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/laps"
	"retune/internal/server/secrets"
	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

type fixture struct {
	ctx context.Context
	st  *store.Store
	svc *laps.Service
	now time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	key, _, err := secrets.Generate()
	if err != nil {
		t.Fatal(err)
	}
	st := storetest.New(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	return &fixture{
		ctx: context.Background(), st: st, now: now,
		svc: &laps.Service{Store: st, Key: key, Now: func() time.Time { return now }},
	}
}

func (f *fixture) device(t *testing.T, hostname string) uuid.UUID {
	t.Helper()
	d := store.Device{
		ID: uuid.Must(uuid.NewV7()), Hostname: hostname, Status: store.DeviceActive,
		CertSerial: "c", CertExpiresAt: f.now.Add(time.Hour), EnrolledAt: f.now,
	}
	if err := f.st.Q().CreateDevice(f.ctx, d); err != nil {
		t.Fatal(err)
	}
	return d.ID
}

// command queues a command of the given type for a device and, if running,
// starts it.
func (f *fixture) command(t *testing.T, deviceID uuid.UUID, typ string, running bool) store.Command {
	t.Helper()
	c := store.Command{
		ID: uuid.Must(uuid.NewV7()), DeviceID: deviceID, Type: typ, Payload: []byte(`{}`),
		Status: store.CommandQueued, CreatedBy: "test", CreatedAt: f.now, ExpiresAt: f.now.Add(time.Hour),
	}
	q := f.st.Q()
	if err := q.CreateCommand(f.ctx, c); err != nil {
		t.Fatal(err)
	}
	if running {
		if ok, err := q.MarkCommandRunning(f.ctx, store.DefaultTenantID, c.ID, deviceID, f.now); err != nil || !ok {
			t.Fatalf("start: %v %v", ok, err)
		}
	}
	got, err := q.GetCommand(f.ctx, store.DefaultTenantID, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func escrowReq(c store.Command, account, password string) protocol.AdminPasswordEscrowRequest {
	return protocol.AdminPasswordEscrowRequest{CommandID: c.ID.String(), Account: account, Password: password}
}

const goodPassword = "A-Long-Enough-Password-123"

// TestEscrowRefuses covers every way Escrow turns a request away, and that
// none of them leaves anything stored.
func TestEscrowRefuses(t *testing.T) {
	f := newFixture(t)
	dev := f.device(t, "PC-ONE")
	other := f.device(t, "PC-TWO")
	running := f.command(t, dev, protocol.CommandRotateAdminPassword, true)
	queued := f.command(t, dev, protocol.CommandRotateAdminPassword, false)
	lock := f.command(t, dev, protocol.CommandLock, true)

	cases := []struct {
		name   string
		device uuid.UUID
		req    protocol.AdminPasswordEscrowRequest
		want   error
	}{
		{"unparseable command", dev, protocol.AdminPasswordEscrowRequest{CommandID: "nope", Account: "Administrator", Password: goodPassword}, laps.ErrNotFound},
		{"unknown command", dev, protocol.AdminPasswordEscrowRequest{CommandID: uuid.NewString(), Account: "Administrator", Password: goodPassword}, laps.ErrNotFound},
		{"another device's command", other, escrowReq(running, "Administrator", goodPassword), laps.ErrNotFound},
		{"blank account", dev, escrowReq(running, "   ", goodPassword), laps.ErrBadRequest},
		{"account too long", dev, escrowReq(running, strings.Repeat("a", 257), goodPassword), laps.ErrBadRequest},
		{"password too short", dev, escrowReq(running, "Administrator", strings.Repeat("x", protocol.MinAdminPasswordLength-1)), laps.ErrBadRequest},
		{"password too long", dev, escrowReq(running, "Administrator", strings.Repeat("x", protocol.MaxAdminPasswordLength+1)), laps.ErrBadRequest},
		// Characters, not bytes: 64 two-byte runes is 128 bytes but in range,
		// 65 is one over.
		{"too many runes", dev, escrowReq(running, "Administrator", strings.Repeat("é", protocol.MaxAdminPasswordLength+1)), laps.ErrBadRequest},
		{"not a rotation", dev, escrowReq(lock, "Administrator", goodPassword), laps.ErrConflict},
		{"not started", dev, escrowReq(queued, "Administrator", goodPassword), laps.ErrConflict},
	}
	for _, c := range cases {
		if err := f.svc.Escrow(f.ctx, c.device, c.req); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
	for _, id := range []uuid.UUID{dev, other} {
		if got, err := f.svc.List(f.ctx, id); err != nil || len(got) != 0 {
			t.Fatalf("a refused escrow stored something: %+v %v", got, err)
		}
	}

	noKey := &laps.Service{Store: f.st}
	if err := noKey.Escrow(f.ctx, dev, escrowReq(running, "Administrator", goodPassword)); err == nil {
		t.Fatal("escrow without a server key succeeded")
	}
}

// TestEscrowSettleReveal follows a password from escrow to reveal: account
// names are trimmed, multibyte passwords within the limit are accepted, a
// retried escrow replaces the pending one, and the settled result decides
// what becomes active.
func TestEscrowSettleReveal(t *testing.T) {
	f := newFixture(t)
	q := f.st.Q()
	dev := f.device(t, "PC-LAPS")

	first := f.command(t, dev, protocol.CommandRotateAdminPassword, true)
	multibyte := strings.Repeat("é", protocol.MaxAdminPasswordLength)
	if err := f.svc.Escrow(f.ctx, dev, escrowReq(first, "  Administrator  ", goodPassword)); err != nil {
		t.Fatal(err)
	}
	// The agent retried with the password it actually set.
	if err := f.svc.Escrow(f.ctx, dev, escrowReq(first, "Administrator", multibyte)); err != nil {
		t.Fatal(err)
	}
	list, err := f.svc.List(f.ctx, dev)
	if err != nil || len(list) != 1 || list[0].State != store.AdminPasswordPending || list[0].Account != "Administrator" {
		t.Fatalf("after escrow: %+v %v", list, err)
	}
	if err := laps.Settle(f.ctx, q, first, protocol.ResultSucceeded, f.now); err != nil {
		t.Fatal(err)
	}

	// A second rotation, for the same account in another case, fails: the
	// first stays active and the second is abandoned.
	second := f.command(t, dev, protocol.CommandRotateAdminPassword, true)
	if err := f.svc.Escrow(f.ctx, dev, escrowReq(second, "ADMINISTRATOR", "Another-Long-Password-4567")); err != nil {
		t.Fatal(err)
	}
	if err := laps.Settle(f.ctx, q, second, protocol.ResultFailed, f.now); err != nil {
		t.Fatal(err)
	}
	// Settling a command of another type touches nothing.
	lock := f.command(t, dev, protocol.CommandLock, true)
	if err := laps.Settle(f.ctx, q, lock, protocol.ResultSucceeded, f.now); err != nil {
		t.Fatal(err)
	}
	states := map[uuid.UUID]string{}
	list, _ = f.svc.List(f.ctx, dev)
	for _, p := range list {
		states[p.CommandID] = p.State
	}
	if len(states) != 2 || states[first.ID] != store.AdminPasswordActive || states[second.ID] != store.AdminPasswordAbandoned {
		t.Fatalf("states = %v", states)
	}

	var active store.AdminPassword
	for _, p := range list {
		if p.CommandID == first.ID {
			active = p
		}
	}
	for _, reason := range []string{"", "   ", strings.Repeat("r", 501)} {
		if _, _, err := f.svc.Reveal(f.ctx, active.ID, "admin:ops", reason); !errors.Is(err, laps.ErrBadRequest) {
			t.Errorf("reason %q: %v", reason, err)
		}
	}
	if _, _, err := f.svc.Reveal(f.ctx, uuid.New(), "admin:ops", "ticket 7"); !errors.Is(err, laps.ErrNotFound) {
		t.Errorf("an unknown password: %v", err)
	}
	if _, _, err := (&laps.Service{Store: f.st}).Reveal(f.ctx, active.ID, "admin:ops", "ticket 7"); err == nil {
		t.Error("reveal without a server key succeeded")
	}
	// The longest reason allowed is accepted, and the plaintext handed back
	// is the retried escrow's, not the first.
	p, plain, err := f.svc.Reveal(f.ctx, active.ID, "admin:ops", "  "+strings.Repeat("r", 500)+"  ")
	if err != nil {
		t.Fatal(err)
	}
	if plain != multibyte {
		t.Fatalf("revealed %q", plain)
	}
	if p.Ciphertext != nil || p.Nonce != nil {
		t.Fatal("reveal handed back the sealed form")
	}

	entries, err := q.ListAudit(f.ctx, 20)
	if err != nil {
		t.Fatal(err)
	}
	var escrowed, revealed int
	for _, e := range entries {
		for _, v := range e.Details {
			if s, ok := v.(string); ok && (s == goodPassword || s == multibyte) {
				t.Fatalf("a password is in the audit log: %+v", e)
			}
		}
		switch e.Action {
		case "local_admin_password.escrowed":
			escrowed++
		case "local_admin_password.revealed":
			revealed++
			if e.Actor != "admin:ops" || e.Details["reason"] != strings.Repeat("r", 500) {
				t.Errorf("reveal audit = %+v", e)
			}
		}
	}
	if escrowed != 3 || revealed != 1 {
		t.Fatalf("audit: %d escrowed, %d revealed", escrowed, revealed)
	}
}

// TestSealContext: a sealed password opens only for its own device and
// account, and the account is compared the way Windows compares names.
func TestSealContext(t *testing.T) {
	key, _, err := secrets.Generate()
	if err != nil {
		t.Fatal(err)
	}
	dev, other := uuid.New(), uuid.New()
	ct, nonce, err := key.Seal([]byte("secret"), laps.SealContext(dev, "Administrator"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := key.Open(ct, nonce, laps.SealContext(dev, "administrator")); err != nil {
		t.Errorf("another case of the same account: %v", err)
	}
	if _, err := key.Open(ct, nonce, laps.SealContext(other, "Administrator")); err == nil {
		t.Error("opened for another device")
	}
	if _, err := key.Open(ct, nonce, laps.SealContext(dev, "Guest")); err == nil {
		t.Error("opened for another account")
	}
}
