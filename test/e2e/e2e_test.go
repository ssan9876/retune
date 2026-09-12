// Package e2e exercises server and agent together.
package e2e

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/agent/client"
	"retune/internal/agent/enrollment"
	"retune/internal/agent/identity"
	"retune/internal/config"
	"retune/internal/pki"
	"retune/internal/protocol"
	"retune/internal/server/app"
	"retune/internal/server/enroll"
	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

func TestEnrollAndCheckin(t *testing.T) {
	ctx := context.Background()
	cfg := config.Server{
		DatabaseURL: storetest.DatabaseURL(t), PublicURL: "https://127.0.0.1",
		TLSMode: "self-signed", DataDir: t.TempDir(), CheckinInterval: 2 * time.Minute,
	}
	a, err := app.New(ctx, cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	srv := httptest.NewUnstartedServer(a.Handler)
	srv.TLS = a.TLSConfig
	srv.StartTLS()
	defer srv.Close()

	maxUses := 2
	token, _, err := a.Enroll.CreateToken(ctx, enroll.TokenOptions{Label: "e2e", MaxUses: &maxUses, CreatedBy: "test"})
	if err != nil {
		t.Fatal(err)
	}
	pin := pki.Fingerprint(a.CA.Cert().Raw)
	facts := protocol.DeviceFacts{Hostname: "PC-001", Serial: "SN1", SMBIOSUUID: "UUID-1", OSVersion: "Windows 11 Pro"}
	opts := func() enrollment.Options {
		return enrollment.Options{ServerURL: srv.URL, Token: token, Pin: pin, Facts: facts,
			Store: identity.Store{Dir: t.TempDir(), Keys: identity.PlainKeys{}}}
	}

	// A wrong pin fails before the token is used.
	bad := opts()
	bad.Pin = "sha256:0000"
	if _, err := enrollment.Enroll(ctx, bad); err == nil {
		t.Fatal("enrollment with wrong pin must fail")
	}

	// Enroll, reload identity from disk, check in.
	o1 := opts()
	id1, err := enrollment.Enroll(ctx, o1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enrollment.Enroll(ctx, o1); !errors.Is(err, enrollment.ErrAlreadyEnrolled) {
		t.Fatalf("second enroll into same dir: %v", err)
	}
	loaded, err := o1.Store.Load()
	if err != nil {
		t.Fatal(err)
	}
	c1, err := enrollment.Connect(loaded)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c1.Checkin(ctx, protocol.CheckinRequest{AgentVersion: "e2e"})
	if err != nil || resp.IntervalSeconds != 120 {
		t.Fatalf("checkin: %+v, %v", resp, err)
	}
	d1, _ := a.Store.Q().GetDevice(ctx, uuid.MustParse(id1.DeviceID))
	if d1.LastSeenAt == nil || d1.AgentVersion != "e2e" || d1.Hostname != "PC-001" {
		t.Fatalf("device after checkin: %+v", d1)
	}

	// Reimage: same hardware enrolls again; old identity is rejected.
	id2, err := enrollment.Enroll(ctx, opts())
	if err != nil {
		t.Fatal(err)
	}
	if d1, _ = a.Store.Q().GetDevice(ctx, uuid.MustParse(id1.DeviceID)); d1.Status != store.DeviceReplaced {
		t.Fatalf("old device status = %s", d1.Status)
	}
	var he *client.HTTPError
	if _, err := c1.Checkin(ctx, protocol.CheckinRequest{}); !errors.As(err, &he) || he.Status != http.StatusUnauthorized {
		t.Fatalf("replaced device checkin err = %v", err)
	}

	// Token had 2 uses; a third enrollment is refused.
	if _, err := enrollment.Enroll(ctx, opts()); !errors.As(err, &he) || he.Status != http.StatusForbidden {
		t.Fatalf("exhausted token err = %v", err)
	}

	// Retired device is rejected.
	c2, err := enrollment.Connect(id2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c2.Checkin(ctx, protocol.CheckinRequest{}); err != nil {
		t.Fatalf("new device checkin: %v", err)
	}
	if err := a.Store.Q().SetDeviceStatus(ctx, uuid.MustParse(id2.DeviceID), store.DeviceRetired); err != nil {
		t.Fatal(err)
	}
	if _, err := c2.Checkin(ctx, protocol.CheckinRequest{}); !errors.As(err, &he) || he.Status != http.StatusUnauthorized {
		t.Fatalf("retired device checkin err = %v", err)
	}
}
