package app_test

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"retune/internal/config"
	"retune/internal/protocol"
	"retune/internal/release"
	"retune/internal/server/app"
	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

// TestTwoServersActAsOne: two servers started at the same moment against one
// database and one empty, shared DATA_DIR - the high-availability layout -
// agree on the CA and the secret key, and a person or a device can be sent
// to either.
func TestTwoServersActAsOne(t *testing.T) {
	priv, err := release.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Server{
		DatabaseURL: storetest.DatabaseURL(t), PublicURL: "https://127.0.0.1",
		TLSMode: "self-signed", DataDir: t.TempDir(),
		CheckinInterval: 5 * time.Minute, SessionTTL: 12 * time.Hour, SessionMaxLifetime: 24 * time.Hour,
		AgentReleaseKeys: []release.PublicKey{priv.Public()},
	}

	// Started together, racing to create the CA, the secret key and the
	// schema.
	var apps [2]*app.App
	var errs [2]error
	var wg sync.WaitGroup
	for i := range apps {
		wg.Add(1)
		go func() {
			defer wg.Done()
			apps[i], errs[i] = app.New(context.Background(), cfg, slog.New(slog.DiscardHandler))
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("server %d: %v", i, err)
		}
		t.Cleanup(apps[i].Close)
	}
	a, b := apps[0], apps[1]
	if !bytes.Equal(a.CA.Cert().Raw, b.CA.Cert().Raw) {
		t.Fatal("the two servers made different CAs")
	}
	var srvs [2]*httptest.Server
	for i, x := range apps {
		srvs[i] = httptest.NewUnstartedServer(x.Handler)
		srvs[i].TLS = x.TLSConfig
		srvs[i].StartTLS()
		t.Cleanup(srvs[i].Close)
	}

	// Signed in through one, the session works through the other.
	seedAdmin(t, a, "ops@example.com", testPassword, store.RoleAdmin)
	admin := newAdminClient(t, a, srvs[0])
	if status, body := admin.login("ops@example.com", testPassword, ""); status != http.StatusOK {
		t.Fatalf("login on the first: %d %s", status, body)
	}
	admin.base = srvs[1].URL + "/api/admin/v1"
	if status, body := admin.do(http.MethodGet, "/session", nil); status != http.StatusOK {
		t.Fatalf("the session on the second: %d %s", status, body)
	}

	// Enrolled through one, the device checks in through the other.
	deviceID, agent := enrollDevice(t, a, srvs[0], "PC-HA")
	if status, body := send(t, agent, http.MethodPost, srvs[1].URL+"/api/agent/v1/checkin",
		protocol.CheckinRequest{AgentVersion: "1.0.0"}); status != http.StatusOK {
		t.Fatalf("check-in on the second: %d %s", status, body)
	}

	// Sealed by one, opened by the other: they share the secret key.
	if err := a.BitLocker.Escrow(context.Background(), deviceID, "C:", "XtsAes256", "123456-654321"); err != nil {
		t.Fatal(err)
	}
	keys, err := b.BitLocker.List(context.Background(), deviceID)
	if err != nil || len(keys) != 1 {
		t.Fatalf("keys = %v, %v", keys, err)
	}
	if _, plain, err := b.BitLocker.Reveal(context.Background(), keys[0].ID, "ops@example.com", "HA test"); err != nil || plain != "123456-654321" {
		t.Fatalf("revealed on the second: %q, %v", plain, err)
	}
}
