// Command console runs a throwaway Retune server for the console's browser
// tests. It starts Postgres (or uses DATABASE_URL), builds the server exactly
// as retune-server does, seeds it through the real agent API with simulated
// devices, writes what the tests need to know to a fixture file and then
// serves until it is stopped.
//
// The console it serves is whatever was last built into
// internal/server/console/dist, so run `npm --prefix web run build` first.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	stdlog "log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"retune/internal/agent/enrollment"
	"retune/internal/agent/identity"
	"retune/internal/config"
	"retune/internal/pki"
	"retune/internal/protocol"
	"retune/internal/server/app"
	"retune/internal/server/auth"
	"retune/internal/server/compliance"
	"retune/internal/server/enroll"
	"retune/internal/server/store"
)

// Password is every seeded admin's password.
const Password = "e2e-correct-horse-battery"

// Fixture is what the browser tests read to know what was seeded.
type Fixture struct {
	BaseURL   string            `json:"base_url"`
	Admin     Account           `json:"admin"`
	TOTPAdmin Account           `json:"totp_admin"`
	Devices   map[string]Device `json:"devices"`
}

type Account struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	TOTPSecret string `json:"totp_secret,omitempty"`
}

type Device struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
}

func main() {
	addr := flag.String("addr", "127.0.0.1:18443", "address to serve on")
	fixture := flag.String("fixture", "", "where to write the fixture JSON")
	flag.Parse()
	if *fixture == "" {
		fmt.Fprintln(os.Stderr, "error: --fixture is required")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, *addr, *fixture); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, addr, fixturePath string) error {
	tmp, err := os.MkdirTemp("", "retune-console-e2e-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		var stopDB func()
		if dbURL, stopDB, err = startPostgres(ctx); err != nil {
			return err
		}
		defer stopDB()
	}

	cfg := config.Server{
		DatabaseURL: dbURL, PublicURL: "https://" + addr, AgentListen: addr,
		TLSMode: "self-signed", DataDir: filepath.Join(tmp, "data"),
		CheckinInterval: 5 * time.Minute, SessionTTL: time.Hour, SessionMaxLifetime: 12 * time.Hour,
		SweepInterval: time.Minute,
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	a, err := app.New(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer a.Close()

	// Seed through a private listener, so the real address only answers once
	// everything the tests expect is in place.
	seedSrv := httptest.NewUnstartedServer(a.Handler)
	seedSrv.TLS = a.TLSConfig
	seedSrv.StartTLS()
	fx, err := seed(ctx, a, dbURL, seedSrv.URL, filepath.Join(tmp, "agents"))
	seedSrv.Close()
	if err != nil {
		return fmt.Errorf("seed: %w", err)
	}
	fx.BaseURL = "https://" + addr

	b, err := json.MarshalIndent(fx, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(fixturePath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(fixturePath, b, 0o644); err != nil {
		return err
	}

	// The browser drops its first connection to a certificate it doesn't
	// trust, which net/http would log as a handshake error every time.
	srv := &http.Server{Addr: addr, Handler: a.Handler, TLSConfig: a.TLSConfig, ReadHeaderTimeout: 10 * time.Second,
		ErrorLog: stdlog.New(io.Discard, "", 0)}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServeTLS("", "") }()
	fmt.Fprintf(os.Stderr, "console e2e server ready on https://%s\n", addr)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shut)
	}
}

func startPostgres(ctx context.Context) (string, func(), error) {
	// See storetest.DatabaseURL: naming the pipe avoids a flaky Docker probe.
	if runtime.GOOS == "windows" && os.Getenv("DOCKER_HOST") == "" {
		os.Setenv("DOCKER_HOST", "npipe:////./pipe/docker_engine")
	}
	ctr, err := postgres.Run(ctx, "postgres:17-alpine",
		postgres.WithDatabase("retune"), postgres.WithUsername("retune"), postgres.WithPassword("retune"),
		postgres.BasicWaitStrategies(),
	)
	if err != nil {
		return "", nil, fmt.Errorf("start postgres (is Docker running?): %w", err)
	}
	stop := func() { _ = ctr.Terminate(context.Background()) }
	url, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		stop()
		return "", nil, err
	}
	return url, stop, nil
}

// seed creates two admins and four devices that between them cover every
// device-list filter:
//
//	E2E-COMPLIANT     active, compliant
//	E2E-NONCOMPLIANT  active, non-compliant
//	E2E-STALE         active but last seen ten days ago, not evaluated
//	E2E-RETIRED       retired
func seed(ctx context.Context, a *app.App, dbURL, serverURL, agentDir string) (Fixture, error) {
	fx := Fixture{Devices: map[string]Device{}}

	if _, err := a.Auth.CreateAdmin(ctx, auth.CreateAdminOptions{
		Email: "admin@e2e.test", Password: Password, Role: store.RoleAdmin, Actor: "e2e",
	}); err != nil {
		return fx, err
	}
	fx.Admin = Account{Email: "admin@e2e.test", Password: Password}
	totpAdmin, err := a.Auth.CreateAdmin(ctx, auth.CreateAdminOptions{
		Email: "totp@e2e.test", Password: Password, Role: store.RoleAdmin, Actor: "e2e",
	})
	if err != nil {
		return fx, err
	}
	secret, _, err := a.Auth.EnableTOTP(ctx, totpAdmin.ID, "e2e")
	if err != nil {
		return fx, err
	}
	fx.TOTPAdmin = Account{Email: "totp@e2e.test", Password: Password, TOTPSecret: secret}

	// Compliance: BitLocker on the system volume, for every device.
	policy, err := a.Compliance.Create(ctx, compliance.NewPolicy{
		Name: "BitLocker required", Rules: json.RawMessage(`[{"type":"bitlocker","volumes":"system"}]`), Actor: "e2e",
	})
	if err != nil {
		return fx, err
	}
	if _, err := a.Store.Q().CreateAssignment(ctx, store.Assignment{
		ID: uuid.Must(uuid.NewV7()), ItemKind: compliance.ItemKindCompliance, ItemID: policy.ID,
		GroupID: store.BuiltinGroupID, Mode: store.ModeInclude, CreatedAt: time.Now().UTC(), CreatedBy: "e2e",
	}); err != nil {
		return fx, err
	}

	maxUses := 4
	token, _, err := a.Enroll.CreateToken(ctx, enroll.TokenOptions{Label: "e2e seed", MaxUses: &maxUses, CreatedBy: "e2e"})
	if err != nil {
		return fx, err
	}
	pin := pki.Fingerprint(a.CA.Cert().Raw)

	devices := []struct {
		key, hostname, bitlocker string
	}{
		{"compliant", "E2E-COMPLIANT", "on"},
		{"noncompliant", "E2E-NONCOMPLIANT", "off"},
		{"stale", "E2E-STALE", ""},
		{"retired", "E2E-RETIRED", ""},
	}
	for i, d := range devices {
		id, err := enrollment.Enroll(ctx, enrollment.Options{
			ServerURL: serverURL, Token: token, Pin: pin,
			Facts: protocol.DeviceFacts{
				Hostname: d.hostname, Serial: fmt.Sprintf("E2E-SN-%d", i), SMBIOSUUID: fmt.Sprintf("E2E-UUID-%d", i),
				OSVersion: "Windows 11 Pro",
			},
			Store: identity.Store{Dir: filepath.Join(agentDir, d.key), Keys: identity.PlainKeys{}},
		})
		if err != nil {
			return fx, fmt.Errorf("enroll %s: %w", d.hostname, err)
		}
		c, err := enrollment.Connect(id)
		if err != nil {
			return fx, err
		}
		if _, err := c.Checkin(ctx, protocol.CheckinRequest{AgentVersion: "0.1.0-e2e"}); err != nil {
			return fx, fmt.Errorf("check in %s: %w", d.hostname, err)
		}
		if d.bitlocker != "" {
			if _, err := c.PutInventory(ctx, protocol.Inventory{
				CollectedAt: time.Now().UTC(), Hostname: d.hostname,
				OS:       protocol.OSInfo{Name: "Windows 11 Pro", Version: "10.0.26100", Build: "26100"},
				Hardware: protocol.Hardware{Manufacturer: "Retune", Model: "Simulated", RAMBytes: 16 << 30},
				Disks:    []protocol.Disk{{Name: "C:", BitLocker: d.bitlocker}},
			}); err != nil {
				return fx, fmt.Errorf("inventory %s: %w", d.hostname, err)
			}
		}
		fx.Devices[d.key] = Device{ID: id.DeviceID, Hostname: d.hostname}
	}

	if err := a.Store.Q().SetDeviceStatus(ctx, store.DefaultTenantID,
		uuid.MustParse(fx.Devices["retired"].ID), store.DeviceRetired); err != nil {
		return fx, err
	}
	// Nothing in the API makes a device old, so age the stale one directly.
	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		return fx, err
	}
	defer conn.Close(ctx)
	tag, err := conn.Exec(ctx, `UPDATE devices SET last_seen_at = now() - interval '10 days' WHERE id = $1`,
		fx.Devices["stale"].ID)
	if err != nil {
		return fx, err
	}
	if tag.RowsAffected() != 1 {
		return fx, errors.New("aging the stale device changed no rows")
	}
	return fx, nil
}
