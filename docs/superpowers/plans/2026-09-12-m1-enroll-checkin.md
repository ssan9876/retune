# M1: Enroll & Check-in Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Windows agent enrolls with a one-time token against a Retune server (pinning the server's internal CA), receives a client certificate, and checks in over mTLS; retired or replaced devices are rejected.

**Architecture:** One Go module. The server (`internal/server/...`) owns Postgres (pgx + embedded golang-migrate migrations), an internal ECDSA CA, the enrollment service, and the agent HTTP API; `internal/server/app` wires them for both the `serve` command and tests. The agent (`internal/agent/...`) holds its identity on disk (private key sealed with DPAPI on Windows), talks to the server through a pinning HTTP client, and runs a jittered check-in loop with backoff.

**Tech Stack:** Go 1.27, PostgreSQL 17, `github.com/jackc/pgx/v5`, `github.com/golang-migrate/migrate/v4` (pgx v5 driver + iofs), `github.com/google/uuid` (v7), `golang.org/x/sys/windows`, `github.com/testcontainers/testcontainers-go` (+ postgres module).

**Spec:** `docs/superpowers/specs/2026-09-12-core-platform-design.md` (roadmap: `docs/superpowers/plans/2026-09-12-roadmap.md`)

## Global Constraints

- Module path: `retune`. Go toolchain 1.27.
- Every table has `tenant_id uuid NOT NULL REFERENCES tenants(id)`; the single tenant is `00000000-0000-0000-0000-000000000001`.
- All IDs are UUIDv7 (`uuid.NewV7()`); all timestamps are `timestamptz`.
- API errors are JSON `{"code": "...", "message": "..."}`.
- Agent API paths are under `/api/agent/v1/`.
- Client certificates: ECDSA P-256, 90-day validity, subject CN = device ID, ExtKeyUsage ClientAuth.
- Enrollment tokens are shown once; only their SHA-256 hash is stored.
- Check-in default interval 5 minutes, ±20% jitter; backoff 30 s doubling to a 30-minute cap; on `401` retry after 24 h.
- Server trust: if a pin (`sha256:<hex>`) is given, the agent requires a cert in the server chain with that fingerprint; otherwise it uses system roots. No trust-on-first-use.
- Postgres tests use testcontainers and need Docker running; they are skipped with `go test -short`.
- Every task ends with `go vet ./...` and `go test ./...` passing.

## File Structure

```
retune/
├ .gitignore
├ go.mod / go.sum
├ cmd/
│  ├ retune-server/main.go        serve | migrate | token create | ca fingerprint
│  ├ retune-server/main_test.go
│  └ retune-agent/main.go         enroll | run [--once]
├ internal/
│  ├ config/server.go             env config for the server (+ _test)
│  ├ protocol/v1.go               shared request/response types
│  ├ pki/fingerprint.go           sha256 cert fingerprint (+ _test)
│  ├ server/
│  │  ├ store/                    Postgres: store.go, migrate.go, models.go,
│  │  │  │                        tokens.go, devices.go, audit.go, migrations/
│  │  │  └ storetest/storetest.go testcontainers helper
│  │  ├ ca/                       keystore.go, ca.go (+ _test)
│  │  ├ enroll/                   token.go, service.go (+ _test)
│  │  ├ agentapi/                 handler.go, json.go
│  │  └ app/                      app.go, app_test.go
│  └ agent/
│     ├ identity/                 identity.go, keys.go, keys_windows.go,
│     │                           keys_other.go (+ _test)
│     ├ client/                   client.go (+ _test)
│     ├ checkin/                  loop.go (+ _test)
│     ├ enrollment/               enrollment.go
│     └ facts/                    facts.go, facts_windows.go, facts_other.go
└ test/e2e/e2e_test.go
```

---

### Task 1: Module scaffold, config, protocol, fingerprint

**Files:**
- Create: `go.mod`, `.gitignore`, `internal/config/server.go`, `internal/config/server_test.go`, `internal/protocol/v1.go`, `internal/pki/fingerprint.go`, `internal/pki/fingerprint_test.go`

**Interfaces:**
- Produces:
  - `config.Server{DatabaseURL, PublicURL, AgentListen, TLSMode, TLSCertFile, TLSKeyFile, DataDir string; CheckinInterval time.Duration}`
  - `config.LoadServer(getenv func(string) string) (config.Server, error)`, `(config.Server).PublicHost() string`
  - `protocol.DeviceFacts`, `protocol.EnrollRequest`, `protocol.EnrollResponse`, `protocol.CheckinRequest`, `protocol.CheckinResponse`, `protocol.Error`
  - `pki.Fingerprint(der []byte) string` → `"sha256:<lowercase hex>"`

- [ ] **Step 1: Initialize module and dependencies**

```bash
go mod init retune
go get github.com/google/uuid@latest github.com/jackc/pgx/v5@latest github.com/golang-migrate/migrate/v4@latest golang.org/x/sys@latest github.com/testcontainers/testcontainers-go@latest github.com/testcontainers/testcontainers-go/modules/postgres@latest
```

Create `.gitignore`:

```gitignore
/data/
/agent-data/
/bin/
*.exe
```

- [ ] **Step 2: Write failing tests**

`internal/config/server_test.go`:

```go
package config

import (
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadServerDefaults(t *testing.T) {
	c, err := LoadServer(env(map[string]string{
		"DATABASE_URL": "postgres://u:p@db/retune",
		"PUBLIC_URL":   "https://mdm.example.com",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.AgentListen != ":8443" || c.TLSMode != "self-signed" || c.DataDir != "data" || c.CheckinInterval != 5*time.Minute {
		t.Fatalf("unexpected defaults: %+v", c)
	}
	if c.PublicHost() != "mdm.example.com" {
		t.Fatalf("PublicHost = %q", c.PublicHost())
	}
}

func TestLoadServerErrors(t *testing.T) {
	base := map[string]string{"DATABASE_URL": "postgres://x", "PUBLIC_URL": "https://h"}
	cases := map[string]struct {
		override map[string]string
		wantErr  string
	}{
		"missing db":          {map[string]string{"DATABASE_URL": ""}, "DATABASE_URL"},
		"http public url":     {map[string]string{"PUBLIC_URL": "http://h"}, "PUBLIC_URL"},
		"missing public url":  {map[string]string{"PUBLIC_URL": ""}, "PUBLIC_URL"},
		"bad tls mode":        {map[string]string{"TLS_MODE": "behind-proxy"}, "TLS_MODE"},
		"provided needs cert": {map[string]string{"TLS_MODE": "provided"}, "TLS_CERT_FILE"},
		"interval too small":  {map[string]string{"CHECKIN_INTERVAL_SECONDS": "5"}, "CHECKIN_INTERVAL_SECONDS"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			m := map[string]string{}
			for k, v := range base {
				m[k] = v
			}
			for k, v := range tc.override {
				m[k] = v
			}
			_, err := LoadServer(env(m))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want mention of %s", err, tc.wantErr)
			}
		})
	}
}

func TestLoadServerProvidedAndInterval(t *testing.T) {
	c, err := LoadServer(env(map[string]string{
		"DATABASE_URL": "postgres://x", "PUBLIC_URL": "https://h",
		"TLS_MODE": "provided", "TLS_CERT_FILE": "c.pem", "TLS_KEY_FILE": "k.pem",
		"CHECKIN_INTERVAL_SECONDS": "60",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.TLSMode != "provided" || c.CheckinInterval != time.Minute {
		t.Fatalf("got %+v", c)
	}
}
```

`internal/pki/fingerprint_test.go`:

```go
package pki

import "testing"

func TestFingerprint(t *testing.T) {
	want := "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got := Fingerprint(nil); got != want {
		t.Fatalf("Fingerprint(nil) = %s", got)
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/config/ ./internal/pki/`
Expected: FAIL — `undefined: LoadServer`, `undefined: Fingerprint`.

- [ ] **Step 4: Implement**

`internal/config/server.go`:

```go
// Package config loads process configuration.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"
)

// Server is the retune-server configuration.
type Server struct {
	DatabaseURL     string
	PublicURL       string
	AgentListen     string
	TLSMode         string // "self-signed" | "provided"
	TLSCertFile     string
	TLSKeyFile      string
	DataDir         string
	CheckinInterval time.Duration
}

// LoadServer reads configuration from environment variables via getenv.
func LoadServer(getenv func(string) string) (Server, error) {
	c := Server{
		DatabaseURL:     getenv("DATABASE_URL"),
		PublicURL:       getenv("PUBLIC_URL"),
		AgentListen:     or(getenv("AGENT_API_LISTEN"), ":8443"),
		TLSMode:         or(getenv("TLS_MODE"), "self-signed"),
		TLSCertFile:     getenv("TLS_CERT_FILE"),
		TLSKeyFile:      getenv("TLS_KEY_FILE"),
		DataDir:         or(getenv("DATA_DIR"), "data"),
		CheckinInterval: 5 * time.Minute,
	}
	if v := getenv("CHECKIN_INTERVAL_SECONDS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 30 {
			return Server{}, errors.New("CHECKIN_INTERVAL_SECONDS must be an integer >= 30")
		}
		c.CheckinInterval = time.Duration(n) * time.Second
	}
	if c.DatabaseURL == "" {
		return Server{}, errors.New("DATABASE_URL is required")
	}
	u, err := url.Parse(c.PublicURL)
	if c.PublicURL == "" || err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return Server{}, errors.New("PUBLIC_URL must be an https URL, e.g. https://mdm.example.com")
	}
	switch c.TLSMode {
	case "self-signed":
	case "provided":
		if c.TLSCertFile == "" || c.TLSKeyFile == "" {
			return Server{}, errors.New("TLS_MODE=provided requires TLS_CERT_FILE and TLS_KEY_FILE")
		}
	default:
		return Server{}, fmt.Errorf("unsupported TLS_MODE %q (supported: self-signed, provided)", c.TLSMode)
	}
	return c, nil
}

// PublicHost is the hostname (or IP) part of PublicURL.
func (c Server) PublicHost() string {
	u, err := url.Parse(c.PublicURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func or(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
```

`internal/protocol/v1.go`:

```go
// Package protocol defines the v1 agent <-> server wire types.
package protocol

// DeviceFacts identifies a device at enrollment time.
type DeviceFacts struct {
	Hostname   string `json:"hostname"`
	Serial     string `json:"serial"`
	SMBIOSUUID string `json:"smbios_uuid"`
	OSVersion  string `json:"os_version"`
}

// EnrollRequest is POSTed to /api/agent/v1/enroll.
type EnrollRequest struct {
	Token  string      `json:"token"`
	CSRPEM string      `json:"csr_pem"`
	Device DeviceFacts `json:"device"`
}

// EnrollResponse returns the device identity.
type EnrollResponse struct {
	DeviceID string `json:"device_id"`
	CertPEM  string `json:"cert_pem"`
	CAPEM    string `json:"ca_pem"`
}

// CheckinRequest is POSTed to /api/agent/v1/checkin over mTLS.
type CheckinRequest struct {
	AgentVersion  string   `json:"agent_version"`
	UptimeSeconds int64    `json:"uptime_seconds"`
	LoggedInUser  string   `json:"logged_in_user"`
	IPAddresses   []string `json:"ip_addresses"`
	InventoryHash string   `json:"inventory_hash"`
}

// CheckinResponse tells the agent when to check in next.
type CheckinResponse struct {
	IntervalSeconds int `json:"interval_seconds"`
}

// Error is the JSON body of every non-2xx response.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
```

`internal/pki/fingerprint.go`:

```go
// Package pki holds certificate helpers shared by server and agent.
package pki

import (
	"crypto/sha256"
	"encoding/hex"
)

// Fingerprint returns "sha256:<hex>" of a DER-encoded certificate.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:])
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go vet ./... && go test ./...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add .gitignore go.mod go.sum internal/config internal/protocol internal/pki
git commit -m "feat: scaffold module with server config, protocol types, cert fingerprint"
```

---

### Task 2: Postgres store and migrations

**Files:**
- Create: `internal/server/store/store.go`, `migrate.go`, `migrate_internal_test.go`, `models.go`, `tokens.go`, `devices.go`, `audit.go`, `store_test.go`, `migrations/0001_init.up.sql`, `migrations/0001_init.down.sql`, `internal/server/store/storetest/storetest.go`

**Interfaces:**
- Produces:
  - `store.Migrate(databaseURL string) error`; `store.Open(ctx, databaseURL) (*store.Store, error)`; `(*Store).Close()`; `(*Store).Q() *Queries`; `(*Store).InTx(ctx, func(q *Queries) error) error`
  - `store.ErrNotFound`, `store.DefaultTenantID`, `store.DeviceActive|DeviceRetired|DeviceReplaced`
  - `store.EnrollmentToken{ID uuid.UUID; TokenHash []byte; Label string; ExpiresAt *time.Time; MaxUses *int; UseCount int; RevokedAt *time.Time; CreatedBy string; CreatedAt time.Time}`
  - `store.Device{ID uuid.UUID; Hostname, Serial, SMBIOSUUID, OSVersion, Status, CertSerial string; CertExpiresAt time.Time; LastSeenAt *time.Time; AgentVersion string; EnrolledAt time.Time; ReplacedBy *uuid.UUID}`
  - `store.AuditEntry{Actor, Action, TargetKind, TargetID string; Details map[string]any; At time.Time}`
  - `*Queries` methods: `CreateEnrollmentToken(ctx, EnrollmentToken) error`, `GetEnrollmentToken(ctx, id uuid.UUID) (EnrollmentToken, error)`, `GetEnrollmentTokenByHashForUpdate(ctx, hash []byte) (EnrollmentToken, error)`, `IncrementTokenUse(ctx, id uuid.UUID) error`, `RevokeEnrollmentToken(ctx, id uuid.UUID, at time.Time) error`, `CreateDevice(ctx, Device) error`, `GetDevice(ctx, id uuid.UUID) (Device, error)`, `FindActiveDeviceByHardware(ctx, serial, smbiosUUID string) (Device, error)`, `MarkDeviceReplaced(ctx, oldID, newID uuid.UUID) error`, `SetDeviceStatus(ctx, id uuid.UUID, status string) error`, `RecordCheckin(ctx, id uuid.UUID, agentVersion string, at time.Time) error`, `InsertAudit(ctx, AuditEntry) error`, `ListAudit(ctx, limit int) ([]AuditEntry, error)`
  - `storetest.DatabaseURL(t) string` (fresh Postgres container, not migrated), `storetest.New(t) *store.Store` (migrated + opened, closed on cleanup)

- [ ] **Step 1: Write migrations**

`internal/server/store/migrations/0001_init.up.sql`:

```sql
CREATE TABLE tenants (
    id   uuid PRIMARY KEY,
    name text NOT NULL
);
INSERT INTO tenants (id, name) VALUES ('00000000-0000-0000-0000-000000000001', 'default');

CREATE TABLE enrollment_tokens (
    id         uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    token_hash bytea NOT NULL UNIQUE,
    label      text NOT NULL DEFAULT '',
    expires_at timestamptz,
    max_uses   integer CHECK (max_uses > 0),
    use_count  integer NOT NULL DEFAULT 0,
    revoked_at timestamptz,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE devices (
    id              uuid PRIMARY KEY,
    tenant_id       uuid NOT NULL REFERENCES tenants(id),
    hostname        text NOT NULL,
    serial          text NOT NULL DEFAULT '',
    smbios_uuid     text NOT NULL DEFAULT '',
    os_version      text NOT NULL DEFAULT '',
    status          text NOT NULL CHECK (status IN ('active', 'retired', 'replaced')),
    cert_serial     text NOT NULL,
    cert_expires_at timestamptz NOT NULL,
    last_seen_at    timestamptz,
    agent_version   text NOT NULL DEFAULT '',
    enrolled_at     timestamptz NOT NULL,
    replaced_by     uuid REFERENCES devices(id)
);
CREATE INDEX devices_active_smbios ON devices (tenant_id, smbios_uuid) WHERE status = 'active';
CREATE INDEX devices_active_serial ON devices (tenant_id, serial) WHERE status = 'active';

CREATE TABLE audit_log (
    id          uuid PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES tenants(id),
    actor       text NOT NULL,
    action      text NOT NULL,
    target_kind text NOT NULL,
    target_id   text NOT NULL,
    details     jsonb NOT NULL DEFAULT '{}',
    at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_log_at ON audit_log (tenant_id, at DESC);
```

`internal/server/store/migrations/0001_init.down.sql`:

```sql
DROP TABLE audit_log;
DROP TABLE devices;
DROP TABLE enrollment_tokens;
DROP TABLE tenants;
```

- [ ] **Step 2: Write the test helper and failing tests**

`internal/server/store/storetest/storetest.go`:

```go
// Package storetest starts disposable Postgres databases for tests.
package storetest

import (
	"context"
	"testing"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"retune/internal/server/store"
)

// DatabaseURL starts a fresh Postgres 17 container and returns its URL.
// The database is empty (not migrated). Skipped under -short.
func DatabaseURL(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping Postgres test in -short mode")
	}
	ctx := context.Background()
	ctr, err := postgres.Run(ctx, "postgres:17-alpine",
		postgres.WithDatabase("retune"),
		postgres.WithUsername("retune"),
		postgres.WithPassword("retune"),
		postgres.BasicWaitStrategies(),
	)
	testcontainers.CleanupContainer(t, ctr)
	if err != nil {
		t.Fatalf("start postgres (is Docker running?): %v", err)
	}
	url, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("postgres connection string: %v", err)
	}
	return url
}

// New returns a migrated, open Store backed by a fresh container.
func New(t *testing.T) *store.Store {
	t.Helper()
	url := DatabaseURL(t)
	if err := store.Migrate(url); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	s, err := store.Open(context.Background(), url)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}
```

`internal/server/store/migrate_internal_test.go`:

```go
package store

import "testing"

func TestMigrateURL(t *testing.T) {
	cases := map[string]string{
		"postgres://u:p@h/db":   "pgx5://u:p@h/db",
		"postgresql://u:p@h/db": "pgx5://u:p@h/db",
		"pgx5://u:p@h/db":       "pgx5://u:p@h/db",
	}
	for in, want := range cases {
		if got := migrateURL(in); got != want {
			t.Errorf("migrateURL(%q) = %q, want %q", in, got, want)
		}
	}
}
```

`internal/server/store/store_test.go`:

```go
package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

func TestStore(t *testing.T) {
	ctx := context.Background()
	url := storetest.DatabaseURL(t)
	if err := store.Migrate(url); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := store.Migrate(url); err != nil {
		t.Fatalf("second migrate should be a no-op: %v", err)
	}
	s, err := store.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	q := s.Q()
	now := time.Now().UTC().Truncate(time.Microsecond)

	// Enrollment tokens.
	maxUses := 3
	tok := store.EnrollmentToken{ID: uuid.Must(uuid.NewV7()), TokenHash: []byte("hash-1"), Label: "lab", MaxUses: &maxUses, CreatedBy: "test"}
	if err := q.CreateEnrollmentToken(ctx, tok); err != nil {
		t.Fatal(err)
	}
	if err := q.IncrementTokenUse(ctx, tok.ID); err != nil {
		t.Fatal(err)
	}
	err = s.InTx(ctx, func(q *store.Queries) error {
		got, err := q.GetEnrollmentTokenByHashForUpdate(ctx, []byte("hash-1"))
		if err != nil {
			return err
		}
		if got.ID != tok.ID || got.UseCount != 1 || got.MaxUses == nil || *got.MaxUses != 3 || got.Label != "lab" {
			t.Errorf("token = %+v", got)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.GetEnrollmentTokenByHashForUpdate(ctx, []byte("missing")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing token err = %v", err)
	}
	if err := q.RevokeEnrollmentToken(ctx, tok.ID, now); err != nil {
		t.Fatal(err)
	}
	got, err := q.GetEnrollmentToken(ctx, tok.ID)
	if err != nil || got.RevokedAt == nil || !got.RevokedAt.Equal(now) {
		t.Fatalf("revoked token = %+v, err = %v", got, err)
	}

	// Devices.
	d1 := store.Device{ID: uuid.Must(uuid.NewV7()), Hostname: "PC-1", Serial: "SN1", SMBIOSUUID: "U1", Status: store.DeviceActive, CertSerial: "abc", CertExpiresAt: now.Add(time.Hour), EnrolledAt: now}
	if err := q.CreateDevice(ctx, d1); err != nil {
		t.Fatal(err)
	}
	for _, hw := range [][2]string{{"", "U1"}, {"SN1", ""}, {"SN1", "U1"}} {
		found, err := q.FindActiveDeviceByHardware(ctx, hw[0], hw[1])
		if err != nil || found.ID != d1.ID {
			t.Fatalf("FindActiveDeviceByHardware(%q,%q) = %v, %v", hw[0], hw[1], found.ID, err)
		}
	}
	for _, hw := range [][2]string{{"", ""}, {"SN-x", "U-x"}} {
		if _, err := q.FindActiveDeviceByHardware(ctx, hw[0], hw[1]); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("FindActiveDeviceByHardware(%q,%q) err = %v, want ErrNotFound", hw[0], hw[1], err)
		}
	}

	d2 := d1
	d2.ID = uuid.Must(uuid.NewV7())
	if err := q.CreateDevice(ctx, d2); err != nil {
		t.Fatal(err)
	}
	if err := q.MarkDeviceReplaced(ctx, d1.ID, d2.ID); err != nil {
		t.Fatal(err)
	}
	old, err := q.GetDevice(ctx, d1.ID)
	if err != nil || old.Status != store.DeviceReplaced || old.ReplacedBy == nil || *old.ReplacedBy != d2.ID {
		t.Fatalf("replaced device = %+v, err = %v", old, err)
	}

	if err := q.RecordCheckin(ctx, d2.ID, "1.2.3", now); err != nil {
		t.Fatal(err)
	}
	cur, err := q.GetDevice(ctx, d2.ID)
	if err != nil || cur.LastSeenAt == nil || !cur.LastSeenAt.Equal(now) || cur.AgentVersion != "1.2.3" {
		t.Fatalf("after checkin = %+v, err = %v", cur, err)
	}
	if _, err := q.GetDevice(ctx, uuid.Must(uuid.NewV7())); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing device err = %v", err)
	}

	// Transactions roll back on error.
	boom := errors.New("boom")
	err = s.InTx(ctx, func(q *store.Queries) error {
		if err := q.SetDeviceStatus(ctx, d2.ID, store.DeviceRetired); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("InTx err = %v", err)
	}
	if cur, _ := q.GetDevice(ctx, d2.ID); cur.Status != store.DeviceActive {
		t.Fatalf("status after rollback = %s", cur.Status)
	}

	// Audit log.
	if err := q.InsertAudit(ctx, store.AuditEntry{Actor: "test", Action: "thing.done", TargetKind: "device", TargetID: d2.ID.String(), Details: map[string]any{"k": "v"}}); err != nil {
		t.Fatal(err)
	}
	entries, err := q.ListAudit(ctx, 10)
	if err != nil || len(entries) != 1 || entries[0].Action != "thing.done" || entries[0].Details["k"] != "v" {
		t.Fatalf("audit = %+v, err = %v", entries, err)
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/server/store/...`
Expected: FAIL — `undefined: store.Migrate` (build error).

- [ ] **Step 4: Implement the store**

`internal/server/store/store.go`:

```go
// Package store is the Postgres persistence layer.
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned when a looked-up row does not exist.
var ErrNotFound = errors.New("not found")

// DefaultTenantID is the single tenant used until multi-tenancy ships.
var DefaultTenantID = uuid.MustParse("00000000-0000-0000-0000-000000000001")

// DBTX is satisfied by both *pgxpool.Pool and pgx.Tx.
type DBTX interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Store owns the connection pool.
type Store struct {
	pool *pgxpool.Pool
}

// Queries runs statements against a pool or a transaction.
type Queries struct {
	db DBTX
}

// Open connects to Postgres and verifies the connection.
func Open(ctx context.Context, databaseURL string) (*Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close releases all connections.
func (s *Store) Close() { s.pool.Close() }

// Q returns Queries that run outside an explicit transaction.
func (s *Store) Q() *Queries { return &Queries{db: s.pool} }

// InTx runs fn in a transaction, committing if fn returns nil.
func (s *Store) InTx(ctx context.Context, fn func(q *Queries) error) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return fn(&Queries{db: tx})
	})
}

func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}
```

`internal/server/store/migrate.go`:

```go
package store

import (
	"embed"
	"errors"
	"fmt"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// Migrate applies all pending migrations. It takes an advisory lock, so
// concurrent server replicas are safe.
func Migrate(databaseURL string) error {
	src, err := iofs.New(migrationFiles, "migrations")
	if err != nil {
		return fmt.Errorf("load migrations: %w", err)
	}
	m, err := migrate.NewWithSourceInstance("iofs", src, migrateURL(databaseURL))
	if err != nil {
		return fmt.Errorf("init migrations: %w", err)
	}
	defer m.Close()
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("apply migrations: %w", err)
	}
	return nil
}

// migrateURL rewrites a postgres:// URL to the pgx5:// scheme the
// golang-migrate pgx v5 driver registers.
func migrateURL(u string) string {
	for _, p := range []string{"postgres://", "postgresql://"} {
		if strings.HasPrefix(u, p) {
			return "pgx5://" + strings.TrimPrefix(u, p)
		}
	}
	return u
}
```

`internal/server/store/models.go`:

```go
package store

import (
	"time"

	"github.com/google/uuid"
)

// Device statuses.
const (
	DeviceActive   = "active"
	DeviceRetired  = "retired"
	DeviceReplaced = "replaced"
)

// EnrollmentToken authorizes device enrollment. Only the hash is stored.
type EnrollmentToken struct {
	ID        uuid.UUID
	TokenHash []byte
	Label     string
	ExpiresAt *time.Time
	MaxUses   *int
	UseCount  int
	RevokedAt *time.Time
	CreatedBy string
	CreatedAt time.Time
}

// Device is an enrolled endpoint.
type Device struct {
	ID            uuid.UUID
	Hostname      string
	Serial        string
	SMBIOSUUID    string
	OSVersion     string
	Status        string
	CertSerial    string
	CertExpiresAt time.Time
	LastSeenAt    *time.Time
	AgentVersion  string
	EnrolledAt    time.Time
	ReplacedBy    *uuid.UUID
}

// AuditEntry records an administrative or security-relevant action.
type AuditEntry struct {
	Actor      string
	Action     string
	TargetKind string
	TargetID   string
	Details    map[string]any
	At         time.Time
}
```

`internal/server/store/tokens.go`:

```go
package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const tokenCols = `id, token_hash, label, expires_at, max_uses, use_count, revoked_at, created_by, created_at`

func scanToken(row pgx.Row) (EnrollmentToken, error) {
	var t EnrollmentToken
	err := row.Scan(&t.ID, &t.TokenHash, &t.Label, &t.ExpiresAt, &t.MaxUses, &t.UseCount, &t.RevokedAt, &t.CreatedBy, &t.CreatedAt)
	return t, notFound(err)
}

func (q *Queries) CreateEnrollmentToken(ctx context.Context, t EnrollmentToken) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO enrollment_tokens (id, tenant_id, token_hash, label, expires_at, max_uses, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		t.ID, DefaultTenantID, t.TokenHash, t.Label, t.ExpiresAt, t.MaxUses, t.CreatedBy)
	return err
}

func (q *Queries) GetEnrollmentToken(ctx context.Context, id uuid.UUID) (EnrollmentToken, error) {
	return scanToken(q.db.QueryRow(ctx, `SELECT `+tokenCols+` FROM enrollment_tokens WHERE id = $1`, id))
}

// GetEnrollmentTokenByHashForUpdate locks the token row; call inside InTx.
func (q *Queries) GetEnrollmentTokenByHashForUpdate(ctx context.Context, hash []byte) (EnrollmentToken, error) {
	return scanToken(q.db.QueryRow(ctx, `SELECT `+tokenCols+` FROM enrollment_tokens WHERE token_hash = $1 FOR UPDATE`, hash))
}

func (q *Queries) IncrementTokenUse(ctx context.Context, id uuid.UUID) error {
	_, err := q.db.Exec(ctx, `UPDATE enrollment_tokens SET use_count = use_count + 1 WHERE id = $1`, id)
	return err
}

func (q *Queries) RevokeEnrollmentToken(ctx context.Context, id uuid.UUID, at time.Time) error {
	_, err := q.db.Exec(ctx, `UPDATE enrollment_tokens SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL`, id, at)
	return err
}
```

`internal/server/store/devices.go`:

```go
package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const deviceCols = `id, hostname, serial, smbios_uuid, os_version, status, cert_serial, cert_expires_at, last_seen_at, agent_version, enrolled_at, replaced_by`

func scanDevice(row pgx.Row) (Device, error) {
	var d Device
	err := row.Scan(&d.ID, &d.Hostname, &d.Serial, &d.SMBIOSUUID, &d.OSVersion, &d.Status, &d.CertSerial, &d.CertExpiresAt, &d.LastSeenAt, &d.AgentVersion, &d.EnrolledAt, &d.ReplacedBy)
	return d, notFound(err)
}

func (q *Queries) CreateDevice(ctx context.Context, d Device) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO devices (id, tenant_id, hostname, serial, smbios_uuid, os_version, status, cert_serial, cert_expires_at, enrolled_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		d.ID, DefaultTenantID, d.Hostname, d.Serial, d.SMBIOSUUID, d.OSVersion, d.Status, d.CertSerial, d.CertExpiresAt, d.EnrolledAt)
	return err
}

func (q *Queries) GetDevice(ctx context.Context, id uuid.UUID) (Device, error) {
	return scanDevice(q.db.QueryRow(ctx, `SELECT `+deviceCols+` FROM devices WHERE id = $1`, id))
}

// FindActiveDeviceByHardware finds an active device with the same non-empty
// SMBIOS UUID or serial number (used to detect reimaged machines).
func (q *Queries) FindActiveDeviceByHardware(ctx context.Context, serial, smbiosUUID string) (Device, error) {
	if serial == "" && smbiosUUID == "" {
		return Device{}, ErrNotFound
	}
	return scanDevice(q.db.QueryRow(ctx, `
		SELECT `+deviceCols+` FROM devices
		WHERE status = 'active'
		  AND ((smbios_uuid <> '' AND smbios_uuid = $1) OR (serial <> '' AND serial = $2))
		ORDER BY enrolled_at DESC
		LIMIT 1`, smbiosUUID, serial))
}

func (q *Queries) MarkDeviceReplaced(ctx context.Context, oldID, newID uuid.UUID) error {
	_, err := q.db.Exec(ctx, `UPDATE devices SET status = 'replaced', replaced_by = $2 WHERE id = $1`, oldID, newID)
	return err
}

func (q *Queries) SetDeviceStatus(ctx context.Context, id uuid.UUID, status string) error {
	_, err := q.db.Exec(ctx, `UPDATE devices SET status = $2 WHERE id = $1`, id, status)
	return err
}

func (q *Queries) RecordCheckin(ctx context.Context, id uuid.UUID, agentVersion string, at time.Time) error {
	_, err := q.db.Exec(ctx, `UPDATE devices SET last_seen_at = $2, agent_version = $3 WHERE id = $1`, id, at, agentVersion)
	return err
}
```

`internal/server/store/audit.go`:

```go
package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

func (q *Queries) InsertAudit(ctx context.Context, a AuditEntry) error {
	details := a.Details
	if details == nil {
		details = map[string]any{}
	}
	b, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("marshal audit details: %w", err)
	}
	id, err := uuid.NewV7()
	if err != nil {
		return err
	}
	_, err = q.db.Exec(ctx, `
		INSERT INTO audit_log (id, tenant_id, actor, action, target_kind, target_id, details)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		id, DefaultTenantID, a.Actor, a.Action, a.TargetKind, a.TargetID, b)
	return err
}

// ListAudit returns the newest entries first.
func (q *Queries) ListAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	rows, err := q.db.Query(ctx, `
		SELECT actor, action, target_kind, target_id, details, at
		FROM audit_log ORDER BY at DESC, id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var a AuditEntry
		var raw []byte
		if err := rows.Scan(&a.Actor, &a.Action, &a.TargetKind, &a.TargetID, &raw, &a.At); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &a.Details); err != nil {
			return nil, fmt.Errorf("unmarshal audit details: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go mod tidy && go vet ./... && go test ./internal/server/store/...`
Expected: PASS (requires Docker).

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/server/store
git commit -m "feat(store): Postgres store with tenants, tokens, devices, audit log"
```

---

### Task 3: Enrollment token logic

**Files:**
- Create: `internal/server/enroll/token.go`, `internal/server/enroll/token_test.go`

**Interfaces:**
- Consumes: `store.EnrollmentToken`
- Produces: `enroll.GenerateToken() (plain string, hash []byte, err error)`, `enroll.HashToken(plain string) []byte`, `enroll.CheckUsable(t store.EnrollmentToken, now time.Time) error`, errors `ErrTokenNotFound`, `ErrTokenRevoked`, `ErrTokenExpired`, `ErrTokenExhausted`

- [ ] **Step 1: Write failing tests**

`internal/server/enroll/token_test.go`:

```go
package enroll

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"retune/internal/server/store"
)

func TestGenerateToken(t *testing.T) {
	p1, h1, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	p2, _, _ := GenerateToken()
	if !strings.HasPrefix(p1, "rt_") || len(p1) < 40 {
		t.Fatalf("token %q has wrong shape", p1)
	}
	if p1 == p2 {
		t.Fatal("tokens must be unique")
	}
	if !bytes.Equal(h1, HashToken(p1)) || !bytes.Equal(h1, HashToken("  "+p1+"\n")) {
		t.Fatal("hash must match HashToken and ignore surrounding whitespace")
	}
}

func TestCheckUsable(t *testing.T) {
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Minute), now.Add(time.Minute)
	two := 2
	cases := map[string]struct {
		tok  store.EnrollmentToken
		want error
	}{
		"fresh":             {store.EnrollmentToken{}, nil},
		"not yet expired":   {store.EnrollmentToken{ExpiresAt: &future}, nil},
		"expired":           {store.EnrollmentToken{ExpiresAt: &past}, ErrTokenExpired},
		"expires right now": {store.EnrollmentToken{ExpiresAt: &now}, ErrTokenExpired},
		"revoked":           {store.EnrollmentToken{RevokedAt: &past}, ErrTokenRevoked},
		"uses left":         {store.EnrollmentToken{MaxUses: &two, UseCount: 1}, nil},
		"exhausted":         {store.EnrollmentToken{MaxUses: &two, UseCount: 2}, ErrTokenExhausted},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if err := CheckUsable(tc.tok, now); !errors.Is(err, tc.want) {
				t.Fatalf("CheckUsable = %v, want %v", err, tc.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/server/enroll/`
Expected: FAIL — `undefined: GenerateToken`.

- [ ] **Step 3: Implement**

`internal/server/enroll/token.go`:

```go
// Package enroll implements enrollment tokens and device enrollment.
package enroll

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"retune/internal/server/store"
)

var (
	ErrTokenNotFound  = errors.New("enrollment token not found")
	ErrTokenRevoked   = errors.New("enrollment token has been revoked")
	ErrTokenExpired   = errors.New("enrollment token has expired")
	ErrTokenExhausted = errors.New("enrollment token has no uses left")
)

const tokenPrefix = "rt_"

// GenerateToken returns a new random token and its storage hash.
func GenerateToken() (plain string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	plain = tokenPrefix + base64.RawURLEncoding.EncodeToString(b)
	return plain, HashToken(plain), nil
}

// HashToken is the value stored in enrollment_tokens.token_hash.
func HashToken(plain string) []byte {
	sum := sha256.Sum256([]byte(strings.TrimSpace(plain)))
	return sum[:]
}

// CheckUsable reports why a token cannot be used right now, or nil.
func CheckUsable(t store.EnrollmentToken, now time.Time) error {
	switch {
	case t.RevokedAt != nil:
		return ErrTokenRevoked
	case t.ExpiresAt != nil && !now.Before(*t.ExpiresAt):
		return ErrTokenExpired
	case t.MaxUses != nil && t.UseCount >= *t.MaxUses:
		return ErrTokenExhausted
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go vet ./... && go test ./internal/server/enroll/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/server/enroll
git commit -m "feat(enroll): token generation, hashing, and usability checks"
```

---

### Task 4: Internal certificate authority

**Files:**
- Create: `internal/server/ca/keystore.go`, `internal/server/ca/ca.go`, `internal/server/ca/ca_test.go`

**Interfaces:**
- Produces:
  - `ca.KeyStore` interface `{ Load(ctx) (certPEM, keyPEM []byte, err error); Save(ctx, certPEM, keyPEM []byte) error }`, `ca.ErrNotExist`, `ca.FileKeyStore{Dir string}` (files `ca.crt`, `ca.key`)
  - `ca.LoadOrCreate(ctx, ks KeyStore, now time.Time) (*ca.CA, error)`
  - `(*CA).Cert() *x509.Certificate`, `(*CA).CertPEM() []byte`, `(*CA).Pool() *x509.CertPool`
  - `(*CA).SignClientCSR(csrPEM []byte, deviceID string, now time.Time, validity time.Duration) (ca.IssuedCert, error)`; `ca.IssuedCert{PEM []byte; Serial string /* hex */; NotAfter time.Time}`; `ca.ErrBadCSR`
  - `(*CA).IssueServerCert(hosts []string, now time.Time) (tls.Certificate, error)` — chain is `[leaf, CA]`

- [ ] **Step 1: Write failing tests**

`internal/server/ca/ca_test.go`:

```go
package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"
)

var now = time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)

func newCA(t *testing.T) *CA {
	t.Helper()
	c, err := LoadOrCreate(context.Background(), FileKeyStore{Dir: t.TempDir()}, now)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func csrPEM(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func parseCert(t *testing.T, p []byte) *x509.Certificate {
	t.Helper()
	b, _ := pem.Decode(p)
	if b == nil {
		t.Fatal("no PEM block")
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLoadOrCreatePersists(t *testing.T) {
	ks := FileKeyStore{Dir: t.TempDir()}
	a1, err := LoadOrCreate(context.Background(), ks, now)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := LoadOrCreate(context.Background(), ks, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !a1.Cert().Equal(a2.Cert()) {
		t.Fatal("second LoadOrCreate must load the same CA")
	}
	if !a1.Cert().IsCA {
		t.Fatal("CA cert must have IsCA")
	}
	if !parseCert(t, a1.CertPEM()).Equal(a1.Cert()) {
		t.Fatal("CertPEM must encode Cert")
	}
}

func TestSignClientCSR(t *testing.T) {
	a := newCA(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issued, err := a.SignClientCSR(csrPEM(t, key), "dev-1", now, 90*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert := parseCert(t, issued.PEM)
	if cert.Subject.CommonName != "dev-1" || cert.SerialNumber.Text(16) != issued.Serial || !cert.NotAfter.Equal(issued.NotAfter) {
		t.Fatalf("cert CN=%s serial=%s notAfter=%s; issued=%+v", cert.Subject.CommonName, cert.SerialNumber.Text(16), cert.NotAfter, issued)
	}
	if !issued.NotAfter.Equal(now.Add(90 * 24 * time.Hour)) {
		t.Fatalf("NotAfter = %s", issued.NotAfter)
	}
	opts := x509.VerifyOptions{Roots: a.Pool(), CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if _, err := cert.Verify(opts); err != nil {
		t.Fatalf("client cert must verify for ClientAuth: %v", err)
	}
	opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if _, err := cert.Verify(opts); err == nil {
		t.Fatal("client cert must not verify for ServerAuth")
	}
}

func TestSignClientCSRRejects(t *testing.T) {
	a := newCA(t)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	cases := map[string][]byte{
		"garbage":  []byte("not a csr"),
		"cert pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}}),
		"rsa key":  csrPEM(t, rsaKey),
		"p384 key": csrPEM(t, p384),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := a.SignClientCSR(in, "dev", now, time.Hour); !errors.Is(err, ErrBadCSR) {
				t.Fatalf("err = %v, want ErrBadCSR", err)
			}
		})
	}
}

func TestIssueServerCert(t *testing.T) {
	a := newCA(t)
	tc, err := a.IssueServerCert([]string{"mdm.example.com", "127.0.0.1"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(tc.Certificate) != 2 {
		t.Fatalf("chain length = %d, want 2 (leaf + CA)", len(tc.Certificate))
	}
	leaf, err := x509.ParseCertificate(tc.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"mdm.example.com", "127.0.0.1"} {
		opts := x509.VerifyOptions{DNSName: host, Roots: a.Pool(), CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		if _, err := leaf.Verify(opts); err != nil {
			t.Fatalf("verify for %s: %v", host, err)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/server/ca/`
Expected: FAIL — `undefined: LoadOrCreate`.

- [ ] **Step 3: Implement**

`internal/server/ca/keystore.go`:

```go
package ca

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// ErrNotExist is returned by KeyStore.Load when no CA has been saved yet.
var ErrNotExist = errors.New("CA material does not exist")

// KeyStore persists the CA certificate and private key. Cloud deployments
// will add secret-manager/KMS implementations.
type KeyStore interface {
	Load(ctx context.Context) (certPEM, keyPEM []byte, err error)
	Save(ctx context.Context, certPEM, keyPEM []byte) error
}

// FileKeyStore stores ca.crt and ca.key in Dir.
type FileKeyStore struct {
	Dir string
}

func (f FileKeyStore) Load(ctx context.Context) ([]byte, []byte, error) {
	certPEM, err := os.ReadFile(filepath.Join(f.Dir, "ca.crt"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, ErrNotExist
	}
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(f.Dir, "ca.key"))
	if err != nil {
		return nil, nil, err
	}
	return certPEM, keyPEM, nil
}

// Save writes the key first and refuses to overwrite an existing key.
func (f FileKeyStore) Save(ctx context.Context, certPEM, keyPEM []byte) error {
	if err := os.MkdirAll(f.Dir, 0o700); err != nil {
		return err
	}
	if err := writeNew(filepath.Join(f.Dir, "ca.key"), keyPEM, 0o600); err != nil {
		return err
	}
	return writeNew(filepath.Join(f.Dir, "ca.crt"), certPEM, 0o644)
}

func writeNew(path string, data []byte, perm os.FileMode) error {
	fh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := fh.Write(data); err != nil {
		fh.Close()
		return err
	}
	return fh.Close()
}
```

`internal/server/ca/ca.go`:

```go
// Package ca is Retune's internal certificate authority.
package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

// ErrBadCSR is returned for unparseable or unacceptable CSRs.
var ErrBadCSR = errors.New("invalid certificate signing request")

// CA signs device client certificates and the self-signed server certificate.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// IssuedCert is a signed client certificate.
type IssuedCert struct {
	PEM      []byte
	Serial   string // lowercase hex
	NotAfter time.Time
}

// LoadOrCreate loads the CA from ks, creating and saving a new one if none exists.
func LoadOrCreate(ctx context.Context, ks KeyStore, now time.Time) (*CA, error) {
	certPEM, keyPEM, err := ks.Load(ctx)
	if errors.Is(err, ErrNotExist) {
		c, certPEM, keyPEM, err := create(now)
		if err != nil {
			return nil, err
		}
		if err := ks.Save(ctx, certPEM, keyPEM); err != nil {
			return nil, fmt.Errorf("save CA: %w", err)
		}
		return c, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load CA: %w", err)
	}
	return parse(certPEM, keyPEM)
}

func create(now time.Time) (*CA, []byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Retune Internal CA", Organization: []string{"Retune"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return &CA{cert: cert, key: key}, certPEM, keyPEM, nil
}

func parse(certPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil || cb.Type != "CERTIFICATE" {
		return nil, errors.New("CA certificate is not PEM CERTIFICATE")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	if !cert.IsCA {
		return nil, errors.New("stored CA certificate is not a CA")
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil || kb.Type != "EC PRIVATE KEY" {
		return nil, errors.New("CA key is not PEM EC PRIVATE KEY")
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}
	return &CA{cert: cert, key: key}, nil
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func (c *CA) Cert() *x509.Certificate { return c.cert }

func (c *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})
}

func (c *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.cert)
	return p
}

// SignClientCSR issues a ClientAuth certificate with CN = deviceID.
// Only ECDSA P-256 keys are accepted.
func (c *CA) SignClientCSR(csrPEM []byte, deviceID string, now time.Time, validity time.Duration) (IssuedCert, error) {
	b, _ := pem.Decode(csrPEM)
	if b == nil || b.Type != "CERTIFICATE REQUEST" {
		return IssuedCert{}, fmt.Errorf("%w: not a PEM CERTIFICATE REQUEST", ErrBadCSR)
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return IssuedCert{}, fmt.Errorf("%w: %v", ErrBadCSR, err)
	}
	if err := csr.CheckSignature(); err != nil {
		return IssuedCert{}, fmt.Errorf("%w: %v", ErrBadCSR, err)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return IssuedCert{}, fmt.Errorf("%w: key must be ECDSA P-256", ErrBadCSR)
	}
	serial, err := randomSerial()
	if err != nil {
		return IssuedCert{}, err
	}
	notAfter := now.Add(validity).Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: deviceID},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, pub, c.key)
	if err != nil {
		return IssuedCert{}, err
	}
	return IssuedCert{
		PEM:      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		Serial:   serial.Text(16),
		NotAfter: notAfter,
	}, nil
}

// IssueServerCert creates a fresh ServerAuth certificate for hosts (DNS names
// or IPs) signed by the CA. The returned chain includes the CA so agents
// that pin the CA fingerprint can find it.
func (c *CA) IssueServerCert(hosts []string, now time.Time) (tls.Certificate, error) {
	if len(hosts) == 0 {
		return tls.Certificate{}, errors.New("at least one host is required")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hosts[0]},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der, c.cert.Raw}, PrivateKey: key}, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go vet ./... && go test ./internal/server/ca/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/server/ca
git commit -m "feat(ca): internal CA with file keystore, client CSR signing, server certs"
```

---

### Task 5: Enrollment service

**Files:**
- Create: `internal/server/enroll/service.go`, `internal/server/enroll/service_test.go`

**Interfaces:**
- Consumes: Task 2 `*store.Store`/`*store.Queries` methods, Task 3 token functions, Task 4 `*ca.CA`
- Produces:
  - `enroll.Service{Store *store.Store; CA *ca.CA; Now func() time.Time; CertValidity time.Duration}`
  - `enroll.TokenOptions{Label string; MaxUses *int; ExpiresAt *time.Time; CreatedBy string}`
  - `(*Service).CreateToken(ctx, TokenOptions) (plain string, tok store.EnrollmentToken, err error)`
  - `(*Service).Enroll(ctx, protocol.EnrollRequest) (protocol.EnrollResponse, error)` — errors: token errors from Task 3, `ca.ErrBadCSR`, `enroll.ErrBadRequest`

- [ ] **Step 1: Write failing tests**

`internal/server/enroll/service_test.go`:

```go
package enroll_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/ca"
	"retune/internal/server/enroll"
	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

var now = time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)

func newService(t *testing.T) *enroll.Service {
	t.Helper()
	st := storetest.New(t)
	authority, err := ca.LoadOrCreate(context.Background(), ca.FileKeyStore{Dir: t.TempDir()}, now)
	if err != nil {
		t.Fatal(err)
	}
	return &enroll.Service{Store: st, CA: authority, Now: func() time.Time { return now }, CertValidity: 90 * 24 * time.Hour}
}

func newCSR(t *testing.T) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func TestEnroll(t *testing.T) {
	ctx := context.Background()
	svc := newService(t)
	q := svc.Store.Q()

	newToken := func(t *testing.T, o enroll.TokenOptions) (string, store.EnrollmentToken) {
		t.Helper()
		o.CreatedBy = "test"
		plain, tok, err := svc.CreateToken(ctx, o)
		if err != nil {
			t.Fatal(err)
		}
		return plain, tok
	}

	t.Run("valid token enrolls device", func(t *testing.T) {
		plain, tok := newToken(t, enroll.TokenOptions{Label: "a"})
		facts := protocol.DeviceFacts{Hostname: "PC-1", Serial: "SN-A", SMBIOSUUID: "U-A", OSVersion: "Windows 11"}
		resp, err := svc.Enroll(ctx, protocol.EnrollRequest{Token: plain, CSRPEM: newCSR(t), Device: facts})
		if err != nil {
			t.Fatal(err)
		}
		d, err := q.GetDevice(ctx, uuid.MustParse(resp.DeviceID))
		if err != nil {
			t.Fatal(err)
		}
		if d.Status != store.DeviceActive || d.Hostname != "PC-1" || d.SMBIOSUUID != "U-A" || !d.CertExpiresAt.Equal(now.Add(90*24*time.Hour)) {
			t.Fatalf("device = %+v", d)
		}
		b, _ := pem.Decode([]byte(resp.CertPEM))
		cert, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if cert.Subject.CommonName != resp.DeviceID || cert.SerialNumber.Text(16) != d.CertSerial {
			t.Fatalf("cert CN=%s serial=%s, device serial=%s", cert.Subject.CommonName, cert.SerialNumber.Text(16), d.CertSerial)
		}
		opts := x509.VerifyOptions{Roots: svc.CA.Pool(), CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		if _, err := cert.Verify(opts); err != nil {
			t.Fatal(err)
		}
		if resp.CAPEM != string(svc.CA.CertPEM()) {
			t.Fatal("response must include CA PEM")
		}
		got, _ := q.GetEnrollmentToken(ctx, tok.ID)
		if got.UseCount != 1 {
			t.Fatalf("use count = %d", got.UseCount)
		}
	})

	t.Run("same hardware replaces previous device", func(t *testing.T) {
		plain, _ := newToken(t, enroll.TokenOptions{})
		facts := protocol.DeviceFacts{Hostname: "PC-2", SMBIOSUUID: "U-B"}
		first, err := svc.Enroll(ctx, protocol.EnrollRequest{Token: plain, CSRPEM: newCSR(t), Device: facts})
		if err != nil {
			t.Fatal(err)
		}
		second, err := svc.Enroll(ctx, protocol.EnrollRequest{Token: plain, CSRPEM: newCSR(t), Device: facts})
		if err != nil {
			t.Fatal(err)
		}
		old, _ := q.GetDevice(ctx, uuid.MustParse(first.DeviceID))
		if old.Status != store.DeviceReplaced || old.ReplacedBy == nil || old.ReplacedBy.String() != second.DeviceID {
			t.Fatalf("old device = %+v", old)
		}
	})

	errCases := []struct {
		name string
		opts enroll.TokenOptions
		prep func(t *testing.T, tok store.EnrollmentToken, plain string)
		want error
	}{
		{name: "revoked token", prep: func(t *testing.T, tok store.EnrollmentToken, _ string) {
			if err := q.RevokeEnrollmentToken(ctx, tok.ID, now); err != nil {
				t.Fatal(err)
			}
		}, want: enroll.ErrTokenRevoked},
		{name: "expired token", opts: enroll.TokenOptions{ExpiresAt: ptr(now.Add(-time.Minute))}, want: enroll.ErrTokenExpired},
		{name: "exhausted token", opts: enroll.TokenOptions{MaxUses: ptr(1)}, prep: func(t *testing.T, _ store.EnrollmentToken, plain string) {
			if _, err := svc.Enroll(ctx, protocol.EnrollRequest{Token: plain, CSRPEM: newCSR(t), Device: protocol.DeviceFacts{Hostname: "PC-3"}}); err != nil {
				t.Fatal(err)
			}
		}, want: enroll.ErrTokenExhausted},
	}
	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			plain, tok := newToken(t, tc.opts)
			if tc.prep != nil {
				tc.prep(t, tok, plain)
			}
			_, err := svc.Enroll(ctx, protocol.EnrollRequest{Token: plain, CSRPEM: newCSR(t), Device: protocol.DeviceFacts{Hostname: "PC-4"}})
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}

	t.Run("unknown token", func(t *testing.T) {
		_, err := svc.Enroll(ctx, protocol.EnrollRequest{Token: "rt_nope", CSRPEM: newCSR(t), Device: protocol.DeviceFacts{Hostname: "PC-5"}})
		if !errors.Is(err, enroll.ErrTokenNotFound) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("bad CSR does not consume token", func(t *testing.T) {
		plain, tok := newToken(t, enroll.TokenOptions{})
		_, err := svc.Enroll(ctx, protocol.EnrollRequest{Token: plain, CSRPEM: "garbage", Device: protocol.DeviceFacts{Hostname: "PC-6"}})
		if !errors.Is(err, ca.ErrBadCSR) {
			t.Fatalf("err = %v", err)
		}
		got, _ := q.GetEnrollmentToken(ctx, tok.ID)
		if got.UseCount != 0 {
			t.Fatalf("use count = %d, want 0", got.UseCount)
		}
	})

	t.Run("missing hostname", func(t *testing.T) {
		plain, _ := newToken(t, enroll.TokenOptions{})
		_, err := svc.Enroll(ctx, protocol.EnrollRequest{Token: plain, CSRPEM: newCSR(t)})
		if !errors.Is(err, enroll.ErrBadRequest) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("create token rejects non-positive max uses", func(t *testing.T) {
		if _, _, err := svc.CreateToken(ctx, enroll.TokenOptions{MaxUses: ptr(0), CreatedBy: "test"}); !errors.Is(err, enroll.ErrBadRequest) {
			t.Fatalf("err = %v", err)
		}
	})

	entries, err := q.ListAudit(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	var enrolled int
	for _, e := range entries {
		if e.Action == "device.enrolled" {
			enrolled++
		}
	}
	if enrolled != 4 {
		t.Fatalf("device.enrolled audit entries = %d, want 4", enrolled)
	}
}

func ptr[T any](v T) *T { return &v }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/server/enroll/`
Expected: FAIL — `undefined: enroll.Service`.

- [ ] **Step 3: Implement**

`internal/server/enroll/service.go`:

```go
package enroll

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/ca"
	"retune/internal/server/store"
)

// ErrBadRequest marks invalid input from the caller.
var ErrBadRequest = errors.New("bad request")

// Service creates enrollment tokens and enrolls devices.
type Service struct {
	Store        *store.Store
	CA           *ca.CA
	Now          func() time.Time
	CertValidity time.Duration
}

// TokenOptions configure a new enrollment token.
type TokenOptions struct {
	Label     string
	MaxUses   *int
	ExpiresAt *time.Time
	CreatedBy string
}

// CreateToken stores a new token and returns its plaintext (shown once).
func (s *Service) CreateToken(ctx context.Context, o TokenOptions) (string, store.EnrollmentToken, error) {
	if o.MaxUses != nil && *o.MaxUses <= 0 {
		return "", store.EnrollmentToken{}, fmt.Errorf("%w: max uses must be positive", ErrBadRequest)
	}
	plain, hash, err := GenerateToken()
	if err != nil {
		return "", store.EnrollmentToken{}, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return "", store.EnrollmentToken{}, err
	}
	tok := store.EnrollmentToken{ID: id, TokenHash: hash, Label: o.Label, MaxUses: o.MaxUses, ExpiresAt: o.ExpiresAt, CreatedBy: o.CreatedBy}
	err = s.Store.InTx(ctx, func(q *store.Queries) error {
		if err := q.CreateEnrollmentToken(ctx, tok); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: o.CreatedBy, Action: "enrollment_token.created",
			TargetKind: "enrollment_token", TargetID: id.String(),
			Details: map[string]any{"label": o.Label},
		})
	})
	if err != nil {
		return "", store.EnrollmentToken{}, err
	}
	return plain, tok, nil
}

// Enroll validates the token, creates the device, and issues its client
// certificate, all in one transaction.
func (s *Service) Enroll(ctx context.Context, req protocol.EnrollRequest) (protocol.EnrollResponse, error) {
	if strings.TrimSpace(req.Device.Hostname) == "" {
		return protocol.EnrollResponse{}, fmt.Errorf("%w: device hostname is required", ErrBadRequest)
	}
	now := s.Now()
	var resp protocol.EnrollResponse
	err := s.Store.InTx(ctx, func(q *store.Queries) error {
		tok, err := q.GetEnrollmentTokenByHashForUpdate(ctx, HashToken(req.Token))
		if errors.Is(err, store.ErrNotFound) {
			return ErrTokenNotFound
		}
		if err != nil {
			return err
		}
		if err := CheckUsable(tok, now); err != nil {
			return err
		}

		deviceID, err := uuid.NewV7()
		if err != nil {
			return err
		}
		issued, err := s.CA.SignClientCSR([]byte(req.CSRPEM), deviceID.String(), now, s.CertValidity)
		if err != nil {
			return err
		}

		prev, err := q.FindActiveDeviceByHardware(ctx, req.Device.Serial, req.Device.SMBIOSUUID)
		replacing := err == nil
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}

		if err := q.CreateDevice(ctx, store.Device{
			ID:            deviceID,
			Hostname:      req.Device.Hostname,
			Serial:        req.Device.Serial,
			SMBIOSUUID:    req.Device.SMBIOSUUID,
			OSVersion:     req.Device.OSVersion,
			Status:        store.DeviceActive,
			CertSerial:    issued.Serial,
			CertExpiresAt: issued.NotAfter,
			EnrolledAt:    now,
		}); err != nil {
			return err
		}
		details := map[string]any{"token_id": tok.ID.String(), "hostname": req.Device.Hostname}
		if replacing {
			if err := q.MarkDeviceReplaced(ctx, prev.ID, deviceID); err != nil {
				return err
			}
			details["replaced_device_id"] = prev.ID.String()
		}
		if err := q.IncrementTokenUse(ctx, tok.ID); err != nil {
			return err
		}
		if err := q.InsertAudit(ctx, store.AuditEntry{
			Actor: "token:" + tok.ID.String(), Action: "device.enrolled",
			TargetKind: "device", TargetID: deviceID.String(), Details: details,
		}); err != nil {
			return err
		}
		resp = protocol.EnrollResponse{DeviceID: deviceID.String(), CertPEM: string(issued.PEM), CAPEM: string(s.CA.CertPEM())}
		return nil
	})
	if err != nil {
		return protocol.EnrollResponse{}, err
	}
	return resp, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go vet ./... && go test ./internal/server/enroll/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/server/enroll
git commit -m "feat(enroll): transactional device enrollment and token creation"
```

---

### Task 6: Agent API and app wiring

**Files:**
- Create: `internal/server/agentapi/json.go`, `internal/server/agentapi/handler.go`, `internal/server/app/app.go`, `internal/server/app/app_test.go`

**Interfaces:**
- Consumes: `config.Server` (Task 1), store (Task 2), ca (Task 4), `enroll.Service` (Task 5)
- Produces:
  - `agentapi.Handler{Enroll *enroll.Service; Store *store.Store; Now func() time.Time; CheckinInterval time.Duration; Log *slog.Logger}`, `(*Handler).Routes() http.Handler`
  - Routes: `POST /api/agent/v1/enroll` (no client cert), `POST /api/agent/v1/checkin` (mTLS; device must be `active` and presented cert serial must equal `devices.cert_serial`, else `401 device_not_active`)
  - Error codes: `bad_request` (400), `enrollment_token_invalid` (403), `client_cert_required` (401), `device_not_active` (401), `internal` (500)
  - `app.New(ctx, config.Server, *slog.Logger) (*app.App, error)`; `app.App{Store *store.Store; CA *ca.CA; Enroll *enroll.Service; Handler http.Handler; TLSConfig *tls.Config}`; `(*App).Close()`. `New` runs migrations. CA is stored under `<DataDir>/ca`.

- [ ] **Step 1: Write the failing test**

`internal/server/app/app_test.go`:

```go
package app_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/config"
	"retune/internal/protocol"
	"retune/internal/server/app"
	"retune/internal/server/enroll"
	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

func newTestApp(t *testing.T) (*app.App, *httptest.Server) {
	t.Helper()
	cfg := config.Server{
		DatabaseURL: storetest.DatabaseURL(t), PublicURL: "https://127.0.0.1",
		TLSMode: "self-signed", DataDir: t.TempDir(), CheckinInterval: 5 * time.Minute,
	}
	a, err := app.New(context.Background(), cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	srv := httptest.NewUnstartedServer(a.Handler)
	srv.TLS = a.TLSConfig
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return a, srv
}

func httpClient(a *app.App, cert *tls.Certificate) *http.Client {
	cfg := &tls.Config{RootCAs: a.CA.Pool()}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
}

func post(t *testing.T, c *http.Client, url string, body any) (int, []byte) {
	t.Helper()
	b, _ := json.Marshal(body)
	res, err := c.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, out
}

func TestAgentAPI(t *testing.T) {
	ctx := context.Background()
	a, srv := newTestApp(t)
	plain, _, err := a.Enroll.CreateToken(ctx, enroll.TokenOptions{CreatedBy: "test"})
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	anon := httpClient(a, nil)

	status, body := post(t, anon, srv.URL+"/api/agent/v1/enroll", protocol.EnrollRequest{Token: "rt_bad", CSRPEM: csrPEM, Device: protocol.DeviceFacts{Hostname: "PC-1"}})
	if status != http.StatusForbidden || !bytes.Contains(body, []byte("enrollment_token_invalid")) {
		t.Fatalf("bad token: %d %s", status, body)
	}
	status, body = post(t, anon, srv.URL+"/api/agent/v1/enroll", protocol.EnrollRequest{Token: plain, CSRPEM: "junk", Device: protocol.DeviceFacts{Hostname: "PC-1"}})
	if status != http.StatusBadRequest {
		t.Fatalf("bad csr: %d %s", status, body)
	}

	status, body = post(t, anon, srv.URL+"/api/agent/v1/enroll", protocol.EnrollRequest{Token: plain, CSRPEM: csrPEM, Device: protocol.DeviceFacts{Hostname: "PC-1"}})
	if status != http.StatusOK {
		t.Fatalf("enroll: %d %s", status, body)
	}
	var enrolled protocol.EnrollResponse
	if err := json.Unmarshal(body, &enrolled); err != nil {
		t.Fatal(err)
	}

	status, _ = post(t, anon, srv.URL+"/api/agent/v1/checkin", protocol.CheckinRequest{})
	if status != http.StatusUnauthorized {
		t.Fatalf("checkin without cert: %d", status)
	}

	block, _ := pem.Decode([]byte(enrolled.CertPEM))
	mtls := httpClient(a, &tls.Certificate{Certificate: [][]byte{block.Bytes}, PrivateKey: key})
	status, body = post(t, mtls, srv.URL+"/api/agent/v1/checkin", protocol.CheckinRequest{AgentVersion: "0.1.0"})
	if status != http.StatusOK {
		t.Fatalf("checkin: %d %s", status, body)
	}
	var cr protocol.CheckinResponse
	if err := json.Unmarshal(body, &cr); err != nil || cr.IntervalSeconds != 300 {
		t.Fatalf("checkin response %s, err %v", body, err)
	}
	id := uuid.MustParse(enrolled.DeviceID)
	if d, _ := a.Store.Q().GetDevice(ctx, id); d.LastSeenAt == nil || d.AgentVersion != "0.1.0" {
		t.Fatalf("device after checkin = %+v", d)
	}

	if err := a.Store.Q().SetDeviceStatus(ctx, id, store.DeviceRetired); err != nil {
		t.Fatal(err)
	}
	status, body = post(t, mtls, srv.URL+"/api/agent/v1/checkin", protocol.CheckinRequest{})
	if status != http.StatusUnauthorized || !bytes.Contains(body, []byte("device_not_active")) {
		t.Fatalf("retired checkin: %d %s", status, body)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/server/app/`
Expected: FAIL — package `retune/internal/server/app` not found.

- [ ] **Step 3: Implement**

`internal/server/agentapi/json.go`:

```go
package agentapi

import (
	"encoding/json"
	"net/http"

	"retune/internal/protocol"
)

const maxBody = 1 << 20

// decode reads a JSON body (max 1 MB). Unknown fields are allowed so newer
// agents can talk to older servers.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, protocol.Error{Code: code, Message: msg})
}
```

`internal/server/agentapi/handler.go`:

```go
// Package agentapi serves the endpoints agents call.
package agentapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/ca"
	"retune/internal/server/enroll"
	"retune/internal/server/store"
)

// Handler serves /api/agent/v1.
type Handler struct {
	Enroll          *enroll.Service
	Store           *store.Store
	Now             func() time.Time
	CheckinInterval time.Duration
	Log             *slog.Logger
}

type deviceKey struct{}

// Routes returns the agent API mux.
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/agent/v1/enroll", h.enroll)
	mux.Handle("POST /api/agent/v1/checkin", h.requireDevice(http.HandlerFunc(h.checkin)))
	return mux
}

func (h *Handler) enroll(w http.ResponseWriter, r *http.Request) {
	var req protocol.EnrollRequest
	if !decode(w, r, &req) {
		return
	}
	resp, err := h.Enroll.Enroll(r.Context(), req)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, resp)
	case errors.Is(err, enroll.ErrTokenNotFound), errors.Is(err, enroll.ErrTokenRevoked),
		errors.Is(err, enroll.ErrTokenExpired), errors.Is(err, enroll.ErrTokenExhausted):
		writeError(w, http.StatusForbidden, "enrollment_token_invalid", err.Error())
	case errors.Is(err, ca.ErrBadCSR), errors.Is(err, enroll.ErrBadRequest):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	default:
		h.Log.Error("enroll failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
	}
}

// requireDevice authenticates the mTLS client certificate and loads the
// device. The certificate must be the device's current one.
func (h *Handler) requireDevice(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			writeError(w, http.StatusUnauthorized, "client_cert_required", "a device client certificate is required")
			return
		}
		leaf := r.TLS.VerifiedChains[0][0]
		id, err := uuid.Parse(leaf.Subject.CommonName)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "device_not_active", "unrecognized device certificate")
			return
		}
		d, err := h.Store.Q().GetDevice(r.Context(), id)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			h.Log.Error("load device", "device_id", id, "error", err)
			writeError(w, http.StatusInternalServerError, "internal", "internal server error")
			return
		}
		if err != nil || d.Status != store.DeviceActive || d.CertSerial != leaf.SerialNumber.Text(16) {
			writeError(w, http.StatusUnauthorized, "device_not_active", "device is retired, replaced, or using an outdated certificate")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), deviceKey{}, d)))
	})
}

func (h *Handler) checkin(w http.ResponseWriter, r *http.Request) {
	d := r.Context().Value(deviceKey{}).(store.Device)
	var req protocol.CheckinRequest
	if !decode(w, r, &req) {
		return
	}
	if err := h.Store.Q().RecordCheckin(r.Context(), d.ID, req.AgentVersion, h.Now()); err != nil {
		h.Log.Error("record checkin", "device_id", d.ID, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, protocol.CheckinResponse{IntervalSeconds: int(h.CheckinInterval / time.Second)})
}
```

`internal/server/app/app.go`:

```go
// Package app wires the server's components together.
package app

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"time"

	"retune/internal/config"
	"retune/internal/server/agentapi"
	"retune/internal/server/ca"
	"retune/internal/server/enroll"
	"retune/internal/server/store"
)

const clientCertValidity = 90 * 24 * time.Hour

// App is a fully wired server.
type App struct {
	Store     *store.Store
	CA        *ca.CA
	Enroll    *enroll.Service
	Handler   http.Handler
	TLSConfig *tls.Config
}

// New migrates the database, loads (or creates) the CA, and builds handlers.
func New(ctx context.Context, cfg config.Server, log *slog.Logger) (*App, error) {
	if err := store.Migrate(cfg.DatabaseURL); err != nil {
		return nil, err
	}
	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	authority, err := ca.LoadOrCreate(ctx, ca.FileKeyStore{Dir: filepath.Join(cfg.DataDir, "ca")}, time.Now())
	if err != nil {
		st.Close()
		return nil, err
	}
	serverCert, err := loadServerCert(cfg, authority)
	if err != nil {
		st.Close()
		return nil, err
	}

	svc := &enroll.Service{Store: st, CA: authority, Now: time.Now, CertValidity: clientCertValidity}
	h := &agentapi.Handler{Enroll: svc, Store: st, Now: time.Now, CheckinInterval: cfg.CheckinInterval, Log: log}
	return &App{
		Store:   st,
		CA:      authority,
		Enroll:  svc,
		Handler: h.Routes(),
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{serverCert},
			ClientAuth:   tls.VerifyClientCertIfGiven,
			ClientCAs:    authority.Pool(),
		},
	}, nil
}

// Close releases the database pool.
func (a *App) Close() { a.Store.Close() }

func loadServerCert(cfg config.Server, authority *ca.CA) (tls.Certificate, error) {
	switch cfg.TLSMode {
	case "self-signed":
		return authority.IssueServerCert(uniq(cfg.PublicHost(), "localhost", "127.0.0.1"), time.Now())
	case "provided":
		c, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("load TLS certificate: %w", err)
		}
		return c, nil
	default:
		return tls.Certificate{}, fmt.Errorf("unsupported TLS mode %q", cfg.TLSMode)
	}
}

func uniq(items ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range items {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go vet ./... && go test ./internal/server/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/server/agentapi internal/server/app
git commit -m "feat(server): agent API with mTLS device auth and app wiring"
```

---

### Task 7: Server CLI

**Files:**
- Create: `cmd/retune-server/main.go`, `cmd/retune-server/main_test.go`

**Interfaces:**
- Consumes: `config.LoadServer`, `app.New`, `store.Migrate`, `store.Open`, `enroll.Service.CreateToken`, `ca.LoadOrCreate`, `pki.Fingerprint`
- Produces: CLI `retune-server serve | migrate | token create [--label L] [--max-uses N] [--expires-in D] | ca fingerprint`. `token create` prints `Token ID: <uuid>` and `Token:    rt_...`. `ca fingerprint` prints `sha256:<hex>` of the CA in `$DATA_DIR/ca` (default `data`), creating the CA if absent.

- [ ] **Step 1: Write failing tests**

`cmd/retune-server/main_test.go`:

```go
package main

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"retune/internal/server/store/storetest"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestRun(t *testing.T) {
	ctx := context.Background()

	t.Run("unknown command", func(t *testing.T) {
		if err := run(ctx, []string{"bogus"}, env(nil), io.Discard); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("ca fingerprint is stable", func(t *testing.T) {
		e := env(map[string]string{"DATA_DIR": t.TempDir()})
		var a, b bytes.Buffer
		if err := run(ctx, []string{"ca", "fingerprint"}, e, &a); err != nil {
			t.Fatal(err)
		}
		if err := run(ctx, []string{"ca", "fingerprint"}, e, &b); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(a.String(), "sha256:") || a.String() != b.String() {
			t.Fatalf("fingerprints %q vs %q", a.String(), b.String())
		}
	})

	t.Run("migrate then token create", func(t *testing.T) {
		e := env(map[string]string{"DATABASE_URL": storetest.DatabaseURL(t)})
		if err := run(ctx, []string{"migrate"}, e, io.Discard); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := run(ctx, []string{"token", "create", "--label", "lab", "--max-uses", "5", "--expires-in", "24h"}, e, &out); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "Token:    rt_") {
			t.Fatalf("output = %q", out.String())
		}
		if err := run(ctx, []string{"token", "create", "--max-uses", "-1"}, e, io.Discard); err == nil {
			t.Fatal("negative max uses must fail")
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/retune-server/`
Expected: FAIL — `undefined: run`.

- [ ] **Step 3: Implement**

`cmd/retune-server/main.go`:

```go
// Command retune-server runs the Retune management server.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"retune/internal/config"
	"retune/internal/pki"
	"retune/internal/server/app"
	"retune/internal/server/ca"
	"retune/internal/server/enroll"
	"retune/internal/server/store"
)

const usage = `usage: retune-server <command>

commands:
  serve                  run the server
  migrate                apply database migrations
  token create [flags]   create an enrollment token (--label, --max-uses, --expires-in)
  ca fingerprint         print the internal CA fingerprint for agent pinning`

func main() {
	if err := run(context.Background(), os.Args[1:], os.Getenv, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, getenv func(string) string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	switch args[0] {
	case "serve":
		return serve(ctx, getenv)
	case "migrate":
		url := getenv("DATABASE_URL")
		if url == "" {
			return errors.New("DATABASE_URL is required")
		}
		return store.Migrate(url)
	case "token":
		return tokenCmd(ctx, args[1:], getenv, out)
	case "ca":
		return caCmd(ctx, args[1:], getenv, out)
	default:
		return fmt.Errorf("unknown command %q\n%s", args[0], usage)
	}
}

func serve(ctx context.Context, getenv func(string) string) error {
	cfg, err := config.LoadServer(getenv)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	a, err := app.New(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer a.Close()

	srv := &http.Server{
		Addr:              cfg.AgentListen,
		Handler:           a.Handler,
		TLSConfig:         a.TLSConfig,
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServeTLS("", "") }()
	log.Info("agent API listening", "addr", cfg.AgentListen, "public_url", cfg.PublicURL,
		"ca_fingerprint", pki.Fingerprint(a.CA.Cert().Raw))

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

func tokenCmd(ctx context.Context, args []string, getenv func(string) string, out io.Writer) error {
	if len(args) == 0 || args[0] != "create" {
		return errors.New("usage: retune-server token create [--label L] [--max-uses N] [--expires-in 168h]")
	}
	fs := flag.NewFlagSet("token create", flag.ContinueOnError)
	label := fs.String("label", "", "label shown in the console")
	maxUses := fs.Int("max-uses", 0, "maximum enrollments (0 = unlimited)")
	expiresIn := fs.Duration("expires-in", 0, "lifetime, e.g. 168h (0 = never)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *maxUses < 0 || *expiresIn < 0 {
		return errors.New("--max-uses and --expires-in must not be negative")
	}
	url := getenv("DATABASE_URL")
	if url == "" {
		return errors.New("DATABASE_URL is required")
	}
	st, err := store.Open(ctx, url)
	if err != nil {
		return err
	}
	defer st.Close()

	opts := enroll.TokenOptions{Label: *label, CreatedBy: "cli"}
	if *maxUses > 0 {
		opts.MaxUses = maxUses
	}
	if *expiresIn > 0 {
		exp := time.Now().Add(*expiresIn)
		opts.ExpiresAt = &exp
	}
	svc := &enroll.Service{Store: st, Now: time.Now}
	plain, tok, err := svc.CreateToken(ctx, opts)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Token ID: %s\nToken:    %s\n(The token is shown only once.)\n", tok.ID, plain)
	return nil
}

func caCmd(ctx context.Context, args []string, getenv func(string) string, out io.Writer) error {
	if len(args) != 1 || args[0] != "fingerprint" {
		return errors.New("usage: retune-server ca fingerprint")
	}
	dir := getenv("DATA_DIR")
	if dir == "" {
		dir = "data"
	}
	authority, err := ca.LoadOrCreate(ctx, ca.FileKeyStore{Dir: filepath.Join(dir, "ca")}, time.Now())
	if err != nil {
		return err
	}
	fmt.Fprintln(out, pki.Fingerprint(authority.Cert().Raw))
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go vet ./... && go test ./cmd/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/retune-server
git commit -m "feat(server): CLI with serve, migrate, token create, ca fingerprint"
```

---

### Task 8: Agent identity and pinning client

**Files:**
- Create: `internal/agent/identity/identity.go`, `internal/agent/identity/keys.go`, `internal/agent/identity/keys_windows.go`, `internal/agent/identity/keys_other.go`, `internal/agent/identity/identity_test.go`, `internal/agent/identity/keys_windows_test.go`, `internal/agent/client/client.go`, `internal/agent/client/client_test.go`

**Interfaces:**
- Consumes: `pki.Fingerprint`, `protocol` types
- Produces:
  - `identity.KeyProvider` interface `{ Protect([]byte) ([]byte, error); Unprotect([]byte) ([]byte, error) }`, `identity.PlainKeys{}`, `identity.DPAPIKeys{}` (Windows only), `identity.DefaultKeys() KeyProvider`
  - `identity.Identity{DeviceID, ServerURL, ServerPin, CertPEM, CAPEM string; Key *ecdsa.PrivateKey}`, `(*Identity).TLSCertificate() (tls.Certificate, error)`
  - `identity.Store{Dir string; Keys KeyProvider}`, `(Store).Save(*Identity) error`, `(Store).Load() (*Identity, error)`, `identity.ErrNotEnrolled`
  - `identity.NewKeyAndCSR(hostname string) (*ecdsa.PrivateKey, string /*CSR PEM*/, error)`
  - `client.New(serverURL, pin string, clientCert *tls.Certificate) (*client.Client, error)`, `(*Client).Enroll(ctx, protocol.EnrollRequest) (protocol.EnrollResponse, error)`, `(*Client).Checkin(ctx, protocol.CheckinRequest) (protocol.CheckinResponse, error)`
  - `client.HTTPError{Status int; Code, Message string}` with `Error() string`, `Retryable() bool` (5xx or 429)

- [ ] **Step 1: Write failing tests**

`internal/agent/identity/identity_test.go`:

```go
package identity

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// xorKeys is a fake KeyProvider that proves Save seals the key.
type xorKeys struct{}

func (xorKeys) Protect(b []byte) ([]byte, error)   { return xor(b), nil }
func (xorKeys) Unprotect(b []byte) ([]byte, error) { return xor(b), nil }
func xor(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[i] ^ 0x5a
	}
	return out
}

func TestNewKeyAndCSR(t *testing.T) {
	key, csrPEM, err := NewKeyAndCSR("PC-1")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode([]byte(csrPEM))
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "PC-1" || csr.CheckSignature() != nil || !key.PublicKey.Equal(csr.PublicKey) {
		t.Fatal("CSR does not match key/hostname")
	}
}

func TestStoreRoundTrip(t *testing.T) {
	s := Store{Dir: t.TempDir(), Keys: xorKeys{}}
	if _, err := s.Load(); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("Load on empty dir = %v, want ErrNotEnrolled", err)
	}
	key, _, err := NewKeyAndCSR("PC-1")
	if err != nil {
		t.Fatal(err)
	}
	id := &Identity{DeviceID: "d1", ServerURL: "https://mdm", ServerPin: "sha256:ab", CertPEM: "cert", CAPEM: "ca", Key: key}
	if err := s.Save(id); err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalECPrivateKey(key)
	onDisk, err := os.ReadFile(filepath.Join(s.Dir, "key.bin"))
	if err != nil || bytes.Equal(onDisk, der) {
		t.Fatal("key.bin must hold the sealed key, not raw DER")
	}
	got, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.DeviceID != "d1" || got.ServerURL != "https://mdm" || got.ServerPin != "sha256:ab" || got.CertPEM != "cert" || got.CAPEM != "ca" || !got.Key.Equal(key) {
		t.Fatalf("loaded identity = %+v", got)
	}
}
```

`internal/agent/identity/keys_windows_test.go`:

```go
//go:build windows

package identity

import (
	"bytes"
	"testing"
)

func TestDPAPIRoundTrip(t *testing.T) {
	plain := []byte("secret key material")
	sealed, err := DPAPIKeys{}.Protect(plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, plain) {
		t.Fatal("sealed data contains plaintext")
	}
	got, err := DPAPIKeys{}.Unprotect(sealed)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("Unprotect = %q, %v", got, err)
	}
}
```

`internal/agent/client/client_test.go`:

```go
package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"retune/internal/pki"
	"retune/internal/protocol"
)

func newServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/agent/v1/checkin" {
			_ = json.NewEncoder(w).Encode(protocol.CheckinResponse{IntervalSeconds: 60})
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(protocol.Error{Code: "enrollment_token_invalid", Message: "nope"})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestPinnedClient(t *testing.T) {
	ctx := context.Background()
	srv := newServer(t)
	pin := pki.Fingerprint(srv.Certificate().Raw)

	for _, p := range []string{pin, strings.ToUpper(pin)} {
		c, err := New(srv.URL, p, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := c.Checkin(ctx, protocol.CheckinRequest{})
		if err != nil || resp.IntervalSeconds != 60 {
			t.Fatalf("pin %s: resp=%+v err=%v", p, resp, err)
		}
	}

	c, _ := New(srv.URL, "sha256:"+strings.Repeat("0", 64), nil)
	_, err := c.Checkin(ctx, protocol.CheckinRequest{})
	var he *HTTPError
	if err == nil || errors.As(err, &he) {
		t.Fatalf("wrong pin must fail at TLS, got %v", err)
	}

	c, _ = New(srv.URL, "", nil)
	if _, err := c.Checkin(ctx, protocol.CheckinRequest{}); err == nil {
		t.Fatal("unpinned client must not trust a self-signed server")
	}
}

func TestHTTPError(t *testing.T) {
	srv := newServer(t)
	c, _ := New(srv.URL, pki.Fingerprint(srv.Certificate().Raw), nil)
	_, err := c.Enroll(context.Background(), protocol.EnrollRequest{})
	var he *HTTPError
	if !errors.As(err, &he) || he.Status != 403 || he.Code != "enrollment_token_invalid" || he.Retryable() {
		t.Fatalf("err = %#v", err)
	}
	for status, want := range map[int]bool{500: true, 503: true, 429: true, 400: false, 401: false} {
		if got := (&HTTPError{Status: status}).Retryable(); got != want {
			t.Errorf("Retryable(%d) = %v", status, got)
		}
	}
}

func TestNewRejectsHTTP(t *testing.T) {
	if _, err := New("http://mdm.example.com", "", nil); err == nil {
		t.Fatal("http URLs must be rejected")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/agent/...`
Expected: FAIL — `undefined: NewKeyAndCSR`, `undefined: New`.

- [ ] **Step 3: Implement identity**

`internal/agent/identity/keys.go`:

```go
package identity

// KeyProvider seals the agent's private key at rest.
type KeyProvider interface {
	Protect(plain []byte) ([]byte, error)
	Unprotect(sealed []byte) ([]byte, error)
}

// PlainKeys stores keys unsealed. Use only in tests and non-Windows dev builds.
type PlainKeys struct{}

func (PlainKeys) Protect(b []byte) ([]byte, error)   { return b, nil }
func (PlainKeys) Unprotect(b []byte) ([]byte, error) { return b, nil }
```

`internal/agent/identity/keys_windows.go`:

```go
//go:build windows

package identity

import (
	"bytes"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// DPAPIKeys seals data with DPAPI in machine scope, so only processes on
// this machine can unseal it; file ACLs restrict it further to SYSTEM.
type DPAPIKeys struct{}

// DefaultKeys returns the platform key provider.
func DefaultKeys() KeyProvider { return DPAPIKeys{} }

func (DPAPIKeys) Protect(plain []byte) ([]byte, error) {
	var out windows.DataBlob
	flags := uint32(windows.CRYPTPROTECT_LOCAL_MACHINE | windows.CRYPTPROTECT_UI_FORBIDDEN)
	if err := windows.CryptProtectData(blob(plain), nil, nil, 0, nil, flags, &out); err != nil {
		return nil, fmt.Errorf("CryptProtectData: %w", err)
	}
	return takeBlob(&out), nil
}

func (DPAPIKeys) Unprotect(sealed []byte) ([]byte, error) {
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(blob(sealed), nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, fmt.Errorf("CryptUnprotectData: %w", err)
	}
	return takeBlob(&out), nil
}

func blob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

// takeBlob copies a DPAPI-allocated buffer into Go memory and frees it.
func takeBlob(b *windows.DataBlob) []byte {
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(b.Data)))
	return bytes.Clone(unsafe.Slice(b.Data, b.Size))
}
```

`internal/agent/identity/keys_other.go`:

```go
//go:build !windows

package identity

// DefaultKeys returns the platform key provider. Non-Windows builds are
// development-only until the macOS/Linux agents ship.
func DefaultKeys() KeyProvider { return PlainKeys{} }
```

`internal/agent/identity/identity.go`:

```go
// Package identity stores the agent's enrolled device identity on disk.
package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// ErrNotEnrolled is returned by Load when no identity exists.
var ErrNotEnrolled = errors.New("agent is not enrolled")

// Identity is everything the agent needs to talk to its server.
type Identity struct {
	DeviceID  string            `json:"device_id"`
	ServerURL string            `json:"server_url"`
	ServerPin string            `json:"server_pin,omitempty"`
	CertPEM   string            `json:"cert_pem"`
	CAPEM     string            `json:"ca_pem"`
	Key       *ecdsa.PrivateKey `json:"-"`
}

// TLSCertificate returns the client certificate for mTLS.
func (id *Identity) TLSCertificate() (tls.Certificate, error) {
	b, _ := pem.Decode([]byte(id.CertPEM))
	if b == nil || b.Type != "CERTIFICATE" {
		return tls.Certificate{}, errors.New("identity certificate is not PEM CERTIFICATE")
	}
	return tls.Certificate{Certificate: [][]byte{b.Bytes}, PrivateKey: id.Key}, nil
}

// Store persists an Identity as identity.json plus a sealed key.bin.
type Store struct {
	Dir  string
	Keys KeyProvider
}

func (s Store) Save(id *Identity) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	der, err := x509.MarshalECPrivateKey(id.Key)
	if err != nil {
		return err
	}
	sealed, err := s.Keys.Protect(der)
	if err != nil {
		return err
	}
	meta, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(s.Dir, "key.bin"), sealed); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(s.Dir, "identity.json"), meta)
}

func (s Store) Load() (*Identity, error) {
	meta, err := os.ReadFile(filepath.Join(s.Dir, "identity.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotEnrolled
	}
	if err != nil {
		return nil, err
	}
	var id Identity
	if err := json.Unmarshal(meta, &id); err != nil {
		return nil, fmt.Errorf("parse identity.json: %w", err)
	}
	sealed, err := os.ReadFile(filepath.Join(s.Dir, "key.bin"))
	if err != nil {
		return nil, err
	}
	der, err := s.Keys.Unprotect(sealed)
	if err != nil {
		return nil, err
	}
	if id.Key, err = x509.ParseECPrivateKey(der); err != nil {
		return nil, fmt.Errorf("parse device key: %w", err)
	}
	return &id, nil
}

// NewKeyAndCSR generates the device keypair and a CSR for enrollment.
func NewKeyAndCSR(hostname string) (*ecdsa.PrivateKey, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: hostname}}, key)
	if err != nil {
		return nil, "", err
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
```

- [ ] **Step 4: Implement the client**

`internal/agent/client/client.go`:

```go
// Package client is the agent's HTTP client for the Retune server.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"retune/internal/pki"
	"retune/internal/protocol"
)

// HTTPError is a non-2xx response from the server.
type HTTPError struct {
	Status  int
	Code    string
	Message string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("server returned %d %s: %s", e.Status, e.Code, e.Message)
}

// Retryable reports whether the request may succeed if retried later.
func (e *HTTPError) Retryable() bool {
	return e.Status >= 500 || e.Status == http.StatusTooManyRequests
}

// Client calls the agent API.
type Client struct {
	base string
	http *http.Client
}

// New builds a client. If pin is set ("sha256:<hex>"), the server chain must
// contain a certificate with that fingerprint; otherwise system roots are
// used. clientCert enables mTLS.
func New(serverURL, pin string, clientCert *tls.Certificate) (*Client, error) {
	u, err := url.Parse(serverURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return nil, fmt.Errorf("server URL must be https, got %q", serverURL)
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if pin != "" {
		// Standard verification is replaced (not skipped) by verifyPinned.
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = verifyPinned(pin, u.Hostname())
	}
	if clientCert != nil {
		cfg.Certificates = []tls.Certificate{*clientCert}
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = cfg
	return &Client{
		base: strings.TrimRight(serverURL, "/"),
		http: &http.Client{Transport: tr, Timeout: 60 * time.Second},
	}, nil
}

func (c *Client) Enroll(ctx context.Context, req protocol.EnrollRequest) (protocol.EnrollResponse, error) {
	var resp protocol.EnrollResponse
	err := c.post(ctx, "/api/agent/v1/enroll", req, &resp)
	return resp, err
}

func (c *Client) Checkin(ctx context.Context, req protocol.CheckinRequest) (protocol.CheckinResponse, error) {
	var resp protocol.CheckinResponse
	err := c.post(ctx, "/api/agent/v1/checkin", req, &resp)
	return resp, err
}

func (c *Client) post(ctx context.Context, path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", path, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		var e protocol.Error
		_ = json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&e)
		return &HTTPError{Status: res.StatusCode, Code: e.Code, Message: e.Message}
	}
	if err := json.NewDecoder(res.Body).Decode(out); err != nil {
		return fmt.Errorf("decode %s response: %w", path, err)
	}
	return nil
}

// verifyPinned trusts the presented chain only if one of its certificates
// matches pin, and the leaf verifies for host against that certificate.
func verifyPinned(pin, host string) func([][]byte, [][]*x509.Certificate) error {
	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) == 0 {
			return errors.New("server presented no certificate")
		}
		roots, inter := x509.NewCertPool(), x509.NewCertPool()
		var leaf *x509.Certificate
		found := false
		for i, r := range raw {
			c, err := x509.ParseCertificate(r)
			if err != nil {
				return fmt.Errorf("parse server certificate: %w", err)
			}
			if i == 0 {
				leaf = c
			}
			if strings.EqualFold(pki.Fingerprint(c.Raw), pin) {
				roots.AddCert(c)
				found = true
			} else {
				inter.AddCert(c)
			}
		}
		if !found {
			return fmt.Errorf("server certificate chain does not match pinned fingerprint %s", pin)
		}
		_, err := leaf.Verify(x509.VerifyOptions{
			DNSName:       host,
			Roots:         roots,
			Intermediates: inter,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		return err
	}
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go mod tidy && go vet ./... && go test ./internal/agent/...`
Expected: PASS (on Windows, `TestDPAPIRoundTrip` runs too).

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/agent/identity internal/agent/client
git commit -m "feat(agent): DPAPI-sealed identity store and pinning HTTP client"
```

---

### Task 9: Check-in loop

**Files:**
- Create: `internal/agent/checkin/loop.go`, `internal/agent/checkin/loop_test.go`

**Interfaces:**
- Consumes: `client.HTTPError` (Task 8), `protocol.CheckinRequest/Response`
- Produces:
  - `checkin.Checker` interface `{ Checkin(ctx, protocol.CheckinRequest) (protocol.CheckinResponse, error) }` (satisfied by `*client.Client`)
  - `checkin.Loop{Client Checker; Facts func() protocol.CheckinRequest; Log *slog.Logger; Rand func() float64}`
  - `(*Loop).RunOnce(ctx) (wait time.Duration, err error)`, `(*Loop).Run(ctx)` (returns when ctx is done)
  - `checkin.Jitter(d time.Duration, r float64) time.Duration`, `checkin.Backoff(failures int) time.Duration`, `checkin.DefaultInterval`

- [ ] **Step 1: Write failing tests**

`internal/agent/checkin/loop_test.go`:

```go
package checkin

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"retune/internal/agent/client"
	"retune/internal/protocol"
)

type step struct {
	resp  protocol.CheckinResponse
	err   error
	panic bool
}

type fakeChecker struct {
	steps []step
	calls int
}

func (f *fakeChecker) Checkin(context.Context, protocol.CheckinRequest) (protocol.CheckinResponse, error) {
	s := f.steps[f.calls]
	f.calls++
	if s.panic {
		panic("boom")
	}
	return s.resp, s.err
}

func newLoop(c Checker) *Loop {
	return &Loop{
		Client: c,
		Facts:  func() protocol.CheckinRequest { return protocol.CheckinRequest{} },
		Log:    slog.New(slog.DiscardHandler),
		Rand:   func() float64 { return 0.5 }, // Jitter(d, 0.5) == d
	}
}

func TestJitter(t *testing.T) {
	if got := Jitter(100*time.Second, 0); got != 80*time.Second {
		t.Errorf("Jitter(100s, 0) = %s", got)
	}
	if got := Jitter(100*time.Second, 0.5); got != 100*time.Second {
		t.Errorf("Jitter(100s, 0.5) = %s", got)
	}
	if got := Jitter(100*time.Second, 0.9999); got >= 120*time.Second {
		t.Errorf("Jitter(100s, ~1) = %s, want < 120s", got)
	}
}

func TestBackoff(t *testing.T) {
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute, 30 * time.Minute, 30 * time.Minute}
	for i, w := range want {
		if got := Backoff(i + 1); got != w {
			t.Errorf("Backoff(%d) = %s, want %s", i+1, got, w)
		}
	}
}

func TestRunOnce(t *testing.T) {
	ctx := context.Background()
	netErr := errors.New("connection refused")
	f := &fakeChecker{steps: []step{
		{resp: protocol.CheckinResponse{IntervalSeconds: 120}},
		{err: netErr},
		{err: &client.HTTPError{Status: 503}},
		{resp: protocol.CheckinResponse{}},
		{err: &client.HTTPError{Status: 401, Code: "device_not_active"}},
		{panic: true},
	}}
	l := newLoop(f)
	expect := []struct {
		wait    time.Duration
		wantErr bool
	}{
		{120 * time.Second, false}, // server interval
		{30 * time.Second, true},   // first failure
		{time.Minute, true},        // second failure
		{120 * time.Second, false}, // success resets failures, keeps last interval
		{24 * time.Hour, true},     // revoked
		{30 * time.Second, true},   // panic recovered, counted as failure
	}
	for i, e := range expect {
		wait, err := l.RunOnce(ctx)
		if wait != e.wait || (err != nil) != e.wantErr {
			t.Fatalf("call %d: wait=%s err=%v, want wait=%s wantErr=%v", i, wait, err, e.wait, e.wantErr)
		}
	}
}

func TestRunOnceDefaultInterval(t *testing.T) {
	l := newLoop(&fakeChecker{steps: []step{{resp: protocol.CheckinResponse{}}}})
	if wait, err := l.RunOnce(context.Background()); err != nil || wait != DefaultInterval {
		t.Fatalf("wait=%s err=%v", wait, err)
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	f := &fakeChecker{steps: []step{{resp: protocol.CheckinResponse{IntervalSeconds: 3600}}}}
	done := make(chan struct{})
	go func() { newLoop(f).Run(ctx); close(done) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/agent/checkin/`
Expected: FAIL — `undefined: Loop`.

- [ ] **Step 3: Implement**

`internal/agent/checkin/loop.go`:

```go
// Package checkin runs the agent's periodic check-in loop.
package checkin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"retune/internal/agent/client"
	"retune/internal/protocol"
)

const (
	DefaultInterval = 5 * time.Minute
	firstBackoff    = 30 * time.Second
	maxBackoff      = 30 * time.Minute
	revokedRetry    = 24 * time.Hour
)

// Checker is the part of the client the loop needs.
type Checker interface {
	Checkin(ctx context.Context, req protocol.CheckinRequest) (protocol.CheckinResponse, error)
}

// Loop checks in periodically. It never exits on errors.
type Loop struct {
	Client Checker
	Facts  func() protocol.CheckinRequest
	Log    *slog.Logger
	Rand   func() float64 // uniform in [0, 1)

	interval time.Duration
	failures int
}

// Run checks in until ctx is cancelled.
func (l *Loop) Run(ctx context.Context) {
	for {
		wait, _ := l.RunOnce(ctx)
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// RunOnce performs one check-in and returns how long to wait before the next.
// Errors are logged and returned for callers that want them (e.g. --once).
func (l *Loop) RunOnce(ctx context.Context) (wait time.Duration, err error) {
	if l.interval == 0 {
		l.interval = DefaultInterval
	}
	defer func() {
		if r := recover(); r != nil {
			l.failures++
			l.Log.Error("check-in panicked", "panic", r)
			wait, err = Backoff(l.failures), fmt.Errorf("check-in panicked: %v", r)
		}
	}()

	resp, err := l.Client.Checkin(ctx, l.Facts())
	var httpErr *client.HTTPError
	switch {
	case err == nil:
		l.failures = 0
		if resp.IntervalSeconds > 0 {
			l.interval = time.Duration(resp.IntervalSeconds) * time.Second
		}
		return Jitter(l.interval, l.Rand()), nil
	case errors.As(err, &httpErr) && httpErr.Status == http.StatusUnauthorized:
		l.Log.Error("server rejected this device's identity; it may be retired or replaced", "error", err)
		return revokedRetry, err
	default:
		l.failures++
		l.Log.Warn("check-in failed", "error", err, "consecutive_failures", l.failures)
		return Backoff(l.failures), err
	}
}

// Jitter spreads d by ±20%: r=0 → 0.8d, r=0.5 → d, r→1 → 1.2d.
func Jitter(d time.Duration, r float64) time.Duration {
	return time.Duration(float64(d) * (0.8 + 0.4*r))
}

// Backoff is 30s doubled per consecutive failure, capped at 30 minutes.
func Backoff(failures int) time.Duration {
	d := firstBackoff
	for i := 1; i < failures && d < maxBackoff; i++ {
		d *= 2
	}
	return min(d, maxBackoff)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go vet ./... && go test ./internal/agent/checkin/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/agent/checkin
git commit -m "feat(agent): jittered check-in loop with backoff and panic recovery"
```

---

### Task 10: Agent enrollment, agent CLI, end-to-end test

**Files:**
- Create: `internal/agent/enrollment/enrollment.go`, `internal/agent/facts/facts.go`, `internal/agent/facts/facts_windows.go`, `internal/agent/facts/facts_other.go`, `cmd/retune-agent/main.go`, `test/e2e/e2e_test.go`

**Interfaces:**
- Consumes: everything above
- Produces:
  - `enrollment.Options{ServerURL, Token, Pin string; Facts protocol.DeviceFacts; Store identity.Store}`, `enrollment.Enroll(ctx, Options) (*identity.Identity, error)`, `enrollment.ErrAlreadyEnrolled`, `enrollment.Connect(*identity.Identity) (*client.Client, error)`
  - `facts.AgentVersion`, `facts.Device() protocol.DeviceFacts`, `facts.Checkin() protocol.CheckinRequest`
  - CLI `retune-agent enroll --server URL --token T [--pin sha256:...] [--data-dir D]`, `retune-agent run [--data-dir D] [--once]`

- [ ] **Step 1: Write the failing end-to-end test**

`test/e2e/e2e_test.go`:

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./test/e2e/`
Expected: FAIL — package `retune/internal/agent/enrollment` not found.

- [ ] **Step 3: Implement enrollment and facts**

`internal/agent/enrollment/enrollment.go`:

```go
// Package enrollment enrolls the agent and builds its authenticated client.
package enrollment

import (
	"context"
	"errors"
	"fmt"

	"retune/internal/agent/client"
	"retune/internal/agent/identity"
	"retune/internal/protocol"
)

// ErrAlreadyEnrolled is returned when an identity already exists.
var ErrAlreadyEnrolled = errors.New("agent is already enrolled; unenroll first")

// Options configure enrollment.
type Options struct {
	ServerURL string
	Token     string
	Pin       string
	Facts     protocol.DeviceFacts
	Store     identity.Store
}

// Enroll generates a keypair, enrolls with the server, and saves the identity.
func Enroll(ctx context.Context, o Options) (*identity.Identity, error) {
	if _, err := o.Store.Load(); err == nil {
		return nil, ErrAlreadyEnrolled
	} else if !errors.Is(err, identity.ErrNotEnrolled) {
		return nil, err
	}
	key, csrPEM, err := identity.NewKeyAndCSR(o.Facts.Hostname)
	if err != nil {
		return nil, err
	}
	c, err := client.New(o.ServerURL, o.Pin, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Enroll(ctx, protocol.EnrollRequest{Token: o.Token, CSRPEM: csrPEM, Device: o.Facts})
	if err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	id := &identity.Identity{
		DeviceID:  resp.DeviceID,
		ServerURL: o.ServerURL,
		ServerPin: o.Pin,
		CertPEM:   resp.CertPEM,
		CAPEM:     resp.CAPEM,
		Key:       key,
	}
	if err := o.Store.Save(id); err != nil {
		return nil, fmt.Errorf("save identity: %w", err)
	}
	return id, nil
}

// Connect returns an mTLS client for an enrolled identity.
func Connect(id *identity.Identity) (*client.Client, error) {
	cert, err := id.TLSCertificate()
	if err != nil {
		return nil, err
	}
	return client.New(id.ServerURL, id.ServerPin, &cert)
}
```

`internal/agent/facts/facts.go`:

```go
// Package facts collects the lightweight device facts sent at enrollment
// and check-in. Full inventory arrives in M2.
package facts

import (
	"net"
	"os"

	"retune/internal/protocol"
)

// AgentVersion is reported on every check-in.
const AgentVersion = "0.1.0-dev"

// Device returns facts for enrollment. Serial and SMBIOS UUID are filled in
// by the M2 inventory collector.
func Device() protocol.DeviceFacts {
	host, _ := os.Hostname()
	return protocol.DeviceFacts{Hostname: host, OSVersion: osVersion()}
}

// Checkin returns the heartbeat payload.
func Checkin() protocol.CheckinRequest {
	return protocol.CheckinRequest{
		AgentVersion:  AgentVersion,
		UptimeSeconds: uptimeSeconds(),
		IPAddresses:   ipAddresses(),
	}
}

func ipAddresses() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() && !ipn.IP.IsLinkLocalUnicast() {
			out = append(out, ipn.IP.String())
		}
	}
	return out
}
```

`internal/agent/facts/facts_windows.go`:

```go
//go:build windows

package facts

import (
	"fmt"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func osVersion() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return "Windows"
	}
	defer k.Close()
	name, _, _ := k.GetStringValue("ProductName")
	build, _, _ := k.GetStringValue("CurrentBuild")
	return fmt.Sprintf("%s (build %s)", name, build)
}

func uptimeSeconds() int64 {
	return int64(windows.GetTickCount64() / 1000)
}
```

`internal/agent/facts/facts_other.go`:

```go
//go:build !windows

package facts

import "runtime"

func osVersion() string    { return runtime.GOOS }
func uptimeSeconds() int64 { return 0 }
```

- [ ] **Step 4: Run the end-to-end test**

Run: `go vet ./... && go test ./test/e2e/`
Expected: PASS.

- [ ] **Step 5: Implement the agent CLI**

`cmd/retune-agent/main.go`:

```go
// Command retune-agent is the Retune endpoint agent.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"retune/internal/agent/checkin"
	"retune/internal/agent/enrollment"
	"retune/internal/agent/facts"
	"retune/internal/agent/identity"
)

const usage = `usage: retune-agent <command>

commands:
  enroll --server URL --token T [--pin sha256:...] [--data-dir D]
  run [--data-dir D] [--once]`

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	dataDir := fs.String("data-dir", defaultDataDir(), "agent state directory")
	switch args[0] {
	case "enroll":
		server := fs.String("server", "", "server URL, e.g. https://mdm.example.com")
		token := fs.String("token", "", "enrollment token")
		pin := fs.String("pin", "", "server CA fingerprint (sha256:...) for self-signed servers")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *server == "" || *token == "" {
			return errors.New("--server and --token are required")
		}
		id, err := enrollment.Enroll(ctx, enrollment.Options{
			ServerURL: *server, Token: *token, Pin: *pin, Facts: facts.Device(),
			Store: identity.Store{Dir: *dataDir, Keys: identity.DefaultKeys()},
		})
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Enrolled as device %s\n", id.DeviceID)
		return nil

	case "run":
		once := fs.Bool("once", false, "check in once and exit")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		id, err := identity.Store{Dir: *dataDir, Keys: identity.DefaultKeys()}.Load()
		if err != nil {
			return err
		}
		c, err := enrollment.Connect(id)
		if err != nil {
			return err
		}
		loop := &checkin.Loop{
			Client: c,
			Facts:  facts.Checkin,
			Log:    slog.New(slog.NewTextHandler(os.Stderr, nil)),
			Rand:   rand.Float64,
		}
		if *once {
			wait, err := loop.RunOnce(ctx)
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "Check-in OK; next in %s\n", wait.Round(time.Second))
			return nil
		}
		ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer stop()
		loop.Run(ctx)
		return nil

	default:
		return fmt.Errorf("unknown command %q\n%s", args[0], usage)
	}
}

func defaultDataDir() string {
	if runtime.GOOS == "windows" {
		if pd := os.Getenv("ProgramData"); pd != "" {
			return filepath.Join(pd, "Retune")
		}
		return `C:\ProgramData\Retune`
	}
	return "/var/lib/retune"
}
```

- [ ] **Step 6: Full verification**

Run: `go vet ./... && go test ./... && go build ./cmd/...`
Expected: all PASS, both binaries build.

- [ ] **Step 7: Manual smoke test (PowerShell)**

```powershell
docker run -d --name retune-pg -e POSTGRES_USER=retune -e POSTGRES_PASSWORD=retune -e POSTGRES_DB=retune -p 5432:5432 postgres:17-alpine
$env:DATABASE_URL = "postgres://retune:retune@localhost:5432/retune?sslmode=disable"
$env:PUBLIC_URL = "https://localhost:8443"
$env:DATA_DIR = ".\data"
go run ./cmd/retune-server migrate
go run ./cmd/retune-server token create --label smoke --max-uses 1
go run ./cmd/retune-server ca fingerprint
# in a second terminal with the same env vars:
go run ./cmd/retune-server serve
# back in the first terminal:
go run ./cmd/retune-agent enroll --server https://localhost:8443 --token <TOKEN> --pin <FINGERPRINT> --data-dir .\agent-data
go run ./cmd/retune-agent run --once --data-dir .\agent-data
```

Expected: `Enrolled as device <uuid>` then `Check-in OK; next in ~5m0s`. Clean up with `docker rm -f retune-pg`.

- [ ] **Step 8: Commit**

```bash
git add internal/agent/enrollment internal/agent/facts cmd/retune-agent test/e2e go.mod go.sum
git commit -m "feat(agent): enrollment, CLI, and end-to-end enroll/check-in test"
```
