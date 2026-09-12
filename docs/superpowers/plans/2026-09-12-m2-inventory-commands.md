# M2: Inventory, Commands, Renewal, Unenroll Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enrolled devices report full inventory, run ad-hoc commands with results that survive an offline period, renew their client certificate before it expires, and wipe themselves when unenrolled.

**Architecture:** The server gains three services (`inventory`, `commands`, `devices`) plus a renewal path on `enroll`, all exposed through new `/api/agent/v1` endpoints and a `retune-server device|command` CLI. The agent gains a bbolt state store (queued results, a command ledger, the last inventory hash), a WMI/registry inventory collector, a PowerShell executor behind a `Runner` interface, and a `session` type that implements the existing `checkin.Checker` so one check-in renews, flushes, uploads and dispatches.

**Tech Stack:** Go 1.27, PostgreSQL 17, `go.etcd.io/bbolt`, `github.com/yusufpapurcu/wmi`, `golang.org/x/sys/windows/registry`, existing M1 packages.

**Spec:** `docs/superpowers/specs/2026-09-12-core-platform-design.md` (roadmap: `docs/superpowers/plans/2026-09-12-roadmap.md`; M1 plan: `docs/superpowers/plans/2026-09-12-m1-enroll-checkin.md`)

## Global Constraints

- Module path `retune`, Go toolchain 1.27; every table keeps `tenant_id`; IDs are UUIDv7; timestamps `timestamptz`.
- API errors stay JSON `{"code": "...", "message": "..."}`; agent endpoints stay under `/api/agent/v1/`.
- Command types: `run_powershell` (script, timeout), `restart` (delay, message), `refresh_inventory`. Ad-hoc scripts run as SYSTEM; `run_as: logged_in_user` is deferred to M6.
- Command lifecycle: `queued → delivered → running → succeeded | failed | timed_out | expired`; default TTL 7 days; default script timeout 10 minutes, maximum 24 hours.
- `stdout` and `stderr` are capped at 1 MiB each (`protocol.MaxOutputBytes`), with a truncation flag; the server strips NUL bytes and invalid UTF-8 before storing.
- Result delivery is idempotent: the agent records completed command IDs locally and never re-runs one; re-submitting a completed result is a success.
- Full inventory at enrollment, every 24 hours, and on `refresh_inventory`. The server rewrites `device_software` only when the software hash changes.
- Client certificates renew when fewer than 30 days remain. The certificate presented during renewal stays valid until the new one is used, then is cleared.
- Unenroll is a device status (`unenrolled`) answered with `410`; the agent then deletes its identity and state. Uninstalling the service arrives with the MSI in M4.
- Agent state lives in `<data-dir>/state.db` (bbolt); the identity is a single `identity.json` holding the sealed key.
- Postgres tests use testcontainers and need Docker; they skip under `go test -short`. Every task ends with `go vet ./...` and `go test ./...` passing.

## File Structure

```
internal/protocol/
  v1.go                  MODIFY: CheckinResponse gains InventoryDue + Commands
  commands.go            NEW: command, payload, result, renew types + caps
  inventory.go           NEW: inventory document + InventoryHash/SoftwareHash
internal/server/
  store/migrations/0002_inventory_commands.{up,down}.sql   NEW
  store/models.go        MODIFY: Device gains PrevCertSerial/OSBuild/Manufacturer/Model
  store/devices.go       MODIFY: new columns, ListDevices, hardware + cert updates
  store/inventory.go     NEW: inventory + software queries
  store/commands.go      NEW: command + result queries and statuses
  store/store.go         MODIFY: DBTX gains CopyFrom
  inventory/service.go   NEW: Due + Ingest
  commands/service.go    NEW: Queue, Deliver, Start, Complete, Get
  devices/service.go     NEW: Retire, Unenroll
  enroll/renew.go        NEW: (*Service).Renew
  agentapi/handler.go    MODIFY: new routes, 410 on unenrolled, prev-serial auth
  agentapi/json.go       MODIFY: per-route body limits, 413, 204 helper
  app/app.go             MODIFY: wire the three services
cmd/retune-server/
  main.go                MODIFY: device + command commands, openStore helper
  devices.go             NEW: device list|show|retire|unenroll
  commands.go            NEW: command queue|show
internal/agent/
  state/state.go         NEW: bbolt results queue, ledger, inventory meta
  identity/identity.go   MODIFY: single-file identity, Delete, CertNotAfter
  client/client.go       MODIFY: do(), PutInventory, StartCommand, SubmitResult, Renew
  executor/              NEW: executor.go, capped.go, runner_windows.go, runner_other.go
  inventory/             NEW: collector.go, software.go, collector_windows.go, collector_other.go
  facts/facts.go         MODIFY: real serial/UUID and logged-in user
  checkin/loop.go        MODIFY: ErrUnenrolled stops the loop; Run returns error
  session/session.go     NEW: the per-cycle orchestration
cmd/retune-agent/main.go MODIFY: build state + collector + executor + session
test/e2e/m2_test.go      NEW: inventory, commands, offline queue, renewal, unenroll
```

---

### Task 1: Protocol types and inventory hashing

**Files:**
- Modify: `internal/protocol/v1.go` (CheckinResponse)
- Create: `internal/protocol/commands.go`, `internal/protocol/inventory.go`, `internal/protocol/inventory_test.go`

**Interfaces:**
- Consumes: nothing (leaf package)
- Produces:
  - `protocol.CheckinResponse{IntervalSeconds int; InventoryDue bool; Commands []Command}`
  - `protocol.Command{ID, Type string; Payload json.RawMessage}`; type constants `CommandRunPowerShell`, `CommandRestart`, `CommandRefreshInventory`
  - `protocol.RunPowerShellPayload{Script string; TimeoutSeconds int}`, `protocol.RestartPayload{DelaySeconds int; Message string}`
  - `protocol.CommandResult{Status string; ExitCode int; Stdout, Stderr string; StdoutTruncated, StderrTruncated bool; Error string; StartedAt, FinishedAt time.Time}`; status constants `ResultSucceeded`, `ResultFailed`, `ResultTimedOut`; `protocol.MaxOutputBytes = 1 << 20`
  - `protocol.RenewRequest{CSRPEM string}`, `protocol.RenewResponse{CertPEM string}`
  - `protocol.Inventory`, `OSInfo`, `Hardware`, `Disk`, `NetworkAdapter`, `Software`, `LocalUser`, `InventoryResponse{Hash string}`
  - `protocol.InventoryHash(Inventory) string` (ignores `CollectedAt`, `OS.LastBoot` and list order), `protocol.SoftwareHash([]Software) string`

- [ ] **Step 1: Write the failing test**

`internal/protocol/inventory_test.go`:

```go
package protocol

import (
	"slices"
	"testing"
	"time"
)

func sample() Inventory {
	boot := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	return Inventory{
		CollectedAt: time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC),
		Hostname:    "PC-1",
		OS:          OSInfo{Name: "Microsoft Windows 11 Pro", Version: "10.0.26200", Build: "26200", LastBoot: &boot},
		Hardware:    Hardware{Manufacturer: "Contoso", Model: "Book 9", Serial: "SN1", RAMBytes: 16 << 30},
		Disks:       []Disk{{Name: "C:", SizeBytes: 500 << 30, FreeBytes: 200 << 30}, {Name: "D:", SizeBytes: 100 << 30}},
		NetworkAdapters: []NetworkAdapter{
			{Name: "Wi-Fi", MAC: "00:11:22:33:44:55", IPs: []string{"10.0.0.5", "fe80::1"}},
			{Name: "Ethernet", MAC: "aa:bb:cc:dd:ee:ff", IPs: []string{"10.0.0.6"}},
		},
		Software:    []Software{{Name: "7-Zip", Version: "24.08", Scope: "machine"}, {Name: "Git", Version: "2.51.0", Scope: "machine"}},
		LocalUsers:  []LocalUser{{Name: "admin"}, {Name: "guest", Disabled: true}},
		LocalAdmins: []string{`PC-1\admin`, `PC-1\ops`},
	}
}

func TestInventoryHashIgnoresOrderAndTimes(t *testing.T) {
	a := sample()
	b := sample()
	b.CollectedAt = a.CollectedAt.Add(72 * time.Hour)
	later := a.OS.LastBoot.Add(time.Hour)
	b.OS.LastBoot = &later
	slices.Reverse(b.Disks)
	slices.Reverse(b.Software)
	slices.Reverse(b.NetworkAdapters)
	slices.Reverse(b.LocalUsers)
	slices.Reverse(b.LocalAdmins)
	slices.Reverse(b.NetworkAdapters[0].IPs)
	if InventoryHash(a) != InventoryHash(b) {
		t.Fatal("hash must ignore collection time, boot time and list order")
	}
	if b.Disks[0].Name != "D:" {
		t.Fatal("hashing must not reorder the caller's slices")
	}
}

func TestInventoryHashDetectsChanges(t *testing.T) {
	base := InventoryHash(sample())
	cases := map[string]func(*Inventory){
		"software version": func(i *Inventory) { i.Software[1].Version = "2.52.0" },
		"new package":      func(i *Inventory) { i.Software = append(i.Software, Software{Name: "Go", Version: "1.27"}) },
		"ram":              func(i *Inventory) { i.Hardware.RAMBytes = 32 << 30 },
		"free space":       func(i *Inventory) { i.Disks[0].FreeBytes = 1 << 30 },
		"hostname":         func(i *Inventory) { i.Hostname = "PC-2" },
		"admins":           func(i *Inventory) { i.LocalAdmins = append(i.LocalAdmins, `PC-1\eve`) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			inv := sample()
			mutate(&inv)
			if InventoryHash(inv) == base {
				t.Fatal("hash must change")
			}
		})
	}
}

func TestSoftwareHash(t *testing.T) {
	a := sample().Software
	b := slices.Clone(a)
	slices.Reverse(b)
	if SoftwareHash(a) != SoftwareHash(b) {
		t.Fatal("software hash must ignore order")
	}
	c := slices.Clone(a)
	c[0].Publisher = "Igor Pavlov"
	if SoftwareHash(c) == SoftwareHash(a) {
		t.Fatal("software hash must cover publisher")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/protocol/`
Expected: FAIL — `undefined: Inventory`, `undefined: InventoryHash`.

- [ ] **Step 3: Write the protocol types**

`internal/protocol/commands.go`:

```go
package protocol

import (
	"encoding/json"
	"time"
)

// Command types.
const (
	CommandRunPowerShell    = "run_powershell"
	CommandRestart          = "restart"
	CommandRefreshInventory = "refresh_inventory"
)

// Terminal result statuses reported by the agent.
const (
	ResultSucceeded = "succeeded"
	ResultFailed    = "failed"
	ResultTimedOut  = "timed_out"
)

// MaxOutputBytes caps each of stdout and stderr.
const MaxOutputBytes = 1 << 20

// Command is one unit of work handed to an agent at check-in.
type Command struct {
	ID      string          `json:"id"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// RunPowerShellPayload configures CommandRunPowerShell.
type RunPowerShellPayload struct {
	Script         string `json:"script"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

// RestartPayload configures CommandRestart.
type RestartPayload struct {
	DelaySeconds int    `json:"delay_seconds"`
	Message      string `json:"message"`
}

// CommandResult is POSTed to /api/agent/v1/commands/{id}/result.
type CommandResult struct {
	Status          string    `json:"status"`
	ExitCode        int       `json:"exit_code"`
	Stdout          string    `json:"stdout"`
	Stderr          string    `json:"stderr"`
	StdoutTruncated bool      `json:"stdout_truncated"`
	StderrTruncated bool      `json:"stderr_truncated"`
	Error           string    `json:"error"`
	StartedAt       time.Time `json:"started_at"`
	FinishedAt      time.Time `json:"finished_at"`
}

// RenewRequest asks for a fresh client certificate.
type RenewRequest struct {
	CSRPEM string `json:"csr_pem"`
}

// RenewResponse carries the reissued client certificate.
type RenewResponse struct {
	CertPEM string `json:"cert_pem"`
}
```

`internal/protocol/inventory.go`:

```go
package protocol

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"
)

// Inventory is the full device inventory document.
type Inventory struct {
	CollectedAt           time.Time        `json:"collected_at"`
	Hostname              string           `json:"hostname"`
	OS                    OSInfo           `json:"os"`
	Hardware              Hardware         `json:"hardware"`
	Disks                 []Disk           `json:"disks"`
	NetworkAdapters       []NetworkAdapter `json:"network_adapters"`
	Software              []Software       `json:"software"`
	LocalUsers            []LocalUser      `json:"local_users"`
	LocalAdmins           []string         `json:"local_admins"`
	PendingReboot         bool             `json:"pending_reboot"`
	LastUpdateInstalledAt *time.Time       `json:"last_update_installed_at,omitempty"`
}

// OSInfo describes the operating system.
type OSInfo struct {
	Name        string     `json:"name"`
	Version     string     `json:"version"`
	Build       string     `json:"build"`
	InstallDate *time.Time `json:"install_date,omitempty"`
	LastBoot    *time.Time `json:"last_boot,omitempty"`
}

// Hardware describes the machine.
type Hardware struct {
	Manufacturer string `json:"manufacturer"`
	Model        string `json:"model"`
	Serial       string `json:"serial"`
	SMBIOSUUID   string `json:"smbios_uuid"`
	CPU          string `json:"cpu"`
	CPUCores     int    `json:"cpu_cores"`
	CPULogical   int    `json:"cpu_logical"`
	RAMBytes     uint64 `json:"ram_bytes"`
	TPMPresent   bool   `json:"tpm_present"`
	TPMVersion   string `json:"tpm_version"`
}

// Disk is one fixed volume. BitLocker is "on", "off" or "unknown".
type Disk struct {
	Name       string `json:"name"`
	FileSystem string `json:"file_system"`
	SizeBytes  uint64 `json:"size_bytes"`
	FreeBytes  uint64 `json:"free_bytes"`
	BitLocker  string `json:"bitlocker"`
}

// NetworkAdapter is one IP-enabled adapter.
type NetworkAdapter struct {
	Name string   `json:"name"`
	MAC  string   `json:"mac"`
	IPs  []string `json:"ips"`
}

// Software is one installed package. Scope is "machine" or "user".
type Software struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Publisher   string `json:"publisher"`
	InstallDate string `json:"install_date"`
	Scope       string `json:"scope"`
}

// LocalUser is one local account.
type LocalUser struct {
	Name     string `json:"name"`
	Disabled bool   `json:"disabled"`
}

// InventoryResponse returns the hash the server stored, which the agent
// echoes in later check-ins.
type InventoryResponse struct {
	Hash string `json:"hash"`
}

// InventoryHash identifies inventory content. It ignores the collection
// time, the last boot time and the order of list items.
func InventoryHash(inv Inventory) string {
	c := canonicalInventory(inv)
	c.CollectedAt = time.Time{}
	c.OS.LastBoot = nil
	return hashJSON(c)
}

// SoftwareHash identifies the installed-software list regardless of order.
func SoftwareHash(sw []Software) string { return hashJSON(sortedSoftware(sw)) }

func canonicalInventory(inv Inventory) Inventory {
	c := inv
	c.Software = sortedSoftware(inv.Software)

	c.Disks = slices.Clone(inv.Disks)
	slices.SortFunc(c.Disks, func(a, b Disk) int { return cmp.Compare(a.Name, b.Name) })

	c.NetworkAdapters = slices.Clone(inv.NetworkAdapters)
	for i := range c.NetworkAdapters {
		ips := slices.Clone(c.NetworkAdapters[i].IPs)
		slices.Sort(ips)
		c.NetworkAdapters[i].IPs = ips
	}
	slices.SortFunc(c.NetworkAdapters, func(a, b NetworkAdapter) int {
		return cmp.Or(cmp.Compare(a.MAC, b.MAC), cmp.Compare(a.Name, b.Name))
	})

	c.LocalUsers = slices.Clone(inv.LocalUsers)
	slices.SortFunc(c.LocalUsers, func(a, b LocalUser) int { return cmp.Compare(a.Name, b.Name) })

	c.LocalAdmins = slices.Clone(inv.LocalAdmins)
	slices.Sort(c.LocalAdmins)
	return c
}

func sortedSoftware(sw []Software) []Software {
	out := slices.Clone(sw)
	slices.SortFunc(out, func(a, b Software) int {
		return cmp.Or(
			cmp.Compare(a.Name, b.Name),
			cmp.Compare(a.Version, b.Version),
			cmp.Compare(a.Scope, b.Scope),
			cmp.Compare(a.Publisher, b.Publisher),
		)
	})
	return out
}

func hashJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic("protocol: hashing inventory: " + err.Error())
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
```

- [ ] **Step 4: Extend CheckinResponse**

In `internal/protocol/v1.go`, replace the `CheckinResponse` block with:

```go
// CheckinResponse tells the agent when to check in next, whether inventory
// is due, and which commands to run.
type CheckinResponse struct {
	IntervalSeconds int       `json:"interval_seconds"`
	InventoryDue    bool      `json:"inventory_due"`
	Commands        []Command `json:"commands"`
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go vet ./internal/protocol/ && go test ./internal/protocol/`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/protocol
git commit -m "feat(protocol): inventory, command, result and renewal types"
```

---

### Task 2: Migration 0002 plus device and inventory queries

**Files:**
- Create: `internal/server/store/migrations/0002_inventory_commands.up.sql`, `internal/server/store/migrations/0002_inventory_commands.down.sql`, `internal/server/store/inventory.go`, `internal/server/store/store_m2_test.go`
- Modify: `internal/server/store/models.go`, `internal/server/store/devices.go`, `internal/server/store/store.go`

**Interfaces:**
- Consumes: M1 `store.Store`, `store.Queries`, `store.ErrNotFound`, `store.DefaultTenantID`
- Produces:
  - `store.DeviceUnenrolled = "unenrolled"`; `store.Device` gains `PrevCertSerial, OSBuild, Manufacturer, Model string`
  - `store.DeviceInventory{DeviceID uuid.UUID; CollectedAt, ReceivedAt time.Time; Hash, SoftwareHash string; Data []byte; RAMGB, DiskFreeGB float64}`
  - `store.Software{Name, Version, Publisher, InstallDate, Scope string}`, `store.HardwareInfo{Hostname, Serial, SMBIOSUUID, OSVersion, OSBuild, Manufacturer, Model string}`
  - `*Queries`: `GetInventory(ctx, deviceID) (DeviceInventory, error)`, `UpsertInventory(ctx, DeviceInventory) error`, `ReplaceSoftware(ctx, deviceID, []Software) error`, `ListSoftware(ctx, deviceID) ([]Software, error)`, `UpdateDeviceHardware(ctx, id, HardwareInfo) error`, `UpdateDeviceCert(ctx, id, prevSerial, newSerial string, expiresAt time.Time) error`, `ClearPrevCertSerial(ctx, id) error`, `ListDevices(ctx) ([]Device, error)`
  - `store.DBTX` gains `CopyFrom(ctx, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error)`

- [ ] **Step 1: Write the migrations**

`internal/server/store/migrations/0002_inventory_commands.up.sql`:

```sql
ALTER TABLE devices DROP CONSTRAINT devices_status_check;
ALTER TABLE devices ADD CONSTRAINT devices_status_check
    CHECK (status IN ('active', 'retired', 'replaced', 'unenrolled'));
ALTER TABLE devices
    ADD COLUMN prev_cert_serial text NOT NULL DEFAULT '',
    ADD COLUMN os_build         text NOT NULL DEFAULT '',
    ADD COLUMN manufacturer     text NOT NULL DEFAULT '',
    ADD COLUMN model            text NOT NULL DEFAULT '';

CREATE TABLE device_inventory (
    device_id     uuid PRIMARY KEY REFERENCES devices(id),
    tenant_id     uuid NOT NULL REFERENCES tenants(id),
    collected_at  timestamptz NOT NULL,
    received_at   timestamptz NOT NULL,
    hash          text NOT NULL,
    software_hash text NOT NULL,
    data          jsonb NOT NULL,
    ram_gb        double precision NOT NULL DEFAULT 0,
    disk_free_gb  double precision NOT NULL DEFAULT 0
);

CREATE TABLE device_software (
    device_id    uuid NOT NULL REFERENCES devices(id),
    tenant_id    uuid NOT NULL REFERENCES tenants(id),
    name         text NOT NULL,
    version      text NOT NULL DEFAULT '',
    publisher    text NOT NULL DEFAULT '',
    install_date text NOT NULL DEFAULT '',
    scope        text NOT NULL DEFAULT 'machine'
);
CREATE INDEX device_software_device ON device_software (device_id);
CREATE INDEX device_software_name ON device_software (tenant_id, lower(name));

CREATE TABLE commands (
    id           uuid PRIMARY KEY,
    tenant_id    uuid NOT NULL REFERENCES tenants(id),
    device_id    uuid NOT NULL REFERENCES devices(id),
    type         text NOT NULL,
    payload      jsonb NOT NULL DEFAULT '{}',
    status       text NOT NULL CHECK (status IN ('queued', 'delivered', 'running', 'succeeded', 'failed', 'timed_out', 'expired')),
    created_by   text NOT NULL,
    created_at   timestamptz NOT NULL,
    delivered_at timestamptz,
    started_at   timestamptz,
    completed_at timestamptz,
    expires_at   timestamptz NOT NULL
);
CREATE INDEX commands_pending ON commands (device_id, created_at)
    WHERE status IN ('queued', 'delivered', 'running');

CREATE TABLE command_results (
    command_id       uuid PRIMARY KEY REFERENCES commands(id),
    tenant_id        uuid NOT NULL REFERENCES tenants(id),
    exit_code        integer NOT NULL,
    stdout           text NOT NULL DEFAULT '',
    stderr           text NOT NULL DEFAULT '',
    stdout_truncated boolean NOT NULL DEFAULT false,
    stderr_truncated boolean NOT NULL DEFAULT false,
    error            text NOT NULL DEFAULT '',
    started_at       timestamptz NOT NULL,
    finished_at      timestamptz NOT NULL
);
```

`internal/server/store/migrations/0002_inventory_commands.down.sql`:

```sql
DROP TABLE command_results;
DROP TABLE commands;
DROP TABLE device_software;
DROP TABLE device_inventory;
ALTER TABLE devices
    DROP COLUMN model,
    DROP COLUMN manufacturer,
    DROP COLUMN os_build,
    DROP COLUMN prev_cert_serial;
ALTER TABLE devices DROP CONSTRAINT devices_status_check;
ALTER TABLE devices ADD CONSTRAINT devices_status_check
    CHECK (status IN ('active', 'retired', 'replaced'));
```

- [ ] **Step 2: Write the failing test**

`internal/server/store/store_m2_test.go`:

```go
package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

func newDevice(t *testing.T, q *store.Queries, hostname string) store.Device {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	d := store.Device{
		ID: uuid.Must(uuid.NewV7()), Hostname: hostname, Serial: "SN1", SMBIOSUUID: "U1",
		Status: store.DeviceActive, CertSerial: "c1", CertExpiresAt: now.Add(time.Hour), EnrolledAt: now,
	}
	if err := q.CreateDevice(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestInventoryAndDeviceUpdates(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	q := s.Q()
	now := time.Now().UTC().Truncate(time.Microsecond)
	d := newDevice(t, q, "PC-1")

	if _, err := q.GetInventory(ctx, d.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetInventory before upload = %v", err)
	}

	inv := store.DeviceInventory{
		DeviceID: d.ID, CollectedAt: now, ReceivedAt: now, Hash: "h1", SoftwareHash: "s1",
		Data: []byte(`{"hostname":"PC-1"}`), RAMGB: 15.5, DiskFreeGB: 100.25,
	}
	if err := q.UpsertInventory(ctx, inv); err != nil {
		t.Fatal(err)
	}
	got, err := q.GetInventory(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Hash != "h1" || got.SoftwareHash != "s1" || got.RAMGB != 15.5 || got.DiskFreeGB != 100.25 || !got.CollectedAt.Equal(now) {
		t.Fatalf("inventory = %+v", got)
	}
	var doc map[string]any
	if err := json.Unmarshal(got.Data, &doc); err != nil || doc["hostname"] != "PC-1" {
		t.Fatalf("data = %s, err = %v", got.Data, err)
	}

	inv.Hash, inv.SoftwareHash, inv.RAMGB = "h2", "s2", 32
	if err := q.UpsertInventory(ctx, inv); err != nil {
		t.Fatal(err)
	}
	if got, _ = q.GetInventory(ctx, d.ID); got.Hash != "h2" || got.RAMGB != 32 {
		t.Fatalf("after upsert = %+v", got)
	}

	sw := []store.Software{
		{Name: "Zed", Version: "1", Scope: "machine"},
		{Name: "alpha", Version: "2", Publisher: "Acme", Scope: "user"},
	}
	if err := q.ReplaceSoftware(ctx, d.ID, sw); err != nil {
		t.Fatal(err)
	}
	list, err := q.ListSoftware(ctx, d.ID)
	if err != nil || len(list) != 2 || list[0].Name != "alpha" || list[0].Publisher != "Acme" || list[1].Name != "Zed" {
		t.Fatalf("software = %+v, err = %v", list, err)
	}
	if err := q.ReplaceSoftware(ctx, d.ID, sw[:1]); err != nil {
		t.Fatal(err)
	}
	if list, _ = q.ListSoftware(ctx, d.ID); len(list) != 1 {
		t.Fatalf("software after replace = %+v", list)
	}
	if err := q.ReplaceSoftware(ctx, d.ID, nil); err != nil {
		t.Fatal(err)
	}
	if list, _ = q.ListSoftware(ctx, d.ID); len(list) != 0 {
		t.Fatalf("software after empty replace = %+v", list)
	}

	if err := q.UpdateDeviceHardware(ctx, d.ID, store.HardwareInfo{
		Hostname: "PC-RENAMED", OSVersion: "Windows 11 Pro 10.0.26200", OSBuild: "26200",
		Manufacturer: "Dell Inc.", Model: "Latitude 7440",
	}); err != nil {
		t.Fatal(err)
	}
	cur, err := q.GetDevice(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cur.Hostname != "PC-RENAMED" || cur.Manufacturer != "Dell Inc." || cur.Model != "Latitude 7440" || cur.OSBuild != "26200" {
		t.Fatalf("device = %+v", cur)
	}
	if cur.Serial != "SN1" || cur.SMBIOSUUID != "U1" {
		t.Fatal("empty inventory values must not blank existing identity fields")
	}

	expires := now.Add(90 * 24 * time.Hour)
	if err := q.UpdateDeviceCert(ctx, d.ID, "c1", "c2", expires); err != nil {
		t.Fatal(err)
	}
	if cur, _ = q.GetDevice(ctx, d.ID); cur.CertSerial != "c2" || cur.PrevCertSerial != "c1" || !cur.CertExpiresAt.Equal(expires) {
		t.Fatalf("after renew = %+v", cur)
	}
	if err := q.ClearPrevCertSerial(ctx, d.ID); err != nil {
		t.Fatal(err)
	}
	if cur, _ = q.GetDevice(ctx, d.ID); cur.PrevCertSerial != "" {
		t.Fatalf("prev serial = %q", cur.PrevCertSerial)
	}

	if err := q.SetDeviceStatus(ctx, d.ID, store.DeviceUnenrolled); err != nil {
		t.Fatalf("unenrolled must be an allowed status: %v", err)
	}
	newDevice(t, q, "PC-2")
	devices, err := q.ListDevices(ctx)
	if err != nil || len(devices) != 2 {
		t.Fatalf("ListDevices = %d devices, err = %v", len(devices), err)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/server/store/ -run TestInventoryAndDeviceUpdates`
Expected: FAIL — `q.GetInventory undefined`.

- [ ] **Step 4: Extend the Device model**

In `internal/server/store/models.go`, add `DeviceUnenrolled` to the status constants and the four fields to `Device`:

```go
// Device statuses.
const (
	DeviceActive     = "active"
	DeviceRetired    = "retired"
	DeviceReplaced   = "replaced"
	DeviceUnenrolled = "unenrolled"
)
```

Add to the `Device` struct, after `ReplacedBy`:

```go
	PrevCertSerial string
	OSBuild        string
	Manufacturer   string
	Model          string
```

- [ ] **Step 5: Add CopyFrom to DBTX**

In `internal/server/store/store.go`, add to the `DBTX` interface:

```go
	CopyFrom(ctx context.Context, tableName pgx.Identifier, columnNames []string, rowSrc pgx.CopyFromSource) (int64, error)
```

- [ ] **Step 6: Extend device queries**

In `internal/server/store/devices.go`, replace `deviceCols` and `scanDevice`, and append the new queries:

```go
const deviceCols = `id, hostname, serial, smbios_uuid, os_version, status, cert_serial, cert_expires_at, last_seen_at, agent_version, enrolled_at, replaced_by, prev_cert_serial, os_build, manufacturer, model`

func scanDevice(row pgx.Row) (Device, error) {
	var d Device
	err := row.Scan(&d.ID, &d.Hostname, &d.Serial, &d.SMBIOSUUID, &d.OSVersion, &d.Status, &d.CertSerial,
		&d.CertExpiresAt, &d.LastSeenAt, &d.AgentVersion, &d.EnrolledAt, &d.ReplacedBy,
		&d.PrevCertSerial, &d.OSBuild, &d.Manufacturer, &d.Model)
	return d, notFound(err)
}
```

Append:

```go
// ListDevices returns every device, ordered by hostname.
func (q *Queries) ListDevices(ctx context.Context) ([]Device, error) {
	rows, err := q.db.Query(ctx, `SELECT `+deviceCols+` FROM devices ORDER BY lower(hostname), enrolled_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// UpdateDeviceHardware applies non-empty inventory values; empty values leave
// the existing column untouched.
func (q *Queries) UpdateDeviceHardware(ctx context.Context, id uuid.UUID, h HardwareInfo) error {
	_, err := q.db.Exec(ctx, `
		UPDATE devices SET
			hostname     = COALESCE(NULLIF($2, ''), hostname),
			serial       = COALESCE(NULLIF($3, ''), serial),
			smbios_uuid  = COALESCE(NULLIF($4, ''), smbios_uuid),
			os_version   = COALESCE(NULLIF($5, ''), os_version),
			os_build     = COALESCE(NULLIF($6, ''), os_build),
			manufacturer = COALESCE(NULLIF($7, ''), manufacturer),
			model        = COALESCE(NULLIF($8, ''), model)
		WHERE id = $1`,
		id, h.Hostname, h.Serial, h.SMBIOSUUID, h.OSVersion, h.OSBuild, h.Manufacturer, h.Model)
	return err
}

// UpdateDeviceCert records a reissued certificate. prevSerial is the serial
// the renewal request authenticated with; it stays acceptable until the
// device uses the new certificate.
func (q *Queries) UpdateDeviceCert(ctx context.Context, id uuid.UUID, prevSerial, newSerial string, expiresAt time.Time) error {
	_, err := q.db.Exec(ctx, `
		UPDATE devices SET prev_cert_serial = $2, cert_serial = $3, cert_expires_at = $4 WHERE id = $1`,
		id, prevSerial, newSerial, expiresAt)
	return err
}

// ClearPrevCertSerial drops the superseded certificate serial.
func (q *Queries) ClearPrevCertSerial(ctx context.Context, id uuid.UUID) error {
	_, err := q.db.Exec(ctx, `UPDATE devices SET prev_cert_serial = '' WHERE id = $1`, id)
	return err
}
```

- [ ] **Step 7: Write the inventory queries**

`internal/server/store/inventory.go`:

```go
package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// DeviceInventory is the latest inventory document for a device.
type DeviceInventory struct {
	DeviceID     uuid.UUID
	CollectedAt  time.Time
	ReceivedAt   time.Time
	Hash         string
	SoftwareHash string
	Data         []byte
	RAMGB        float64
	DiskFreeGB   float64
}

// Software is one installed package.
type Software struct {
	Name        string
	Version     string
	Publisher   string
	InstallDate string
	Scope       string
}

// HardwareInfo carries the device columns refreshed from inventory.
type HardwareInfo struct {
	Hostname     string
	Serial       string
	SMBIOSUUID   string
	OSVersion    string
	OSBuild      string
	Manufacturer string
	Model        string
}

func (q *Queries) GetInventory(ctx context.Context, deviceID uuid.UUID) (DeviceInventory, error) {
	var inv DeviceInventory
	err := q.db.QueryRow(ctx, `
		SELECT device_id, collected_at, received_at, hash, software_hash, data, ram_gb, disk_free_gb
		FROM device_inventory WHERE device_id = $1`, deviceID).
		Scan(&inv.DeviceID, &inv.CollectedAt, &inv.ReceivedAt, &inv.Hash, &inv.SoftwareHash, &inv.Data, &inv.RAMGB, &inv.DiskFreeGB)
	return inv, notFound(err)
}

func (q *Queries) UpsertInventory(ctx context.Context, inv DeviceInventory) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO device_inventory (device_id, tenant_id, collected_at, received_at, hash, software_hash, data, ram_gb, disk_free_gb)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (device_id) DO UPDATE SET
			collected_at  = EXCLUDED.collected_at,
			received_at   = EXCLUDED.received_at,
			hash          = EXCLUDED.hash,
			software_hash = EXCLUDED.software_hash,
			data          = EXCLUDED.data,
			ram_gb        = EXCLUDED.ram_gb,
			disk_free_gb  = EXCLUDED.disk_free_gb`,
		inv.DeviceID, DefaultTenantID, inv.CollectedAt, inv.ReceivedAt, inv.Hash, inv.SoftwareHash, inv.Data, inv.RAMGB, inv.DiskFreeGB)
	return err
}

// ReplaceSoftware swaps a device's package list.
func (q *Queries) ReplaceSoftware(ctx context.Context, deviceID uuid.UUID, sw []Software) error {
	if _, err := q.db.Exec(ctx, `DELETE FROM device_software WHERE device_id = $1`, deviceID); err != nil {
		return err
	}
	if len(sw) == 0 {
		return nil
	}
	device := pgtype.UUID{Bytes: deviceID, Valid: true}
	tenant := pgtype.UUID{Bytes: DefaultTenantID, Valid: true}
	rows := make([][]any, 0, len(sw))
	for _, s := range sw {
		rows = append(rows, []any{device, tenant, s.Name, s.Version, s.Publisher, s.InstallDate, s.Scope})
	}
	_, err := q.db.CopyFrom(ctx,
		pgx.Identifier{"device_software"},
		[]string{"device_id", "tenant_id", "name", "version", "publisher", "install_date", "scope"},
		pgx.CopyFromRows(rows))
	return err
}

func (q *Queries) ListSoftware(ctx context.Context, deviceID uuid.UUID) ([]Software, error) {
	rows, err := q.db.Query(ctx, `
		SELECT name, version, publisher, install_date, scope FROM device_software
		WHERE device_id = $1 ORDER BY lower(name), version`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Software
	for rows.Next() {
		var s Software
		if err := rows.Scan(&s.Name, &s.Version, &s.Publisher, &s.InstallDate, &s.Scope); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `go vet ./internal/server/store/... && go test ./internal/server/store/`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add internal/server/store
git commit -m "feat(store): inventory and software tables with device hardware columns"
```

---

### Task 3: Command queries

**Files:**
- Create: `internal/server/store/commands.go`, `internal/server/store/store_commands_test.go`

**Interfaces:**
- Consumes: Task 2 store, `newDevice` helper from `store_m2_test.go` (same test package)
- Produces:
  - Status constants `store.CommandQueued|CommandDelivered|CommandRunning|CommandSucceeded|CommandFailed|CommandTimedOut|CommandExpired`
  - `store.Command{ID, DeviceID uuid.UUID; Type string; Payload []byte; Status, CreatedBy string; CreatedAt time.Time; DeliveredAt, StartedAt, CompletedAt *time.Time; ExpiresAt time.Time}`
  - `store.CommandResult{CommandID uuid.UUID; ExitCode int; Stdout, Stderr string; StdoutTruncated, StderrTruncated bool; Error string; StartedAt, FinishedAt time.Time}`
  - `*Queries`: `CreateCommand`, `GetCommand`, `ExpireCommands(ctx, now) (int64, error)`, `PendingCommands(ctx, deviceID) ([]Command, error)`, `MarkCommandsDelivered(ctx, ids []uuid.UUID, at) error`, `MarkCommandRunning(ctx, id, deviceID, at) (bool, error)`, `CompleteCommand(ctx, id, deviceID uuid.UUID, status string, at time.Time) (bool, error)`, `InsertCommandResult(ctx, CommandResult) error`, `GetCommandResult(ctx, id) (CommandResult, error)`, `ListCommands(ctx, deviceID, limit) ([]Command, error)`

- [ ] **Step 1: Write the failing test**

`internal/server/store/store_commands_test.go`:

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

func TestCommands(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	q := s.Q()
	now := time.Now().UTC().Truncate(time.Microsecond)
	d := newDevice(t, q, "PC-CMD")
	other := newDevice(t, q, "PC-OTHER")

	mk := func(created time.Time, expires time.Time) store.Command {
		c := store.Command{
			ID: uuid.Must(uuid.NewV7()), DeviceID: d.ID, Type: "run_powershell",
			Payload: []byte(`{"script":"Get-Date"}`), Status: store.CommandQueued,
			CreatedBy: "test", CreatedAt: created, ExpiresAt: expires,
		}
		if err := q.CreateCommand(ctx, c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	c1 := mk(now, now.Add(time.Hour))
	c2 := mk(now.Add(time.Second), now.Add(time.Hour))
	stale := mk(now.Add(-3*time.Hour), now.Add(-time.Hour))

	n, err := q.ExpireCommands(ctx, now)
	if err != nil || n != 1 {
		t.Fatalf("ExpireCommands = %d, %v", n, err)
	}
	if got, _ := q.GetCommand(ctx, stale.ID); got.Status != store.CommandExpired || got.CompletedAt == nil {
		t.Fatalf("stale command = %+v", got)
	}

	pending, err := q.PendingCommands(ctx, d.ID)
	if err != nil || len(pending) != 2 || pending[0].ID != c1.ID || pending[1].ID != c2.ID {
		t.Fatalf("pending = %+v, err = %v", pending, err)
	}
	if string(pending[0].Payload) == "" {
		t.Fatal("payload must round-trip")
	}

	if err := q.MarkCommandsDelivered(ctx, []uuid.UUID{c1.ID, c2.ID}, now); err != nil {
		t.Fatal(err)
	}
	got, _ := q.GetCommand(ctx, c1.ID)
	if got.Status != store.CommandDelivered || got.DeliveredAt == nil {
		t.Fatalf("delivered = %+v", got)
	}

	ok, err := q.MarkCommandRunning(ctx, c1.ID, d.ID, now)
	if err != nil || !ok {
		t.Fatalf("MarkCommandRunning = %v, %v", ok, err)
	}
	if ok, _ = q.MarkCommandRunning(ctx, c1.ID, d.ID, now); ok {
		t.Fatal("second MarkCommandRunning must report no change")
	}
	if ok, _ = q.MarkCommandRunning(ctx, c2.ID, other.ID, now); ok {
		t.Fatal("a command must not be startable by another device")
	}

	ok, err = q.CompleteCommand(ctx, c1.ID, d.ID, store.CommandSucceeded, now)
	if err != nil || !ok {
		t.Fatalf("CompleteCommand = %v, %v", ok, err)
	}
	if ok, _ = q.CompleteCommand(ctx, c1.ID, d.ID, store.CommandFailed, now); ok {
		t.Fatal("completing twice must report no change")
	}
	if err := q.InsertCommandResult(ctx, store.CommandResult{
		CommandID: c1.ID, ExitCode: 0, Stdout: "hi", StdoutTruncated: true, StartedAt: now, FinishedAt: now.Add(time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	r, err := q.GetCommandResult(ctx, c1.ID)
	if err != nil || r.Stdout != "hi" || !r.StdoutTruncated || !r.FinishedAt.Equal(now.Add(time.Second)) {
		t.Fatalf("result = %+v, err = %v", r, err)
	}
	if _, err := q.GetCommandResult(ctx, c2.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing result err = %v", err)
	}

	if pending, _ = q.PendingCommands(ctx, d.ID); len(pending) != 1 || pending[0].ID != c2.ID {
		t.Fatalf("pending after completion = %+v", pending)
	}
	list, err := q.ListCommands(ctx, d.ID, 10)
	if err != nil || len(list) != 3 || list[0].ID != c2.ID || list[2].ID != stale.ID {
		t.Fatalf("ListCommands = %+v, err = %v", list, err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/server/store/ -run TestCommands`
Expected: FAIL — `q.CreateCommand undefined`.

- [ ] **Step 3: Write the command queries**

`internal/server/store/commands.go`:

```go
package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Command statuses.
const (
	CommandQueued    = "queued"
	CommandDelivered = "delivered"
	CommandRunning   = "running"
	CommandSucceeded = "succeeded"
	CommandFailed    = "failed"
	CommandTimedOut  = "timed_out"
	CommandExpired   = "expired"
)

// Command is one ad-hoc instruction for a device.
type Command struct {
	ID          uuid.UUID
	DeviceID    uuid.UUID
	Type        string
	Payload     []byte
	Status      string
	CreatedBy   string
	CreatedAt   time.Time
	DeliveredAt *time.Time
	StartedAt   *time.Time
	CompletedAt *time.Time
	ExpiresAt   time.Time
}

// CommandResult is what the agent reported for a command.
type CommandResult struct {
	CommandID       uuid.UUID
	ExitCode        int
	Stdout          string
	Stderr          string
	StdoutTruncated bool
	StderrTruncated bool
	Error           string
	StartedAt       time.Time
	FinishedAt      time.Time
}

const commandCols = `id, device_id, type, payload, status, created_by, created_at, delivered_at, started_at, completed_at, expires_at`

func scanCommand(row pgx.Row) (Command, error) {
	var c Command
	err := row.Scan(&c.ID, &c.DeviceID, &c.Type, &c.Payload, &c.Status, &c.CreatedBy, &c.CreatedAt,
		&c.DeliveredAt, &c.StartedAt, &c.CompletedAt, &c.ExpiresAt)
	return c, notFound(err)
}

func (q *Queries) queryCommands(ctx context.Context, sql string, args ...any) ([]Command, error) {
	rows, err := q.db.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Command
	for rows.Next() {
		c, err := scanCommand(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (q *Queries) CreateCommand(ctx context.Context, c Command) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO commands (id, tenant_id, device_id, type, payload, status, created_by, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		c.ID, DefaultTenantID, c.DeviceID, c.Type, c.Payload, c.Status, c.CreatedBy, c.CreatedAt, c.ExpiresAt)
	return err
}

func (q *Queries) GetCommand(ctx context.Context, id uuid.UUID) (Command, error) {
	return scanCommand(q.db.QueryRow(ctx, `SELECT `+commandCols+` FROM commands WHERE id = $1`, id))
}

// ExpireCommands marks undelivered and delivered commands past their TTL as
// expired. Running commands are left alone.
func (q *Queries) ExpireCommands(ctx context.Context, now time.Time) (int64, error) {
	tag, err := q.db.Exec(ctx, `
		UPDATE commands SET status = 'expired', completed_at = $1
		WHERE status IN ('queued', 'delivered') AND expires_at <= $1`, now)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// PendingCommands returns commands still owed to a device, oldest first.
func (q *Queries) PendingCommands(ctx context.Context, deviceID uuid.UUID) ([]Command, error) {
	return q.queryCommands(ctx, `
		SELECT `+commandCols+` FROM commands
		WHERE device_id = $1 AND status IN ('queued', 'delivered', 'running')
		ORDER BY created_at, id`, deviceID)
}

func (q *Queries) MarkCommandsDelivered(ctx context.Context, ids []uuid.UUID, at time.Time) error {
	if len(ids) == 0 {
		return nil
	}
	text := make([]string, len(ids))
	for i, id := range ids {
		text[i] = id.String()
	}
	_, err := q.db.Exec(ctx, `
		UPDATE commands SET status = 'delivered', delivered_at = $2
		WHERE id = ANY($1::uuid[]) AND status = 'queued'`, text, at)
	return err
}

// MarkCommandRunning reports whether the command moved to running.
func (q *Queries) MarkCommandRunning(ctx context.Context, id, deviceID uuid.UUID, at time.Time) (bool, error) {
	tag, err := q.db.Exec(ctx, `
		UPDATE commands SET status = 'running', started_at = $3
		WHERE id = $1 AND device_id = $2 AND status IN ('queued', 'delivered')`, id, deviceID, at)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// CompleteCommand reports whether the command moved to a terminal status.
func (q *Queries) CompleteCommand(ctx context.Context, id, deviceID uuid.UUID, status string, at time.Time) (bool, error) {
	tag, err := q.db.Exec(ctx, `
		UPDATE commands SET status = $3, completed_at = $4
		WHERE id = $1 AND device_id = $2 AND status IN ('queued', 'delivered', 'running')`, id, deviceID, status, at)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (q *Queries) InsertCommandResult(ctx context.Context, r CommandResult) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO command_results (command_id, tenant_id, exit_code, stdout, stderr, stdout_truncated, stderr_truncated, error, started_at, finished_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		r.CommandID, DefaultTenantID, r.ExitCode, r.Stdout, r.Stderr, r.StdoutTruncated, r.StderrTruncated, r.Error, r.StartedAt, r.FinishedAt)
	return err
}

func (q *Queries) GetCommandResult(ctx context.Context, id uuid.UUID) (CommandResult, error) {
	var r CommandResult
	err := q.db.QueryRow(ctx, `
		SELECT command_id, exit_code, stdout, stderr, stdout_truncated, stderr_truncated, error, started_at, finished_at
		FROM command_results WHERE command_id = $1`, id).
		Scan(&r.CommandID, &r.ExitCode, &r.Stdout, &r.Stderr, &r.StdoutTruncated, &r.StderrTruncated, &r.Error, &r.StartedAt, &r.FinishedAt)
	return r, notFound(err)
}

// ListCommands returns a device's newest commands first.
func (q *Queries) ListCommands(ctx context.Context, deviceID uuid.UUID, limit int) ([]Command, error) {
	return q.queryCommands(ctx, `
		SELECT `+commandCols+` FROM commands WHERE device_id = $1
		ORDER BY created_at DESC, id DESC LIMIT $2`, deviceID, limit)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go vet ./internal/server/store/ && go test ./internal/server/store/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/server/store
git commit -m "feat(store): command queue and result queries"
```

---

### Task 4: Inventory service

**Files:**
- Create: `internal/server/inventory/service.go`, `internal/server/inventory/service_test.go`

**Interfaces:**
- Consumes: Task 1 protocol types, Task 2 store queries
- Produces:
  - `inventory.Service{Store *store.Store; Now func() time.Time}`
  - `(*Service).Due(ctx, deviceID uuid.UUID, agentHash string) (bool, error)` — true when there is no inventory, the agent's hash differs, or the last upload is 24h old
  - `(*Service).Ingest(ctx, deviceID uuid.UUID, inv protocol.Inventory) (hash string, err error)` — rewrites `device_software` only when the software hash changes, and refreshes the device's hardware columns
  - `inventory.ErrBadRequest`, `inventory.RefreshAfter = 24 * time.Hour`, `inventory.MaxSoftwareEntries = 20000`

- [ ] **Step 1: Write the failing test**

`internal/server/inventory/service_test.go`:

```go
package inventory_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/inventory"
	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

func sampleInventory() protocol.Inventory {
	return protocol.Inventory{
		CollectedAt: time.Date(2026, 9, 12, 11, 0, 0, 0, time.UTC),
		Hostname:    "PC-NEW",
		OS:          protocol.OSInfo{Name: "Microsoft Windows 11 Pro", Version: "10.0.26200", Build: "26200"},
		Hardware: protocol.Hardware{
			Manufacturer: "Dell Inc.", Model: "Latitude 7440", Serial: "ABC123",
			SMBIOSUUID: "4C4C4544-0044", RAMBytes: 16 << 30,
		},
		Disks: []protocol.Disk{
			{Name: "C:", SizeBytes: 500 << 30, FreeBytes: 200 << 30},
			{Name: "D:", SizeBytes: 100 << 30, FreeBytes: 50 << 30},
		},
		Software: []protocol.Software{
			{Name: "7-Zip", Version: "24.08", Scope: "machine"},
			{Name: "Git", Version: "2.51.0", Scope: "machine"},
		},
	}
}

func TestInventoryService(t *testing.T) {
	ctx := context.Background()
	st := storetest.New(t)
	q := st.Q()
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	clock := now
	svc := &inventory.Service{Store: st, Now: func() time.Time { return clock }}

	d := store.Device{
		ID: uuid.Must(uuid.NewV7()), Hostname: "PC-OLD", Serial: "KEEP", SMBIOSUUID: "KEEPU",
		Status: store.DeviceActive, CertSerial: "c1", CertExpiresAt: now.Add(time.Hour), EnrolledAt: now,
	}
	if err := q.CreateDevice(ctx, d); err != nil {
		t.Fatal(err)
	}

	due, err := svc.Due(ctx, d.ID, "")
	if err != nil || !due {
		t.Fatalf("Due before any upload = %v, %v", due, err)
	}

	inv := sampleInventory()
	hash, err := svc.Ingest(ctx, d.ID, inv)
	if err != nil {
		t.Fatal(err)
	}
	if hash != protocol.InventoryHash(inv) {
		t.Fatalf("hash = %s", hash)
	}

	if due, _ = svc.Due(ctx, d.ID, hash); due {
		t.Fatal("matching hash must not be due")
	}
	if due, _ = svc.Due(ctx, d.ID, "stale-hash"); !due {
		t.Fatal("a different agent hash must be due")
	}
	clock = now.Add(25 * time.Hour)
	if due, _ = svc.Due(ctx, d.ID, hash); !due {
		t.Fatal("inventory older than 24h must be due")
	}
	clock = now

	dev, err := q.GetDevice(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if dev.Hostname != "PC-NEW" || dev.Manufacturer != "Dell Inc." || dev.Model != "Latitude 7440" ||
		dev.OSBuild != "26200" || dev.OSVersion != "Microsoft Windows 11 Pro 10.0.26200" ||
		dev.Serial != "ABC123" || dev.SMBIOSUUID != "4C4C4544-0044" {
		t.Fatalf("device after ingest = %+v", dev)
	}

	stored, err := q.GetInventory(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.RAMGB != 16 || stored.DiskFreeGB != 250 || !stored.ReceivedAt.Equal(now) ||
		stored.SoftwareHash != protocol.SoftwareHash(inv.Software) {
		t.Fatalf("stored inventory = %+v", stored)
	}
	if sw, _ := q.ListSoftware(ctx, d.ID); len(sw) != 2 {
		t.Fatalf("software rows = %d", len(sw))
	}

	// A changed package list is written; an unchanged one keeps the rows.
	changed := sampleInventory()
	changed.Software = append(changed.Software, protocol.Software{Name: "Go", Version: "1.27", Scope: "machine"})
	if _, err := svc.Ingest(ctx, d.ID, changed); err != nil {
		t.Fatal(err)
	}
	if sw, _ := q.ListSoftware(ctx, d.ID); len(sw) != 3 {
		t.Fatalf("software rows after change = %d", len(sw))
	}
	sameSoftware := sampleInventory()
	sameSoftware.Software = changed.Software
	sameSoftware.Disks[0].FreeBytes = 1 << 30
	if _, err := svc.Ingest(ctx, d.ID, sameSoftware); err != nil {
		t.Fatal(err)
	}
	if sw, _ := q.ListSoftware(ctx, d.ID); len(sw) != 3 {
		t.Fatalf("software rows after unchanged list = %d", len(sw))
	}

	huge := sampleInventory()
	huge.Software = make([]protocol.Software, inventory.MaxSoftwareEntries+1)
	for i := range huge.Software {
		huge.Software[i] = protocol.Software{Name: fmt.Sprintf("app-%d", i), Scope: "machine"}
	}
	if _, err := svc.Ingest(ctx, d.ID, huge); !errors.Is(err, inventory.ErrBadRequest) {
		t.Fatalf("oversized software list err = %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/server/inventory/`
Expected: FAIL — no such package.

- [ ] **Step 3: Write the service**

`internal/server/inventory/service.go`:

```go
// Package inventory stores the inventory documents agents upload.
package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/store"
)

// ErrBadRequest marks an unacceptable inventory document.
var ErrBadRequest = errors.New("bad request")

// RefreshAfter is how old inventory may get before a new upload is due.
const RefreshAfter = 24 * time.Hour

// MaxSoftwareEntries caps one inventory document's package list.
const MaxSoftwareEntries = 20000

// Service ingests inventory and decides when it is due.
type Service struct {
	Store *store.Store
	Now   func() time.Time
}

// Due reports whether the device should collect and upload inventory.
// agentHash is the hash the agent last stored; an empty or differing value
// means the agent and server disagree, so a fresh upload is due.
func (s *Service) Due(ctx context.Context, deviceID uuid.UUID, agentHash string) (bool, error) {
	inv, err := s.Store.Q().GetInventory(ctx, deviceID)
	if errors.Is(err, store.ErrNotFound) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if agentHash != inv.Hash {
		return true, nil
	}
	return s.Now().Sub(inv.ReceivedAt) >= RefreshAfter, nil
}

// Ingest stores a document and returns its hash. Software rows are rewritten
// only when the package list changed.
func (s *Service) Ingest(ctx context.Context, deviceID uuid.UUID, inv protocol.Inventory) (string, error) {
	if len(inv.Software) > MaxSoftwareEntries {
		return "", fmt.Errorf("%w: at most %d software entries", ErrBadRequest, MaxSoftwareEntries)
	}
	hash := protocol.InventoryHash(inv)
	softwareHash := protocol.SoftwareHash(inv.Software)
	data, err := json.Marshal(inv)
	if err != nil {
		return "", err
	}
	now := s.Now()

	err = s.Store.InTx(ctx, func(q *store.Queries) error {
		prev, err := q.GetInventory(ctx, deviceID)
		switch {
		case errors.Is(err, store.ErrNotFound):
		case err != nil:
			return err
		}
		rewriteSoftware := errors.Is(err, store.ErrNotFound) || prev.SoftwareHash != softwareHash

		if err := q.UpsertInventory(ctx, store.DeviceInventory{
			DeviceID:     deviceID,
			CollectedAt:  inv.CollectedAt,
			ReceivedAt:   now,
			Hash:         hash,
			SoftwareHash: softwareHash,
			Data:         data,
			RAMGB:        gigabytes(inv.Hardware.RAMBytes),
			DiskFreeGB:   gigabytes(freeBytes(inv.Disks)),
		}); err != nil {
			return err
		}
		if rewriteSoftware {
			rows := make([]store.Software, 0, len(inv.Software))
			for _, sw := range inv.Software {
				rows = append(rows, store.Software{
					Name: sw.Name, Version: sw.Version, Publisher: sw.Publisher,
					InstallDate: sw.InstallDate, Scope: sw.Scope,
				})
			}
			if err := q.ReplaceSoftware(ctx, deviceID, rows); err != nil {
				return err
			}
		}
		return q.UpdateDeviceHardware(ctx, deviceID, store.HardwareInfo{
			Hostname:     inv.Hostname,
			Serial:       inv.Hardware.Serial,
			SMBIOSUUID:   inv.Hardware.SMBIOSUUID,
			OSVersion:    strings.TrimSpace(inv.OS.Name + " " + inv.OS.Version),
			OSBuild:      inv.OS.Build,
			Manufacturer: inv.Hardware.Manufacturer,
			Model:        inv.Hardware.Model,
		})
	})
	if err != nil {
		return "", err
	}
	return hash, nil
}

func freeBytes(disks []protocol.Disk) uint64 {
	var total uint64
	for _, d := range disks {
		total += d.FreeBytes
	}
	return total
}

func gigabytes(b uint64) float64 {
	return math.Round(float64(b)/(1<<30)*100) / 100
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go vet ./internal/server/inventory/ && go test ./internal/server/inventory/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/server/inventory
git commit -m "feat(server): inventory ingest with software-hash change detection"
```

---

### Task 5: Commands service

**Files:**
- Create: `internal/server/commands/service.go`, `internal/server/commands/service_test.go`

**Interfaces:**
- Consumes: Task 1 protocol types, Task 3 store queries
- Produces:
  - `commands.Service{Store *store.Store; Now func() time.Time}`
  - `commands.QueueOptions{DeviceID uuid.UUID; Type string; Payload json.RawMessage; CreatedBy string; TTL time.Duration}`
  - `(*Service).Queue(ctx, QueueOptions) (store.Command, error)` — validates type and payload, requires an active device, audits `command.queued`
  - `(*Service).Deliver(ctx, deviceID uuid.UUID) ([]protocol.Command, error)` — expires stale commands, returns pending ones (never nil), marks queued ones delivered
  - `(*Service).Start(ctx, deviceID, commandID uuid.UUID) error` — idempotent
  - `(*Service).Complete(ctx, deviceID, commandID uuid.UUID, r protocol.CommandResult) error` — idempotent, clamps output
  - `(*Service).Get(ctx, commandID uuid.UUID) (store.Command, *store.CommandResult, error)`
  - `commands.ErrBadRequest`, `commands.ErrNotFound`, `commands.ErrDeviceNotActive`, `commands.DefaultTTL`, `commands.DefaultScriptTimeout`, `commands.MaxScriptTimeout`

- [ ] **Step 1: Write the failing test**

`internal/server/commands/service_test.go`:

```go
package commands_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/commands"
	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

func newDevice(t *testing.T, st *store.Store, hostname, status string) store.Device {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	d := store.Device{
		ID: uuid.Must(uuid.NewV7()), Hostname: hostname, Status: status,
		CertSerial: "c1", CertExpiresAt: now.Add(time.Hour), EnrolledAt: now,
	}
	if err := st.Q().CreateDevice(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestQueueValidation(t *testing.T) {
	ctx := context.Background()
	st := storetest.New(t)
	svc := &commands.Service{Store: st, Now: time.Now}
	active := newDevice(t, st, "PC-1", store.DeviceActive)
	retired := newDevice(t, st, "PC-2", store.DeviceRetired)

	cases := map[string]struct {
		opts commands.QueueOptions
		want error
	}{
		"unknown type":    {commands.QueueOptions{DeviceID: active.ID, Type: "nope"}, commands.ErrBadRequest},
		"empty script":    {commands.QueueOptions{DeviceID: active.ID, Type: protocol.CommandRunPowerShell, Payload: json.RawMessage(`{"script":"  "}`)}, commands.ErrBadRequest},
		"bad json":        {commands.QueueOptions{DeviceID: active.ID, Type: protocol.CommandRunPowerShell, Payload: json.RawMessage(`{`)}, commands.ErrBadRequest},
		"timeout too big": {commands.QueueOptions{DeviceID: active.ID, Type: protocol.CommandRunPowerShell, Payload: json.RawMessage(`{"script":"x","timeout_seconds":90000}`)}, commands.ErrBadRequest},
		"long message":    {commands.QueueOptions{DeviceID: active.ID, Type: protocol.CommandRestart, Payload: json.RawMessage(`{"message":"` + strings.Repeat("m", 600) + `"}`)}, commands.ErrBadRequest},
		"retired device":  {commands.QueueOptions{DeviceID: retired.ID, Type: protocol.CommandRefreshInventory}, commands.ErrDeviceNotActive},
		"missing device":  {commands.QueueOptions{DeviceID: uuid.Must(uuid.NewV7()), Type: protocol.CommandRefreshInventory}, commands.ErrNotFound},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			tc.opts.CreatedBy = "test"
			if _, err := svc.Queue(ctx, tc.opts); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestCommandLifecycle(t *testing.T) {
	ctx := context.Background()
	st := storetest.New(t)
	clock := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	svc := &commands.Service{Store: st, Now: func() time.Time { return clock }}
	d := newDevice(t, st, "PC-1", store.DeviceActive)
	other := newDevice(t, st, "PC-2", store.DeviceActive)

	script, err := svc.Queue(ctx, commands.QueueOptions{
		DeviceID: d.ID, Type: protocol.CommandRunPowerShell,
		Payload: json.RawMessage(`{"script":"Get-Date"}`), CreatedBy: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	var sp protocol.RunPowerShellPayload
	if err := json.Unmarshal(script.Payload, &sp); err != nil || sp.TimeoutSeconds != int(commands.DefaultScriptTimeout/time.Second) {
		t.Fatalf("normalized payload = %s, err = %v", script.Payload, err)
	}
	if !script.ExpiresAt.Equal(clock.Add(commands.DefaultTTL)) {
		t.Fatalf("expires = %s", script.ExpiresAt)
	}
	if _, err := svc.Queue(ctx, commands.QueueOptions{DeviceID: d.ID, Type: protocol.CommandRestart, CreatedBy: "test"}); err != nil {
		t.Fatalf("restart with no payload: %v", err)
	}

	delivered, err := svc.Deliver(ctx, d.ID)
	if err != nil || len(delivered) != 2 || delivered[0].ID != script.ID.String() {
		t.Fatalf("Deliver = %+v, err = %v", delivered, err)
	}
	if again, _ := svc.Deliver(ctx, d.ID); len(again) != 2 {
		t.Fatal("undelivered work must be offered again until it completes")
	}
	if empty, err := svc.Deliver(ctx, other.ID); err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("Deliver for idle device = %#v, err = %v", empty, err)
	}

	if err := svc.Start(ctx, d.ID, script.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.Start(ctx, d.ID, script.ID); err != nil {
		t.Fatalf("Start must be idempotent: %v", err)
	}
	if err := svc.Start(ctx, other.ID, script.ID); !errors.Is(err, commands.ErrNotFound) {
		t.Fatalf("Start from another device = %v", err)
	}

	res := protocol.CommandResult{
		Status: protocol.ResultSucceeded, ExitCode: 0,
		Stdout: "ok\x00" + strings.Repeat("x", protocol.MaxOutputBytes),
		Stderr: "warn", StartedAt: clock, FinishedAt: clock.Add(time.Second),
	}
	if err := svc.Complete(ctx, d.ID, script.ID, res); err != nil {
		t.Fatal(err)
	}
	if err := svc.Complete(ctx, d.ID, script.ID, res); err != nil {
		t.Fatalf("re-submitting a result must succeed: %v", err)
	}
	got, stored, err := svc.Get(ctx, script.ID)
	if err != nil || got.Status != store.CommandSucceeded || stored == nil {
		t.Fatalf("command = %+v, result = %+v, err = %v", got, stored, err)
	}
	if len(stored.Stdout) > protocol.MaxOutputBytes || !stored.StdoutTruncated || strings.Contains(stored.Stdout, "\x00") {
		t.Fatalf("stdout len = %d truncated = %v", len(stored.Stdout), stored.StdoutTruncated)
	}
	if err := svc.Complete(ctx, d.ID, script.ID, protocol.CommandResult{Status: "weird"}); !errors.Is(err, commands.ErrBadRequest) {
		t.Fatalf("bad status err = %v", err)
	}
	if err := svc.Complete(ctx, d.ID, uuid.Must(uuid.NewV7()), res); !errors.Is(err, commands.ErrNotFound) {
		t.Fatalf("unknown command err = %v", err)
	}

	if pending, _ := svc.Deliver(ctx, d.ID); len(pending) != 1 {
		t.Fatalf("pending after completion = %d", len(pending))
	}
	clock = clock.Add(commands.DefaultTTL + time.Hour)
	if pending, _ := svc.Deliver(ctx, d.ID); len(pending) != 0 {
		t.Fatalf("expired commands must not be delivered: %d", len(pending))
	}

	entries, err := st.Q().ListAudit(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	var queued int
	for _, e := range entries {
		if e.Action == "command.queued" {
			queued++
		}
	}
	if queued != 2 {
		t.Fatalf("command.queued audit entries = %d", queued)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/server/commands/`
Expected: FAIL — no such package.

- [ ] **Step 3: Write the service**

`internal/server/commands/service.go`:

```go
// Package commands queues ad-hoc device commands and records their results.
package commands

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/store"
)

var (
	ErrBadRequest      = errors.New("bad request")
	ErrNotFound        = errors.New("command not found")
	ErrDeviceNotActive = errors.New("device is not active")
)

// Timing defaults.
const (
	DefaultTTL           = 7 * 24 * time.Hour
	DefaultScriptTimeout = 10 * time.Minute
	MaxScriptTimeout     = 24 * time.Hour
	maxRestartMessage    = 512
)

// Service owns the command queue.
type Service struct {
	Store *store.Store
	Now   func() time.Time
}

// QueueOptions describe a command to queue.
type QueueOptions struct {
	DeviceID  uuid.UUID
	Type      string
	Payload   json.RawMessage
	CreatedBy string
	TTL       time.Duration
}

// Queue validates and stores a command for an active device.
func (s *Service) Queue(ctx context.Context, o QueueOptions) (store.Command, error) {
	payload, err := normalizePayload(o.Type, o.Payload)
	if err != nil {
		return store.Command{}, err
	}
	now := s.Now()
	ttl := o.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	id, err := uuid.NewV7()
	if err != nil {
		return store.Command{}, err
	}
	c := store.Command{
		ID: id, DeviceID: o.DeviceID, Type: o.Type, Payload: payload, Status: store.CommandQueued,
		CreatedBy: o.CreatedBy, CreatedAt: now, ExpiresAt: now.Add(ttl),
	}
	err = s.Store.InTx(ctx, func(q *store.Queries) error {
		d, err := q.GetDevice(ctx, o.DeviceID)
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("%w: no device %s", ErrNotFound, o.DeviceID)
		}
		if err != nil {
			return err
		}
		if d.Status != store.DeviceActive {
			return fmt.Errorf("%w: %s is %s", ErrDeviceNotActive, d.Hostname, d.Status)
		}
		if err := q.CreateCommand(ctx, c); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: o.CreatedBy, Action: "command.queued", TargetKind: "command", TargetID: id.String(),
			Details: map[string]any{"device_id": o.DeviceID.String(), "type": o.Type},
		})
	})
	if err != nil {
		return store.Command{}, err
	}
	return c, nil
}

// normalizePayload validates a payload and returns its canonical JSON.
func normalizePayload(typ string, raw json.RawMessage) ([]byte, error) {
	switch typ {
	case protocol.CommandRunPowerShell:
		var p protocol.RunPowerShellPayload
		if err := decodePayload(raw, &p); err != nil {
			return nil, err
		}
		if strings.TrimSpace(p.Script) == "" {
			return nil, fmt.Errorf("%w: script is required", ErrBadRequest)
		}
		switch {
		case p.TimeoutSeconds == 0:
			p.TimeoutSeconds = int(DefaultScriptTimeout / time.Second)
		case p.TimeoutSeconds < 0 || p.TimeoutSeconds > int(MaxScriptTimeout/time.Second):
			return nil, fmt.Errorf("%w: timeout_seconds must be between 1 and %d", ErrBadRequest, int(MaxScriptTimeout/time.Second))
		}
		return json.Marshal(p)
	case protocol.CommandRestart:
		var p protocol.RestartPayload
		if err := decodePayload(raw, &p); err != nil {
			return nil, err
		}
		if p.DelaySeconds < 0 || p.DelaySeconds > 86400 {
			return nil, fmt.Errorf("%w: delay_seconds must be between 0 and 86400", ErrBadRequest)
		}
		if len(p.Message) > maxRestartMessage {
			return nil, fmt.Errorf("%w: message must be at most %d characters", ErrBadRequest, maxRestartMessage)
		}
		return json.Marshal(p)
	case protocol.CommandRefreshInventory:
		return []byte(`{}`), nil
	default:
		return nil, fmt.Errorf("%w: unsupported command type %q", ErrBadRequest, typ)
	}
}

func decodePayload(raw json.RawMessage, v any) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("%w: %v", ErrBadRequest, err)
	}
	return nil
}

// Deliver returns the commands a device still owes, marking queued ones as
// delivered. Commands past their TTL expire first.
func (s *Service) Deliver(ctx context.Context, deviceID uuid.UUID) ([]protocol.Command, error) {
	now := s.Now()
	out := []protocol.Command{}
	err := s.Store.InTx(ctx, func(q *store.Queries) error {
		if _, err := q.ExpireCommands(ctx, now); err != nil {
			return err
		}
		pending, err := q.PendingCommands(ctx, deviceID)
		if err != nil {
			return err
		}
		var fresh []uuid.UUID
		for _, c := range pending {
			if c.Status == store.CommandQueued {
				fresh = append(fresh, c.ID)
			}
			out = append(out, protocol.Command{ID: c.ID.String(), Type: c.Type, Payload: json.RawMessage(c.Payload)})
		}
		return q.MarkCommandsDelivered(ctx, fresh, now)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Start records that the device began a command. Repeat calls are accepted so
// a retrying agent is not punished.
func (s *Service) Start(ctx context.Context, deviceID, commandID uuid.UUID) error {
	now := s.Now()
	return s.Store.InTx(ctx, func(q *store.Queries) error {
		ok, err := q.MarkCommandRunning(ctx, commandID, deviceID, now)
		if err != nil || ok {
			return err
		}
		c, err := q.GetCommand(ctx, commandID)
		if errors.Is(err, store.ErrNotFound) || (err == nil && c.DeviceID != deviceID) {
			return fmt.Errorf("%w: %s", ErrNotFound, commandID)
		}
		return err
	})
}

// Complete stores a terminal result. Re-submitting a completed command's
// result succeeds without changing anything.
func (s *Service) Complete(ctx context.Context, deviceID, commandID uuid.UUID, r protocol.CommandResult) error {
	switch r.Status {
	case protocol.ResultSucceeded, protocol.ResultFailed, protocol.ResultTimedOut:
	default:
		return fmt.Errorf("%w: unsupported result status %q", ErrBadRequest, r.Status)
	}
	now := s.Now()
	stdout, stdoutTruncated := clampOutput(r.Stdout, r.StdoutTruncated)
	stderr, stderrTruncated := clampOutput(r.Stderr, r.StderrTruncated)
	errText, _ := clampOutput(r.Error, false)

	return s.Store.InTx(ctx, func(q *store.Queries) error {
		ok, err := q.CompleteCommand(ctx, commandID, deviceID, r.Status, now)
		if err != nil {
			return err
		}
		if !ok {
			c, err := q.GetCommand(ctx, commandID)
			if errors.Is(err, store.ErrNotFound) || (err == nil && c.DeviceID != deviceID) {
				return fmt.Errorf("%w: %s", ErrNotFound, commandID)
			}
			if err != nil {
				return err
			}
			return nil // already terminal: a duplicate submission
		}
		return q.InsertCommandResult(ctx, store.CommandResult{
			CommandID: commandID, ExitCode: r.ExitCode,
			Stdout: stdout, Stderr: stderr,
			StdoutTruncated: stdoutTruncated, StderrTruncated: stderrTruncated,
			Error: errText, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt,
		})
	})
}

// Get returns a command and its result, if it has one.
func (s *Service) Get(ctx context.Context, commandID uuid.UUID) (store.Command, *store.CommandResult, error) {
	q := s.Store.Q()
	c, err := q.GetCommand(ctx, commandID)
	if errors.Is(err, store.ErrNotFound) {
		return store.Command{}, nil, fmt.Errorf("%w: %s", ErrNotFound, commandID)
	}
	if err != nil {
		return store.Command{}, nil, err
	}
	r, err := q.GetCommandResult(ctx, commandID)
	if errors.Is(err, store.ErrNotFound) {
		return c, nil, nil
	}
	if err != nil {
		return store.Command{}, nil, err
	}
	return c, &r, nil
}

// clampOutput makes agent output safe to store: no NUL bytes, valid UTF-8,
// and no longer than the cap.
func clampOutput(s string, truncated bool) (string, bool) {
	s = strings.ReplaceAll(s, "\x00", "")
	if len(s) > protocol.MaxOutputBytes {
		s = s[:protocol.MaxOutputBytes]
		truncated = true
	}
	return strings.ToValidUTF8(s, "�"), truncated
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go vet ./internal/server/commands/ && go test ./internal/server/commands/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/server/commands
git commit -m "feat(server): command queue service with idempotent results"
```

---

### Task 6: Device status service and certificate renewal

**Files:**
- Create: `internal/server/devices/service.go`, `internal/server/devices/service_test.go`, `internal/server/enroll/renew.go`, `internal/server/enroll/renew_test.go`

**Interfaces:**
- Consumes: Task 2 store queries, M1 `enroll.Service` (has `Store`, `CA`, `Now`, `CertValidity`), M1 `ca.CA`
- Produces:
  - `devices.Service{Store *store.Store}`; `(*Service).Retire(ctx, id uuid.UUID, actor string) error` (from `active`); `(*Service).Unenroll(ctx, id, actor) error` (from `active` or `retired`); `devices.ErrNotFound`, `devices.ErrInvalidTransition`
  - `(*enroll.Service).Renew(ctx, deviceID uuid.UUID, presentedSerial string, req protocol.RenewRequest) (protocol.RenewResponse, error)` — signs the CSR, stores the new serial with `presentedSerial` as the previous one, audits `device.cert_renewed`

- [ ] **Step 1: Write the failing tests**

`internal/server/devices/service_test.go`:

```go
package devices_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/devices"
	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

func newDevice(t *testing.T, st *store.Store, status string) store.Device {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	d := store.Device{
		ID: uuid.Must(uuid.NewV7()), Hostname: "PC-1", Status: status,
		CertSerial: "c1", CertExpiresAt: now.Add(time.Hour), EnrolledAt: now,
	}
	if err := st.Q().CreateDevice(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestRetireAndUnenroll(t *testing.T) {
	ctx := context.Background()
	st := storetest.New(t)
	svc := &devices.Service{Store: st}

	d := newDevice(t, st, store.DeviceActive)
	if err := svc.Retire(ctx, d.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.Q().GetDevice(ctx, d.ID); got.Status != store.DeviceRetired {
		t.Fatalf("status = %s", got.Status)
	}
	if err := svc.Retire(ctx, d.ID, "admin"); !errors.Is(err, devices.ErrInvalidTransition) {
		t.Fatalf("retiring twice = %v", err)
	}
	// A retired device can still be unenrolled so the agent wipes itself.
	if err := svc.Unenroll(ctx, d.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.Q().GetDevice(ctx, d.ID); got.Status != store.DeviceUnenrolled {
		t.Fatalf("status = %s", got.Status)
	}
	if err := svc.Unenroll(ctx, d.ID, "admin"); !errors.Is(err, devices.ErrInvalidTransition) {
		t.Fatalf("unenrolling twice = %v", err)
	}

	fresh := newDevice(t, st, store.DeviceActive)
	if err := svc.Unenroll(ctx, fresh.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := svc.Retire(ctx, uuid.Must(uuid.NewV7()), "admin"); !errors.Is(err, devices.ErrNotFound) {
		t.Fatalf("missing device = %v", err)
	}

	entries, err := st.Q().ListAudit(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, e := range entries {
		seen[e.Action]++
	}
	if seen["device.retired"] != 1 || seen["device.unenrolled"] != 2 {
		t.Fatalf("audit actions = %v", seen)
	}
}
```

`internal/server/enroll/renew_test.go`:

```go
package enroll_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/ca"
	"retune/internal/server/enroll"
)

func TestRenew(t *testing.T) {
	ctx := context.Background()
	svc := newService(t)
	q := svc.Store.Q()

	plain, _, err := svc.CreateToken(ctx, enroll.TokenOptions{CreatedBy: "test"})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := svc.Enroll(ctx, protocol.EnrollRequest{
		Token: plain, CSRPEM: newCSR(t), Device: protocol.DeviceFacts{Hostname: "PC-RENEW"},
	})
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.MustParse(resp.DeviceID)
	before, err := q.GetDevice(ctx, id)
	if err != nil {
		t.Fatal(err)
	}

	renewed, err := svc.Renew(ctx, id, before.CertSerial, protocol.RenewRequest{CSRPEM: newCSR(t)})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(renewed.CertPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != resp.DeviceID {
		t.Fatalf("renewed cert CN = %s", cert.Subject.CommonName)
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots: svc.CA.Pool(), CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("renewed cert must verify: %v", err)
	}

	after, err := q.GetDevice(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if after.CertSerial == before.CertSerial || after.CertSerial != cert.SerialNumber.Text(16) {
		t.Fatalf("serial = %s (was %s)", after.CertSerial, before.CertSerial)
	}
	if after.PrevCertSerial != before.CertSerial {
		t.Fatalf("prev serial = %s, want %s", after.PrevCertSerial, before.CertSerial)
	}
	if !after.CertExpiresAt.Equal(now.Add(90 * 24 * time.Hour)) {
		t.Fatalf("expiry = %s", after.CertExpiresAt)
	}

	// Renewing again from the superseded certificate keeps it usable.
	if _, err := svc.Renew(ctx, id, after.PrevCertSerial, protocol.RenewRequest{CSRPEM: newCSR(t)}); err != nil {
		t.Fatal(err)
	}
	if again, _ := q.GetDevice(ctx, id); again.PrevCertSerial != before.CertSerial {
		t.Fatalf("prev serial = %s, want the certificate the agent still holds", again.PrevCertSerial)
	}

	if _, err := svc.Renew(ctx, id, after.CertSerial, protocol.RenewRequest{CSRPEM: "garbage"}); !errors.Is(err, ca.ErrBadCSR) {
		t.Fatalf("bad CSR err = %v", err)
	}

	entries, _ := q.ListAudit(ctx, 100)
	var renewals int
	for _, e := range entries {
		if e.Action == "device.cert_renewed" {
			renewals++
		}
	}
	if renewals != 2 {
		t.Fatalf("device.cert_renewed audit entries = %d", renewals)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/server/devices/ ./internal/server/enroll/`
Expected: FAIL — no `devices` package; `svc.Renew undefined`.

- [ ] **Step 3: Write the devices service**

`internal/server/devices/service.go`:

```go
// Package devices changes device lifecycle status.
package devices

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/google/uuid"

	"retune/internal/server/store"
)

var (
	ErrNotFound          = errors.New("device not found")
	ErrInvalidTransition = errors.New("invalid device status change")
)

// Service retires and unenrolls devices.
type Service struct {
	Store *store.Store
}

// Retire stops an active device from checking in; its agent idles.
func (s *Service) Retire(ctx context.Context, id uuid.UUID, actor string) error {
	return s.transition(ctx, id, actor, store.DeviceRetired, "device.retired", store.DeviceActive)
}

// Unenroll tells the agent to delete its identity and local state.
func (s *Service) Unenroll(ctx context.Context, id uuid.UUID, actor string) error {
	return s.transition(ctx, id, actor, store.DeviceUnenrolled, "device.unenrolled", store.DeviceActive, store.DeviceRetired)
}

func (s *Service) transition(ctx context.Context, id uuid.UUID, actor, to, action string, from ...string) error {
	return s.Store.InTx(ctx, func(q *store.Queries) error {
		d, err := q.GetDevice(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("%w: %s", ErrNotFound, id)
		}
		if err != nil {
			return err
		}
		if !slices.Contains(from, d.Status) {
			return fmt.Errorf("%w: %s cannot go from %s to %s", ErrInvalidTransition, d.Hostname, d.Status, to)
		}
		if err := q.SetDeviceStatus(ctx, id, to); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: actor, Action: action, TargetKind: "device", TargetID: id.String(),
			Details: map[string]any{"from": d.Status},
		})
	})
}
```

- [ ] **Step 4: Write the renewal path**

`internal/server/enroll/renew.go`:

```go
package enroll

import (
	"context"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/store"
)

// Renew issues a fresh client certificate for a device. presentedSerial is the
// serial of the certificate that authenticated the request; it remains
// acceptable until the device uses the new one, so a crash between issuing and
// saving cannot lock the device out.
func (s *Service) Renew(ctx context.Context, deviceID uuid.UUID, presentedSerial string, req protocol.RenewRequest) (protocol.RenewResponse, error) {
	now := s.Now()
	issued, err := s.CA.SignClientCSR([]byte(req.CSRPEM), deviceID.String(), now, s.CertValidity)
	if err != nil {
		return protocol.RenewResponse{}, err
	}
	err = s.Store.InTx(ctx, func(q *store.Queries) error {
		if err := q.UpdateDeviceCert(ctx, deviceID, presentedSerial, issued.Serial, issued.NotAfter); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: "device:" + deviceID.String(), Action: "device.cert_renewed",
			TargetKind: "device", TargetID: deviceID.String(),
			Details: map[string]any{"serial": issued.Serial, "not_after": issued.NotAfter.Format(time.RFC3339)},
		})
	})
	if err != nil {
		return protocol.RenewResponse{}, err
	}
	return protocol.RenewResponse{CertPEM: string(issued.PEM)}, nil
}
```

Add `"time"` to the import block above (it is used for `time.RFC3339`).

- [ ] **Step 5: Run tests to verify they pass**

Run: `go vet ./internal/server/... && go test ./internal/server/devices/ ./internal/server/enroll/`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/server/devices internal/server/enroll
git commit -m "feat(server): device retire/unenroll and certificate renewal"
```

---

### Task 7: Agent API endpoints and app wiring

**Files:**
- Modify: `internal/server/agentapi/json.go`, `internal/server/agentapi/handler.go`, `internal/server/app/app.go`
- Create: `internal/server/app/helpers_test.go`, `internal/server/app/app_m2_test.go`

**Interfaces:**
- Consumes: Tasks 4–6 services
- Produces:
  - `agentapi.Handler` gains `Inventory *inventory.Service`, `Commands *commands.Service`
  - Routes: `POST /api/agent/v1/renew`, `PUT /api/agent/v1/inventory`, `POST /api/agent/v1/commands/{id}/start`, `POST /api/agent/v1/commands/{id}/result`; check-in now returns `inventory_due` and `commands`
  - `410 device_unenrolled` for unenrolled devices; the previous certificate serial is accepted until the new one is used, then cleared
  - Error codes: `bad_request` (400), `body_too_large` (413), `command_not_found` (404)
  - `app.App` gains `Inventory *inventory.Service`, `Commands *commands.Service`, `Devices *devices.Service`

- [ ] **Step 1: Write the failing test**

`internal/server/app/helpers_test.go`:

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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/app"
	"retune/internal/server/enroll"
)

// newKeyAndCSR returns a device keypair and its CSR in PEM form.
func newKeyAndCSR(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// clientFor builds an mTLS client from a device key and its certificate.
func clientFor(t *testing.T, a *app.App, key *ecdsa.PrivateKey, certPEM string) *http.Client {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatal("certificate is not PEM")
	}
	return httpClient(a, &tls.Certificate{Certificate: [][]byte{block.Bytes}, PrivateKey: key})
}

// send performs a JSON request and returns the status and raw body.
func send(t *testing.T, c *http.Client, method, url string, body any) (int, []byte) {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, url, r)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, out
}

// enrollDevice enrolls one device and returns its ID and mTLS client.
func enrollDevice(t *testing.T, a *app.App, srv *httptest.Server, hostname string) (uuid.UUID, *http.Client) {
	t.Helper()
	ctx := context.Background()
	plain, _, err := a.Enroll.CreateToken(ctx, enroll.TokenOptions{CreatedBy: "test"})
	if err != nil {
		t.Fatal(err)
	}
	key, csrPEM := newKeyAndCSR(t)
	status, body := send(t, httpClient(a, nil), http.MethodPost, srv.URL+"/api/agent/v1/enroll",
		protocol.EnrollRequest{Token: plain, CSRPEM: csrPEM, Device: protocol.DeviceFacts{Hostname: hostname}})
	if status != http.StatusOK {
		t.Fatalf("enroll: %d %s", status, body)
	}
	var resp protocol.EnrollResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	return uuid.MustParse(resp.DeviceID), clientFor(t, a, key, resp.CertPEM)
}

func decodeJSON[T any](t *testing.T, body []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return v
}
```

`internal/server/app/app_m2_test.go`:

```go
package app_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/commands"
)

func TestInventoryEndpoint(t *testing.T) {
	ctx := context.Background()
	a, srv := newTestApp(t)
	id, mtls := enrollDevice(t, a, srv, "PC-INV")
	base := srv.URL + "/api/agent/v1"

	status, body := send(t, mtls, http.MethodPost, base+"/checkin", protocol.CheckinRequest{})
	resp := decodeJSON[protocol.CheckinResponse](t, body)
	if status != http.StatusOK || !resp.InventoryDue {
		t.Fatalf("first check-in: %d %s", status, body)
	}
	if !bytes.Contains(body, []byte(`"commands":[]`)) {
		t.Fatalf("commands must be an empty array, got %s", body)
	}

	inv := protocol.Inventory{
		Hostname: "PC-INV",
		OS:       protocol.OSInfo{Name: "Microsoft Windows 11 Pro", Version: "10.0.26200", Build: "26200"},
		Hardware: protocol.Hardware{Manufacturer: "Contoso", RAMBytes: 8 << 30},
		Software: []protocol.Software{{Name: "App", Version: "1", Scope: "machine"}},
	}
	status, body = send(t, mtls, http.MethodPut, base+"/inventory", inv)
	if status != http.StatusOK {
		t.Fatalf("inventory: %d %s", status, body)
	}
	hash := decodeJSON[protocol.InventoryResponse](t, body).Hash
	if hash != protocol.InventoryHash(inv) {
		t.Fatalf("hash = %s", hash)
	}
	if d, _ := a.Store.Q().GetDevice(ctx, id); d.Manufacturer != "Contoso" {
		t.Fatalf("device not refreshed from inventory: %+v", d)
	}

	_, body = send(t, mtls, http.MethodPost, base+"/checkin", protocol.CheckinRequest{InventoryHash: hash})
	if decodeJSON[protocol.CheckinResponse](t, body).InventoryDue {
		t.Fatal("inventory must not be due right after an upload")
	}

	big := protocol.Inventory{Hostname: strings.Repeat("a", 9<<20)}
	status, body = send(t, mtls, http.MethodPut, base+"/inventory", big)
	if status != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: %d %s", status, body)
	}
}

func TestCommandEndpoints(t *testing.T) {
	ctx := context.Background()
	a, srv := newTestApp(t)
	id, mtls := enrollDevice(t, a, srv, "PC-CMD")
	base := srv.URL + "/api/agent/v1"

	c, err := a.Commands.Queue(ctx, commands.QueueOptions{
		DeviceID: id, Type: protocol.CommandRefreshInventory, CreatedBy: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, body := send(t, mtls, http.MethodPost, base+"/checkin", protocol.CheckinRequest{})
	got := decodeJSON[protocol.CheckinResponse](t, body).Commands
	if len(got) != 1 || got[0].ID != c.ID.String() || got[0].Type != protocol.CommandRefreshInventory {
		t.Fatalf("commands = %+v", got)
	}

	if status, body := send(t, mtls, http.MethodPost, base+"/commands/"+c.ID.String()+"/start", nil); status != http.StatusNoContent {
		t.Fatalf("start: %d %s", status, body)
	}
	result := protocol.CommandResult{Status: protocol.ResultSucceeded, Stdout: "done"}
	if status, body := send(t, mtls, http.MethodPost, base+"/commands/"+c.ID.String()+"/result", result); status != http.StatusNoContent {
		t.Fatalf("result: %d %s", status, body)
	}
	if status, _ := send(t, mtls, http.MethodPost, base+"/commands/"+c.ID.String()+"/result", result); status != http.StatusNoContent {
		t.Fatal("re-submitting a result must succeed")
	}
	if stored, res, _ := a.Commands.Get(ctx, c.ID); stored.Status != "succeeded" || res == nil || res.Stdout != "done" {
		t.Fatalf("stored command = %+v result = %+v", stored, res)
	}

	if status, _ := send(t, mtls, http.MethodPost, base+"/commands/"+uuid.Must(uuid.NewV7()).String()+"/result", result); status != http.StatusNotFound {
		t.Fatal("unknown command must be 404")
	}
	if status, _ := send(t, mtls, http.MethodPost, base+"/commands/not-a-uuid/start", nil); status != http.StatusNotFound {
		t.Fatal("malformed command ID must be 404")
	}
	if status, body := send(t, mtls, http.MethodPost, base+"/commands/"+c.ID.String()+"/result",
		protocol.CommandResult{Status: "weird"}); status != http.StatusBadRequest {
		t.Fatalf("bad status: %d %s", status, body)
	}
}

func TestRenewAndUnenroll(t *testing.T) {
	ctx := context.Background()
	a, srv := newTestApp(t)
	id, oldClient := enrollDevice(t, a, srv, "PC-RENEW")
	base := srv.URL + "/api/agent/v1"
	before, _ := a.Store.Q().GetDevice(ctx, id)

	newKey, csrPEM := newKeyAndCSR(t)
	status, body := send(t, oldClient, http.MethodPost, base+"/renew", protocol.RenewRequest{CSRPEM: csrPEM})
	if status != http.StatusOK {
		t.Fatalf("renew: %d %s", status, body)
	}
	renewed := decodeJSON[protocol.RenewResponse](t, body)
	after, _ := a.Store.Q().GetDevice(ctx, id)
	if after.CertSerial == before.CertSerial || after.PrevCertSerial != before.CertSerial {
		t.Fatalf("device after renew = %+v", after)
	}

	// The old certificate still works until the new one is used.
	if status, _ := send(t, oldClient, http.MethodPost, base+"/checkin", protocol.CheckinRequest{}); status != http.StatusOK {
		t.Fatal("superseded certificate must stay valid until the new one is used")
	}
	newClient := clientFor(t, a, newKey, renewed.CertPEM)
	if status, _ := send(t, newClient, http.MethodPost, base+"/checkin", protocol.CheckinRequest{}); status != http.StatusOK {
		t.Fatal("renewed certificate must be accepted")
	}
	if cur, _ := a.Store.Q().GetDevice(ctx, id); cur.PrevCertSerial != "" {
		t.Fatalf("prev serial must be cleared once the new certificate is used: %q", cur.PrevCertSerial)
	}
	if status, _ := send(t, oldClient, http.MethodPost, base+"/checkin", protocol.CheckinRequest{}); status != http.StatusUnauthorized {
		t.Fatal("superseded certificate must stop working")
	}

	block, _ := pem.Decode([]byte(renewed.CertPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != id.String() {
		t.Fatalf("renewed CN = %s", cert.Subject.CommonName)
	}

	if err := a.Devices.Unenroll(ctx, id, "test"); err != nil {
		t.Fatal(err)
	}
	status, body = send(t, newClient, http.MethodPost, base+"/checkin", protocol.CheckinRequest{})
	if status != http.StatusGone || !bytes.Contains(body, []byte("device_unenrolled")) {
		t.Fatalf("unenrolled check-in: %d %s", status, body)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/server/app/`
Expected: FAIL — `a.Commands undefined`, `a.Devices undefined`.

- [ ] **Step 3: Rewrite the JSON helpers**

`internal/server/agentapi/json.go`:

```go
package agentapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"retune/internal/protocol"
)

// Request body limits.
const (
	maxCheckinBody   = 1 << 20
	maxInventoryBody = 8 << 20
	maxResultBody    = 8 << 20
)

// decode reads a JSON body no larger than limit. Unknown fields are allowed so
// newer agents can talk to older servers.
func decode(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	err := json.NewDecoder(r.Body).Decode(v)
	if err == nil {
		return true
	}
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body is too large")
		return false
	}
	writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
	return false
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeNoContent(w http.ResponseWriter) { w.WriteHeader(http.StatusNoContent) }

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, protocol.Error{Code: code, Message: msg})
}
```

- [ ] **Step 4: Rewrite the handler**

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
	"retune/internal/server/commands"
	"retune/internal/server/enroll"
	"retune/internal/server/inventory"
	"retune/internal/server/store"
)

// Handler serves /api/agent/v1.
type Handler struct {
	Enroll          *enroll.Service
	Inventory       *inventory.Service
	Commands        *commands.Service
	Store           *store.Store
	Now             func() time.Time
	CheckinInterval time.Duration
	Log             *slog.Logger
}

type authKey struct{}

// authInfo is the authenticated device plus the certificate serial it used.
type authInfo struct {
	Device     store.Device
	CertSerial string
}

// Routes returns the agent API mux.
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/agent/v1/enroll", h.enroll)
	mux.Handle("POST /api/agent/v1/checkin", h.requireDevice(h.checkin))
	mux.Handle("POST /api/agent/v1/renew", h.requireDevice(h.renew))
	mux.Handle("PUT /api/agent/v1/inventory", h.requireDevice(h.putInventory))
	mux.Handle("POST /api/agent/v1/commands/{id}/start", h.requireDevice(h.startCommand))
	mux.Handle("POST /api/agent/v1/commands/{id}/result", h.requireDevice(h.commandResult))
	return mux
}

func (h *Handler) enroll(w http.ResponseWriter, r *http.Request) {
	var req protocol.EnrollRequest
	if !decode(w, r, &req, maxCheckinBody) {
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

// requireDevice authenticates the mTLS client certificate. The certificate
// must be the device's current one, or the one it presented at its last
// renewal; using the current one clears the superseded serial.
func (h *Handler) requireDevice(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			writeError(w, http.StatusUnauthorized, "client_cert_required", "a device client certificate is required")
			return
		}
		leaf := r.TLS.VerifiedChains[0][0]
		serial := leaf.SerialNumber.Text(16)
		id, err := uuid.Parse(leaf.Subject.CommonName)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "device_not_active", "unrecognized device certificate")
			return
		}
		ctx := r.Context()
		d, err := h.Store.Q().GetDevice(ctx, id)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			h.Log.Error("load device", "device_id", id, "error", err)
			writeError(w, http.StatusInternalServerError, "internal", "internal server error")
			return
		}
		known := err == nil && (serial == d.CertSerial || (d.PrevCertSerial != "" && serial == d.PrevCertSerial))
		if !known {
			writeError(w, http.StatusUnauthorized, "device_not_active", "unrecognized device certificate")
			return
		}
		switch d.Status {
		case store.DeviceUnenrolled:
			writeError(w, http.StatusGone, "device_unenrolled", "device was unenrolled; remove the local identity")
			return
		case store.DeviceActive:
		default:
			writeError(w, http.StatusUnauthorized, "device_not_active", "device is retired or replaced")
			return
		}
		if serial == d.CertSerial && d.PrevCertSerial != "" {
			if err := h.Store.Q().ClearPrevCertSerial(ctx, d.ID); err != nil {
				h.Log.Error("clear superseded certificate serial", "device_id", d.ID, "error", err)
			} else {
				d.PrevCertSerial = ""
			}
		}
		next(w, r.WithContext(context.WithValue(ctx, authKey{}, authInfo{Device: d, CertSerial: serial})))
	})
}

func auth(r *http.Request) authInfo { return r.Context().Value(authKey{}).(authInfo) }

func (h *Handler) checkin(w http.ResponseWriter, r *http.Request) {
	a := auth(r)
	var req protocol.CheckinRequest
	if !decode(w, r, &req, maxCheckinBody) {
		return
	}
	ctx := r.Context()
	if err := h.Store.Q().RecordCheckin(ctx, a.Device.ID, req.AgentVersion, h.Now()); err != nil {
		h.Log.Error("record checkin", "device_id", a.Device.ID, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	due, err := h.Inventory.Due(ctx, a.Device.ID, req.InventoryHash)
	if err != nil {
		h.Log.Error("inventory due check", "device_id", a.Device.ID, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	cmds, err := h.Commands.Deliver(ctx, a.Device.ID)
	if err != nil {
		h.Log.Error("deliver commands", "device_id", a.Device.ID, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, protocol.CheckinResponse{
		IntervalSeconds: int(h.CheckinInterval / time.Second),
		InventoryDue:    due,
		Commands:        cmds,
	})
}

func (h *Handler) renew(w http.ResponseWriter, r *http.Request) {
	a := auth(r)
	var req protocol.RenewRequest
	if !decode(w, r, &req, maxCheckinBody) {
		return
	}
	resp, err := h.Enroll.Renew(r.Context(), a.Device.ID, a.CertSerial, req)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, resp)
	case errors.Is(err, ca.ErrBadCSR):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	default:
		h.Log.Error("renew failed", "device_id", a.Device.ID, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
	}
}

func (h *Handler) putInventory(w http.ResponseWriter, r *http.Request) {
	a := auth(r)
	var inv protocol.Inventory
	if !decode(w, r, &inv, maxInventoryBody) {
		return
	}
	hash, err := h.Inventory.Ingest(r.Context(), a.Device.ID, inv)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, protocol.InventoryResponse{Hash: hash})
	case errors.Is(err, inventory.ErrBadRequest):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	default:
		h.Log.Error("ingest inventory", "device_id", a.Device.ID, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
	}
}

func (h *Handler) startCommand(w http.ResponseWriter, r *http.Request) {
	a := auth(r)
	id, ok := commandID(w, r)
	if !ok {
		return
	}
	err := h.Commands.Start(r.Context(), a.Device.ID, id)
	switch {
	case err == nil:
		writeNoContent(w)
	case errors.Is(err, commands.ErrNotFound):
		writeError(w, http.StatusNotFound, "command_not_found", err.Error())
	default:
		h.Log.Error("start command", "device_id", a.Device.ID, "command_id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
	}
}

func (h *Handler) commandResult(w http.ResponseWriter, r *http.Request) {
	a := auth(r)
	id, ok := commandID(w, r)
	if !ok {
		return
	}
	var res protocol.CommandResult
	if !decode(w, r, &res, maxResultBody) {
		return
	}
	err := h.Commands.Complete(r.Context(), a.Device.ID, id, res)
	switch {
	case err == nil:
		writeNoContent(w)
	case errors.Is(err, commands.ErrNotFound):
		writeError(w, http.StatusNotFound, "command_not_found", err.Error())
	case errors.Is(err, commands.ErrBadRequest):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	default:
		h.Log.Error("complete command", "device_id", a.Device.ID, "command_id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
	}
}

func commandID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "command_not_found", "unknown command")
		return uuid.UUID{}, false
	}
	return id, true
}
```

- [ ] **Step 5: Wire the services into the app**

In `internal/server/app/app.go`, add the imports `"retune/internal/server/commands"`, `"retune/internal/server/devices"` and `"retune/internal/server/inventory"`, add the fields to `App`:

```go
	Inventory *inventory.Service
	Commands  *commands.Service
	Devices   *devices.Service
```

and replace the service/handler construction near the end of `New` with:

```go
	svc := &enroll.Service{Store: st, CA: authority, Now: time.Now, CertValidity: clientCertValidity}
	inv := &inventory.Service{Store: st, Now: time.Now}
	cmd := &commands.Service{Store: st, Now: time.Now}
	dev := &devices.Service{Store: st}
	h := &agentapi.Handler{
		Enroll: svc, Inventory: inv, Commands: cmd, Store: st,
		Now: time.Now, CheckinInterval: cfg.CheckinInterval, Log: log,
	}
	return &App{
		Store:     st,
		CA:        authority,
		Enroll:    svc,
		Inventory: inv,
		Commands:  cmd,
		Devices:   dev,
		Handler:   h.Routes(),
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{serverCert},
			ClientAuth:   tls.VerifyClientCertIfGiven,
			ClientCAs:    authority.Pool(),
		},
	}, nil
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `go vet ./internal/server/... && go test ./internal/server/app/`
Expected: PASS (M1's `TestAgentAPI` still passes alongside the new tests).

- [ ] **Step 7: Commit**

```bash
git add internal/server/agentapi internal/server/app
git commit -m "feat(server): inventory, command, renew endpoints and 410 on unenroll"
```

---

### Task 8: Server CLI for devices and commands

**Files:**
- Create: `cmd/retune-server/devices.go`, `cmd/retune-server/commands.go`, `cmd/retune-server/cli_m2_test.go`
- Modify: `cmd/retune-server/main.go` (usage, `device`/`command` cases, `openStore` helper)

**Interfaces:**
- Consumes: Tasks 4–6 services, Task 2/3 store queries
- Produces:
  - `retune-server device list|show <id>|retire <id>|unenroll <id>`
  - `retune-server command queue --device <id> --type <t> [--script S | --script-file F] [--timeout 10m] [--delay 1m] [--message M] [--ttl 168h]` and `command show <id>`
  - `openStore(ctx, getenv) (*store.Store, error)` shared by `token`, `device` and `command`

- [ ] **Step 1: Write the failing test**

`cmd/retune-server/cli_m2_test.go`:

```go
package main

import (
	"bytes"
	"context"
	"io"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

func runOut(t *testing.T, getenv func(string) string, args ...string) string {
	t.Helper()
	var out bytes.Buffer
	if err := run(context.Background(), args, getenv, &out); err != nil {
		t.Fatalf("run %v: %v", args, err)
	}
	return out.String()
}

func TestDeviceAndCommandCLI(t *testing.T) {
	ctx := context.Background()
	url := storetest.DatabaseURL(t)
	e := env(map[string]string{"DATABASE_URL": url})
	if err := run(ctx, []string{"migrate"}, e, io.Discard); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now().UTC().Truncate(time.Microsecond)
	id := uuid.Must(uuid.NewV7())
	if err := st.Q().CreateDevice(ctx, store.Device{
		ID: id, Hostname: "PC-CLI", Serial: "SN-CLI", Status: store.DeviceActive,
		CertSerial: "c1", CertExpiresAt: now.Add(time.Hour), EnrolledAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	if out := runOut(t, e, "device", "list"); !strings.Contains(out, "PC-CLI") || !strings.Contains(out, "active") {
		t.Fatalf("device list = %q", out)
	}
	if out := runOut(t, e, "device", "show", id.String()); !strings.Contains(out, "PC-CLI") || !strings.Contains(out, "none yet") {
		t.Fatalf("device show = %q", out)
	}

	out := runOut(t, e, "command", "queue", "--device", id.String(), "--type", "run_powershell", "--script", "Get-Date")
	m := regexp.MustCompile(`Command ID: (\S+)`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("command queue = %q", out)
	}
	if out := runOut(t, e, "command", "show", m[1]); !strings.Contains(out, "run_powershell") || !strings.Contains(out, "queued") {
		t.Fatalf("command show = %q", out)
	}
	if out := runOut(t, e, "device", "show", id.String()); !strings.Contains(out, "run_powershell") {
		t.Fatalf("device show must list recent commands: %q", out)
	}

	scriptFile := t.TempDir() + "/task.ps1"
	if err := os.WriteFile(scriptFile, []byte("Write-Output hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out := runOut(t, e, "command", "queue", "--device", id.String(), "--type", "run_powershell", "--script-file", scriptFile); !strings.Contains(out, "Command ID: ") {
		t.Fatalf("queue from file = %q", out)
	}
	if out := runOut(t, e, "command", "queue", "--device", id.String(), "--type", "restart", "--delay", "30s", "--message", "patching"); !strings.Contains(out, "Command ID: ") {
		t.Fatalf("queue restart = %q", out)
	}

	if err := run(ctx, []string{"command", "queue", "--device", id.String(), "--type", "bogus"}, e, io.Discard); err == nil {
		t.Fatal("unknown command type must fail")
	}
	if err := run(ctx, []string{"command", "queue", "--device", id.String(), "--type", "run_powershell"}, e, io.Discard); err == nil {
		t.Fatal("run_powershell without a script must fail")
	}
	if err := run(ctx, []string{"device", "show", "not-a-uuid"}, e, io.Discard); err == nil {
		t.Fatal("malformed device ID must fail")
	}

	runOut(t, e, "device", "retire", id.String())
	if d, _ := st.Q().GetDevice(ctx, id); d.Status != store.DeviceRetired {
		t.Fatalf("status after retire = %s", d.Status)
	}
	runOut(t, e, "device", "unenroll", id.String())
	if d, _ := st.Q().GetDevice(ctx, id); d.Status != store.DeviceUnenrolled {
		t.Fatalf("status after unenroll = %s", d.Status)
	}
	if err := run(ctx, []string{"device", "retire", id.String()}, e, io.Discard); err == nil {
		t.Fatal("retiring an unenrolled device must fail")
	}
}
```

Add `"os"` to that file's imports (used for `os.WriteFile`).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/retune-server/ -run TestDeviceAndCommandCLI`
Expected: FAIL — `unknown command "device"`.

- [ ] **Step 3: Add the shared store helper and new commands to main.go**

In `cmd/retune-server/main.go`, extend `usage`:

```go
const usage = `usage: retune-server <command>

commands:
  serve                  run the server
  migrate                apply database migrations
  token create [flags]   create an enrollment token (--label, --max-uses, --expires-in)
  ca fingerprint         print the internal CA fingerprint for agent pinning
  device list            list enrolled devices
  device show <id>       show one device with its inventory and recent commands
  device retire <id>     stop accepting check-ins from a device
  device unenroll <id>   tell the agent to delete its identity and state
  command queue [flags]  queue a command (--device, --type, --script, --script-file, --timeout, --delay, --message, --ttl)
  command show <id>      show a command and its result`
```

Add the two cases to the `switch` in `run`:

```go
	case "device":
		return deviceCmd(ctx, args[1:], getenv, out)
	case "command":
		return commandCmd(ctx, args[1:], getenv, out)
```

Add the helper:

```go
func openStore(ctx context.Context, getenv func(string) string) (*store.Store, error) {
	url := getenv("DATABASE_URL")
	if url == "" {
		return nil, errors.New("DATABASE_URL is required")
	}
	return store.Open(ctx, url)
}
```

And replace the store opening inside `tokenCmd` with it:

```go
	st, err := openStore(ctx, getenv)
	if err != nil {
		return err
	}
	defer st.Close()
```

- [ ] **Step 4: Write the device command**

`cmd/retune-server/devices.go`:

```go
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/devices"
	"retune/internal/server/store"
)

const deviceUsage = `usage: retune-server device list | show <id> | retire <id> | unenroll <id>`

func deviceCmd(ctx context.Context, args []string, getenv func(string) string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(deviceUsage)
	}
	var id uuid.UUID
	if args[0] != "list" {
		var err error
		if id, err = oneID(args[1:]); err != nil {
			return err
		}
	}
	st, err := openStore(ctx, getenv)
	if err != nil {
		return err
	}
	defer st.Close()

	switch args[0] {
	case "list":
		return deviceList(ctx, st, out)
	case "show":
		return deviceShow(ctx, st, id, out)
	case "retire":
		if err := (&devices.Service{Store: st}).Retire(ctx, id, "cli"); err != nil {
			return err
		}
		fmt.Fprintf(out, "Device %s retired.\n", id)
		return nil
	case "unenroll":
		if err := (&devices.Service{Store: st}).Unenroll(ctx, id, "cli"); err != nil {
			return err
		}
		fmt.Fprintf(out, "Device %s unenrolled; its agent will wipe its identity at the next check-in.\n", id)
		return nil
	default:
		return errors.New(deviceUsage)
	}
}

func oneID(args []string) (uuid.UUID, error) {
	if len(args) != 1 {
		return uuid.UUID{}, errors.New("expected exactly one device ID")
	}
	id, err := uuid.Parse(args[0])
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("invalid device ID %q", args[0])
	}
	return id, nil
}

func deviceList(ctx context.Context, st *store.Store, out io.Writer) error {
	list, err := st.Q().ListDevices(ctx)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tHOSTNAME\tSTATUS\tOS\tLAST SEEN")
	for _, d := range list {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", d.ID, d.Hostname, d.Status, orDash(d.OSVersion), timeOrNever(d.LastSeenAt))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(out, "\n%d device(s).\n", len(list))
	return nil
}

func deviceShow(ctx context.Context, st *store.Store, id uuid.UUID, out io.Writer) error {
	q := st.Q()
	d, err := q.GetDevice(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("no device %s", id)
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "ID:            %s\nHostname:      %s\nStatus:        %s\n", d.ID, d.Hostname, d.Status)
	fmt.Fprintf(out, "OS:            %s (build %s)\nHardware:      %s %s\nSerial:        %s\nSMBIOS UUID:   %s\n",
		orDash(d.OSVersion), orDash(d.OSBuild), orDash(d.Manufacturer), orDash(d.Model), orDash(d.Serial), orDash(d.SMBIOSUUID))
	fmt.Fprintf(out, "Agent version: %s\nEnrolled:      %s\nLast seen:     %s\nCert expires:  %s\n",
		orDash(d.AgentVersion), d.EnrolledAt.Format(time.RFC3339), timeOrNever(d.LastSeenAt), d.CertExpiresAt.Format(time.RFC3339))

	inv, err := q.GetInventory(ctx, id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		fmt.Fprintln(out, "Inventory:     none yet")
	case err != nil:
		return err
	default:
		sw, err := q.ListSoftware(ctx, id)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Inventory:     collected %s, %.1f GB RAM, %.1f GB free, %d package(s)\n",
			inv.CollectedAt.Format(time.RFC3339), inv.RAMGB, inv.DiskFreeGB, len(sw))
	}

	cmds, err := q.ListCommands(ctx, id, 10)
	if err != nil {
		return err
	}
	if len(cmds) == 0 {
		fmt.Fprintln(out, "Commands:      none")
		return nil
	}
	fmt.Fprintln(out, "\nRecent commands:")
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tTYPE\tSTATUS\tCREATED")
	for _, c := range cmds {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", c.ID, c.Type, c.Status, c.CreatedAt.Format(time.RFC3339))
	}
	return tw.Flush()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func timeOrNever(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return t.Format(time.RFC3339)
}
```

- [ ] **Step 5: Write the command command**

`cmd/retune-server/commands.go`:

```go
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/commands"
)

const commandUsage = `usage: retune-server command queue --device <id> --type <type> [flags] | command show <id>`

func commandCmd(ctx context.Context, args []string, getenv func(string) string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(commandUsage)
	}
	switch args[0] {
	case "queue":
		return commandQueue(ctx, args[1:], getenv, out)
	case "show":
		id, err := oneID(args[1:])
		if err != nil {
			return err
		}
		return commandShow(ctx, id, getenv, out)
	default:
		return errors.New(commandUsage)
	}
}

func commandQueue(ctx context.Context, args []string, getenv func(string) string, out io.Writer) error {
	fs := flag.NewFlagSet("command queue", flag.ContinueOnError)
	device := fs.String("device", "", "device ID")
	typ := fs.String("type", "", "run_powershell | restart | refresh_inventory")
	script := fs.String("script", "", "PowerShell script text")
	scriptFile := fs.String("script-file", "", "path to a .ps1 file")
	timeout := fs.Duration("timeout", commands.DefaultScriptTimeout, "script timeout")
	delay := fs.Duration("delay", time.Minute, "restart delay")
	message := fs.String("message", "", "restart message shown to the user")
	ttl := fs.Duration("ttl", commands.DefaultTTL, "how long the command stays deliverable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	id, err := uuid.Parse(*device)
	if err != nil {
		return fmt.Errorf("--device must be a device ID")
	}

	var payload json.RawMessage
	switch *typ {
	case protocol.CommandRunPowerShell:
		body := *script
		if *scriptFile != "" {
			b, err := os.ReadFile(*scriptFile)
			if err != nil {
				return err
			}
			body = string(b)
		}
		payload, err = json.Marshal(protocol.RunPowerShellPayload{Script: body, TimeoutSeconds: int(timeout.Seconds())})
	case protocol.CommandRestart:
		payload, err = json.Marshal(protocol.RestartPayload{DelaySeconds: int(delay.Seconds()), Message: *message})
	case protocol.CommandRefreshInventory:
	default:
		return fmt.Errorf("--type must be one of run_powershell, restart, refresh_inventory")
	}
	if err != nil {
		return err
	}

	st, err := openStore(ctx, getenv)
	if err != nil {
		return err
	}
	defer st.Close()

	svc := &commands.Service{Store: st, Now: time.Now}
	c, err := svc.Queue(ctx, commands.QueueOptions{
		DeviceID: id, Type: *typ, Payload: payload, CreatedBy: "cli", TTL: *ttl,
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Command ID: %s\nQueued for device %s; expires %s.\n", c.ID, id, c.ExpiresAt.Format(time.RFC3339))
	return nil
}

func commandShow(ctx context.Context, id uuid.UUID, getenv func(string) string, out io.Writer) error {
	st, err := openStore(ctx, getenv)
	if err != nil {
		return err
	}
	defer st.Close()

	c, res, err := (&commands.Service{Store: st, Now: time.Now}).Get(ctx, id)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "ID:        %s\nDevice:    %s\nType:      %s\nStatus:    %s\nPayload:   %s\n",
		c.ID, c.DeviceID, c.Type, c.Status, c.Payload)
	fmt.Fprintf(out, "Created:   %s by %s\nDelivered: %s\nStarted:   %s\nCompleted: %s\nExpires:   %s\n",
		c.CreatedAt.Format(time.RFC3339), c.CreatedBy, timeOrNever(c.DeliveredAt), timeOrNever(c.StartedAt),
		timeOrNever(c.CompletedAt), c.ExpiresAt.Format(time.RFC3339))
	if res == nil {
		fmt.Fprintln(out, "Result:    none yet")
		return nil
	}
	fmt.Fprintf(out, "\nExit code: %d\nDuration:  %s\n", res.ExitCode, res.FinishedAt.Sub(res.StartedAt).Round(time.Millisecond))
	if res.Error != "" {
		fmt.Fprintf(out, "Error:     %s\n", res.Error)
	}
	printOutput(out, "stdout", res.Stdout, res.StdoutTruncated)
	printOutput(out, "stderr", res.Stderr, res.StderrTruncated)
	return nil
}

func printOutput(out io.Writer, name, body string, truncated bool) {
	if body == "" {
		return
	}
	fmt.Fprintf(out, "\n--- %s", name)
	if truncated {
		fmt.Fprint(out, " (truncated)")
	}
	fmt.Fprintf(out, " ---\n%s\n", body)
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `go vet ./cmd/... && go test ./cmd/retune-server/`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add cmd/retune-server
git commit -m "feat(server): device and command CLI"
```

---

### Task 9: Agent local state

**Files:**
- Create: `internal/agent/state/state.go`, `internal/agent/state/state_test.go`

**Interfaces:**
- Consumes: Task 1 `protocol.CommandResult`
- Produces:
  - `state.Open(path string) (*state.Store, error)`, `(*Store).Close() error`, `(*Store).Destroy() error` (close and delete the file)
  - `state.QueuedResult{CommandID string; Result protocol.CommandResult}`
  - `(*Store).QueueResult(QueuedResult) error`, `(*Store).PendingResults() ([]QueuedResult, error)`, `(*Store).DeleteResult(id string) error`
  - `(*Store).MarkStarted(id string, at time.Time) (first bool, err error)`, `(*Store).MarkCompleted(id string, at time.Time) error`, `(*Store).LedgerState(id string) (string, error)`, `(*Store).PruneLedger(before time.Time) (int, error)`
  - `(*Store).InventoryHash() (string, error)`, `(*Store).SetInventoryHash(string) error`
  - Constants `state.LedgerStarted = "started"`, `state.LedgerCompleted = "completed"`

- [ ] **Step 1: Add the dependency**

```bash
go get go.etcd.io/bbolt@latest
```

- [ ] **Step 2: Write the failing test**

`internal/agent/state/state_test.go`:

```go
package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"retune/internal/protocol"
)

func TestStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)

	if hash, err := s.InventoryHash(); err != nil || hash != "" {
		t.Fatalf("initial inventory hash = %q, %v", hash, err)
	}
	if pending, err := s.PendingResults(); err != nil || len(pending) != 0 {
		t.Fatalf("initial pending = %+v, %v", pending, err)
	}

	// Results queue, ordered by command ID.
	for _, id := range []string{"b", "a"} {
		if err := s.QueueResult(QueuedResult{
			CommandID: id,
			Result:    protocol.CommandResult{Status: protocol.ResultSucceeded, Stdout: "out-" + id, StartedAt: now, FinishedAt: now},
		}); err != nil {
			t.Fatal(err)
		}
	}
	pending, err := s.PendingResults()
	if err != nil || len(pending) != 2 || pending[0].CommandID != "a" || pending[0].Result.Stdout != "out-a" {
		t.Fatalf("pending = %+v, err = %v", pending, err)
	}
	if err := s.DeleteResult("a"); err != nil {
		t.Fatal(err)
	}
	if pending, _ = s.PendingResults(); len(pending) != 1 || pending[0].CommandID != "b" {
		t.Fatalf("pending after delete = %+v", pending)
	}

	// Command ledger.
	first, err := s.MarkStarted("cmd-1", now)
	if err != nil || !first {
		t.Fatalf("MarkStarted = %v, %v", first, err)
	}
	if first, _ = s.MarkStarted("cmd-1", now); first {
		t.Fatal("a second MarkStarted must report the command was already seen")
	}
	if got, _ := s.LedgerState("cmd-1"); got != LedgerStarted {
		t.Fatalf("ledger state = %q", got)
	}
	if err := s.MarkCompleted("cmd-1", now); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.LedgerState("cmd-1"); got != LedgerCompleted {
		t.Fatalf("ledger state = %q", got)
	}
	if got, err := s.LedgerState("unknown"); err != nil || got != "" {
		t.Fatalf("unknown ledger state = %q, %v", got, err)
	}

	if err := s.SetInventoryHash("h1"); err != nil {
		t.Fatal(err)
	}

	// State survives a reopen.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if hash, _ := s.InventoryHash(); hash != "h1" {
		t.Fatalf("hash after reopen = %q", hash)
	}
	if pending, _ = s.PendingResults(); len(pending) != 1 {
		t.Fatalf("pending after reopen = %+v", pending)
	}
	if got, _ := s.LedgerState("cmd-1"); got != LedgerCompleted {
		t.Fatalf("ledger after reopen = %q", got)
	}

	// Pruning drops old ledger entries only.
	if _, err := s.MarkStarted("old", now.Add(-60*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	n, err := s.PruneLedger(now.Add(-30 * 24 * time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("PruneLedger = %d, %v", n, err)
	}
	if got, _ := s.LedgerState("old"); got != "" {
		t.Fatalf("pruned entry still present: %q", got)
	}
	if got, _ := s.LedgerState("cmd-1"); got != LedgerCompleted {
		t.Fatal("pruning must keep recent entries")
	}

	if err := s.Destroy(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("state file still exists: %v", err)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/agent/state/`
Expected: FAIL — `undefined: Open`.

- [ ] **Step 4: Implement the store**

`internal/agent/state/state.go`:

```go
// Package state is the agent's durable local store: results waiting to be
// sent, which commands have already run, and the last inventory hash.
package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"

	"retune/internal/protocol"
)

// Ledger states.
const (
	LedgerStarted   = "started"
	LedgerCompleted = "completed"
)

var (
	bucketResults = []byte("results")
	bucketLedger  = []byte("ledger")
	bucketMeta    = []byte("meta")
	keyInventory  = []byte("inventory_hash")
)

// Store is the agent's bbolt database.
type Store struct {
	db   *bolt.DB
	path string
}

// QueuedResult is a command result waiting to reach the server.
type QueuedResult struct {
	CommandID string                 `json:"command_id"`
	Result    protocol.CommandResult `json:"result"`
}

type ledgerEntry struct {
	State string    `json:"state"`
	At    time.Time `json:"at"`
}

// Open creates or opens the state database.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, fmt.Errorf("open agent state %s: %w", path, err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketResults, bucketLedger, bucketMeta} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, path: path}, nil
}

// Close releases the database file.
func (s *Store) Close() error { return s.db.Close() }

// Destroy closes the database and deletes it, for unenrollment.
func (s *Store) Destroy() error {
	if err := s.db.Close(); err != nil {
		return err
	}
	if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// QueueResult stores a result to send at the next opportunity.
func (s *Store) QueueResult(r QueuedResult) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := json.Marshal(r)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketResults).Put([]byte(r.CommandID), b)
	})
}

// PendingResults returns queued results ordered by command ID (UUIDv7 IDs sort
// oldest first).
func (s *Store) PendingResults() ([]QueuedResult, error) {
	var out []QueuedResult
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketResults).ForEach(func(_, v []byte) error {
			var r QueuedResult
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			out = append(out, r)
			return nil
		})
	})
	return out, err
}

// DeleteResult drops a result the server has accepted.
func (s *Store) DeleteResult(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketResults).Delete([]byte(id))
	})
}

// MarkStarted records that a command is about to run. It reports false when
// the command was already seen, which is how repeat deliveries are ignored.
func (s *Store) MarkStarted(id string, at time.Time) (bool, error) {
	first := false
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketLedger)
		if b.Get([]byte(id)) != nil {
			return nil
		}
		first = true
		return putJSON(b, id, ledgerEntry{State: LedgerStarted, At: at})
	})
	return first, err
}

// MarkCompleted records that a command finished and its result is stored.
func (s *Store) MarkCompleted(id string, at time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return putJSON(tx.Bucket(bucketLedger), id, ledgerEntry{State: LedgerCompleted, At: at})
	})
}

// LedgerState returns LedgerStarted, LedgerCompleted, or "" if unknown.
func (s *Store) LedgerState(id string) (string, error) {
	var e ledgerEntry
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketLedger).Get([]byte(id))
		if v == nil {
			return nil
		}
		return json.Unmarshal(v, &e)
	})
	return e.State, err
}

// PruneLedger removes entries older than before and returns how many went.
func (s *Store) PruneLedger(before time.Time) (int, error) {
	removed := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketLedger).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var e ledgerEntry
			if err := json.Unmarshal(v, &e); err != nil || e.At.Before(before) {
				if err := c.Delete(); err != nil {
					return err
				}
				removed++
			}
		}
		return nil
	})
	return removed, err
}

// InventoryHash is the hash the server acknowledged for the last upload.
func (s *Store) InventoryHash() (string, error) {
	var hash string
	err := s.db.View(func(tx *bolt.Tx) error {
		hash = string(tx.Bucket(bucketMeta).Get(keyInventory))
		return nil
	})
	return hash, err
}

// SetInventoryHash records the hash the server acknowledged.
func (s *Store) SetInventoryHash(hash string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketMeta).Put(keyInventory, []byte(hash))
	})
}

func putJSON(b *bolt.Bucket, key string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return b.Put([]byte(key), raw)
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go mod tidy && go vet ./internal/agent/state/ && go test ./internal/agent/state/`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/agent/state
git commit -m "feat(agent): bbolt state for queued results, command ledger, inventory hash"
```

---

### Task 10: Single-file identity and new client calls

**Files:**
- Modify: `internal/agent/identity/identity.go`, `internal/agent/identity/identity_test.go`, `internal/agent/client/client.go`
- Create: `internal/agent/client/client_m2_test.go`

**Interfaces:**
- Consumes: Task 1 protocol types
- Produces:
  - `identity.json` now holds the sealed key (`sealed_key`), so a renewal is one atomic file write; a legacy `key.bin` is still read and removed on the next save
  - `(identity.Store).Delete() error`; `(*identity.Identity).CertNotAfter() (time.Time, error)`
  - `(*client.Client).PutInventory(ctx, protocol.Inventory) (protocol.InventoryResponse, error)`, `StartCommand(ctx, id string) error`, `SubmitResult(ctx, id string, protocol.CommandResult) error`, `Renew(ctx, protocol.RenewRequest) (protocol.RenewResponse, error)`

- [ ] **Step 1: Write the failing tests**

Replace `TestStoreRoundTrip` in `internal/agent/identity/identity_test.go` and add the new tests:

```go
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

	raw, err := os.ReadFile(filepath.Join(s.Dir, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalECPrivateKey(key)
	if bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(der))) {
		t.Fatal("identity.json must hold the sealed key, not the raw key")
	}
	if _, err := os.Stat(filepath.Join(s.Dir, "key.bin")); !os.IsNotExist(err) {
		t.Fatal("the key must live inside identity.json")
	}

	got, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.DeviceID != "d1" || got.ServerURL != "https://mdm" || got.ServerPin != "sha256:ab" ||
		got.CertPEM != "cert" || got.CAPEM != "ca" || !got.Key.Equal(key) {
		t.Fatalf("loaded identity = %+v", got)
	}

	if err := s.Delete(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("Load after Delete = %v", err)
	}
	if err := s.Delete(); err != nil {
		t.Fatalf("Delete must be repeatable: %v", err)
	}
}

func TestLoadLegacyKeyFile(t *testing.T) {
	dir := t.TempDir()
	s := Store{Dir: dir, Keys: xorKeys{}}
	key, _, err := NewKeyAndCSR("PC-1")
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalECPrivateKey(key)
	sealed, _ := xorKeys{}.Protect(der)
	if err := os.WriteFile(filepath.Join(dir, "key.bin"), sealed, 0o600); err != nil {
		t.Fatal(err)
	}
	meta := `{"device_id":"d1","server_url":"https://mdm","cert_pem":"cert","ca_pem":"ca"}`
	if err := os.WriteFile(filepath.Join(dir, "identity.json"), []byte(meta), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := s.Load()
	if err != nil || !got.Key.Equal(key) {
		t.Fatalf("legacy load = %+v, err = %v", got, err)
	}
	if err := s.Save(got); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "key.bin")); !os.IsNotExist(err) {
		t.Fatal("saving must clean up the legacy key file")
	}
}

func TestCertNotAfter(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	notAfter := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: notAfter.Add(-time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	id := &Identity{CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
	got, err := id.CertNotAfter()
	if err != nil || !got.Equal(notAfter) {
		t.Fatalf("CertNotAfter = %s, err = %v", got, err)
	}
	if _, err := (&Identity{CertPEM: "junk"}).CertNotAfter(); err == nil {
		t.Fatal("a malformed certificate must error")
	}
}
```

That file's imports become:

```go
import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)
```

`internal/agent/client/client_m2_test.go`:

```go
package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"retune/internal/pki"
	"retune/internal/protocol"
)

func TestM2Calls(t *testing.T) {
	ctx := context.Background()
	var gotMethod, gotPath string
	var gotBody []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/agent/v1/inventory":
			_ = json.NewEncoder(w).Encode(protocol.InventoryResponse{Hash: "h1"})
		case "/api/agent/v1/renew":
			_ = json.NewEncoder(w).Encode(protocol.RenewResponse{CertPEM: "new-cert"})
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()

	c, err := New(srv.URL, pki.Fingerprint(srv.Certificate().Raw), nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.PutInventory(ctx, protocol.Inventory{Hostname: "PC-1"})
	if err != nil || resp.Hash != "h1" {
		t.Fatalf("PutInventory = %+v, err = %v", resp, err)
	}
	if gotMethod != http.MethodPut || gotPath != "/api/agent/v1/inventory" {
		t.Fatalf("inventory request = %s %s", gotMethod, gotPath)
	}

	if err := c.StartCommand(ctx, "cmd-1"); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPost || gotPath != "/api/agent/v1/commands/cmd-1/start" {
		t.Fatalf("start request = %s %s", gotMethod, gotPath)
	}

	result := protocol.CommandResult{Status: protocol.ResultSucceeded, Stdout: "out"}
	if err := c.SubmitResult(ctx, "cmd-1", result); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/agent/v1/commands/cmd-1/result" {
		t.Fatalf("result path = %s", gotPath)
	}
	var sent protocol.CommandResult
	if err := json.Unmarshal(gotBody, &sent); err != nil || sent.Stdout != "out" {
		t.Fatalf("result body = %s, err = %v", gotBody, err)
	}

	renewed, err := c.Renew(ctx, protocol.RenewRequest{CSRPEM: "csr"})
	if err != nil || renewed.CertPEM != "new-cert" {
		t.Fatalf("Renew = %+v, err = %v", renewed, err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/agent/identity/ ./internal/agent/client/`
Expected: FAIL — `s.Delete undefined`, `c.PutInventory undefined`.

- [ ] **Step 3: Rework the identity store**

In `internal/agent/identity/identity.go`, add the file format and replace `Save`/`Load`, then add `Delete` and `CertNotAfter`:

```go
// fileFormat is identity.json on disk: the identity plus its sealed key, so a
// renewal replaces key and certificate in one atomic write.
type fileFormat struct {
	Identity
	SealedKey []byte `json:"sealed_key"`
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
	meta, err := json.MarshalIndent(fileFormat{Identity: *id, SealedKey: sealed}, "", "  ")
	if err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(s.Dir, "identity.json"), meta); err != nil {
		return err
	}
	// Clean up the pre-M2 layout.
	if err := os.Remove(filepath.Join(s.Dir, legacyKeyFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func (s Store) Load() (*Identity, error) {
	meta, err := os.ReadFile(filepath.Join(s.Dir, "identity.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotEnrolled
	}
	if err != nil {
		return nil, err
	}
	var f fileFormat
	if err := json.Unmarshal(meta, &f); err != nil {
		return nil, fmt.Errorf("parse identity.json: %w", err)
	}
	sealed := f.SealedKey
	if len(sealed) == 0 {
		if sealed, err = os.ReadFile(filepath.Join(s.Dir, legacyKeyFile)); err != nil {
			return nil, fmt.Errorf("read device key: %w", err)
		}
	}
	der, err := s.Keys.Unprotect(sealed)
	if err != nil {
		return nil, err
	}
	id := f.Identity
	if id.Key, err = x509.ParseECPrivateKey(der); err != nil {
		return nil, fmt.Errorf("parse device key: %w", err)
	}
	return &id, nil
}

// Delete removes the stored identity, for unenrollment.
func (s Store) Delete() error {
	for _, name := range []string{"identity.json", legacyKeyFile} {
		if err := os.Remove(filepath.Join(s.Dir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}
```

Add the constant next to `ErrNotEnrolled`:

```go
// legacyKeyFile is the separate sealed-key file written before M2.
const legacyKeyFile = "key.bin"
```

And add, next to `TLSCertificate`:

```go
// CertNotAfter is when the current client certificate expires.
func (id *Identity) CertNotAfter() (time.Time, error) {
	b, _ := pem.Decode([]byte(id.CertPEM))
	if b == nil || b.Type != "CERTIFICATE" {
		return time.Time{}, errors.New("identity certificate is not PEM CERTIFICATE")
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse identity certificate: %w", err)
	}
	return cert.NotAfter, nil
}
```

Add `"time"` to that file's imports.

- [ ] **Step 4: Add the client calls**

In `internal/agent/client/client.go`, replace `post` with a general `do` and append the new methods:

```go
func (c *Client) post(ctx context.Context, path string, in, out any) error {
	return c.do(ctx, http.MethodPost, path, in, out)
}

// do sends a JSON request and decodes a JSON response. in may be nil for an
// empty body; out may be nil when no response body is expected.
func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusNoContent {
		var e protocol.Error
		_ = json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&e)
		return &HTTPError{Status: res.StatusCode, Code: e.Code, Message: e.Message}
	}
	if out == nil || res.StatusCode == http.StatusNoContent {
		_, _ = io.Copy(io.Discard, res.Body)
		return nil
	}
	if err := json.NewDecoder(res.Body).Decode(out); err != nil {
		return fmt.Errorf("decode %s response: %w", path, err)
	}
	return nil
}

// PutInventory uploads a full inventory document and returns the hash the
// server stored.
func (c *Client) PutInventory(ctx context.Context, inv protocol.Inventory) (protocol.InventoryResponse, error) {
	var resp protocol.InventoryResponse
	err := c.do(ctx, http.MethodPut, "/api/agent/v1/inventory", inv, &resp)
	return resp, err
}

// StartCommand reports that execution has begun.
func (c *Client) StartCommand(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPost, "/api/agent/v1/commands/"+url.PathEscape(id)+"/start", nil, nil)
}

// SubmitResult reports a finished command.
func (c *Client) SubmitResult(ctx context.Context, id string, r protocol.CommandResult) error {
	return c.do(ctx, http.MethodPost, "/api/agent/v1/commands/"+url.PathEscape(id)+"/result", r, nil)
}

// Renew exchanges a CSR for a fresh client certificate.
func (c *Client) Renew(ctx context.Context, req protocol.RenewRequest) (protocol.RenewResponse, error) {
	var resp protocol.RenewResponse
	err := c.do(ctx, http.MethodPost, "/api/agent/v1/renew", req, &resp)
	return resp, err
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go vet ./internal/agent/... && go test ./internal/agent/identity/ ./internal/agent/client/`
Expected: PASS (on Windows the DPAPI test runs too).

- [ ] **Step 6: Commit**

```bash
git add internal/agent/identity internal/agent/client
git commit -m "feat(agent): single-file identity plus inventory, command and renew calls"
```

---

### Task 11: Command executor

**Files:**
- Create: `internal/agent/executor/executor.go`, `internal/agent/executor/capped.go`, `internal/agent/executor/runner_windows.go`, `internal/agent/executor/runner_other.go`, `internal/agent/executor/executor_test.go`, `internal/agent/executor/runner_windows_test.go`

**Interfaces:**
- Consumes: Task 1 protocol types
- Produces:
  - `executor.Runner` interface `{ RunPowerShell(ctx, script string, stdout, stderr io.Writer) (exitCode int, err error) }`
  - `executor.Restarter` interface `{ Restart(delay time.Duration, message string) error }`
  - `executor.Executor{Runner Runner; Restarter Restarter; RefreshInventory func(ctx) error; Now func() time.Time}` with `Execute(ctx, protocol.Command) protocol.CommandResult`
  - `executor.DefaultRunner(scriptDir string) Runner`, `executor.DefaultRestarter() Restarter` (real on Windows, refusing elsewhere)

- [ ] **Step 1: Write the failing test**

`internal/agent/executor/executor_test.go`:

```go
package executor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"retune/internal/protocol"
)

type fakeRunner struct {
	code      int
	err       error
	stdout    string
	stderr    string
	block     bool
	gotScript string
}

func (f *fakeRunner) RunPowerShell(ctx context.Context, script string, stdout, stderr io.Writer) (int, error) {
	f.gotScript = script
	if f.block {
		<-ctx.Done()
		return -1, ctx.Err()
	}
	_, _ = io.WriteString(stdout, f.stdout)
	_, _ = io.WriteString(stderr, f.stderr)
	return f.code, f.err
}

type fakeRestarter struct {
	delay time.Duration
	msg   string
	err   error
}

func (f *fakeRestarter) Restart(d time.Duration, m string) error {
	f.delay, f.msg = d, m
	return f.err
}

func cmd(t *testing.T, typ string, payload any) protocol.Command {
	t.Helper()
	var raw json.RawMessage
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		raw = b
	}
	return protocol.Command{ID: "c1", Type: typ, Payload: raw}
}

func newExecutor(r Runner, rs Restarter, refresh func(context.Context) error) *Executor {
	if refresh == nil {
		refresh = func(context.Context) error { return nil }
	}
	return &Executor{Runner: r, Restarter: rs, RefreshInventory: refresh, Now: time.Now}
}

func TestRunPowerShell(t *testing.T) {
	ctx := context.Background()
	t.Run("success", func(t *testing.T) {
		r := &fakeRunner{stdout: "hello", stderr: "note"}
		res := newExecutor(r, nil, nil).Execute(ctx, cmd(t, protocol.CommandRunPowerShell,
			protocol.RunPowerShellPayload{Script: "Get-Date", TimeoutSeconds: 30}))
		if res.Status != protocol.ResultSucceeded || res.ExitCode != 0 || res.Stdout != "hello" || res.Stderr != "note" {
			t.Fatalf("result = %+v", res)
		}
		if r.gotScript != "Get-Date" {
			t.Fatalf("script = %q", r.gotScript)
		}
		if res.FinishedAt.Before(res.StartedAt) {
			t.Fatal("FinishedAt must not precede StartedAt")
		}
	})
	t.Run("non-zero exit", func(t *testing.T) {
		res := newExecutor(&fakeRunner{code: 3}, nil, nil).Execute(ctx, cmd(t, protocol.CommandRunPowerShell,
			protocol.RunPowerShellPayload{Script: "exit 3", TimeoutSeconds: 30}))
		if res.Status != protocol.ResultFailed || res.ExitCode != 3 {
			t.Fatalf("result = %+v", res)
		}
	})
	t.Run("runner error", func(t *testing.T) {
		res := newExecutor(&fakeRunner{err: errors.New("powershell missing")}, nil, nil).Execute(ctx,
			cmd(t, protocol.CommandRunPowerShell, protocol.RunPowerShellPayload{Script: "x", TimeoutSeconds: 30}))
		if res.Status != protocol.ResultFailed || res.ExitCode != -1 || !strings.Contains(res.Error, "powershell missing") {
			t.Fatalf("result = %+v", res)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		res := newExecutor(&fakeRunner{block: true}, nil, nil).Execute(ctx,
			cmd(t, protocol.CommandRunPowerShell, protocol.RunPowerShellPayload{Script: "sleep", TimeoutSeconds: 1}))
		if res.Status != protocol.ResultTimedOut || res.ExitCode != -1 || !strings.Contains(res.Error, "timed out") {
			t.Fatalf("result = %+v", res)
		}
	})
	t.Run("output is capped", func(t *testing.T) {
		r := &fakeRunner{stdout: strings.Repeat("x", protocol.MaxOutputBytes+10)}
		res := newExecutor(r, nil, nil).Execute(ctx, cmd(t, protocol.CommandRunPowerShell,
			protocol.RunPowerShellPayload{Script: "big", TimeoutSeconds: 30}))
		if len(res.Stdout) != protocol.MaxOutputBytes || !res.StdoutTruncated {
			t.Fatalf("stdout len = %d truncated = %v", len(res.Stdout), res.StdoutTruncated)
		}
	})
	t.Run("invalid payload", func(t *testing.T) {
		res := newExecutor(&fakeRunner{}, nil, nil).Execute(ctx, protocol.Command{ID: "c1", Type: protocol.CommandRunPowerShell, Payload: json.RawMessage(`{`)})
		if res.Status != protocol.ResultFailed || res.Error == "" {
			t.Fatalf("result = %+v", res)
		}
	})
	t.Run("empty script", func(t *testing.T) {
		res := newExecutor(&fakeRunner{}, nil, nil).Execute(ctx, cmd(t, protocol.CommandRunPowerShell, protocol.RunPowerShellPayload{}))
		if res.Status != protocol.ResultFailed {
			t.Fatalf("result = %+v", res)
		}
	})
}

func TestRestartAndRefresh(t *testing.T) {
	ctx := context.Background()
	rs := &fakeRestarter{}
	res := newExecutor(&fakeRunner{}, rs, nil).Execute(ctx, cmd(t, protocol.CommandRestart,
		protocol.RestartPayload{DelaySeconds: 30, Message: "patching"}))
	if res.Status != protocol.ResultSucceeded || rs.delay != 30*time.Second || rs.msg != "patching" {
		t.Fatalf("result = %+v restarter = %+v", res, rs)
	}

	failing := &fakeRestarter{err: errors.New("access denied")}
	res = newExecutor(&fakeRunner{}, failing, nil).Execute(ctx, cmd(t, protocol.CommandRestart, protocol.RestartPayload{}))
	if res.Status != protocol.ResultFailed || !strings.Contains(res.Error, "access denied") {
		t.Fatalf("result = %+v", res)
	}

	called := false
	res = newExecutor(&fakeRunner{}, rs, func(context.Context) error { called = true; return nil }).
		Execute(ctx, cmd(t, protocol.CommandRefreshInventory, nil))
	if res.Status != protocol.ResultSucceeded || !called {
		t.Fatalf("result = %+v called = %v", res, called)
	}

	res = newExecutor(&fakeRunner{}, rs, func(context.Context) error { return errors.New("wmi unavailable") }).
		Execute(ctx, cmd(t, protocol.CommandRefreshInventory, nil))
	if res.Status != protocol.ResultFailed || !strings.Contains(res.Error, "wmi unavailable") {
		t.Fatalf("result = %+v", res)
	}
}

func TestUnknownType(t *testing.T) {
	res := newExecutor(&fakeRunner{}, &fakeRestarter{}, nil).Execute(context.Background(), cmd(t, "fly_to_moon", nil))
	if res.Status != protocol.ResultFailed || !strings.Contains(res.Error, "unsupported") {
		t.Fatalf("result = %+v", res)
	}
}

func TestCappedWriter(t *testing.T) {
	c := newCapped(8)
	if _, err := c.Write([]byte("12345")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("6789")); err != nil {
		t.Fatal(err)
	}
	if c.String() != "12345678" || !c.Truncated() {
		t.Fatalf("capped = %q truncated = %v", c.String(), c.Truncated())
	}

	invalid := newCapped(16)
	if _, err := invalid.Write([]byte{0xff, 'a'}); err != nil {
		t.Fatal(err)
	}
	if !strings.ContainsRune(invalid.String(), '�') || !strings.HasSuffix(invalid.String(), "a") {
		t.Fatalf("invalid UTF-8 not repaired: %q", invalid.String())
	}
}
```

`internal/agent/executor/runner_windows_test.go`:

```go
//go:build windows

package executor

import (
	"context"
	"strings"
	"testing"
	"time"

	"retune/internal/protocol"
)

func TestPowerShellRunner(t *testing.T) {
	e := &Executor{Runner: DefaultRunner(t.TempDir()), Now: time.Now}
	res := e.Execute(context.Background(), cmd(t, protocol.CommandRunPowerShell, protocol.RunPowerShellPayload{
		Script:         "Write-Output 'héllo'; [Console]::Error.WriteLine('oops'); exit 3",
		TimeoutSeconds: 60,
	}))
	if res.Status != protocol.ResultFailed || res.ExitCode != 3 {
		t.Fatalf("result = %+v", res)
	}
	if !strings.Contains(res.Stdout, "héllo") {
		t.Fatalf("stdout = %q (UTF-8 output must survive)", res.Stdout)
	}
	if !strings.Contains(res.Stderr, "oops") {
		t.Fatalf("stderr = %q", res.Stderr)
	}
}

func TestPowerShellRunnerTimeout(t *testing.T) {
	e := &Executor{Runner: DefaultRunner(t.TempDir()), Now: time.Now}
	res := e.Execute(context.Background(), cmd(t, protocol.CommandRunPowerShell, protocol.RunPowerShellPayload{
		Script: "Start-Sleep -Seconds 30", TimeoutSeconds: 2,
	}))
	if res.Status != protocol.ResultTimedOut {
		t.Fatalf("result = %+v", res)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/agent/executor/`
Expected: FAIL — no such package.

- [ ] **Step 3: Write the capped writer**

`internal/agent/executor/capped.go`:

```go
package executor

import (
	"bytes"
	"strings"
)

// capped collects up to limit bytes and remembers whether more arrived.
type capped struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func newCapped(limit int) *capped { return &capped{limit: limit} }

func (c *capped) Write(p []byte) (int, error) {
	room := c.limit - c.buf.Len()
	switch {
	case room <= 0:
		if len(p) > 0 {
			c.truncated = true
		}
	case len(p) > room:
		c.buf.Write(p[:room])
		c.truncated = true
	default:
		c.buf.Write(p)
	}
	return len(p), nil
}

// String returns the captured text with invalid UTF-8 repaired, so it is safe
// to put in JSON and in Postgres.
func (c *capped) String() string {
	return strings.ToValidUTF8(strings.ReplaceAll(c.buf.String(), "\x00", ""), "�")
}

func (c *capped) Truncated() bool { return c.truncated }
```

- [ ] **Step 4: Write the executor**

`internal/agent/executor/executor.go`:

```go
// Package executor runs the commands the server sends.
package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"retune/internal/protocol"
)

// Runner runs a PowerShell script, streaming its output.
type Runner interface {
	RunPowerShell(ctx context.Context, script string, stdout, stderr io.Writer) (exitCode int, err error)
}

// Restarter schedules a reboot.
type Restarter interface {
	Restart(delay time.Duration, message string) error
}

// Executor turns commands into results. It never returns an error: every
// outcome is reported as a CommandResult.
type Executor struct {
	Runner           Runner
	Restarter        Restarter
	RefreshInventory func(ctx context.Context) error
	Now              func() time.Time
}

// Execute runs one command.
func (e *Executor) Execute(ctx context.Context, c protocol.Command) protocol.CommandResult {
	res := protocol.CommandResult{Status: protocol.ResultSucceeded, StartedAt: e.now()}
	switch c.Type {
	case protocol.CommandRunPowerShell:
		e.runPowerShell(ctx, c.Payload, &res)
	case protocol.CommandRestart:
		e.restart(c.Payload, &res)
	case protocol.CommandRefreshInventory:
		if err := e.RefreshInventory(ctx); err != nil {
			fail(&res, fmt.Sprintf("refreshing inventory: %v", err))
		}
	default:
		fail(&res, fmt.Sprintf("unsupported command type %q", c.Type))
	}
	res.FinishedAt = e.now()
	return res
}

func (e *Executor) runPowerShell(ctx context.Context, raw json.RawMessage, res *protocol.CommandResult) {
	var p protocol.RunPowerShellPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		fail(res, fmt.Sprintf("invalid run_powershell payload: %v", err))
		return
	}
	if strings.TrimSpace(p.Script) == "" {
		fail(res, "run_powershell payload has no script")
		return
	}
	timeout := time.Duration(p.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	stdout, stderr := newCapped(protocol.MaxOutputBytes), newCapped(protocol.MaxOutputBytes)
	code, err := e.Runner.RunPowerShell(ctx, p.Script, stdout, stderr)
	res.Stdout, res.StdoutTruncated = stdout.String(), stdout.Truncated()
	res.Stderr, res.StderrTruncated = stderr.String(), stderr.Truncated()

	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		res.Status, res.ExitCode = protocol.ResultTimedOut, -1
		res.Error = fmt.Sprintf("timed out after %s", timeout)
	case err != nil:
		fail(res, err.Error())
	case code != 0:
		res.Status, res.ExitCode = protocol.ResultFailed, code
	default:
		res.ExitCode = 0
	}
}

func (e *Executor) restart(raw json.RawMessage, res *protocol.CommandResult) {
	var p protocol.RestartPayload
	if len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &p); err != nil {
			fail(res, fmt.Sprintf("invalid restart payload: %v", err))
			return
		}
	}
	if err := e.Restarter.Restart(time.Duration(p.DelaySeconds)*time.Second, p.Message); err != nil {
		fail(res, err.Error())
	}
}

func (e *Executor) now() time.Time {
	if e.Now == nil {
		return time.Now()
	}
	return e.Now()
}

func fail(res *protocol.CommandResult, msg string) {
	res.Status, res.ExitCode, res.Error = protocol.ResultFailed, -1, msg
}
```

- [ ] **Step 5: Write the platform runners**

`internal/agent/executor/runner_windows.go`:

```go
//go:build windows

package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"time"
)

// DefaultRunner runs scripts through powershell.exe, using scriptDir for the
// temporary .ps1 files.
func DefaultRunner(scriptDir string) Runner { return PowerShellRunner{ScriptDir: scriptDir} }

// DefaultRestarter reboots with shutdown.exe.
func DefaultRestarter() Restarter { return ShutdownRestarter{} }

// PowerShellRunner executes scripts from a file so any script length works.
type PowerShellRunner struct {
	ScriptDir string
}

// utf8Preamble makes redirected output UTF-8 instead of the console codepage.
const utf8Preamble = "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8\r\n" +
	"$OutputEncoding = [System.Text.Encoding]::UTF8\r\n"

func (r PowerShellRunner) RunPowerShell(ctx context.Context, script string, stdout, stderr io.Writer) (int, error) {
	if err := os.MkdirAll(r.ScriptDir, 0o700); err != nil {
		return -1, err
	}
	f, err := os.CreateTemp(r.ScriptDir, "cmd-*.ps1")
	if err != nil {
		return -1, err
	}
	defer os.Remove(f.Name())
	// The BOM makes PowerShell 5.1 read the file as UTF-8.
	if _, err := f.WriteString("﻿" + utf8Preamble + script); err != nil {
		f.Close()
		return -1, err
	}
	if err := f.Close(); err != nil {
		return -1, err
	}

	cmd := exec.CommandContext(ctx, "powershell.exe",
		"-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", f.Name())
	cmd.Stdout, cmd.Stderr = stdout, stderr
	// Do not hang forever on a child that keeps the pipes open after a kill.
	cmd.WaitDelay = 5 * time.Second

	err = cmd.Run()
	var exitErr *exec.ExitError
	switch {
	case errors.As(err, &exitErr):
		return exitErr.ExitCode(), nil
	case err != nil:
		return -1, fmt.Errorf("run powershell: %w", err)
	}
	return 0, nil
}

// ShutdownRestarter schedules a planned reboot.
type ShutdownRestarter struct{}

func (ShutdownRestarter) Restart(delay time.Duration, message string) error {
	args := []string{"/r", "/t", strconv.Itoa(int(delay.Seconds())), "/d", "p:0:0"}
	if message != "" {
		args = append(args, "/c", message)
	}
	out, err := exec.Command("shutdown.exe", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("schedule restart: %w: %s", err, out)
	}
	return nil
}
```

`internal/agent/executor/runner_other.go`:

```go
//go:build !windows

package executor

import (
	"context"
	"errors"
	"io"
	"time"
)

// errUnsupported is returned by the development stubs on non-Windows hosts.
var errUnsupported = errors.New("command execution is only implemented on Windows")

// DefaultRunner returns a stub until the macOS and Linux agents ship.
func DefaultRunner(string) Runner { return unsupported{} }

// DefaultRestarter returns a stub until the macOS and Linux agents ship.
func DefaultRestarter() Restarter { return unsupported{} }

type unsupported struct{}

func (unsupported) RunPowerShell(context.Context, string, io.Writer, io.Writer) (int, error) {
	return -1, errUnsupported
}

func (unsupported) Restart(time.Duration, string) error { return errUnsupported }
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `go vet ./internal/agent/executor/ && go test ./internal/agent/executor/`
Expected: PASS (on Windows the two real-PowerShell tests run and take a few seconds).

- [ ] **Step 7: Commit**

```bash
git add internal/agent/executor
git commit -m "feat(agent): command executor with PowerShell runner and output caps"
```

---

### Task 12: Inventory collector

**Files:**
- Create: `internal/agent/inventory/collector.go`, `internal/agent/inventory/software.go`, `internal/agent/inventory/collector_test.go`, `internal/agent/inventory/collector_windows.go`, `internal/agent/inventory/collector_other.go`, `internal/agent/inventory/collector_windows_test.go`
- Modify: `internal/agent/facts/facts.go`

**Interfaces:**
- Consumes: Task 1 protocol types
- Produces:
  - `inventory.Collector` interface `{ Collect(ctx) (protocol.Inventory, error) }`; `inventory.NewCollector() Collector`
  - `inventory.HardwareIdentity() (serial, smbiosUUID string)`, `inventory.LoggedInUser() string`
  - `inventory.UninstallEntry{DisplayName, DisplayVersion, Publisher, InstallDate, ParentKeyName string; SystemComponent uint64}`
  - `inventory.NormalizeSoftware(entries []UninstallEntry, scope string) []protocol.Software`
  - `inventory.CleanSerial(string) string`, `inventory.CleanUUID(string) string`, `inventory.ParseQFEDate(string) (time.Time, bool)`
  - `facts.Device()` now reports the real serial and SMBIOS UUID; `facts.Checkin()` reports the logged-in user

- [ ] **Step 1: Add the dependency**

```bash
go get github.com/yusufpapurcu/wmi@latest
```

- [ ] **Step 2: Write the failing test**

`internal/agent/inventory/collector_test.go`:

```go
package inventory

import (
	"testing"
	"time"
)

func TestNormalizeSoftware(t *testing.T) {
	entries := []UninstallEntry{
		{DisplayName: "Git", DisplayVersion: "2.51.0", Publisher: "Git Dev"},
		{DisplayName: "7-Zip", DisplayVersion: "24.08"},
		{DisplayName: "Git", DisplayVersion: "2.51.0", Publisher: "Git Dev"}, // 32- and 64-bit duplicate
		{DisplayName: "  ", DisplayVersion: "1"},                             // no name
		{DisplayName: "Hidden", SystemComponent: 1},                          // system component
		{DisplayName: "KB12345", ParentKeyName: "Office"},                    // update of another product
		{DisplayName: "Go", DisplayVersion: "1.27", InstallDate: "20260901"},
	}
	got := NormalizeSoftware(entries, "machine")
	if len(got) != 3 {
		t.Fatalf("got %d packages: %+v", len(got), got)
	}
	if got[0].Name != "7-Zip" || got[1].Name != "Git" || got[2].Name != "Go" {
		t.Fatalf("unexpected order or filtering: %+v", got)
	}
	if got[1].Publisher != "Git Dev" || got[1].Scope != "machine" || got[2].InstallDate != "20260901" {
		t.Fatalf("fields not carried over: %+v", got)
	}
	if NormalizeSoftware(nil, "user") != nil {
		t.Fatal("no entries must give no packages")
	}
}

func TestCleanSerialAndUUID(t *testing.T) {
	junkSerials := []string{"", "  ", "0", "None", "Default string", "To Be Filled By O.E.M.", "System Serial Number"}
	for _, s := range junkSerials {
		if got := CleanSerial(s); got != "" {
			t.Errorf("CleanSerial(%q) = %q, want empty", s, got)
		}
	}
	if got := CleanSerial("  ABC123 "); got != "ABC123" {
		t.Errorf("CleanSerial = %q", got)
	}

	junkUUIDs := []string{"", "00000000-0000-0000-0000-000000000000", "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF", "03000200-0400-0500-0006-000700080009"}
	for _, s := range junkUUIDs {
		if got := CleanUUID(s); got != "" {
			t.Errorf("CleanUUID(%q) = %q, want empty", s, got)
		}
	}
	if got := CleanUUID(" 4c4c4544-0044-3610 "); got != "4C4C4544-0044-3610" {
		t.Errorf("CleanUUID = %q", got)
	}
}

func TestParseQFEDate(t *testing.T) {
	for _, in := range []string{"9/12/2026", "09/12/2026", "2026-09-12"} {
		got, ok := ParseQFEDate(in)
		if !ok || got.Year() != 2026 || got.Month() != time.September || got.Day() != 12 {
			t.Errorf("ParseQFEDate(%q) = %s, %v", in, got, ok)
		}
	}
	if _, ok := ParseQFEDate("not a date"); ok {
		t.Error("unparseable dates must report false")
	}
}
```

`internal/agent/inventory/collector_windows_test.go`:

```go
//go:build windows

package inventory

import (
	"context"
	"strings"
	"testing"
)

// TestCollectOnThisMachine checks the real collector against the host it runs
// on. BitLocker, TPM and admin-group data need elevation, so they are not
// asserted here.
func TestCollectOnThisMachine(t *testing.T) {
	inv, err := NewCollector().Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if inv.Hostname == "" || inv.CollectedAt.IsZero() {
		t.Fatalf("inventory = %+v", inv)
	}
	if !strings.Contains(inv.OS.Name, "Windows") || inv.OS.Build == "" || inv.OS.Version == "" {
		t.Fatalf("OS = %+v", inv.OS)
	}
	if inv.Hardware.RAMBytes == 0 || inv.Hardware.CPU == "" || inv.Hardware.CPULogical == 0 {
		t.Fatalf("hardware = %+v", inv.Hardware)
	}
	if len(inv.Disks) == 0 {
		t.Fatal("expected at least one fixed disk")
	}
	if len(inv.Software) == 0 {
		t.Fatal("expected at least one installed package")
	}
	if len(inv.LocalUsers) == 0 {
		t.Fatal("expected at least one local user")
	}
}

func TestHardwareIdentityOnThisMachine(t *testing.T) {
	serial, smbios := HardwareIdentity()
	t.Logf("serial=%q smbios=%q logged in=%q", serial, smbios, LoggedInUser())
	if strings.TrimSpace(serial) != serial || strings.TrimSpace(smbios) != smbios {
		t.Fatal("identity values must be trimmed")
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/agent/inventory/`
Expected: FAIL — no such package.

- [ ] **Step 4: Write the shared helpers**

`internal/agent/inventory/collector.go`:

```go
// Package inventory collects the device inventory the server stores.
package inventory

import (
	"context"
	"strings"
	"time"

	"retune/internal/protocol"
)

// Collector gathers a full inventory document.
type Collector interface {
	Collect(ctx context.Context) (protocol.Inventory, error)
}

// junkSerials are placeholder values some firmware reports. Treating them as
// real would make unrelated machines look like the same reimaged device.
var junkSerials = map[string]bool{
	"":                        true,
	"0":                       true,
	"none":                    true,
	"default string":          true,
	"to be filled by o.e.m.":  true,
	"system serial number":    true,
	"chassis serial number":   true,
	"not specified":           true,
	"not applicable":          true,
	"123456789":               true,
	"0123456789":              true,
	"invalid":                 true,
}

// junkUUIDs are placeholder SMBIOS UUIDs.
var junkUUIDs = map[string]bool{
	"":                                     true,
	"00000000-0000-0000-0000-000000000000": true,
	"FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF": true,
	"03000200-0400-0500-0006-000700080009": true,
}

// CleanSerial trims a firmware serial and drops known placeholders.
func CleanSerial(s string) string {
	t := strings.TrimSpace(s)
	if junkSerials[strings.ToLower(t)] {
		return ""
	}
	return t
}

// CleanUUID upper-cases an SMBIOS UUID and drops known placeholders.
func CleanUUID(s string) string {
	t := strings.ToUpper(strings.TrimSpace(s))
	if junkUUIDs[t] {
		return ""
	}
	return t
}

// ParseQFEDate reads the InstalledOn value of Win32_QuickFixEngineering,
// which differs by locale.
func ParseQFEDate(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	for _, layout := range []string{"1/2/2006", "01/02/2006", "2006-01-02", "20060102"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}
```

`internal/agent/inventory/software.go`:

```go
package inventory

import (
	"cmp"
	"slices"
	"strings"

	"retune/internal/protocol"
)

// UninstallEntry is one subkey of a Windows Uninstall registry key.
type UninstallEntry struct {
	DisplayName     string
	DisplayVersion  string
	Publisher       string
	InstallDate     string
	ParentKeyName   string
	SystemComponent uint64
}

// NormalizeSoftware turns raw registry entries into a sorted, deduplicated
// package list. Entries without a name, hidden system components, and updates
// that belong to another product are dropped.
func NormalizeSoftware(entries []UninstallEntry, scope string) []protocol.Software {
	var out []protocol.Software
	seen := map[string]bool{}
	for _, e := range entries {
		name := strings.TrimSpace(e.DisplayName)
		if name == "" || e.SystemComponent == 1 || strings.TrimSpace(e.ParentKeyName) != "" {
			continue
		}
		version := strings.TrimSpace(e.DisplayVersion)
		key := strings.ToLower(name) + "\x00" + version
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, protocol.Software{
			Name:        name,
			Version:     version,
			Publisher:   strings.TrimSpace(e.Publisher),
			InstallDate: strings.TrimSpace(e.InstallDate),
			Scope:       scope,
		})
	}
	slices.SortFunc(out, func(a, b protocol.Software) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Version, b.Version))
	})
	return out
}
```

- [ ] **Step 5: Write the Windows collector**

`internal/agent/inventory/collector_windows.go`:

```go
//go:build windows

package inventory

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/yusufpapurcu/wmi"
	"golang.org/x/sys/windows/registry"

	"retune/internal/protocol"
)

// NewCollector returns the Windows collector.
func NewCollector() Collector { return WindowsCollector{} }

// WindowsCollector reads inventory from WMI and the registry. Sections that
// need elevation (BitLocker, TPM, group membership) are skipped when denied
// rather than failing the whole collection.
type WindowsCollector struct{}

type win32OperatingSystem struct {
	Caption        string
	Version        string
	BuildNumber    string
	InstallDate    time.Time
	LastBootUpTime time.Time
}

type win32ComputerSystem struct {
	Manufacturer        string
	Model               string
	TotalPhysicalMemory uint64
}

type win32Processor struct {
	Name                      string
	NumberOfCores             uint32
	NumberOfLogicalProcessors uint32
}

type win32LogicalDisk struct {
	DeviceID   string
	FileSystem string
	Size       uint64
	FreeSpace  uint64
}

type win32EncryptableVolume struct {
	DriveLetter      string
	ProtectionStatus uint32
}

type win32Tpm struct {
	SpecVersion string
}

type win32NetworkAdapterConfiguration struct {
	Description string
	MACAddress  string
	IPAddress   []string
}

type win32UserAccount struct {
	Name     string
	Disabled bool
}

type win32Account struct {
	Name   string
	Domain string
}

type win32BIOS struct {
	SerialNumber string
}

type win32ComputerSystemProduct struct {
	UUID string
}

type win32UserName struct {
	UserName string
}

type win32QuickFixEngineering struct {
	InstalledOn string
}

// Collect gathers the full inventory document.
func (WindowsCollector) Collect(_ context.Context) (protocol.Inventory, error) {
	inv := protocol.Inventory{CollectedAt: time.Now().UTC()}
	inv.Hostname, _ = os.Hostname()

	var osRows []win32OperatingSystem
	if err := queryOne("SELECT Caption, Version, BuildNumber, InstallDate, LastBootUpTime FROM Win32_OperatingSystem", &osRows); err != nil {
		return inv, err
	}
	o := osRows[0]
	inv.OS = protocol.OSInfo{
		Name: strings.TrimSpace(o.Caption), Version: o.Version, Build: o.BuildNumber,
		InstallDate: timePtr(o.InstallDate), LastBoot: timePtr(o.LastBootUpTime),
	}

	var csRows []win32ComputerSystem
	if err := queryOne("SELECT Manufacturer, Model, TotalPhysicalMemory FROM Win32_ComputerSystem", &csRows); err != nil {
		return inv, err
	}
	serial, smbios := HardwareIdentity()
	inv.Hardware = protocol.Hardware{
		Manufacturer: strings.TrimSpace(csRows[0].Manufacturer),
		Model:        strings.TrimSpace(csRows[0].Model),
		Serial:       serial,
		SMBIOSUUID:   smbios,
		RAMBytes:     csRows[0].TotalPhysicalMemory,
	}

	var cpus []win32Processor
	if wmi.Query("SELECT Name, NumberOfCores, NumberOfLogicalProcessors FROM Win32_Processor", &cpus) == nil && len(cpus) > 0 {
		inv.Hardware.CPU = strings.TrimSpace(cpus[0].Name)
		for _, c := range cpus {
			inv.Hardware.CPUCores += int(c.NumberOfCores)
			inv.Hardware.CPULogical += int(c.NumberOfLogicalProcessors)
		}
	}
	var tpm []win32Tpm
	if wmi.QueryNamespace("SELECT SpecVersion FROM Win32_Tpm", &tpm, `root\CIMV2\Security\MicrosoftTpm`) == nil && len(tpm) > 0 {
		inv.Hardware.TPMPresent = true
		inv.Hardware.TPMVersion = strings.TrimSpace(strings.Split(tpm[0].SpecVersion, ",")[0])
	}

	inv.Disks = collectDisks()
	inv.NetworkAdapters = collectAdapters()
	inv.Software = collectSoftware()
	inv.LocalUsers = collectLocalUsers()
	inv.LocalAdmins = collectLocalAdmins()
	inv.PendingReboot = pendingReboot()
	inv.LastUpdateInstalledAt = lastUpdateInstalled()
	return inv, nil
}

// HardwareIdentity returns the firmware serial and SMBIOS UUID, with
// placeholder values dropped.
func HardwareIdentity() (string, string) {
	var serial, smbios string
	var bios []win32BIOS
	if wmi.Query("SELECT SerialNumber FROM Win32_BIOS", &bios) == nil && len(bios) > 0 {
		serial = CleanSerial(bios[0].SerialNumber)
	}
	var product []win32ComputerSystemProduct
	if wmi.Query("SELECT UUID FROM Win32_ComputerSystemProduct", &product) == nil && len(product) > 0 {
		smbios = CleanUUID(product[0].UUID)
	}
	return serial, smbios
}

// LoggedInUser is the interactive user, or "" when nobody is signed in.
func LoggedInUser() string {
	var rows []win32UserName
	if wmi.Query("SELECT UserName FROM Win32_ComputerSystem", &rows) != nil || len(rows) == 0 {
		return ""
	}
	return strings.TrimSpace(rows[0].UserName)
}

func queryOne[T any](query string, dst *[]T) error {
	if err := wmi.Query(query, dst); err != nil {
		return fmt.Errorf("WMI %q: %w", query, err)
	}
	if len(*dst) == 0 {
		return fmt.Errorf("WMI %q returned no rows", query)
	}
	return nil
}

func collectDisks() []protocol.Disk {
	var rows []win32LogicalDisk
	if wmi.Query("SELECT DeviceID, FileSystem, Size, FreeSpace FROM Win32_LogicalDisk WHERE DriveType = 3", &rows) != nil {
		return nil
	}
	encryption := bitLockerStatus()
	out := make([]protocol.Disk, 0, len(rows))
	for _, r := range rows {
		status := "unknown"
		if s, ok := encryption[strings.ToUpper(r.DeviceID)]; ok {
			status = s
		}
		out = append(out, protocol.Disk{
			Name: r.DeviceID, FileSystem: r.FileSystem,
			SizeBytes: r.Size, FreeBytes: r.FreeSpace, BitLocker: status,
		})
	}
	return out
}

// bitLockerStatus needs elevation; without it the map is empty and disks
// report "unknown".
func bitLockerStatus() map[string]string {
	var vols []win32EncryptableVolume
	if wmi.QueryNamespace("SELECT DriveLetter, ProtectionStatus FROM Win32_EncryptableVolume", &vols,
		`root\CIMV2\Security\MicrosoftVolumeEncryption`) != nil {
		return nil
	}
	out := map[string]string{}
	for _, v := range vols {
		letter := strings.ToUpper(strings.TrimSpace(v.DriveLetter))
		if letter == "" {
			continue
		}
		switch v.ProtectionStatus {
		case 1:
			out[letter] = "on"
		case 0:
			out[letter] = "off"
		default:
			out[letter] = "unknown"
		}
	}
	return out
}

func collectAdapters() []protocol.NetworkAdapter {
	var rows []win32NetworkAdapterConfiguration
	if wmi.Query("SELECT Description, MACAddress, IPAddress FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE", &rows) != nil {
		return nil
	}
	out := make([]protocol.NetworkAdapter, 0, len(rows))
	for _, r := range rows {
		out = append(out, protocol.NetworkAdapter{Name: r.Description, MAC: r.MACAddress, IPs: r.IPAddress})
	}
	return out
}

func collectLocalUsers() []protocol.LocalUser {
	var rows []win32UserAccount
	if wmi.Query("SELECT Name, Disabled FROM Win32_UserAccount WHERE LocalAccount = TRUE", &rows) != nil {
		return nil
	}
	out := make([]protocol.LocalUser, 0, len(rows))
	for _, r := range rows {
		out = append(out, protocol.LocalUser{Name: r.Name, Disabled: r.Disabled})
	}
	return out
}

// collectLocalAdmins resolves the Administrators group by SID, so it works on
// localized installs.
func collectLocalAdmins() []string {
	var groups []win32Account
	if wmi.Query("SELECT Name, Domain FROM Win32_Group WHERE LocalAccount = TRUE AND SID = 'S-1-5-32-544'", &groups) != nil || len(groups) == 0 {
		return nil
	}
	g := groups[0]
	query := fmt.Sprintf("ASSOCIATORS OF {Win32_Group.Domain='%s',Name='%s'} WHERE AssocClass = Win32_GroupUser Role = GroupComponent",
		g.Domain, g.Name)
	var members []win32Account
	if wmi.Query(query, &members) != nil {
		return nil
	}
	out := make([]string, 0, len(members))
	for _, m := range members {
		out = append(out, m.Domain+`\`+m.Name)
	}
	return out
}

const uninstallKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`

func collectSoftware() []protocol.Software {
	machine := append(
		readUninstall(registry.LOCAL_MACHINE, uninstallKey),
		readUninstall(registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`)...,
	)
	var user []UninstallEntry
	if sids, err := registry.USERS.ReadSubKeyNames(-1); err == nil {
		for _, sid := range sids {
			if strings.HasPrefix(sid, "S-1-5-21-") && !strings.HasSuffix(sid, "_Classes") {
				user = append(user, readUninstall(registry.USERS, sid+`\`+uninstallKey)...)
			}
		}
	}
	return append(NormalizeSoftware(machine, "machine"), NormalizeSoftware(user, "user")...)
}

func readUninstall(root registry.Key, path string) []UninstallEntry {
	k, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}
	out := make([]UninstallEntry, 0, len(names))
	for _, name := range names {
		sub, err := registry.OpenKey(k, name, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		var e UninstallEntry
		e.DisplayName, _, _ = sub.GetStringValue("DisplayName")
		e.DisplayVersion, _, _ = sub.GetStringValue("DisplayVersion")
		e.Publisher, _, _ = sub.GetStringValue("Publisher")
		e.InstallDate, _, _ = sub.GetStringValue("InstallDate")
		e.ParentKeyName, _, _ = sub.GetStringValue("ParentKeyName")
		e.SystemComponent, _, _ = sub.GetIntegerValue("SystemComponent")
		sub.Close()
		out = append(out, e)
	}
	return out
}

func pendingReboot() bool {
	for _, path := range []string{
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`,
	} {
		if k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE); err == nil {
			k.Close()
			return true
		}
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetStringsValue("PendingFileRenameOperations")
	return err == nil && len(v) > 0
}

func lastUpdateInstalled() *time.Time {
	var rows []win32QuickFixEngineering
	if wmi.Query("SELECT InstalledOn FROM Win32_QuickFixEngineering", &rows) != nil {
		return nil
	}
	var latest time.Time
	for _, r := range rows {
		if t, ok := ParseQFEDate(r.InstalledOn); ok && t.After(latest) {
			latest = t
		}
	}
	return timePtr(latest)
}
```

`internal/agent/inventory/collector_other.go`:

```go
//go:build !windows

package inventory

import (
	"context"
	"os"
	"runtime"
	"time"

	"retune/internal/protocol"
)

// NewCollector returns a minimal collector for development on non-Windows
// hosts; real collection arrives with the macOS and Linux agents.
func NewCollector() Collector { return basicCollector{} }

type basicCollector struct{}

func (basicCollector) Collect(context.Context) (protocol.Inventory, error) {
	host, _ := os.Hostname()
	return protocol.Inventory{
		CollectedAt: time.Now().UTC(),
		Hostname:    host,
		OS:          protocol.OSInfo{Name: runtime.GOOS},
	}, nil
}

// HardwareIdentity has no portable implementation yet.
func HardwareIdentity() (string, string) { return "", "" }

// LoggedInUser has no portable implementation yet.
func LoggedInUser() string { return "" }
```

- [ ] **Step 6: Report real identity in facts**

In `internal/agent/facts/facts.go`, import `"retune/internal/agent/inventory"` and replace `Device` and `Checkin`:

```go
// Device returns the facts sent at enrollment.
func Device() protocol.DeviceFacts {
	host, _ := os.Hostname()
	serial, smbios := inventory.HardwareIdentity()
	return protocol.DeviceFacts{Hostname: host, Serial: serial, SMBIOSUUID: smbios, OSVersion: osVersion()}
}

// Checkin returns the heartbeat payload.
func Checkin() protocol.CheckinRequest {
	return protocol.CheckinRequest{
		AgentVersion:  AgentVersion,
		UptimeSeconds: uptimeSeconds(),
		LoggedInUser:  inventory.LoggedInUser(),
		IPAddresses:   ipAddresses(),
	}
}
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `go mod tidy && go vet ./internal/agent/... && go test ./internal/agent/inventory/ ./internal/agent/facts/`
Expected: PASS. On Windows the collector test runs against the real machine.

- [ ] **Step 8: Commit**

```bash
git add go.mod go.sum internal/agent/inventory internal/agent/facts
git commit -m "feat(agent): Windows inventory collector via WMI and the registry"
```

---

### Task 13: Unenrollment stops the check-in loop

**Files:**
- Modify: `internal/agent/checkin/loop.go`, `internal/agent/checkin/loop_test.go`

**Interfaces:**
- Consumes: nothing new
- Produces: `checkin.ErrUnenrolled`; `(*Loop).Run(ctx) error` (was no return value) — returns `ErrUnenrolled` when the device has been unenrolled, otherwise nil when ctx ends; `RunOnce` returns `(0, err)` for that case so no further check-ins are scheduled

- [ ] **Step 1: Write the failing test**

Append to `internal/agent/checkin/loop_test.go`:

```go
func TestUnenrolledStopsRun(t *testing.T) {
	f := &fakeChecker{steps: []step{{err: fmt.Errorf("checking in: %w", ErrUnenrolled)}}}
	err := newLoop(f).Run(context.Background())
	if !errors.Is(err, ErrUnenrolled) {
		t.Fatalf("Run = %v, want ErrUnenrolled", err)
	}
	if f.calls != 1 {
		t.Fatalf("calls = %d, want 1", f.calls)
	}
}

func TestRunOnceUnenrolled(t *testing.T) {
	f := &fakeChecker{steps: []step{{err: ErrUnenrolled}}}
	wait, err := newLoop(f).RunOnce(context.Background())
	if !errors.Is(err, ErrUnenrolled) || wait != 0 {
		t.Fatalf("RunOnce = %s, %v", wait, err)
	}
}
```

Add `"fmt"` to that file's imports, and change the existing `TestRunStopsOnCancel` goroutine to ignore the new return value:

```go
	go func() { _ = newLoop(f).Run(ctx); close(done) }()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/agent/checkin/`
Expected: FAIL — `undefined: ErrUnenrolled`.

- [ ] **Step 3: Make the loop stop**

In `internal/agent/checkin/loop.go`, add the sentinel next to the constants:

```go
// ErrUnenrolled means the server has unenrolled this device; the loop stops
// because the local identity is gone.
var ErrUnenrolled = errors.New("device was unenrolled")
```

Replace `Run`:

```go
// Run checks in until ctx is cancelled, or until the device is unenrolled.
func (l *Loop) Run(ctx context.Context) error {
	for {
		wait, err := l.RunOnce(ctx)
		if errors.Is(err, ErrUnenrolled) {
			return err
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-t.C:
		}
	}
}
```

And add the first case inside `RunOnce`'s switch, before the `401` case:

```go
	case errors.Is(err, ErrUnenrolled):
		return 0, err
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go vet ./internal/agent/checkin/ && go test ./internal/agent/checkin/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/agent/checkin
git commit -m "feat(agent): stop the check-in loop once the device is unenrolled"
```

---

### Task 14: Session and agent CLI

**Files:**
- Create: `internal/agent/session/session.go`
- Modify: `cmd/retune-agent/main.go`

**Interfaces:**
- Consumes: Tasks 9–13 (`state`, `identity`, `client`, `executor`, `inventory`, `checkin`), M1 `enrollment.Connect`
- Produces:
  - `session.Config{Identity *identity.Identity; IDStore identity.Store; State *state.Store; Collector inventory.Collector; Executor *executor.Executor; Log *slog.Logger; Now func() time.Time; RenewBefore time.Duration}`
  - `session.New(Config) (*Session, error)`; `session.DefaultRenewBefore = 30 * 24 * time.Hour`
  - `(*Session).Checkin(ctx, protocol.CheckinRequest) (protocol.CheckinResponse, error)` — satisfies `checkin.Checker`: renews, flushes queued results, checks in, uploads inventory when due, queues commands; returns `checkin.ErrUnenrolled` after wiping local state on `410`
  - `(*Session).Start(ctx)` starts the command worker; `(*Session).Wait()` waits for queued commands; `(*Session).FlushResults(ctx) error`; `(*Session).UploadInventory(ctx) error`

- [ ] **Step 1: Write the session**

`internal/agent/session/session.go`:

```go
// Package session performs one check-in cycle: renew the certificate when due,
// flush queued results, check in, upload inventory, and dispatch commands to a
// background worker.
package session

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"retune/internal/agent/checkin"
	"retune/internal/agent/client"
	"retune/internal/agent/enrollment"
	"retune/internal/agent/executor"
	"retune/internal/agent/identity"
	"retune/internal/agent/inventory"
	"retune/internal/agent/state"
	"retune/internal/protocol"
)

// DefaultRenewBefore is how long before expiry the certificate is renewed.
const DefaultRenewBefore = 30 * 24 * time.Hour

// ledgerRetention is how long finished commands stay in the local ledger.
const ledgerRetention = 30 * 24 * time.Hour

// workQueueSize bounds commands waiting to run; anything beyond it is offered
// again at the next check-in.
const workQueueSize = 64

// Config wires a Session.
type Config struct {
	Identity    *identity.Identity
	IDStore     identity.Store
	State       *state.Store
	Collector   inventory.Collector
	Executor    *executor.Executor
	Log         *slog.Logger
	Now         func() time.Time
	RenewBefore time.Duration
}

// Session is the agent's connection to its server plus its local state.
type Session struct {
	cfg Config

	mu       sync.Mutex // guards id, client and inflight
	id       *identity.Identity
	client   *client.Client
	inflight map[string]bool

	flushMu sync.Mutex // one result flush at a time
	work    chan protocol.Command
	pending sync.WaitGroup
}

// New builds a Session for an enrolled identity.
func New(cfg Config) (*Session, error) {
	if cfg.Identity == nil || cfg.State == nil || cfg.Collector == nil || cfg.Executor == nil {
		return nil, errors.New("session: Identity, State, Collector and Executor are required")
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.RenewBefore <= 0 {
		cfg.RenewBefore = DefaultRenewBefore
	}
	c, err := enrollment.Connect(cfg.Identity)
	if err != nil {
		return nil, err
	}
	s := &Session{
		cfg: cfg, id: cfg.Identity, client: c,
		inflight: map[string]bool{},
		work:     make(chan protocol.Command, workQueueSize),
	}
	if cfg.Executor.RefreshInventory == nil {
		cfg.Executor.RefreshInventory = s.UploadInventory
	}
	return s, nil
}

// Start launches the command worker and prunes the old ledger.
func (s *Session) Start(ctx context.Context) {
	if n, err := s.cfg.State.PruneLedger(s.cfg.Now().Add(-ledgerRetention)); err != nil {
		s.cfg.Log.Warn("pruning the command ledger failed", "error", err)
	} else if n > 0 {
		s.cfg.Log.Debug("pruned old command ledger entries", "count", n)
	}
	go s.worker(ctx)
}

// Wait blocks until every queued command has run and its result is stored.
func (s *Session) Wait() { s.pending.Wait() }

// Checkin performs one full cycle. It satisfies checkin.Checker.
func (s *Session) Checkin(ctx context.Context, req protocol.CheckinRequest) (protocol.CheckinResponse, error) {
	if err := s.maybeRenew(ctx); err != nil {
		s.cfg.Log.Warn("renewing the client certificate failed", "error", err)
	}
	if err := s.FlushResults(ctx); err != nil {
		s.cfg.Log.Warn("sending queued command results failed", "error", err)
	}

	hash, err := s.cfg.State.InventoryHash()
	if err != nil {
		return protocol.CheckinResponse{}, fmt.Errorf("read stored inventory hash: %w", err)
	}
	req.InventoryHash = hash

	resp, err := s.currentClient().Checkin(ctx, req)
	var httpErr *client.HTTPError
	if errors.As(err, &httpErr) && httpErr.Status == http.StatusGone {
		s.wipe()
		return resp, fmt.Errorf("%w: %s", checkin.ErrUnenrolled, httpErr.Message)
	}
	if err != nil {
		return resp, err
	}

	if resp.InventoryDue {
		if err := s.UploadInventory(ctx); err != nil {
			s.cfg.Log.Warn("uploading inventory failed", "error", err)
		}
	}
	for _, cmd := range resp.Commands {
		s.enqueue(cmd)
	}
	return resp, nil
}

// UploadInventory collects and uploads inventory, then records the hash the
// server acknowledged.
func (s *Session) UploadInventory(ctx context.Context) error {
	inv, err := s.cfg.Collector.Collect(ctx)
	if err != nil {
		return fmt.Errorf("collect inventory: %w", err)
	}
	resp, err := s.currentClient().PutInventory(ctx, inv)
	if err != nil {
		return err
	}
	return s.cfg.State.SetInventoryHash(resp.Hash)
}

// FlushResults sends queued command results, dropping any the server rejects
// outright and keeping the rest for the next attempt.
func (s *Session) FlushResults(ctx context.Context) error {
	s.flushMu.Lock()
	defer s.flushMu.Unlock()

	pending, err := s.cfg.State.PendingResults()
	if err != nil {
		return err
	}
	for _, qr := range pending {
		err := s.currentClient().SubmitResult(ctx, qr.CommandID, qr.Result)
		var httpErr *client.HTTPError
		switch {
		case err == nil:
		case errors.As(err, &httpErr) && (httpErr.Status == http.StatusNotFound || httpErr.Status == http.StatusBadRequest):
			s.cfg.Log.Warn("server rejected a command result; dropping it",
				"command_id", qr.CommandID, "status", httpErr.Status, "message", httpErr.Message)
		default:
			return err
		}
		if err := s.cfg.State.DeleteResult(qr.CommandID); err != nil {
			return err
		}
	}
	return nil
}

// enqueue hands a command to the worker unless it is already running or the
// ledger shows it was handled.
func (s *Session) enqueue(cmd protocol.Command) {
	s.mu.Lock()
	if s.inflight[cmd.ID] {
		s.mu.Unlock()
		return
	}
	ledger, err := s.cfg.State.LedgerState(cmd.ID)
	if err != nil {
		s.mu.Unlock()
		s.cfg.Log.Warn("reading the command ledger failed", "command_id", cmd.ID, "error", err)
		return
	}
	switch ledger {
	case state.LedgerCompleted:
		// Already run; its result is queued or already sent.
		s.mu.Unlock()
		return
	case state.LedgerStarted:
		// Started before the agent stopped, so it never reported back.
		s.mu.Unlock()
		now := s.cfg.Now()
		s.finish(cmd.ID, protocol.CommandResult{
			Status: protocol.ResultFailed, ExitCode: -1,
			Error:     "the agent restarted while this command was running",
			StartedAt: now, FinishedAt: now,
		})
		return
	}
	select {
	case s.work <- cmd:
		s.inflight[cmd.ID] = true
		s.pending.Add(1)
	default:
		s.cfg.Log.Warn("command queue is full; will retry at the next check-in", "command_id", cmd.ID)
	}
	s.mu.Unlock()
}

func (s *Session) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case cmd := <-s.work:
			s.run(ctx, cmd)
		}
	}
}

func (s *Session) run(ctx context.Context, cmd protocol.Command) {
	defer func() {
		s.mu.Lock()
		delete(s.inflight, cmd.ID)
		s.mu.Unlock()
		s.pending.Done()
	}()
	defer func() {
		if r := recover(); r != nil {
			s.cfg.Log.Error("command execution panicked", "command_id", cmd.ID, "panic", r)
			now := s.cfg.Now()
			s.finish(cmd.ID, protocol.CommandResult{
				Status: protocol.ResultFailed, ExitCode: -1,
				Error:     fmt.Sprintf("the agent panicked while running this command: %v", r),
				StartedAt: now, FinishedAt: now,
			})
		}
	}()

	if _, err := s.cfg.State.MarkStarted(cmd.ID, s.cfg.Now()); err != nil {
		s.cfg.Log.Error("recording command start failed", "command_id", cmd.ID, "error", err)
		return
	}
	if err := s.currentClient().StartCommand(ctx, cmd.ID); err != nil {
		s.cfg.Log.Warn("reporting command start failed", "command_id", cmd.ID, "error", err)
	}
	result := s.cfg.Executor.Execute(ctx, cmd)
	s.finish(cmd.ID, result)
	if err := s.FlushResults(ctx); err != nil {
		s.cfg.Log.Warn("sending the command result failed; it stays queued", "command_id", cmd.ID, "error", err)
	}
}

// finish stores a result before marking the command done, so a crash in
// between leaves the result to be sent rather than losing it.
func (s *Session) finish(id string, r protocol.CommandResult) {
	if err := s.cfg.State.QueueResult(state.QueuedResult{CommandID: id, Result: r}); err != nil {
		s.cfg.Log.Error("queueing a command result failed", "command_id", id, "error", err)
		return
	}
	if err := s.cfg.State.MarkCompleted(id, s.cfg.Now()); err != nil {
		s.cfg.Log.Error("recording command completion failed", "command_id", id, "error", err)
	}
}

// maybeRenew replaces the client certificate when it is close to expiry.
func (s *Session) maybeRenew(ctx context.Context) error {
	s.mu.Lock()
	id := s.id
	s.mu.Unlock()

	notAfter, err := id.CertNotAfter()
	if err != nil {
		return err
	}
	if s.cfg.Now().Add(s.cfg.RenewBefore).Before(notAfter) {
		return nil
	}
	key, csrPEM, err := identity.NewKeyAndCSR(id.DeviceID)
	if err != nil {
		return err
	}
	resp, err := s.currentClient().Renew(ctx, protocol.RenewRequest{CSRPEM: csrPEM})
	if err != nil {
		return err
	}
	next := *id
	next.CertPEM = resp.CertPEM
	next.Key = key
	// Save before switching: the server keeps accepting the old certificate
	// until the new one is used, so a failure here is recoverable.
	if err := s.cfg.IDStore.Save(&next); err != nil {
		return fmt.Errorf("save the renewed identity: %w", err)
	}
	c, err := enrollment.Connect(&next)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.id, s.client = &next, c
	s.mu.Unlock()
	if expires, err := next.CertNotAfter(); err == nil {
		s.cfg.Log.Info("renewed the client certificate", "not_after", expires)
	}
	return nil
}

// wipe removes the local identity and state after unenrollment.
func (s *Session) wipe() {
	if err := s.cfg.IDStore.Delete(); err != nil {
		s.cfg.Log.Error("deleting the local identity failed", "error", err)
	}
	if err := s.cfg.State.Destroy(); err != nil {
		s.cfg.Log.Error("deleting the local state failed", "error", err)
	}
	s.cfg.Log.Warn("this device was unenrolled; local identity and state removed")
}

func (s *Session) currentClient() *client.Client {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.client
}
```

- [ ] **Step 2: Wire the agent CLI**

In `cmd/retune-agent/main.go`, replace the `case "run":` block with:

```go
	case "run":
		once := fs.Bool("once", false, "check in once and exit")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		idStore := identity.Store{Dir: *dataDir, Keys: identity.DefaultKeys()}
		id, err := idStore.Load()
		if err != nil {
			return err
		}
		st, err := state.Open(filepath.Join(*dataDir, "state.db"))
		if err != nil {
			return err
		}
		defer st.Close()

		log := slog.New(slog.NewTextHandler(os.Stderr, nil))
		sess, err := session.New(session.Config{
			Identity:  id,
			IDStore:   idStore,
			State:     st,
			Collector: inventory.NewCollector(),
			Executor: &executor.Executor{
				Runner:    executor.DefaultRunner(filepath.Join(*dataDir, "scripts")),
				Restarter: executor.DefaultRestarter(),
				Now:       time.Now,
			},
			Log: log,
		})
		if err != nil {
			return err
		}

		ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer stop()
		sess.Start(ctx)

		loop := &checkin.Loop{Client: sess, Facts: facts.Checkin, Log: log, Rand: rand.Float64}
		if *once {
			wait, err := loop.RunOnce(ctx)
			switch {
			case errors.Is(err, checkin.ErrUnenrolled):
				fmt.Fprintln(out, "This device was unenrolled; local identity and state removed.")
				return nil
			case err != nil:
				return err
			}
			sess.Wait()
			if err := sess.FlushResults(ctx); err != nil {
				log.Warn("some results are still queued", "error", err)
			}
			fmt.Fprintf(out, "Check-in OK; next in %s\n", wait.Round(time.Second))
			return nil
		}
		if errors.Is(loop.Run(ctx), checkin.ErrUnenrolled) {
			fmt.Fprintln(out, "This device was unenrolled; local identity and state removed.")
		}
		return nil
```

The import block becomes:

```go
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
	"retune/internal/agent/executor"
	"retune/internal/agent/facts"
	"retune/internal/agent/identity"
	"retune/internal/agent/inventory"
	"retune/internal/agent/session"
	"retune/internal/agent/state"
)
```

- [ ] **Step 3: Verify the build and existing tests**

Run: `go vet ./... && go test ./... && go build ./cmd/...`
Expected: PASS; the session gets its own coverage from the end-to-end test in Task 15.

- [ ] **Step 4: Commit**

```bash
git add internal/agent/session cmd/retune-agent
git commit -m "feat(agent): session orchestration for inventory, commands and renewal"
```

---

### Task 15: End-to-end test

**Files:**
- Create: `test/e2e/m2_test.go`

**Interfaces:**
- Consumes: everything above. Runs cross-platform by substituting a fake collector, runner and restarter, so the same test passes on Linux CI and on Windows.
- Produces: coverage for inventory upload and skip, the four command types, the offline result queue, certificate renewal with old-certificate rejection, and unenrollment wiping local files

- [ ] **Step 1: Write the test**

`test/e2e/m2_test.go`:

```go
package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/agent/checkin"
	"retune/internal/agent/client"
	"retune/internal/agent/enrollment"
	"retune/internal/agent/executor"
	"retune/internal/agent/identity"
	"retune/internal/agent/session"
	"retune/internal/agent/state"
	"retune/internal/config"
	"retune/internal/pki"
	"retune/internal/protocol"
	"retune/internal/server/app"
	"retune/internal/server/commands"
	"retune/internal/server/enroll"
	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

// fakeCollector returns a fixed document with a fresh collection time.
type fakeCollector struct{ inv protocol.Inventory }

func (f fakeCollector) Collect(context.Context) (protocol.Inventory, error) {
	inv := f.inv
	inv.CollectedAt = time.Now().UTC()
	return inv, nil
}

// fakeRunner echoes the script, or blocks when asked to, so timeouts are
// deterministic without running PowerShell.
type fakeRunner struct{}

func (fakeRunner) RunPowerShell(ctx context.Context, script string, stdout, stderr io.Writer) (int, error) {
	if script == "sleep" {
		<-ctx.Done()
		return -1, ctx.Err()
	}
	fmt.Fprintf(stdout, "ran: %s", script)
	return 0, nil
}

type fakeRestarter struct {
	mu     sync.Mutex
	delays []time.Duration
}

func (f *fakeRestarter) Restart(d time.Duration, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delays = append(f.delays, d)
	return nil
}

func (f *fakeRestarter) calls() []time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Duration(nil), f.delays...)
}

func TestInventoryCommandsRenewalUnenroll(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
	q := a.Store.Q()

	token, _, err := a.Enroll.CreateToken(ctx, enroll.TokenOptions{Label: "m2", CreatedBy: "test"})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	idStore := identity.Store{Dir: dir, Keys: identity.PlainKeys{}}
	id, err := enrollment.Enroll(ctx, enrollment.Options{
		ServerURL: srv.URL, Token: token, Pin: pki.Fingerprint(a.CA.Cert().Raw),
		Facts: protocol.DeviceFacts{Hostname: "PC-M2", SMBIOSUUID: "UUID-M2"}, Store: idStore,
	})
	if err != nil {
		t.Fatal(err)
	}
	deviceID := uuid.MustParse(id.DeviceID)

	statePath := filepath.Join(dir, "state.db")
	st, err := state.Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	inv := protocol.Inventory{
		Hostname: "PC-M2",
		OS:       protocol.OSInfo{Name: "Microsoft Windows 11 Pro", Version: "10.0.26200", Build: "26200"},
		Hardware: protocol.Hardware{Manufacturer: "Contoso", Model: "Book 9", RAMBytes: 16 << 30},
		Disks:    []protocol.Disk{{Name: "C:", SizeBytes: 500 << 30, FreeBytes: 300 << 30, BitLocker: "on"}},
		Software: []protocol.Software{
			{Name: "7-Zip", Version: "24.08", Scope: "machine"},
			{Name: "Git", Version: "2.51.0", Scope: "machine"},
		},
	}
	restarter := &fakeRestarter{}
	newSession := func(ident *identity.Identity, renewBefore time.Duration) *session.Session {
		t.Helper()
		s, err := session.New(session.Config{
			Identity: ident, IDStore: idStore, State: st, Collector: fakeCollector{inv},
			Executor:    &executor.Executor{Runner: fakeRunner{}, Restarter: restarter, Now: time.Now},
			Log:         slog.New(slog.DiscardHandler),
			RenewBefore: renewBefore,
		})
		if err != nil {
			t.Fatal(err)
		}
		s.Start(ctx)
		return s
	}
	sess := newSession(id, 0)

	// 1. The first check-in uploads inventory.
	resp, err := sess.Checkin(ctx, protocol.CheckinRequest{AgentVersion: "e2e"})
	if err != nil || !resp.InventoryDue {
		t.Fatalf("first check-in = %+v, err = %v", resp, err)
	}
	dev, err := q.GetDevice(ctx, deviceID)
	if err != nil {
		t.Fatal(err)
	}
	if dev.Manufacturer != "Contoso" || dev.Model != "Book 9" || dev.OSBuild != "26200" {
		t.Fatalf("device after inventory = %+v", dev)
	}
	sw, err := q.ListSoftware(ctx, deviceID)
	if err != nil || len(sw) != 2 {
		t.Fatalf("software rows = %d, err = %v", len(sw), err)
	}
	stored, err := q.GetInventory(ctx, deviceID)
	if err != nil || stored.RAMGB != 16 || stored.DiskFreeGB != 300 {
		t.Fatalf("stored inventory = %+v, err = %v", stored, err)
	}

	// 2. Nothing is due on the next cycle.
	resp, err = sess.Checkin(ctx, protocol.CheckinRequest{AgentVersion: "e2e"})
	if err != nil || resp.InventoryDue || len(resp.Commands) != 0 {
		t.Fatalf("second check-in = %+v, err = %v", resp, err)
	}

	// 3. All four command types run.
	queue := func(typ string, payload any) uuid.UUID {
		t.Helper()
		var raw json.RawMessage
		if payload != nil {
			b, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			raw = b
		}
		c, err := a.Commands.Queue(ctx, commands.QueueOptions{
			DeviceID: deviceID, Type: typ, Payload: raw, CreatedBy: "test",
		})
		if err != nil {
			t.Fatal(err)
		}
		return c.ID
	}
	hello := queue(protocol.CommandRunPowerShell, protocol.RunPowerShellPayload{Script: "hello"})
	slow := queue(protocol.CommandRunPowerShell, protocol.RunPowerShellPayload{Script: "sleep", TimeoutSeconds: 1})
	reboot := queue(protocol.CommandRestart, protocol.RestartPayload{DelaySeconds: 30})
	refresh := queue(protocol.CommandRefreshInventory, nil)

	resp, err = sess.Checkin(ctx, protocol.CheckinRequest{AgentVersion: "e2e"})
	if err != nil || len(resp.Commands) != 4 {
		t.Fatalf("commands delivered = %d, err = %v", len(resp.Commands), err)
	}
	sess.Wait()

	want := map[uuid.UUID]string{
		hello:   store.CommandSucceeded,
		slow:    store.CommandTimedOut,
		reboot:  store.CommandSucceeded,
		refresh: store.CommandSucceeded,
	}
	for id, status := range want {
		c, res, err := a.Commands.Get(ctx, id)
		if err != nil || c.Status != status || res == nil {
			t.Fatalf("command %s = %s (want %s), result = %+v, err = %v", id, c.Status, status, res, err)
		}
	}
	if _, res, _ := a.Commands.Get(ctx, hello); res.Stdout != "ran: hello" {
		t.Fatalf("stdout = %q", res.Stdout)
	}
	if _, res, _ := a.Commands.Get(ctx, slow); res.ExitCode != -1 {
		t.Fatalf("timed-out command exit code = %d", res.ExitCode)
	}
	if calls := restarter.calls(); len(calls) != 1 || calls[0] != 30*time.Second {
		t.Fatalf("restart calls = %v", calls)
	}
	if resp, err = sess.Checkin(ctx, protocol.CheckinRequest{}); err != nil || len(resp.Commands) != 0 {
		t.Fatalf("finished commands must not be redelivered: %+v, %v", resp, err)
	}

	// 4. A result stored while offline reaches the server at the next check-in.
	offline := queue(protocol.CommandRunPowerShell, protocol.RunPowerShellPayload{Script: "offline"})
	if _, err := a.Commands.Deliver(ctx, deviceID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := st.MarkStarted(offline.String(), now); err != nil {
		t.Fatal(err)
	}
	if err := st.QueueResult(state.QueuedResult{CommandID: offline.String(), Result: protocol.CommandResult{
		Status: protocol.ResultSucceeded, Stdout: "from the queue", StartedAt: now, FinishedAt: now,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkCompleted(offline.String(), now); err != nil {
		t.Fatal(err)
	}
	if _, err := sess.Checkin(ctx, protocol.CheckinRequest{}); err != nil {
		t.Fatal(err)
	}
	c, res, err := a.Commands.Get(ctx, offline)
	if err != nil || c.Status != store.CommandSucceeded || res == nil || res.Stdout != "from the queue" {
		t.Fatalf("offline command = %+v result = %+v err = %v", c, res, err)
	}
	if pending, _ := st.PendingResults(); len(pending) != 0 {
		t.Fatalf("queue should be empty, has %d", len(pending))
	}

	// 5. The certificate renews, and the superseded one stops working.
	before, err := q.GetDevice(ctx, deviceID)
	if err != nil {
		t.Fatal(err)
	}
	renewing := newSession(id, 365*24*time.Hour)
	if _, err := renewing.Checkin(ctx, protocol.CheckinRequest{}); err != nil {
		t.Fatal(err)
	}
	after, err := q.GetDevice(ctx, deviceID)
	if err != nil {
		t.Fatal(err)
	}
	if after.CertSerial == before.CertSerial {
		t.Fatal("the certificate serial must change on renewal")
	}
	if after.PrevCertSerial != "" {
		t.Fatalf("using the new certificate must clear the old serial: %q", after.PrevCertSerial)
	}
	reloaded, err := idStore.Load()
	if err != nil || reloaded.CertPEM == id.CertPEM {
		t.Fatalf("the renewed identity must be on disk: %v", err)
	}
	var httpErr *client.HTTPError
	if _, err := sess.Checkin(ctx, protocol.CheckinRequest{}); !errors.As(err, &httpErr) || httpErr.Status != 401 {
		t.Fatalf("a session holding the old certificate must be rejected: %v", err)
	}

	// 6. Unenrolling wipes the local identity and state.
	fresh := newSession(reloaded, 0)
	if _, err := fresh.Checkin(ctx, protocol.CheckinRequest{}); err != nil {
		t.Fatal(err)
	}
	if err := a.Devices.Unenroll(ctx, deviceID, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Checkin(ctx, protocol.CheckinRequest{}); !errors.Is(err, checkin.ErrUnenrolled) {
		t.Fatalf("check-in after unenroll = %v", err)
	}
	if _, err := idStore.Load(); !errors.Is(err, identity.ErrNotEnrolled) {
		t.Fatalf("identity must be gone: %v", err)
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("state file must be gone: %v", err)
	}
}
```

- [ ] **Step 2: Run the test**

Run: `go test ./test/e2e/ -run TestInventoryCommandsRenewalUnenroll -v`
Expected: PASS (the timed-out command makes it take a couple of seconds).

- [ ] **Step 3: Full verification**

Run: `go vet ./... && go test -count=1 ./... && go build ./cmd/...`
Expected: all packages PASS and both binaries build.

- [ ] **Step 4: Commit**

```bash
git add test/e2e
git commit -m "test(e2e): inventory, commands, offline queue, renewal and unenroll"
```

---

### Task 16: Manual smoke test on Windows

**Files:** none (verification only)

**Interfaces:**
- Consumes: the built binaries
- Produces: confirmation that real WMI inventory, real PowerShell execution and unenrollment work on a live Windows machine

- [ ] **Step 1: Start a database and the server**

```powershell
docker run -d --name retune-smoke-pg -e POSTGRES_USER=retune -e POSTGRES_PASSWORD=retune -e POSTGRES_DB=retune -p 127.0.0.1::5432 postgres:17-alpine
$port = ((docker port retune-smoke-pg 5432) -split ':')[-1]
$env:DATABASE_URL = "postgres://retune:retune@127.0.0.1:$port/retune?sslmode=disable"
$env:PUBLIC_URL = "https://localhost:18443"
$env:AGENT_API_LISTEN = "127.0.0.1:18443"
$env:DATA_DIR = ".\data"
go build -o bin/ ./cmd/...
.\bin\retune-server.exe migrate
.\bin\retune-server.exe token create --label smoke --max-uses 1
.\bin\retune-server.exe ca fingerprint
# in a second terminal with the same environment variables:
.\bin\retune-server.exe serve
```

- [ ] **Step 2: Enroll and collect real inventory**

```powershell
.\bin\retune-agent.exe enroll --server https://localhost:18443 --token <TOKEN> --pin <FINGERPRINT> --data-dir .\agent-data
.\bin\retune-agent.exe run --once --data-dir .\agent-data
.\bin\retune-server.exe device list
.\bin\retune-server.exe device show <DEVICE-ID>
```

Expected: `device show` reports the real OS build, manufacturer, model, serial, RAM, free space and a package count above zero. Running as a normal user leaves BitLocker and TPM unknown, which is fine here.

- [ ] **Step 3: Run a real PowerShell command**

```powershell
.\bin\retune-server.exe command queue --device <DEVICE-ID> --type run_powershell --script "Get-Date; $env:COMPUTERNAME; exit 0"
.\bin\retune-agent.exe run --once --data-dir .\agent-data
.\bin\retune-server.exe command show <COMMAND-ID>
```

Expected: status `succeeded`, exit code 0, and the date plus computer name under `--- stdout ---`. Do not queue a `restart` here: it would reboot the machine.

- [ ] **Step 4: Unenroll**

```powershell
.\bin\retune-server.exe device unenroll <DEVICE-ID>
.\bin\retune-agent.exe run --once --data-dir .\agent-data
Get-ChildItem .\agent-data
```

Expected: the agent prints that the device was unenrolled, and `identity.json` and `state.db` are gone.

- [ ] **Step 5: Clean up**

```powershell
docker rm -f retune-smoke-pg
Remove-Item -Recurse -Force .\data, .\agent-data
```

- [ ] **Step 6: Commit any fixes the smoke test uncovered**

```bash
git add -A
git commit -m "fix: address issues found during the M2 smoke test"
```
