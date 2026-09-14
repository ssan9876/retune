# M10 Agent Self-Update Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an administrator upload an agent build, assign it to a group, and have each device swap to it under supervision — going back to the previous build if the new one cannot reach the server.

**Architecture:** A fourth assignable item kind, `agent`. The server stores uploaded binaries under `DATA_DIR` with metadata in Postgres and streams them to agents over the existing mTLS channel. On a device the managed binary lives in `DATA_DIR\bin\<version>\` and the service's `binPath` is repointed at it, so the MSI keeps owning exactly the file it installed and a running image is never modified. A copy of the outgoing, known-good build supervises the swap and rolls back if the new agent does not check in before a deadline.

**Tech Stack:** Go 1.27, pgx/v5 + pgxpool, golang-migrate (embedded, `pgx5://`), testcontainers-go, UUIDv7, bbolt, `golang.org/x/sys/windows/svc` and `.../mgr`, React 19 + TypeScript + Vite, vitest + Testing Library.

**Spec:** `docs/superpowers/specs/2026-09-14-m10-agent-self-update-design.md`

## Global Constraints

Copied from the spec. Every task's requirements implicitly include this section.

- **The agent must refuse to self-update while its version is the placeholder.** An agent that keeps reporting an uninjected version after updating would be updated again on every check-in, on every machine, forever. This is the one failure that can take out a whole fleet, and it is guarded in code, not by convention.
- **Proof of life is a successful check-in, not a successful start.** A binary that launches but cannot reach the server is exactly the failure this milestone exists to prevent.
- **The MSI's copy of `retune-agent.exe` in `Program Files` is never modified.** It is a bootstrap. Windows Installer owns it as a keypath component; writing there fights the component rules.
- **A repoint must preserve the service's existing arguments.** An MSI-installed service carries no `--data-dir`; a manually-installed one does. Losing that argument sends the new agent looking for its identity in the wrong directory, where it would try to re-enrol with a spent token.
- **Versions are compared for difference, not ordering.** Assigning an older build is a deliberate downgrade and must work — it is how a fleet is recovered without touching every machine.
- **The SHA-256 recorded at upload is verified after download**, before anything is staged.
- **Only current and previous versions are kept** on a device; older directories are pruned once an update is confirmed.
- **Rollback cannot rely on the service control manager.** WiX-installed services have no recovery actions; the supervisor sets them, and is itself an ordinary detached process.
- **Comments explain why, not what.** Match the density and voice of the surrounding code.
- **Go:** `gofmt -w`, `go vet ./...` and `GOOS=linux go build ./...` must pass. Windows-only code goes behind `//go:build windows` with a matching `_other.go` stub.
- **Never install, upgrade or remove real software during implementation.** The on-machine verification in the spec's §10 is run by the controller at the end, not by task implementers.

## File Structure

**New files:**

| File | Responsibility |
|---|---|
| `internal/protocol/agentversion.go` | `ItemKindAgent`, `AgentOptions`, `ParseAgentOptions`, `AgentVersionResponse` |
| `internal/protocol/agentversion_test.go` | Options defaults, bounds, unknown-field rejection |
| `internal/server/store/migrations/0009_agent_versions.up.sql` | The `agent_versions` table |
| `internal/server/store/migrations/0009_agent_versions.down.sql` | Drops it |
| `internal/server/store/agentversions.go` | Metadata queries |
| `internal/server/artifacts/artifacts.go` | The binary store under `DATA_DIR`: put (hashing as it writes), open, remove |
| `internal/server/artifacts/artifacts_test.go` | Round-trip, hash correctness, refusal to overwrite |
| `internal/server/agentversions/service.go` | Composes metadata and artifact storage; upload, list, get, delete |
| `internal/server/agentversions/service_test.go` | Service behaviour against real Postgres |
| `internal/server/adminapi/agentversions.go` | The `/agent-versions` admin handlers, including the streaming upload |
| `internal/agent/selfupdate/decide.go` | The pure decision: update, skip, or refuse |
| `internal/agent/selfupdate/decide_test.go` | The decision as a table |
| `internal/agent/selfupdate/record.go` | `update.json` — the record, its read and write |
| `internal/agent/selfupdate/record_test.go` | Round-trip including the captured service arguments |
| `internal/agent/selfupdate/syncer.go` | Download, verify, stage, spawn the supervisor |
| `internal/agent/selfupdate/syncer_test.go` | Against fakes: clean update, hash mismatch, refusal |
| `internal/agent/selfupdate/supervise.go` | The supervisor: repoint, start, await proof, roll back |
| `internal/agent/selfupdate/supervise_test.go` | Against a fake controller: success, timeout-then-rollback, stop failure |
| `internal/agent/selfupdate/service_windows.go` | The real `ServiceController` over `golang.org/x/sys/windows/svc/mgr` |
| `internal/agent/selfupdate/service_other.go` | The non-Windows stub |
| `web/src/pages/AgentVersions.tsx` | Upload, list, assign, per-device status |
| `web/src/pages/AgentVersions.css` | Page styles |
| `web/src/pages/AgentVersions.test.tsx` | Console behaviour |

**Modified files:**

| File | Change |
|---|---|
| `internal/agent/facts/facts.go` | `AgentVersion` becomes an injectable `var`, plus a placeholder guard |
| `Makefile`, `deploy/msi/build.ps1`, `.github/workflows/ci.yml` | `-ldflags -X` version injection |
| `internal/agent/client/client.go` | `FetchAgentVersion`, and the first streaming download |
| `internal/server/adminapi/itemkinds.go` | Register the `agent` options parser |
| `internal/server/adminapi/resources.go` | Mount the `/agent-versions` routes |
| `internal/server/adminapi/handler.go` | An `AgentVersions` service field |
| `internal/server/agentapi/handler.go` | The `agent` case in `itemVersion`, and two new routes |
| `internal/server/app/app.go` | Construct and inject the service and the artifact store |
| `internal/agent/session/session.go` | A `SelfUpdate` field, its client adapter and its `ItemSyncer` adapter |
| `internal/agent/runner/runner.go` | Construct the self-update syncer |
| `cmd/retune-agent/main.go` | The `supervise-update` subcommand, and the rollback report at startup |
| `web/src/App.tsx`, `web/src/components/Shell.tsx` | Route and nav entry |
| `web/src/api/types.ts` | `AgentVersion` |
| `README.md` | An "Updating the agent" section |
| `docs/superpowers/plans/2026-09-12-roadmap.md` | The M10 row and status |

---

### Task 1: Version injection, and the refusal that prevents a fleet-wide loop

`facts.AgentVersion` is a `const` unrelated to the version CI stamps on the MSI. An update loop comparing assigned against reported would see an updated agent still reporting `0.1.0-dev`, conclude it had not updated, and update it again on every check-in, on every machine, forever. This task makes the version real and makes the agent refuse to self-update while it is not.

**Files:**
- Modify: `internal/agent/facts/facts.go`
- Modify: `Makefile` — the `agent` target
- Modify: `deploy/msi/build.ps1` — the `go build` line
- Modify: `.github/workflows/ci.yml` — both "Build the binaries" steps
- Test: `internal/agent/facts/facts_test.go` (new)

**Interfaces:**
- Produces, for every later task:
  ```go
  var AgentVersion = "0.1.0-dev"        // was const; now injectable
  const PlaceholderVersion = "0.1.0-dev"
  func VersionInjected() bool           // AgentVersion != PlaceholderVersion && != ""
  ```

- [ ] **Step 1: Write the failing test**

Create `internal/agent/facts/facts_test.go`:

```go
package facts_test

import (
	"testing"

	"retune/internal/agent/facts"
)

// A build whose version was never injected must not self-update. It would
// report the placeholder after updating, be told to update again, and do that
// on every check-in on every machine for as long as the assignment stood.
func TestVersionInjectedGuardsTheDefault(t *testing.T) {
	if facts.PlaceholderVersion == "" {
		t.Fatal("the placeholder must be a real string, or the guard cannot recognise it")
	}
	if facts.AgentVersion == facts.PlaceholderVersion && facts.VersionInjected() {
		t.Error("an uninjected build must report its version as not injected")
	}
}

// Checkin reports whatever the build was stamped with.
func TestCheckinCarriesTheVersion(t *testing.T) {
	if got := facts.Checkin().AgentVersion; got != facts.AgentVersion {
		t.Errorf("check-in reported %q, want %q", got, facts.AgentVersion)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/agent/facts/ -count=1`

Expected: FAIL to compile — `facts.PlaceholderVersion` and `facts.VersionInjected` do not exist.

- [ ] **Step 3: Make the version injectable**

In `internal/agent/facts/facts.go`, replace `const AgentVersion = "0.1.0-dev"` with:

```go
// PlaceholderVersion is what an unstamped build reports. A build carrying it
// refuses to self-update: it would report the same string after updating, be
// told to update again, and do that on every check-in forever.
const PlaceholderVersion = "0.1.0-dev"

// AgentVersion is reported on every check-in. It is a var, not a const, so a
// release build can stamp it:
//
//	go build -ldflags "-X retune/internal/agent/facts.AgentVersion=1.2.3"
var AgentVersion = PlaceholderVersion

// VersionInjected reports whether this build was stamped with a real version.
func VersionInjected() bool {
	return AgentVersion != "" && AgentVersion != PlaceholderVersion
}
```

- [ ] **Step 4: Stamp the version in all three build paths**

`Makefile`, the `agent` target — note recipe lines are TABs:

```make
# agent cross-compiles the Windows agent. VERSION stamps the binary; an
# unstamped build refuses to self-update, on purpose.
VERSION ?= 0.1.0-dev
agent:
	GOOS=windows GOARCH=amd64 go build -trimpath \
	  -ldflags "-X retune/internal/agent/facts.AgentVersion=$(VERSION)" \
	  -o bin/retune-agent.exe ./cmd/retune-agent
```

`deploy/msi/build.ps1`, replacing the existing `go build` invocation:

```powershell
& go build -trimpath `
  -ldflags "-X retune/internal/agent/facts.AgentVersion=$Version" `
  -o $agentExe (Join-Path $root "cmd/retune-agent")
```

`.github/workflows/ci.yml` — **both** jobs have a "Build the binaries" step running `go build -o bin/ ./cmd/...`. Replace each with:

```yaml
      - name: Build the binaries
        run: go build -ldflags "-X retune/internal/agent/facts.AgentVersion=0.1.${{ github.run_number }}" -o bin/ ./cmd/...
```

The MSI step already passes `-Version 0.1.${{ github.run_number }}`, so the packaged agent and the reported version now agree.

- [ ] **Step 5: Run the tests, and prove injection actually works**

```bash
go test ./internal/agent/... -count=1
go vet ./... && GOOS=linux go build ./...
go run -ldflags "-X retune/internal/agent/facts.AgentVersion=9.9.9" ./cmd/retune-agent 2>&1 | head -1
```

The last command prints the usage text; that it builds at all proves the `-X` path resolves. To check the value end to end:

```bash
GOOS=windows go build -ldflags "-X retune/internal/agent/facts.AgentVersion=9.9.9" -o /tmp/a.exe ./cmd/retune-agent && strings /tmp/a.exe | grep -c 9.9.9
```

Expected: a non-zero count. Delete `/tmp/a.exe` afterwards.

- [ ] **Step 6: Commit**

```bash
git add internal/agent/facts/ Makefile deploy/msi/build.ps1 .github/workflows/ci.yml
git commit -m "feat(agent): stamp the version at build time, and refuse to self-update without one"
```

---

### Task 2: The agent-version protocol

**Files:**
- Create: `internal/protocol/agentversion.go`
- Create: `internal/protocol/agentversion_test.go`

**Interfaces:**
- Produces:
  ```go
  const ItemKindAgent = "agent"
  const (MinUpdateDeadlineSeconds = 60; MaxUpdateDeadlineSeconds = 3600)

  type AgentOptions struct {
      DeadlineSeconds int `json:"deadline_seconds"`
  }
  func DefaultAgentOptions() AgentOptions
  func ParseAgentOptions(raw []byte) (AgentOptions, error)
  func (o AgentOptions) Deadline() time.Duration
  func (o AgentOptions) Marshal() ([]byte, error)

  type AgentVersionResponse struct {
      Version   string `json:"version"`
      SHA256    string `json:"sha256"`
      SizeBytes int64  `json:"size_bytes"`
  }

  type AgentUpdateResult struct {
      Version, Status, RolledBackFrom, Detail string
      ReportedAt time.Time
  }
  ```
  `Status` carries `ResultSucceeded` or `ResultFailed`, the constants
  `internal/protocol/commands.go` already defines.

- [ ] **Step 1: Write the failing test**

Create `internal/protocol/agentversion_test.go`:

```go
package protocol_test

import (
	"errors"
	"testing"
	"time"

	"retune/internal/protocol"
)

func TestAgentOptionsDefaults(t *testing.T) {
	for _, raw := range []string{"", "{}", "null"} {
		o, err := protocol.ParseAgentOptions([]byte(raw))
		if err != nil {
			t.Fatalf("ParseAgentOptions(%q): %v", raw, err)
		}
		if o.DeadlineSeconds != 600 {
			t.Errorf("deadline = %d, want 600", o.DeadlineSeconds)
		}
		if o.Deadline() != 10*time.Minute {
			t.Errorf("Deadline() = %v, want 10m", o.Deadline())
		}
	}
}

func TestAgentOptionsRejectsNonsense(t *testing.T) {
	cases := map[string]string{
		"a deadline below the floor":   `{"deadline_seconds":30}`,
		"a deadline above the ceiling": `{"deadline_seconds":7200}`,
		"a misspelled field":           `{"deadline_secondz":600}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := protocol.ParseAgentOptions([]byte(raw))
			if err == nil {
				t.Fatalf("%s should be refused", raw)
			}
			if !errors.Is(err, protocol.ErrBadOptions) {
				t.Errorf("error should wrap ErrBadOptions, got %v", err)
			}
		})
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/protocol/ -run Agent -count=1`

Expected: FAIL to compile — `protocol.ParseAgentOptions` is undefined.

- [ ] **Step 3: Write the implementation**

Create `internal/protocol/agentversion.go`:

```go
package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// ItemKindAgent is the assignment kind for agent builds.
const ItemKindAgent = "agent"

// How long the supervisor waits for a new agent to check in before putting the
// previous one back. Ten minutes comfortably spans a service restart plus a
// check-in interval; an hour would strand a device on a build that is never
// going to work.
const (
	MinUpdateDeadlineSeconds = 60
	MaxUpdateDeadlineSeconds = 3600
)

// AgentOptions are the per-assignment settings of an agent update.
type AgentOptions struct {
	DeadlineSeconds int `json:"deadline_seconds"`
}

// DefaultAgentOptions are applied to anything the caller leaves out.
func DefaultAgentOptions() AgentOptions {
	return AgentOptions{DeadlineSeconds: 600}
}

// Deadline is how long a new agent has to check in before it is rolled back.
func (o AgentOptions) Deadline() time.Duration {
	return time.Duration(o.DeadlineSeconds) * time.Second
}

// ParseAgentOptions validates raw assignment options, filling in the defaults.
// Unknown fields are rejected so a typo is not silently ignored.
func ParseAgentOptions(raw []byte) (AgentOptions, error) {
	o := DefaultAgentOptions()
	if len(bytes.TrimSpace(raw)) > 0 && string(bytes.TrimSpace(raw)) != "null" {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&o); err != nil {
			return AgentOptions{}, fmt.Errorf("%w: %v", ErrBadOptions, err)
		}
	}
	if err := o.validate(); err != nil {
		return AgentOptions{}, err
	}
	return o, nil
}

func (o AgentOptions) validate() error {
	if o.DeadlineSeconds < MinUpdateDeadlineSeconds || o.DeadlineSeconds > MaxUpdateDeadlineSeconds {
		return fmt.Errorf("%w: deadline_seconds must be between %d and %d",
			ErrBadOptions, MinUpdateDeadlineSeconds, MaxUpdateDeadlineSeconds)
	}
	return nil
}

// Marshal returns the canonical JSON for storing on an assignment.
func (o AgentOptions) Marshal() ([]byte, error) { return json.Marshal(o) }

// AgentVersionResponse is the body of GET /api/agent/v1/agent-versions/{id}.
// The binary itself is fetched separately; this is what the agent needs to
// decide whether to fetch it and how to check what it got.
type AgentVersionResponse struct {
	Version   string `json:"version"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

// AgentUpdateResult is POSTed to /api/agent/v1/agent-versions/{id}/result.
// Only terminal outcomes are reported: an update that is still under way is
// the supervisor's business, not the console's.
type AgentUpdateResult struct {
	Version string `json:"version"`
	Status  string `json:"status"`
	// RolledBackFrom names the build that failed, when this report is a
	// restored agent saying what happened to it.
	RolledBackFrom string    `json:"rolled_back_from,omitempty"`
	Detail         string    `json:"detail"`
	ReportedAt     time.Time `json:"reported_at"`
}

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/protocol/ -count=1 && go vet ./internal/protocol/`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/protocol/agentversion.go internal/protocol/agentversion_test.go
git commit -m "feat(protocol): the agent item kind, its options and its definition"
```

---

### Task 3: Storage for agent-version metadata

**Files:**
- Create: `internal/server/store/migrations/0009_agent_versions.up.sql`
- Create: `internal/server/store/migrations/0009_agent_versions.down.sql`
- Create: `internal/server/store/agentversions.go`
- Test: `internal/server/store/agentversions_test.go`

**Interfaces:**
- Produces:
  ```go
  type AgentVersion struct {
      ID uuid.UUID; Version, SHA256 string; SizeBytes int64
      Notes string; CreatedAt time.Time; CreatedBy string
  }
  func (q *Queries) CreateAgentVersion(ctx, v AgentVersion) error
  func (q *Queries) GetAgentVersion(ctx, id uuid.UUID) (AgentVersion, error)
  func (q *Queries) GetAgentVersionByVersion(ctx, version string) (AgentVersion, error)
  func (q *Queries) ListAgentVersions(ctx, page Page) ([]AgentVersion, int, error)
  func (q *Queries) DeleteAgentVersion(ctx, id uuid.UUID) error
  ```

- [ ] **Step 1: Write the migration**

Create `internal/server/store/migrations/0009_agent_versions.up.sql`:

```sql
-- An uploaded agent build. The primary key is a uuid because assignments.item_id
-- is uuid, like every other item kind; the version string is what people read
-- and what an agent compares against its own, so it is unique per tenant --
-- uploading the same version twice is a mistake, not a new build.
CREATE TABLE agent_versions (
    id         uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    version    text NOT NULL,
    sha256     text NOT NULL,
    size_bytes bigint NOT NULL,
    notes      text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL,
    created_by text NOT NULL
);
CREATE UNIQUE INDEX agent_versions_version ON agent_versions (tenant_id, version);
```

Create `internal/server/store/migrations/0009_agent_versions.down.sql`:

```sql
DROP TABLE agent_versions;
```

Nothing is added to `assignments` or `device_item_status`: `item_kind` is free text with no CHECK constraint, so a fourth kind needs no migration there.

- [ ] **Step 2: Write the failing test**

Create `internal/server/store/agentversions_test.go`, following `internal/server/store/apps_test.go`:

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

func TestAgentVersionRoundTrip(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	q := st.Q()
	now := time.Now().UTC().Truncate(time.Millisecond)

	v := store.AgentVersion{
		ID: uuid.Must(uuid.NewV7()), Version: "1.2.3",
		SHA256: "abc123", SizeBytes: 4096, Notes: "first",
		CreatedAt: now, CreatedBy: "ops",
	}
	if err := q.CreateAgentVersion(ctx, v); err != nil {
		t.Fatal(err)
	}

	got, err := q.GetAgentVersion(ctx, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != "1.2.3" || got.SHA256 != "abc123" || got.SizeBytes != 4096 {
		t.Fatalf("version = %+v", got)
	}

	byVersion, err := q.GetAgentVersionByVersion(ctx, "1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if byVersion.ID != v.ID {
		t.Errorf("lookup by version found %v, want %v", byVersion.ID, v.ID)
	}

	// The same version twice is a mistake, not a new build.
	dup := v
	dup.ID = uuid.Must(uuid.NewV7())
	if err := q.CreateAgentVersion(ctx, dup); err == nil {
		t.Error("a duplicate version should be refused")
	}

	if _, err := q.GetAgentVersion(ctx, uuid.Must(uuid.NewV7())); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a missing build should be ErrNotFound, got %v", err)
	}

	if err := q.DeleteAgentVersion(ctx, v.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := q.GetAgentVersion(ctx, v.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("after deletion it should be gone, got %v", err)
	}
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `go test ./internal/server/store/ -run AgentVersion -count=1`

Expected: FAIL to compile — `store.AgentVersion` does not exist. (Needs Docker; a couple of minutes is normal.)

- [ ] **Step 4: Write the queries**

Create `internal/server/store/agentversions.go` following `internal/server/store/apps.go` exactly: an `agentVersionCols` constant, a `scanAgentVersion(row pgx.Row)` helper mapping `pgx.ErrNoRows` to `ErrNotFound`, `DefaultTenantID` in every statement, and `count(*) OVER () AS total` with `page.Normalized()` for the listing. For example:

```go
const agentVersionCols = `id, version, sha256, size_bytes, notes, created_at, created_by`

// CreateAgentVersion records an uploaded build.
func (q *Queries) CreateAgentVersion(ctx context.Context, v AgentVersion) error {
	_, err := q.db.Exec(ctx, `
		INSERT INTO agent_versions (id, tenant_id, version, sha256, size_bytes, notes, created_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		v.ID, DefaultTenantID, v.Version, v.SHA256, v.SizeBytes, v.Notes, v.CreatedAt, v.CreatedBy)
	return err
}
```

`ListAgentVersions` orders `created_at DESC, id DESC` — the UUIDv7 tie-break `ListAppInstalls` uses, because two uploads can share a timestamp.

- [ ] **Step 5: Run the tests**

Run: `go test ./internal/server/store/ -count=1`

Expected: PASS. The migration runs automatically against the throwaway Postgres.

- [ ] **Step 6: Commit**

```bash
git add internal/server/store/migrations/0009_agent_versions.up.sql internal/server/store/migrations/0009_agent_versions.down.sql internal/server/store/agentversions.go internal/server/store/agentversions_test.go
git commit -m "feat(store): agent build metadata"
```

---

### Task 4: The artifact store

The product has never stored a file before. `DATA_DIR` holds the CA and the secret key and nothing else; there is no upload, no download, no blob storage anywhere. This task adds the smallest thing that works, with no HTTP in it, so it can be tested without a server.

**Files:**
- Create: `internal/server/artifacts/artifacts.go`
- Create: `internal/server/artifacts/artifacts_test.go`

**Interfaces:**
- Produces:
  ```go
  type Store struct { Dir string }          // Dir is DATA_DIR/agents
  var ErrNotFound = errors.New("artifact not found")
  var ErrExists = errors.New("that version is already stored")

  // Put streams r to disk, hashing as it goes, and returns the hex SHA-256
  // and the number of bytes written. It refuses to replace an existing
  // version, and leaves nothing behind if the copy fails.
  func (s Store) Put(version string, r io.Reader, limit int64) (sha256Hex string, size int64, err error)
  func (s Store) Open(version string) (io.ReadCloser, int64, error)
  func (s Store) Remove(version string) error
  ```

- [ ] **Step 1: Write the failing test**

Create `internal/server/artifacts/artifacts_test.go`:

```go
package artifacts_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"

	"retune/internal/server/artifacts"
)

func TestPutHashesWhatItWrote(t *testing.T) {
	s := artifacts.Store{Dir: t.TempDir()}
	const body = "a pretend agent binary"

	sum, size, err := s.Put("1.2.3", strings.NewReader(body), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte(body))
	if sum != hex.EncodeToString(want[:]) {
		t.Errorf("sha256 = %s, want %s", sum, hex.EncodeToString(want[:]))
	}
	if size != int64(len(body)) {
		t.Errorf("size = %d, want %d", size, len(body))
	}

	r, got, err := s.Open("1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if got != int64(len(body)) {
		t.Errorf("Open reported %d bytes, want %d", got, len(body))
	}
	read, _ := io.ReadAll(r)
	if string(read) != body {
		t.Errorf("read back %q", read)
	}
}

// A build is immutable once uploaded. Replacing one silently would mean two
// devices could install different bytes for the same version.
func TestPutRefusesToReplace(t *testing.T) {
	s := artifacts.Store{Dir: t.TempDir()}
	if _, _, err := s.Put("1.0.0", strings.NewReader("first"), 1<<20); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Put("1.0.0", strings.NewReader("second"), 1<<20); !errors.Is(err, artifacts.ErrExists) {
		t.Fatalf("want ErrExists, got %v", err)
	}
	r, _, err := s.Open("1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if read, _ := io.ReadAll(r); string(read) != "first" {
		t.Errorf("the original bytes should survive, got %q", read)
	}
}

// An upload larger than the limit is refused, and leaves nothing behind --
// otherwise a hostile or broken client could fill the disk a partial file at
// a time.
func TestPutEnforcesTheLimitAndCleansUp(t *testing.T) {
	dir := t.TempDir()
	s := artifacts.Store{Dir: dir}

	_, _, err := s.Put("2.0.0", strings.NewReader(strings.Repeat("x", 100)), 10)
	if err == nil {
		t.Fatal("an oversized upload should be refused")
	}
	if _, _, err := s.Open("2.0.0"); !errors.Is(err, artifacts.ErrNotFound) {
		t.Errorf("a refused upload must leave nothing readable, got %v", err)
	}
}

func TestOpenAndRemoveMissing(t *testing.T) {
	s := artifacts.Store{Dir: t.TempDir()}
	if _, _, err := s.Open("nope"); !errors.Is(err, artifacts.ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
	// Removing something already gone is what the caller wanted anyway.
	if err := s.Remove("nope"); err != nil {
		t.Errorf("removing a missing artifact should be fine, got %v", err)
	}
}

// A version string arrives from an administrator and becomes a path segment,
// so it must not be able to escape the directory.
func TestPutRejectsAPathTraversingVersion(t *testing.T) {
	s := artifacts.Store{Dir: t.TempDir()}
	for _, bad := range []string{"../evil", "a/b", `a\b`, "", "."} {
		if _, _, err := s.Put(bad, strings.NewReader("x"), 1<<20); err == nil {
			t.Errorf("version %q should be refused", bad)
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/server/artifacts/ -count=1`

Expected: FAIL to compile — the package does not exist.

- [ ] **Step 3: Write the implementation**

Create `internal/server/artifacts/artifacts.go`. Points that matter:

- A version becomes a directory name, so validate it first: non-empty, no separators, no `.` or `..`, and nothing outside `[A-Za-z0-9._+-]`. An administrator's typo must not become a path.
- Write to `<dir>/<version>/retune-agent.exe.part` through an `io.MultiWriter` of the file and a `sha256.New()`, wrapping the reader in `io.LimitReader(r, limit+1)` so exceeding the limit is detectable rather than silently truncating.
- On any failure, remove the partial file and the directory, and return. A refused upload leaves nothing.
- Only on success, rename `.part` to `retune-agent.exe` — the same temp-then-rename shape `identity.writeAtomic` uses, but streaming.
- `Put` refuses when the final file already exists, returning `ErrExists`.
- `Open` returns the file and its size from `Stat`, mapping `os.IsNotExist` to `ErrNotFound`.
- `Remove` deletes the version's directory and tolerates its absence.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/server/artifacts/ -count=1 && go vet ./internal/server/artifacts/`

Expected: PASS. No Docker needed — this is pure filesystem.

- [ ] **Step 5: Commit**

```bash
git add internal/server/artifacts/
git commit -m "feat(server): a place to keep uploaded agent builds"
```

---

### Task 5: The agent-versions service

**Files:**
- Create: `internal/server/agentversions/service.go`
- Create: `internal/server/agentversions/service_test.go`

**Interfaces:**
- Consumes: `store.AgentVersion` and its queries (Task 3), `artifacts.Store` (Task 4), `protocol.ItemKindAgent` (Task 2).
- Produces:
  ```go
  var ErrNotFound, ErrVersionTaken, ErrBadRequest error
  const MaxUploadBytes = 128 << 20   // 128 MiB

  type Service struct {
      Store     *store.Store
      Artifacts artifacts.Store
      Now       func() time.Time
  }
  type NewVersion struct { Version, Notes, Actor string }

  func (s *Service) Upload(ctx context.Context, in NewVersion, body io.Reader) (store.AgentVersion, error)
  func (s *Service) Get(ctx context.Context, id uuid.UUID) (store.AgentVersion, error)
  func (s *Service) List(ctx context.Context, page store.Page) ([]store.AgentVersion, int, error)
  func (s *Service) Delete(ctx context.Context, id uuid.UUID, actor string) error
  func (s *Service) Open(ctx context.Context, id uuid.UUID) (io.ReadCloser, int64, error)
  func (s *Service) RecordResult(ctx context.Context, deviceID, id uuid.UUID, r protocol.AgentUpdateResult) error
  ```

`RecordResult` writes the device's status for this build through
`SetItemStatus` with `protocol.ItemKindAgent` — succeeded or failed, with the
detail the agent sent. There is no separate history table: unlike a script run
or an app install, an agent either is or is not on a given build, and the
status plus the reported version says everything. A rollback arrives here as
`failed` with a detail naming the version that was put back, which is how the
console shows *"3 devices rolled back from 0.2.0"* rather than silence.

- [ ] **Step 1: Write the failing test**

Create `internal/server/agentversions/service_test.go`:

```go
package agentversions_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/agentversions"
	"retune/internal/server/artifacts"
	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

func service(t *testing.T, st *store.Store) *agentversions.Service {
	t.Helper()
	return &agentversions.Service{Store: st, Artifacts: artifacts.Store{Dir: t.TempDir()}}
}

func TestUploadRecordsTheHashItComputed(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(t, st)

	v, err := svc.Upload(ctx, agentversions.NewVersion{Version: "1.2.3", Actor: "ops"},
		strings.NewReader("a pretend agent"))
	if err != nil {
		t.Fatal(err)
	}
	if v.SHA256 == "" || v.SizeBytes != int64(len("a pretend agent")) {
		t.Fatalf("version = %+v", v)
	}

	r, size, err := svc.Open(ctx, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if size != v.SizeBytes {
		t.Errorf("Open reported %d bytes, metadata says %d", size, v.SizeBytes)
	}
	if body, _ := io.ReadAll(r); string(body) != "a pretend agent" {
		t.Errorf("read back %q", body)
	}
}

// The same version twice is a mistake. Accepting it would mean two devices
// could install different bytes for what the console calls one build.
func TestUploadRefusesADuplicateVersion(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(t, st)

	if _, err := svc.Upload(ctx, agentversions.NewVersion{Version: "1.0.0", Actor: "ops"},
		strings.NewReader("first")); err != nil {
		t.Fatal(err)
	}
	_, err := svc.Upload(ctx, agentversions.NewVersion{Version: "1.0.0", Actor: "ops"},
		strings.NewReader("second"))
	if !errors.Is(err, agentversions.ErrVersionTaken) {
		t.Fatalf("want ErrVersionTaken, got %v", err)
	}
}

func TestUploadRejectsBadInput(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(t, st)

	for name, in := range map[string]agentversions.NewVersion{
		"no version":        {Actor: "ops"},
		"a path in version": {Version: "../evil", Actor: "ops"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := svc.Upload(ctx, in, strings.NewReader("x")); !errors.Is(err, agentversions.ErrBadRequest) {
				t.Fatalf("want ErrBadRequest, got %v", err)
			}
		})
	}
}

// Deleting a build removes its bytes and its assignments, so no device is left
// being told to install something that no longer exists.
func TestDeleteRemovesBytesAndAssignments(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(t, st)

	v, err := svc.Upload(ctx, agentversions.NewVersion{Version: "2.0.0", Actor: "ops"},
		strings.NewReader("bytes"))
	if err != nil {
		t.Fatal(err)
	}
	err = st.Q().CreateAssignment(ctx, store.Assignment{
		ID: uuid.Must(uuid.NewV7()), ItemKind: protocol.ItemKindAgent, ItemID: v.ID,
		GroupID: store.BuiltinGroupID, Mode: store.ModeInclude, CreatedBy: "ops",
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := svc.Delete(ctx, v.ID, "ops"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Open(ctx, v.ID); err == nil {
		t.Error("the bytes should be gone")
	}
	rows, err := st.Q().ListAssignments(ctx, protocol.ItemKindAgent, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Errorf("assignments should have gone too, got %+v", rows)
	}
}
```

`store.Assignment` may need a `CreatedAt`; set it from `time.Now()` if the insert complains. `CreateAssignment` returns `(uuid.UUID, error)` — assign both.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/server/agentversions/ -count=1`

Expected: FAIL to compile — the package does not exist.

- [ ] **Step 3: Write the service**

Create `internal/server/agentversions/service.go`, modelled on `internal/server/apps/service.go`. Points that differ:

```go
// MaxUploadBytes caps one uploaded build. The agent is a single static Go
// binary of a few megabytes; a hundred times that is a mistake or an attack,
// not a release.
const MaxUploadBytes = 128 << 20
```

`Upload` is the interesting one, and its **order matters**: write the bytes first, then the metadata row. If the row fails, remove the bytes; if the bytes fail, no row was written. The alternative — row first — can leave metadata describing a file that does not exist, which is the state the agent cannot recover from.

```go
// Upload stores a build and records what was received. The bytes land first:
// a metadata row describing a file that does not exist is a state an agent
// cannot recover from, whereas an orphaned file is merely wasted disk.
func (s *Service) Upload(ctx context.Context, in NewVersion, body io.Reader) (store.AgentVersion, error) {
	version := strings.TrimSpace(in.Version)
	if version == "" {
		return store.AgentVersion{}, fmt.Errorf("%w: a build needs a version", ErrBadRequest)
	}
	if _, err := s.Store.Q().GetAgentVersionByVersion(ctx, version); err == nil {
		return store.AgentVersion{}, ErrVersionTaken
	} else if !errors.Is(err, store.ErrNotFound) {
		return store.AgentVersion{}, err
	}

	sum, size, err := s.Artifacts.Put(version, body, MaxUploadBytes)
	if errors.Is(err, artifacts.ErrExists) {
		return store.AgentVersion{}, ErrVersionTaken
	}
	if err != nil {
		// A bad version string is the caller's to fix, and Put is what knows
		// which strings are usable as a directory name.
		return store.AgentVersion{}, fmt.Errorf("%w: %v", ErrBadRequest, err)
	}

	v := store.AgentVersion{
		ID: uuid.Must(uuid.NewV7()), Version: version, SHA256: sum, SizeBytes: size,
		Notes: in.Notes, CreatedAt: s.now(), CreatedBy: in.Actor,
	}
	err = s.Store.InTx(ctx, func(q *store.Queries) error {
		if err := q.CreateAgentVersion(ctx, v); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: in.Actor, Action: "agent_version.uploaded", TargetKind: "agent_version",
			TargetID: v.ID.String(),
			Details:  map[string]any{"version": version, "sha256": sum, "size_bytes": size},
		})
	})
	if err != nil {
		_ = s.Artifacts.Remove(version)
		return store.AgentVersion{}, err
	}
	return v, nil
}
```

`Delete` looks up the row, calls `DeleteAssignmentsForItem(ctx, protocol.ItemKindAgent, id)`, deletes the row and writes an `agent_version.deleted` audit entry — all in one transaction — and then removes the bytes. Removing the bytes last means a failed transaction cannot destroy a build that is still referenced.

`Open` reads the row for its version string, then `s.Artifacts.Open(v.Version)`.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/server/agentversions/ -count=1 && go vet ./internal/server/agentversions/`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/server/agentversions/
git commit -m "feat(server): the agent-versions service"
```

---

### Task 6: The admin API for agent versions

**Files:**
- Create: `internal/server/adminapi/agentversions.go`
- Modify: `internal/server/adminapi/resources.go`, `handler.go`, `itemkinds.go`
- Modify: `internal/server/app/app.go`
- Test: `internal/server/app/agentversions_test.go`

**Interfaces:**
- Produces: five `/agent-versions` routes, `AgentVersions` on both handler structs, and `App.AgentVersions`.

- [ ] **Step 1: Write the failing test**

Create `internal/server/app/agentversions_test.go`:

```go
package app_test

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"retune/internal/server/store"
)

type agentVersionResp struct {
	ID        string `json:"id"`
	Version   string `json:"version"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
	Notes     string `json:"notes"`
}

// upload posts a build body. The upload is a raw body rather than JSON,
// because the payload is a binary and base64 in JSON would inflate it by a
// third for no benefit.
func uploadAgentVersion(t *testing.T, admin *adminClient, version, body string) (int, []byte) {
	t.Helper()
	return admin.doRaw(http.MethodPost,
		"/agent-versions?version="+version+"&notes=test",
		"application/octet-stream", bytes.NewReader([]byte(body)))
}

func TestAgentVersionLifecycle(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)

	status, body := uploadAgentVersion(t, admin, "1.2.3", "a pretend agent binary")
	if status != http.StatusCreated {
		t.Fatalf("upload: %d %s", status, body)
	}
	v := decodeJSON[agentVersionResp](t, body)
	if v.Version != "1.2.3" || v.SHA256 == "" || v.SizeBytes == 0 {
		t.Fatalf("version = %+v", v)
	}

	status, body = admin.do(http.MethodGet, "/agent-versions", nil)
	if status != http.StatusOK {
		t.Fatalf("list: %d %s", status, body)
	}
	if !strings.Contains(string(body), "1.2.3") {
		t.Errorf("the listing should name the build, got %s", body)
	}

	// The same version twice is refused rather than silently replacing bytes.
	if status, _ := uploadAgentVersion(t, admin, "1.2.3", "different bytes"); status != http.StatusConflict {
		t.Errorf("a duplicate version should be 409, got %d", status)
	}

	status, body = admin.do(http.MethodDelete, "/agent-versions/"+v.ID, nil)
	if status != http.StatusNoContent {
		t.Fatalf("delete: %d %s", status, body)
	}
}

// A read-only administrator can look but not upload.
func TestAgentVersionsAreClosedToReadOnlyAdmins(t *testing.T) {
	a, srv := newTestApp(t)
	c := signedIn(t, a, srv, store.RoleReadOnly)

	if status, _ := c.do(http.MethodGet, "/agent-versions", nil); status != http.StatusOK {
		t.Error("a read-only admin should be able to list builds")
	}
	if status, _ := uploadAgentVersion(t, c, "9.9.9", "x"); status != http.StatusForbidden {
		t.Errorf("a read-only admin must not upload, got %d", status)
	}
}

// An agent assignment carries a rollback deadline, validated at the API.
func TestAgentAssignmentDeadline(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)

	_, body := uploadAgentVersion(t, admin, "1.2.3", "bytes")
	v := decodeJSON[agentVersionResp](t, body)

	status, body := admin.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": "agent", "item_id": v.ID,
		"group_id": store.BuiltinGroupID.String(), "mode": "include",
		"options": map[string]any{"deadline_seconds": 120},
	})
	if status != http.StatusCreated {
		t.Fatalf("assign: %d %s", status, body)
	}
	if !strings.Contains(string(body), `"deadline_seconds":120`) {
		t.Errorf("the stored options should keep the deadline, got %s", body)
	}

	status, body = admin.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": "agent", "item_id": v.ID,
		"group_id": store.BuiltinGroupID.String(), "mode": "include",
		"options": map[string]any{"deadline_seconds": 5},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("a deadline below the floor should be refused, got %d %s", status, body)
	}
}
```

- [ ] **Step 2: Add the raw-body test helper**

`adminClient.do` marshals JSON. Add a sibling to `internal/server/app/admin_helpers_test.go` that sends an arbitrary body, following `do`'s cookie and CSRF handling exactly:

```go
// doRaw sends a non-JSON body, for endpoints that take bytes rather than an
// object. It keeps do's cookie and CSRF handling.
func (c *adminClient) doRaw(method, path, contentType string, body io.Reader) (int, []byte) {
	c.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, c.base+path, body)
	if err != nil {
		c.t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
	if c.csrf != "" {
		req.Header.Set(adminapi.CSRFHeader, c.csrf)
	}
	res, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	c.setCookies = res.Cookies()
	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, out
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `go test ./internal/server/app/ -run AgentVersion -count=1`

Expected: FAIL — `POST /agent-versions` is 404.

- [ ] **Step 4: Write the handlers**

Create `internal/server/adminapi/agentversions.go` modelled on `adminapi/apps.go`: an `agentVersionJSON` struct and constructor, a `writeAgentVersionError` mapping `ErrNotFound`→404, `ErrVersionTaken`→409, `ErrBadRequest`→400, and handlers `listAgentVersions`, `getAgentVersion`, `uploadAgentVersion`, `deleteAgentVersion`.

The upload differs from every other handler in the product:

```go
// uploadAgentVersion takes the build as a raw body rather than JSON. Base64 in
// a JSON object would inflate a multi-megabyte binary by a third and force the
// whole thing into memory; the version and notes travel as query parameters
// instead.
func (h *Handler) uploadAgentVersion(w http.ResponseWriter, r *http.Request) {
	v, err := h.AgentVersions.Upload(r.Context(), agentversions.NewVersion{
		Version: r.URL.Query().Get("version"),
		Notes:   r.URL.Query().Get("notes"),
		Actor:   caller(r).Admin.Email,
	}, http.MaxBytesReader(w, r.Body, agentversions.MaxUploadBytes))
	if err != nil {
		h.writeAgentVersionError(w, "upload agent version", err)
		return
	}
	writeJSON(w, http.StatusCreated, newAgentVersionJSON(v))
}
```

- [ ] **Step 5: Register the routes, the parser and the service**

In `resources.go`, beside the `/apps` block:

```go
	mux.Handle("GET "+base+"/agent-versions", h.read(h.listAgentVersions))
	mux.Handle("POST "+base+"/agent-versions", h.write(h.uploadAgentVersion))
	mux.Handle("GET "+base+"/agent-versions/{id}", h.read(h.getAgentVersion))
	mux.Handle("DELETE "+base+"/agent-versions/{id}", h.write(h.deleteAgentVersion))
```

In `itemkinds.go`, add to `optionsParsers`:

```go
	protocol.ItemKindAgent: func(raw json.RawMessage) ([]byte, error) {
		opts, err := protocol.ParseAgentOptions(raw)
		if err != nil {
			return nil, err
		}
		return opts.Marshal()
	},
```

Add `AgentVersions *agentversions.Service` to **both** `adminapi.Handler` and `agentapi.Handler` — the agent handler does not use it until Task 7, but an unused struct field compiles and this keeps every `app.go` edit in one task.

In `internal/server/app/app.go`: add `AgentVersions *agentversions.Service` to the `App` struct; construct it beside the other services with the artifact store rooted in the data directory —

```go
	agentVers := &agentversions.Service{
		Store: st, Now: time.Now,
		// Beside the CA and the secret key: DATA_DIR is already what the
		// README tells an operator to back up.
		Artifacts: artifacts.Store{Dir: filepath.Join(cfg.DataDir, "agents")},
	}
```

— pass `AgentVersions: agentVers` to both handler literals, and add it to the returned `&App{...}`.

- [ ] **Step 6: Run the tests**

Run: `go test ./internal/server/... -count=1`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/server/adminapi/ internal/server/app/
git commit -m "feat(api): upload and manage agent builds"
```

---

### Task 7: The agent API for agent versions

**Files:**
- Modify: `internal/server/agentapi/handler.go`
- Test: `internal/server/app/agentversions_test.go`

**Interfaces:**
- Produces: `GET /api/agent/v1/agent-versions/{id}` (JSON definition), `GET /api/agent/v1/agent-versions/{id}/binary` (the bytes), `POST /api/agent/v1/agent-versions/{id}/result` (the outcome), plus the `agent` case in `itemVersion`.

- [ ] **Step 1: Write the failing test**

Add to `internal/server/app/agentversions_test.go`:

```go
// A device may only download a build it has been assigned. An unassigned one
// is a 404 -- the same answer as one that does not exist, which is all an
// agent needs to know.
func TestAgentDownloadsOnlyAssignedBuilds(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	_, agent := enrollDevice(t, a, srv, "DESKTOP-UPDATING")

	const payload = "a pretend agent binary"
	_, body := uploadAgentVersion(t, admin, "1.2.3", payload)
	v := decodeJSON[agentVersionResp](t, body)

	for _, path := range []string{"", "/binary"} {
		url := srv.URL + "/api/agent/v1/agent-versions/" + v.ID + path
		if status, _ := send(t, agent, http.MethodGet, url, nil); status != http.StatusNotFound {
			t.Fatalf("an unassigned build must not be readable at %q, got %d", path, status)
		}
	}

	status, body := admin.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": "agent", "item_id": v.ID,
		"group_id": store.BuiltinGroupID.String(), "mode": "include",
	})
	if status != http.StatusCreated {
		t.Fatalf("assign: %d %s", status, body)
	}

	// The definition says what to expect before a byte is downloaded.
	status, body = send(t, agent, http.MethodGet,
		srv.URL+"/api/agent/v1/agent-versions/"+v.ID, nil)
	if status != http.StatusOK {
		t.Fatalf("definition: %d %s", status, body)
	}
	def := decodeJSON[protocol.AgentVersionResponse](t, body)
	if def.Version != "1.2.3" || def.SHA256 != v.SHA256 || def.SizeBytes != int64(len(payload)) {
		t.Fatalf("definition = %+v", def)
	}

	// And the bytes are exactly what was uploaded.
	status, body = send(t, agent, http.MethodGet,
		srv.URL+"/api/agent/v1/agent-versions/"+v.ID+"/binary", nil)
	if status != http.StatusOK {
		t.Fatalf("binary: %d", status)
	}
	if string(body) != payload {
		t.Errorf("downloaded %q, want %q", body, payload)
	}
}

// A reported outcome reaches the console's rollup, and a rollback says which
// build failed rather than going quiet.
func TestAgentUpdateResultIsRecorded(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	_, agent := enrollDevice(t, a, srv, "DESKTOP-UPDATING")

	_, body := uploadAgentVersion(t, admin, "2.0.0", "bytes")
	v := decodeJSON[agentVersionResp](t, body)
	admin.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": "agent", "item_id": v.ID,
		"group_id": store.BuiltinGroupID.String(), "mode": "include",
	})

	status, body := send(t, agent, http.MethodPost,
		srv.URL+"/api/agent/v1/agent-versions/"+v.ID+"/result",
		protocol.AgentUpdateResult{
			Version: "2.0.0", Status: protocol.ResultFailed,
			RolledBackFrom: "2.0.0", Detail: "the new agent never checked in",
		})
	if status != http.StatusNoContent {
		t.Fatalf("report: %d %s", status, body)
	}

	status, body = admin.do(http.MethodGet, "/items/agent/"+v.ID+"/status", nil)
	if status != http.StatusOK {
		t.Fatalf("status: %d %s", status, body)
	}
	resp := decodeJSON[itemStatusResp](t, body)
	if resp.Rollup[store.ItemFailed] != 1 {
		t.Fatalf("want one failed, got %v", resp.Rollup)
	}
	if !strings.Contains(resp.Items[0].Detail, "never checked in") {
		t.Errorf("the detail should say what happened, got %q", resp.Items[0].Detail)
	}
}

// Check-in offers an assigned build.
func TestAgentBuildReachesTheAgent(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	_, agent := enrollDevice(t, a, srv, "DESKTOP-UPDATING")

	_, body := uploadAgentVersion(t, admin, "1.2.3", "bytes")
	v := decodeJSON[agentVersionResp](t, body)
	admin.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": "agent", "item_id": v.ID,
		"group_id": store.BuiltinGroupID.String(), "mode": "include",
	})

	status, body := send(t, agent, http.MethodPost, srv.URL+"/api/agent/v1/checkin",
		protocol.CheckinRequest{AgentVersion: "1.0.0"})
	if status != http.StatusOK {
		t.Fatalf("checkin: %d %s", status, body)
	}
	items := decodeJSON[protocol.CheckinResponse](t, body).Items
	if len(items) != 1 || items[0].Kind != protocol.ItemKindAgent {
		t.Fatalf("the build should be offered, got %+v", items)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/server/app/ -run 'AgentDownloads|AgentBuildReaches' -count=1`

Expected: FAIL — the agent routes 404.

- [ ] **Step 3: Add the `itemVersion` case**

An agent build is immutable — a new build is a new row, never an edit — so its item version is always 1. The version *string* travels in the definition.

```go
	case protocol.ItemKindAgent:
		if _, err := h.AgentVersions.Get(ctx, it.ID); err != nil {
			h.Log.Warn("assigned agent build is missing", "agent_version_id", it.ID, "error", err)
			return 0, false
		}
		// A build is immutable, so there is only ever version 1 of it; the
		// version string an agent compares against travels in the definition.
		return 1, true
```

- [ ] **Step 4: Add the two routes and their handlers**

In `Routes()`:

```go
	mux.Handle("GET /api/agent/v1/agent-versions/{id}", h.requireDevice(h.agentVersion))
	mux.Handle("GET /api/agent/v1/agent-versions/{id}/binary", h.requireDevice(h.agentVersionBinary))
	mux.Handle("POST /api/agent/v1/agent-versions/{id}/result", h.requireDevice(h.agentVersionResult))
```

`agentVersionResult` follows `appResult`: gate on `DeviceHasItem` **before**
decoding anything, decode `protocol.AgentUpdateResult` with `maxResultBody`,
call `h.AgentVersions.RecordResult`, and map `ErrBadRequest` to 400 and
anything else to 500. The gate is what stops a device forging a "succeeded"
for a build it was never given.

`agentVersion` follows `appVersion` exactly — parse the id, gate on `DeviceHasItem(ctx, a.Device.ID, protocol.ItemKindAgent, id)`, answer 404 `agent_version_not_found` for every failure — and writes `protocol.AgentVersionResponse`.

`agentVersionBinary` gates identically, then streams:

```go
	body, size, err := h.AgentVersions.Open(ctx, id)
	if err != nil { /* 404 agent_version_not_found, or 500 */ }
	defer body.Close()

	// The agent verifies the SHA-256 from the definition, so a truncated
	// transfer is caught there; Content-Length lets it fail sooner.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	if _, err := io.Copy(w, body); err != nil {
		// The response is already partly written, so there is nothing useful
		// to say to the client; the agent's hash check is what catches it.
		h.Log.Warn("agent build download was cut short", "device_id", a.Device.ID, "error", err)
	}
```

- [ ] **Step 5: Run the tests**

Run: `go test ./internal/server/... ./test/e2e/ -count=1`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/server/agentapi/handler.go internal/server/app/agentversions_test.go
git commit -m "feat(api): serve agent builds to the devices assigned them"
```

---

### Task 8: Downloading a build

The client has never downloaded a file. Every response body it handles is JSON, and its `http.Client` has a flat 60-second timeout covering the whole request including the body — which would cut off a multi-megabyte download on a slow link. This task adds the first streaming path.

**Files:**
- Modify: `internal/agent/client/client.go`
- Test: `internal/agent/client/client_agentversion_test.go` (new)

**Interfaces:**
- Produces:
  ```go
  func (c *Client) FetchAgentVersion(ctx context.Context, id string) (protocol.AgentVersionResponse, error)

  // DownloadAgentBinary streams the build to dst, verifying its SHA-256 as it
  // goes. It returns an error if the hash does not match what was expected.
  func (c *Client) DownloadAgentBinary(ctx context.Context, id, wantSHA256 string, dst io.Writer) error
  func (c *Client) ReportAgentUpdate(ctx context.Context, id string, r protocol.AgentUpdateResult) error
  ```

`ReportAgentUpdate` is an ordinary JSON POST through `c.do`, following
`ReportAppResult`:

```go
// ReportAgentUpdate tells the server how an update turned out.
func (c *Client) ReportAgentUpdate(ctx context.Context, id string, r protocol.AgentUpdateResult) error {
	return c.do(ctx, http.MethodPost,
		"/api/agent/v1/agent-versions/"+url.PathEscape(id)+"/result", r, nil)
}
```

- [ ] **Step 1: Write the failing test**

Create `internal/agent/client/client_agentversion_test.go`. **Read
`internal/agent/client/client_test.go` first** and use whatever helper it
already has for standing up an `httptest` server and building a `Client`
against it. The sketch below calls `clientFor(t, srv)`; if that helper does not
exist under that name, use the real one rather than adding a duplicate.

```go
// The download is verified against the hash the definition promised, so a
// corrupted or tampered payload is refused rather than executed.
func TestDownloadAgentBinaryVerifiesTheHash(t *testing.T) {
	const payload = "a pretend agent binary"
	sum := sha256.Sum256([]byte(payload))
	good := hex.EncodeToString(sum[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, payload)
	}))
	defer srv.Close()
	c := clientFor(t, srv)

	var buf bytes.Buffer
	if err := c.DownloadAgentBinary(context.Background(), "id", good, &buf); err != nil {
		t.Fatalf("a matching hash should be accepted: %v", err)
	}
	if buf.String() != payload {
		t.Errorf("downloaded %q", buf.String())
	}

	buf.Reset()
	err := c.DownloadAgentBinary(context.Background(), "id", strings.Repeat("0", 64), &buf)
	if err == nil {
		t.Fatal("a mismatched hash must be refused")
	}
	if !strings.Contains(err.Error(), "sha256") {
		t.Errorf("the error should name what failed, got %v", err)
	}
}

// A large download must not be killed by the JSON client's short timeout.
func TestDownloadAgentBinaryOutlivesTheJSONTimeout(t *testing.T) {
	// Served slowly enough that a 60s whole-request budget would be tight, but
	// fast enough for a test: the point is that the download does not share the
	// JSON client's Timeout field at all.
	c := clientFor(t, httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "x")
	})))
	if c.DownloadTimeout() <= 60*time.Second {
		t.Errorf("the download budget is %v; it must be larger than the JSON client's 60s",
			c.DownloadTimeout())
	}
}
```

Add a small accessor so the last assertion is possible:

```go
// DownloadTimeout is the budget for a payload download, exposed so a test can
// assert it is not the JSON client's much shorter one.
func (c *Client) DownloadTimeout() time.Duration { return downloadTimeout }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/agent/client/ -count=1`

Expected: FAIL to compile — the methods do not exist.

- [ ] **Step 3: Write the implementation**

In `internal/agent/client/client.go`:

```go
// downloadTimeout is the budget for fetching a build. The JSON client's flat
// 60 seconds covers a whole request including the body, which is plenty for an
// object and nowhere near enough for a multi-megabyte binary over a slow link.
const downloadTimeout = 30 * time.Minute

// FetchAgentVersion downloads the definition of an assigned agent build: what
// version it is, how big it should be, and what it should hash to.
func (c *Client) FetchAgentVersion(ctx context.Context, id string) (protocol.AgentVersionResponse, error) {
	var resp protocol.AgentVersionResponse
	err := c.do(ctx, http.MethodGet, "/api/agent/v1/agent-versions/"+url.PathEscape(id), nil, &resp)
	return resp, err
}

// DownloadAgentBinary streams a build to dst, hashing as it goes, and refuses
// anything whose SHA-256 is not what the definition promised. It does not use
// the JSON client: that one decodes bodies and would cut a large download off
// at its own timeout.
func (c *Client) DownloadAgentBinary(ctx context.Context, id, wantSHA256 string, dst io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()

	path := "/api/agent/v1/agent-versions/" + url.PathEscape(id) + "/binary"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return err
	}
	// The same transport -- and so the same mutual TLS identity -- with no
	// whole-request deadline of its own.
	res, err := c.download.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", path, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		var e protocol.Error
		_ = json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&e)
		return &HTTPError{Status: res.StatusCode, Code: e.Code, Message: e.Message}
	}

	sum := sha256.New()
	if _, err := io.Copy(io.MultiWriter(dst, sum), res.Body); err != nil {
		return fmt.Errorf("download %s: %w", path, err)
	}
	got := hex.EncodeToString(sum.Sum(nil))
	if !strings.EqualFold(got, wantSHA256) {
		return fmt.Errorf("sha256 mismatch: the server promised %s and sent %s", wantSHA256, got)
	}
	return nil
}
```

In `New`, build the second client on the **same transport** so it carries the same client certificate, and give it no `Timeout` — the per-request context is the budget:

```go
	return &Client{
		base: strings.TrimRight(serverURL, "/"),
		http: &http.Client{Transport: tr, Timeout: 60 * time.Second},
		// A payload download has no whole-request deadline: its context
		// carries one sized for a binary rather than for an object.
		download: &http.Client{Transport: tr},
	}, nil
```

and add the field to the struct.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/agent/client/ -count=1 && go vet ./... && GOOS=linux go build ./...`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/agent/client/
git commit -m "feat(agent): download a build, verifying it against the promised hash"
```

---

### Task 9: The decision, and the record of an attempt

Two small pure pieces, both testable without Windows, a service, or a network.

**Files:**
- Create: `internal/agent/selfupdate/decide.go`, `decide_test.go`
- Create: `internal/agent/selfupdate/record.go`, `record_test.go`

**Interfaces:**
- Produces:
  ```go
  type Action int
  const (ActionNone Action = iota; ActionUpdate)
  type Decision struct { Action Action; Reason string }
  func Decide(running, assigned string, injected bool, attempted Record) Decision

  const RecordName = "update.json"
  type Record struct {
      FromVersion string   `json:"from_version"`
      FromBinPath string   `json:"from_bin_path"`
      FromArgs    []string `json:"from_args"`
      ToVersion   string   `json:"to_version"`
      ToBinPath   string   `json:"to_bin_path"`
      StartedAt   time.Time `json:"started_at"`
      Deadline    time.Time `json:"deadline"`
      Status      string   `json:"status"`
      Detail      string   `json:"detail"`
  }
  const (StatusPending = "pending"; StatusSucceeded = "succeeded"; StatusRolledBack = "rolled_back")
  func ReadRecord(dir string) (Record, bool, error)
  func WriteRecord(dir string, r Record) error
  func RemoveRecord(dir string) error
  ```

- [ ] **Step 1: Write the failing tests**

Create `internal/agent/selfupdate/decide_test.go`:

```go
package selfupdate_test

import (
	"testing"
	"time"

	"retune/internal/agent/selfupdate"
)

func TestDecide(t *testing.T) {
	cases := map[string]struct {
		running, assigned string
		injected          bool
		attempted         selfupdate.Record
		want              selfupdate.Action
		reason            string
	}{
		"already on the assigned version": {
			running: "1.2.3", assigned: "1.2.3", injected: true,
			want: selfupdate.ActionNone, reason: "already",
		},
		"a newer version is assigned": {
			running: "1.2.3", assigned: "1.3.0", injected: true,
			want: selfupdate.ActionUpdate,
		},
		"an older version is assigned: a downgrade is a real instruction": {
			running: "1.3.0", assigned: "1.2.3", injected: true,
			want: selfupdate.ActionUpdate,
		},
		"this build has no injected version": {
			running: "0.1.0-dev", assigned: "1.3.0", injected: false,
			want: selfupdate.ActionNone, reason: "no injected version",
		},
		"the same version already failed and was rolled back": {
			running: "1.2.3", assigned: "1.3.0", injected: true,
			attempted: selfupdate.Record{ToVersion: "1.3.0", Status: selfupdate.StatusRolledBack},
			want:      selfupdate.ActionNone, reason: "rolled back",
		},
		"a different version after a rollback is still attempted": {
			running: "1.2.3", assigned: "1.4.0", injected: true,
			attempted: selfupdate.Record{ToVersion: "1.3.0", Status: selfupdate.StatusRolledBack},
			want:      selfupdate.ActionUpdate,
		},
		"an update is already in flight": {
			running: "1.2.3", assigned: "1.3.0", injected: true,
			attempted: selfupdate.Record{ToVersion: "1.3.0", Status: selfupdate.StatusPending},
			want:      selfupdate.ActionNone, reason: "already under way",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := selfupdate.Decide(tc.running, tc.assigned, tc.injected, tc.attempted)
			if got.Action != tc.want {
				t.Fatalf("action = %v, want %v (reason %q)", got.Action, tc.want, got.Reason)
			}
			if got.Action == selfupdate.ActionNone && got.Reason == "" {
				t.Error("a decision not to update should say why, for the agent's log")
			}
		})
	}
}

// The rollback memory is per-version, not permanent: a build that failed must
// not be retried in a loop, but a later build must not be blocked by it.
func TestARolledBackVersionIsNotRetried(t *testing.T) {
	rolled := selfupdate.Record{ToVersion: "2.0.0", Status: selfupdate.StatusRolledBack}
	if d := selfupdate.Decide("1.0.0", "2.0.0", true, rolled); d.Action != selfupdate.ActionNone {
		t.Error("the version that was rolled back must not be attempted again")
	}
	if d := selfupdate.Decide("1.0.0", "2.0.1", true, rolled); d.Action != selfupdate.ActionUpdate {
		t.Error("a different version must still be attempted")
	}
}

var _ = time.Now
```

Create `internal/agent/selfupdate/record_test.go`:

```go
package selfupdate_test

import (
	"testing"
	"time"

	"retune/internal/agent/selfupdate"
)

// The record is what lets the supervisor put the service back exactly as it
// was. The arguments matter as much as the path: an MSI-installed service
// carries no --data-dir and a manually installed one does, and a repoint that
// loses that argument sends the new agent looking for its identity in the
// wrong directory.
func TestRecordRoundTripKeepsTheServiceArguments(t *testing.T) {
	dir := t.TempDir()
	want := selfupdate.Record{
		FromVersion: "1.2.3",
		FromBinPath: `C:\Program Files\Retune\retune-agent.exe`,
		FromArgs:    []string{"--data-dir", `C:\ProgramData\Retune`},
		ToVersion:   "1.3.0",
		ToBinPath:   `C:\ProgramData\Retune\bin\1.3.0\retune-agent.exe`,
		StartedAt:   time.Now().UTC().Truncate(time.Second),
		Deadline:    time.Now().UTC().Truncate(time.Second).Add(10 * time.Minute),
		Status:      selfupdate.StatusPending,
	}
	if err := selfupdate.WriteRecord(dir, want); err != nil {
		t.Fatal(err)
	}

	got, found, err := selfupdate.ReadRecord(dir)
	if err != nil || !found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	if len(got.FromArgs) != 2 || got.FromArgs[0] != "--data-dir" {
		t.Fatalf("the service arguments must survive, got %+v", got.FromArgs)
	}
	if got.FromBinPath != want.FromBinPath || got.ToVersion != want.ToVersion {
		t.Fatalf("record = %+v", got)
	}

	if err := selfupdate.RemoveRecord(dir); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := selfupdate.ReadRecord(dir); found {
		t.Error("the record should be gone")
	}
}

// No record is the ordinary state, not an error.
func TestReadRecordWithNothingThere(t *testing.T) {
	if _, found, err := selfupdate.ReadRecord(t.TempDir()); err != nil || found {
		t.Errorf("found=%v err=%v", found, err)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/agent/selfupdate/ -count=1`

Expected: FAIL to compile — the package does not exist.

- [ ] **Step 3: Write `decide.go`**

`Decide` is pure: every input is a parameter, and there is no clock, no filesystem and no service in it.

```go
// Decide reports whether this agent should replace itself. It is deliberately
// a pure function: the running version, the assigned one, whether this build
// was stamped at all, and what was last attempted are the whole input.
func Decide(running, assigned string, injected bool, attempted Record) Decision {
	// A build that was never stamped reports the placeholder for ever. It
	// would update, report the same string, be told to update again, and do
	// that on every check-in on every machine. Refusing is the only safe
	// answer, and saying so is how somebody finds out why.
	if !injected {
		return Decision{Reason: "this build has no injected version, so it will not self-update"}
	}
	if assigned == "" {
		return Decision{Reason: "the assigned build has no version"}
	}
	// Difference, not ordering: assigning an older build is how a fleet is
	// recovered from a bad one.
	if running == assigned {
		return Decision{Reason: "this device is already running the assigned version"}
	}
	if attempted.ToVersion == assigned {
		switch attempted.Status {
		case StatusRolledBack:
			return Decision{Reason: "this version was already tried here and rolled back"}
		case StatusPending:
			return Decision{Reason: "an update to this version is already under way"}
		}
	}
	return Decision{Action: ActionUpdate}
}
```

- [ ] **Step 4: Write `record.go`**

`ReadRecord` returns `(Record{}, false, nil)` when the file is absent — that is the ordinary state. `WriteRecord` writes through a temp file and renames, the shape `identity.writeAtomic` uses, because a half-written record is worse than none: the supervisor reads it to decide how to put the service back.

- [ ] **Step 5: Run the tests**

Run: `go test ./internal/agent/selfupdate/ -count=1 && GOOS=linux go build ./...`

Expected: PASS on both platforms — nothing here is Windows-specific.

- [ ] **Step 6: Commit**

```bash
git add internal/agent/selfupdate/
git commit -m "feat(agent): decide whether to self-update, and remember the attempt"
```

---

### Task 10: Controlling the service

Rollback has to drive the service control manager, and the *only* way to test that logic without breaking a real service is to put an interface in front of it. Note the repo has never started a service programmatically — `service_windows.go` stops, configures and deletes, but nothing calls `Start`.

**Files:**
- Create: `internal/agent/selfupdate/controller.go` — the interface and its errors
- Create: `internal/agent/selfupdate/controller_windows.go` — the real one
- Create: `internal/agent/selfupdate/controller_other.go` — the stub
- Test: covered by Task 11 through a fake

**Interfaces:**
- Produces:
  ```go
  // ServiceController is the part of the service control manager an update
  // needs. It exists so rollback can be tested without a real service.
  type ServiceController interface {
      // Config returns the service's current image path and its arguments.
      Config() (binPath string, args []string, err error)
      SetBinPath(binPath string, args []string) error
      SetRecoveryActions() error
      Stop(ctx context.Context) error
      Start() error
      Running() (bool, error)
      // Close releases the manager and service handles behind the
      // controller. NewController opens two; a caller that never closes
      // them leaks both on every update attempt.
      Close() error
  }
  var ErrWindowsOnly = errors.New("controlling a service is only available on Windows")
  func NewController(serviceName string) (ServiceController, error)
  ```

- [ ] **Step 1: Write the interface**

Create `internal/agent/selfupdate/controller.go` with the interface above, no build tag. Document on `Config` **why** the arguments are returned as well as the path: an MSI-installed service has none and a manually installed one has `--data-dir`, and a repoint that loses them sends the new agent to the wrong directory.

- [ ] **Step 2: Write the Windows implementation**

Create `internal/agent/selfupdate/controller_windows.go` with `//go:build windows`, using `golang.org/x/sys/windows/svc/mgr` exactly as `cmd/retune-agent/service_windows.go` does:

- `NewController` connects with `mgr.Connect()` and opens the service; the returned controller keeps both handles and closes them on a `Close` method.
- `Config` reads `s.Config()` for `BinaryPathName`, and splits it into path and arguments. **The stored image path is a command line, not a bare path** — a quoted path may contain spaces. Use `windows.DecomposeCommandLine` (or `CommandLineToArgvW`) rather than splitting on spaces; a naive split is the bug M9 hit with firewall arguments.
- `SetBinPath` reads the config, sets `BinaryPathName` to the quoted path plus arguments, and calls `s.UpdateConfig(cfg)`.
- `SetRecoveryActions` mirrors `installService`: three `mgr.ServiceRestart` actions 60 seconds apart, reset after 24 hours. Comment **why**: a WiX-installed service has none, so a build that crashes on start would never be retried.
- `Stop` copies `stopAndWait`'s shape — `s.Control(svc.Stop)`, then poll `s.Query()` every 300ms until `svc.Stopped` or the context is done.
- `Start` calls `s.Start()`.
- `Running` queries and compares to `svc.Running`.

Create `internal/agent/selfupdate/controller_other.go` with `//go:build !windows`, whose `NewController` returns `ErrWindowsOnly`.

- [ ] **Step 3: Verify it builds on both platforms**

Run: `go vet ./... && GOOS=linux go build ./... && go build ./...`

Expected: both clean. There is nothing to test yet — Task 11 tests the logic that uses this through a fake.

- [ ] **Step 4: Commit**

```bash
git add internal/agent/selfupdate/controller.go internal/agent/selfupdate/controller_windows.go internal/agent/selfupdate/controller_other.go
git commit -m "feat(agent): a seam in front of the service control manager"
```

---

### Task 11: The supervisor

The known-good build supervising its own replacement. This is the safety property of the whole milestone, so it is tested hard, against a fake controller, with no real service involved.

**Files:**
- Create: `internal/agent/selfupdate/supervise.go`
- Create: `internal/agent/selfupdate/supervise_test.go`

**Interfaces:**
- Consumes: `ServiceController` (Task 10), `Record` (Task 9).
- Produces:
  ```go
  type Supervisor struct {
      Dir        string             // the data directory, where update.json lives
      Control    ServiceController
      Log        *slog.Logger
      Now        func() time.Time
      Poll       time.Duration      // how often proof is checked; default 2s
  }
  // Supervise carries out the update described by the record in Dir, and puts
  // the previous build back if the new one does not check in before the
  // deadline. It returns nil when the update stuck.
  func (s *Supervisor) Supervise(ctx context.Context) error
  ```

- [ ] **Step 1: Write the failing test**

Create `internal/agent/selfupdate/supervise_test.go`:

```go
package selfupdate_test

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"retune/internal/agent/selfupdate"
)

// fakeControl records what was done to the service, and lets a test decide
// what happens when it is started.
type fakeControl struct {
	mu       sync.Mutex
	binPath  string
	args     []string
	calls    []string
	running  bool
	recovery bool
	stopErr  error
	startErr error
	// onStart runs when the service is started, standing in for the new agent
	// coming up and doing something.
	onStart func()
}

func (f *fakeControl) Config() (string, []string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.binPath, f.args, nil
}

func (f *fakeControl) SetBinPath(p string, args []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "setbinpath:"+p)
	f.binPath, f.args = p, args
	return nil
}

func (f *fakeControl) SetRecoveryActions() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls, f.recovery = append(f.calls, "recovery"), true
	return nil
}

func (f *fakeControl) Stop(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "stop")
	if f.stopErr != nil {
		return f.stopErr
	}
	f.running = false
	return nil
}

func (f *fakeControl) Start() error {
	f.mu.Lock()
	start := f.onStart
	f.calls = append(f.calls, "start")
	if f.startErr != nil {
		f.mu.Unlock()
		return f.startErr
	}
	f.running = true
	f.mu.Unlock()
	if start != nil {
		start()
	}
	return nil
}

func (f *fakeControl) Running() (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.running, nil
}

func (f *fakeControl) Close() error { return nil }

func (f *fakeControl) did() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func pending(dir string, deadline time.Time) selfupdate.Record {
	return selfupdate.Record{
		FromVersion: "1.0.0", FromBinPath: `C:\Program Files\Retune\retune-agent.exe`,
		FromArgs:  []string{"--data-dir", dir},
		ToVersion: "2.0.0", ToBinPath: dir + `\bin\2.0.0\retune-agent.exe`,
		StartedAt: time.Now(), Deadline: deadline, Status: selfupdate.StatusPending,
	}
}

func supervisor(dir string, c selfupdate.ServiceController) *selfupdate.Supervisor {
	return &selfupdate.Supervisor{
		Dir: dir, Control: c, Log: slog.New(slog.DiscardHandler),
		Poll: time.Millisecond,
	}
}

// The happy path: the new agent checks in, which it proves by marking the
// record succeeded, and the update stands.
func TestSuperviseKeepsAnUpdateThatChecksIn(t *testing.T) {
	dir := t.TempDir()
	rec := pending(dir, time.Now().Add(time.Minute))
	if err := selfupdate.WriteRecord(dir, rec); err != nil {
		t.Fatal(err)
	}
	c := &fakeControl{binPath: rec.FromBinPath, args: rec.FromArgs}
	// Standing in for the new agent reaching the server.
	c.onStart = func() {
		done := rec
		done.Status = selfupdate.StatusSucceeded
		_ = selfupdate.WriteRecord(dir, done)
	}

	if err := supervisor(dir, c).Supervise(context.Background()); err != nil {
		t.Fatalf("a successful update should not error: %v", err)
	}
	if got := c.binPath; got != rec.ToBinPath {
		t.Errorf("binPath = %q, want the new build", got)
	}
	if len(c.args) != 2 || c.args[0] != "--data-dir" {
		t.Errorf("the service arguments must be preserved, got %+v", c.args)
	}
	if !c.recovery {
		t.Error("recovery actions must be set: a WiX-installed service has none")
	}
	if _, found, _ := selfupdate.ReadRecord(dir); found {
		t.Error("a settled update should leave no record behind")
	}
}

// The failure this milestone exists to prevent: the new build starts but never
// reaches the server. The previous one must come back.
func TestSuperviseRollsBackWhenTheNewAgentNeverChecksIn(t *testing.T) {
	dir := t.TempDir()
	rec := pending(dir, time.Now().Add(50*time.Millisecond))
	if err := selfupdate.WriteRecord(dir, rec); err != nil {
		t.Fatal(err)
	}
	c := &fakeControl{binPath: rec.FromBinPath, args: rec.FromArgs}

	if err := supervisor(dir, c).Supervise(context.Background()); err != nil {
		t.Fatalf("a rollback is an outcome, not an error: %v", err)
	}
	if c.binPath != rec.FromBinPath {
		t.Errorf("binPath = %q, want the previous build restored", c.binPath)
	}
	if len(c.args) != 2 || c.args[1] != dir {
		t.Errorf("the previous arguments must be restored, got %+v", c.args)
	}
	got, found, _ := selfupdate.ReadRecord(dir)
	if !found || got.Status != selfupdate.StatusRolledBack {
		t.Fatalf("the rollback must be recorded for the restored agent to report, got %+v", got)
	}
	if got.Detail == "" {
		t.Error("the record should say why it was rolled back")
	}
	// It must actually have been restarted, not merely repointed.
	var starts int
	for _, c := range c.did() {
		if c == "start" {
			starts++
		}
	}
	if starts < 2 {
		t.Errorf("the service should be started twice -- new, then restored -- got %d", starts)
	}
}

// If the service will not stop, nothing is repointed. A half-applied update is
// worse than none.
func TestSuperviseDoesNotRepointIfTheServiceWillNotStop(t *testing.T) {
	dir := t.TempDir()
	rec := pending(dir, time.Now().Add(time.Minute))
	if err := selfupdate.WriteRecord(dir, rec); err != nil {
		t.Fatal(err)
	}
	c := &fakeControl{binPath: rec.FromBinPath, args: rec.FromArgs, stopErr: errors.New("it will not stop")}

	if err := supervisor(dir, c).Supervise(context.Background()); err == nil {
		t.Fatal("a service that will not stop should be an error")
	}
	if c.binPath != rec.FromBinPath {
		t.Errorf("nothing should have been repointed, got %q", c.binPath)
	}
	for _, call := range c.did() {
		if len(call) > 11 && call[:11] == "setbinpath:" {
			t.Fatalf("the image path must not be touched, got %v", c.did())
		}
	}
}

// With no record there is nothing to do, and that is not an error: the
// supervisor may be run after an update has already settled.
func TestSuperviseWithNoRecord(t *testing.T) {
	c := &fakeControl{}
	if err := supervisor(t.TempDir(), c).Supervise(context.Background()); err != nil {
		t.Errorf("no record should be a no-op, got %v", err)
	}
	if len(c.did()) != 0 {
		t.Errorf("nothing should have happened, got %v", c.did())
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/agent/selfupdate/ -run Supervise -count=1`

Expected: FAIL to compile — `selfupdate.Supervisor` does not exist.

- [ ] **Step 3: Write the supervisor**

Create `internal/agent/selfupdate/supervise.go`. The order is the design:

1. Read the record. Absent, or not `pending`: nothing to do, return nil.
2. Stop the service. **If this fails, return the error without touching the image path** — a half-applied update is worse than none.
3. `SetBinPath(rec.ToBinPath, rec.FromArgs)` — the new path, the *old* arguments.
4. `SetRecoveryActions()`, so a crash-on-start is retried rather than leaving the device dead.
5. `Start()`.
6. Poll until the deadline: re-read the record each tick and look for `StatusSucceeded`, which only the new agent writes and only after it has reached the server.
7. On success, `RemoveRecord` and return nil.
8. On the deadline, roll back: `Stop`, `SetBinPath(rec.FromBinPath, rec.FromArgs)`, `Start`, then write the record with `StatusRolledBack` and a detail saying what happened. Return nil — a rollback is an outcome, not an error.

Everything the supervisor does goes to the log, because when this misbehaves the log is the only witness.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/agent/selfupdate/ -count=1 -race && GOOS=linux go build ./...`

Expected: PASS, including under the race detector — `onStart` writes the record from inside `Start`.

- [ ] **Step 5: Commit**

```bash
git add internal/agent/selfupdate/supervise.go internal/agent/selfupdate/supervise_test.go
git commit -m "feat(agent): supervise an update, and put the previous build back if it fails"
```

---

### Task 12: The syncer

**Files:**
- Create: `internal/agent/selfupdate/syncer.go`
- Create: `internal/agent/selfupdate/syncer_test.go`

**Interfaces:**
- Consumes: everything above, plus `protocol.ItemKindAgent` and `protocol.ParseAgentOptions`.
- Produces:
  ```go
  type Client interface {
      FetchAgentVersion(ctx context.Context, id string) (protocol.AgentVersionResponse, error)
      DownloadAgentBinary(ctx context.Context, id, wantSHA256 string, dst io.Writer) error
      ReportAgentUpdate(ctx context.Context, id string, r protocol.AgentUpdateResult) error
  }
  type Syncer struct {
      Dir      string            // the data directory
      Client   Client
      Control  ServiceController // reads the live service's path and arguments
      Running  string            // this build's version
      Injected bool
      Log      *slog.Logger
      Now      func() time.Time
      // Rollback, when set, is a previous attempt that was rolled back and has
      // not been reported yet. The restored agent reports it on its next
      // check-in and then clears the record: the supervisor cannot, because by
      // the time it decides, the agent it was testing is gone.
      Rollback *Record
      // Spawn starts the supervisor. It is a field so a test can observe the
      // hand-off without launching a process.
      Spawn func(supervisorPath string) error
      mu    sync.Mutex
  }
  func (s *Syncer) Sync(ctx context.Context, items []protocol.Item) error
  ```

`Control` may be nil on a platform where `NewController` returned
`ErrWindowsOnly`; the syncer then refuses every assigned build with that
reason rather than pretending it could act.

- [ ] **Step 1: Write the failing test**

Create `internal/agent/selfupdate/syncer_test.go` with a fake client and a `Spawn` that records rather than launching:

```go
// A clean update: the build is downloaded, verified, staged, and the
// supervisor is handed off to.
func TestSyncStagesAndHandsOff(t *testing.T) {
	dir := t.TempDir()
	c := &fakeClient{version: "2.0.0", payload: []byte("new agent bytes")}
	var spawned string
	s := &selfupdate.Syncer{
		Dir: dir, Client: c, Running: "1.0.0", Injected: true,
		Log: slog.New(slog.DiscardHandler), Now: time.Now,
		Spawn: func(p string) error { spawned = p; return nil },
	}

	if err := s.Sync(context.Background(), []protocol.Item{agentItem("v1", nil)}); err != nil {
		t.Fatal(err)
	}
	if spawned == "" {
		t.Fatal("the supervisor should have been handed off to")
	}
	if _, err := os.Stat(filepath.Join(dir, "bin", "2.0.0", "retune-agent.exe")); err != nil {
		t.Errorf("the new build should be staged: %v", err)
	}
	rec, found, _ := selfupdate.ReadRecord(dir)
	if !found || rec.ToVersion != "2.0.0" || rec.Status != selfupdate.StatusPending {
		t.Fatalf("a pending record should describe the attempt, got %+v", rec)
	}
	if rec.FromVersion != "1.0.0" {
		t.Errorf("the record must remember what to go back to, got %q", rec.FromVersion)
	}
}

// A payload whose hash does not match is refused, nothing is staged, and the
// supervisor is never started.
func TestSyncRefusesAMismatchedHash(t *testing.T) {
	dir := t.TempDir()
	c := &fakeClient{version: "2.0.0", payload: []byte("bytes"), downloadErr: errors.New("sha256 mismatch")}
	var spawned bool
	s := &selfupdate.Syncer{
		Dir: dir, Client: c, Running: "1.0.0", Injected: true,
		Log: slog.New(slog.DiscardHandler), Now: time.Now,
		Spawn: func(string) error { spawned = true; return nil },
	}

	if err := s.Sync(context.Background(), []protocol.Item{agentItem("v1", nil)}); err != nil {
		t.Fatal(err)
	}
	if spawned {
		t.Error("a build that failed verification must never be handed to the supervisor")
	}
	if _, found, _ := selfupdate.ReadRecord(dir); found {
		t.Error("nothing should be pending")
	}
}

// A rollback left by a previous attempt is reported, once, and then forgotten.
// Nothing else can report it: the supervisor that decided is gone.
func TestSyncReportsAPendingRollback(t *testing.T) {
	dir := t.TempDir()
	rec := selfupdate.Record{
		FromVersion: "1.0.0", ToVersion: "2.0.0",
		Status: selfupdate.StatusRolledBack, Detail: "the new agent never checked in",
	}
	if err := selfupdate.WriteRecord(dir, rec); err != nil {
		t.Fatal(err)
	}
	c := &fakeClient{version: "1.0.0"}
	s := &selfupdate.Syncer{
		Dir: dir, Client: c, Running: "1.0.0", Injected: true,
		Log: slog.New(slog.DiscardHandler), Now: time.Now, Rollback: &rec,
		Spawn: func(string) error { return nil },
	}

	if err := s.Sync(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if len(c.reports) != 1 {
		t.Fatalf("the rollback should be reported exactly once, got %+v", c.reports)
	}
	if c.reports[0].RolledBackFrom != "2.0.0" || c.reports[0].Status != protocol.ResultFailed {
		t.Errorf("report = %+v", c.reports[0])
	}
	if _, found, _ := selfupdate.ReadRecord(dir); found {
		t.Error("a reported rollback should leave no record behind")
	}

	// A second cycle must not report it again.
	if err := s.Sync(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if len(c.reports) != 1 {
		t.Errorf("it must not be reported twice, got %d", len(c.reports))
	}
}

// An unstamped build refuses outright, does not download, and says why -- so
// somebody can see that the fleet is not updating and know the reason.
func TestSyncRefusesWithoutAnInjectedVersion(t *testing.T) {
	dir := t.TempDir()
	c := &fakeClient{version: "2.0.0", payload: []byte("bytes")}
	s := &selfupdate.Syncer{
		Dir: dir, Client: c, Running: "0.1.0-dev", Injected: false,
		Log: slog.New(slog.DiscardHandler), Now: time.Now,
		Spawn: func(string) error { t.Fatal("nothing should be handed off"); return nil },
	}

	if err := s.Sync(context.Background(), []protocol.Item{agentItem("v1", nil)}); err != nil {
		t.Fatal(err)
	}
	if c.downloads != 0 {
		t.Errorf("it must not download, got %d downloads", c.downloads)
	}
	if len(c.reports) != 1 || c.reports[0].Status != protocol.ResultFailed {
		t.Fatalf("the refusal should be reported, got %+v", c.reports)
	}
	if !strings.Contains(c.reports[0].Detail, "injected") {
		t.Errorf("the detail should say why, got %q", c.reports[0].Detail)
	}
}

// Items of other kinds are ignored, which is how an older agent copes with a
// newer server.
func TestSyncIgnoresOtherKinds() { /* ... */ }
```

`TestSyncIgnoresOtherKinds` is still sketched above — write it out in full,
following the shape of the others: a single `script`-kind item, and assertions
that nothing was fetched, downloaded, reported or handed off.

`fakeClient` needs `fetches`, `downloads` and `reports []protocol.AgentUpdateResult`
counters, and a `downloadErr` to simulate a hash mismatch. `agentItem(id, opts)`
is a helper you write in the same file, returning
`protocol.Item{Kind: protocol.ItemKindAgent, ID: id, Version: 1, Options: raw}`
with the options marshalled from `protocol.DefaultAgentOptions()` when `opts`
is nil — an agent build is immutable, so its item version is always 1.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/agent/selfupdate/ -run Sync -count=1`

Expected: FAIL to compile.

- [ ] **Step 3: Write the syncer**

`Sync` takes `s.mu` for the whole call and filters to `protocol.ItemKindAgent`. For each item:

1. Parse the options for the deadline.
2. Fetch the definition, read the existing record, and call `Decide(s.Running, def.Version, s.Injected, record)`. On `ActionNone`, log the reason and return.
3. Create `Dir/bin/<version>/`, download to `retune-agent.exe.part` with the hash verified by the client, then rename into place. A failure here removes the partial directory and returns — nothing has changed that matters.
4. Read the service's current image path and arguments through a `ServiceController`, and write the record. **The arguments are captured here**, from the live service, which is the only place that knows whether this device was installed by the MSI or by hand.
5. Copy the running executable to `Dir/supervisor.exe` — a copy, because the service image is locked and is about to be stopped.
6. `s.Spawn(supervisorPath)`.

**Reporting.** Before anything else in `Sync`, if `s.Rollback` is set, report
it — `protocol.ResultFailed`, `RolledBackFrom` naming the build that failed,
and the record's detail — then `RemoveRecord` and clear the field. That is the
only way a rollback becomes visible; the supervisor cannot report it, because
by the time it decides, the agent it was testing has been replaced by this one.

Every terminal outcome is reported through `ReportAgentUpdate`: a refusal for
want of an injected version, a hash mismatch, a download that failed, a
controller that is unavailable. An update that is merely *under way* is not
reported — the supervisor owns that, and a "pending" row the console could
never clear would be worse than silence.

Failures at each step are logged and returned; the next check-in tries again,
which is the right behaviour for a transient download failure.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/agent/selfupdate/ -count=1 -race && go vet ./... && GOOS=linux go build ./...`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/agent/selfupdate/syncer.go internal/agent/selfupdate/syncer_test.go
git commit -m "feat(agent): stage an assigned build and hand off to the supervisor"
```

---

### Task 13: Wiring it into the agent

**Files:**
- Modify: `internal/agent/session/session.go` — a `SelfUpdate` field, a client adapter, an `ItemSyncer` adapter
- Modify: `internal/agent/runner/runner.go` — construct it, and report a rollback at startup
- Modify: `cmd/retune-agent/main.go` — the `supervise-update` subcommand and the usage text
- Modify: `internal/agent/selfupdate/controller.go` — add `const ServiceName = "Retune"`
- Create: `internal/agent/selfupdate/spawn.go` — `SpawnSupervisor`, no build tag
- Create: `internal/agent/selfupdate/spawn_windows.go` — `detachedAttr` for Windows
- Create: `internal/agent/selfupdate/spawn_other.go` — `detachedAttr` returning nil elsewhere
- Test: `internal/agent/session/dispatch_test.go` (extend)

**Interfaces:**
- Consumes: `selfupdate.Syncer`, `selfupdate.Supervisor`, `selfupdate.NewController`.

- [ ] **Step 1: Add the session wiring**

In `internal/agent/session/session.go`, following the `Apps` precedent exactly:

```go
	// SelfUpdate, when set, replaces this agent with an assigned build.
	SelfUpdate *selfupdate.Syncer
```

```go
// selfUpdateClient routes the self-update syncer's calls through the session's
// current client, so a certificate renewal is picked up without the syncer
// knowing anything about certificates.
type selfUpdateClient struct{ s *Session }

func (c selfUpdateClient) FetchAgentVersion(ctx context.Context, id string) (protocol.AgentVersionResponse, error) {
	return c.s.currentClient().FetchAgentVersion(ctx, id)
}

func (c selfUpdateClient) DownloadAgentBinary(ctx context.Context, id, sha string, dst io.Writer) error {
	return c.s.currentClient().DownloadAgentBinary(ctx, id, sha, dst)
}

func (c selfUpdateClient) ReportAgentUpdate(ctx context.Context, id string, r protocol.AgentUpdateResult) error {
	return c.s.currentClient().ReportAgentUpdate(ctx, id, r)
}

// selfUpdateSyncer adapts the self-update syncer. It is not called with an
// empty item list: an agent that is no longer assigned a build keeps the one
// it is running, because unassignment is not a downgrade instruction.
type selfUpdateSyncer struct{ s *selfupdate.Syncer }

func (a selfUpdateSyncer) Sync(ctx context.Context, items []protocol.Item) error {
	return a.s.Sync(ctx, items)
}
func (selfUpdateSyncer) RunOnEmpty() bool { return false }
func (selfUpdateSyncer) Name() string     { return "agent self-update" }
```

In `New`, wire the client on the local `cfg` and append the syncer to **`s.cfg.Syncers`** — the same distinction the existing code makes, because `s` holds a copy:

```go
	if cfg.SelfUpdate != nil && cfg.SelfUpdate.Client == nil {
		cfg.SelfUpdate.Client = selfUpdateClient{s}
	}
	...
	if cfg.SelfUpdate != nil {
		s.cfg.Syncers = append(s.cfg.Syncers, selfUpdateSyncer{cfg.SelfUpdate})
	}
```

- [ ] **Step 2: Extend the dispatch test**

Add to `internal/agent/session/dispatch_test.go` a case asserting a syncer whose `RunOnEmpty` is false is not started with an empty list — this already exists; extend the table name list so the new syncer's semantics are covered by name. Then run `go test ./internal/agent/session/ -count=1`.

- [ ] **Step 3: Report a rollback, and construct the syncer**

In `internal/agent/runner/runner.go`, after the state store is opened and before the session is built:

```go
	// A rollback is only visible to the server if the restored agent says so.
	// The supervisor cannot report it: by the time it decides, the agent it
	// was testing is gone and the one that comes back is this process.
	if rec, found, err := selfupdate.ReadRecord(opts.DataDir); err == nil && found &&
		rec.Status == selfupdate.StatusRolledBack {
		opts.Log.Warn("a previous update was rolled back",
			"attempted", rec.ToVersion, "restored", rec.FromVersion, "detail", rec.Detail)
		rollback = &rec
	}
```

Carry `rollback` into the syncer so it reports the failure on the next check-in and then removes the record. Construct the syncer the way `appSyncer` is constructed:

```go
	updater := &selfupdate.Syncer{
		Dir: opts.DataDir, Running: facts.AgentVersion, Injected: facts.VersionInjected(),
		Log: opts.Log, Now: time.Now, Rollback: rollback,
		Spawn: selfupdate.SpawnSupervisor,
	}
	// A platform with no service control manager cannot self-update. Every
	// assigned build is then refused with that reason rather than the device
	// going quiet about it.
	if control, err := selfupdate.NewController(selfupdate.ServiceName); err != nil {
		opts.Log.Info("self-update is unavailable on this machine", "error", err)
	} else {
		updater.Control = control
		defer control.Close()
	}
```

The `defer` is correct here: `Run` holds the controller for exactly as long as
the syncer lives, and the handles go back when `Run` returns.

`serviceName` lives in `cmd/retune-agent`, not here. Export the constant the
runner needs from `selfupdate` instead — add `const ServiceName = "Retune"` to
`internal/agent/selfupdate/controller.go` and use that in both places, so the
name is declared once.

`SpawnSupervisor` is the real hand-off, and belongs beside the controller:

```go
// SpawnSupervisor starts a detached copy of the outgoing build. It must
// outlive the service that starts it -- that service is about to be stopped by
// the very process being spawned.
func SpawnSupervisor(path string) error {
	cmd := exec.Command(path, "supervise-update")
	cmd.SysProcAttr = detachedAttr()
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
```

with `detachedAttr()` in the platform files: on Windows
`&syscall.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NO_WINDOW}`,
and nil elsewhere.

and pass `SelfUpdate: updater` in the `session.Config`.

- [ ] **Step 4: Add the `supervise-update` subcommand**

In `cmd/retune-agent/main.go`, add a case before `default:`:

```go
	case "supervise-update":
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		// Run from a copy of the outgoing build, detached, by the agent that
		// is about to be replaced. It is the known-good binary supervising its
		// own replacement.
		control, err := selfupdate.NewController(serviceName)
		if err != nil {
			return err
		}
		defer control.Close()
		log, closeLog, err := logging.New(logging.Options{Dir: *dataDir, EventLog: true})
		if err != nil {
			return err
		}
		defer closeLog()
		return (&selfupdate.Supervisor{Dir: *dataDir, Control: control, Log: log}).Supervise(ctx)
```

`serviceName` is declared in `service_windows.go`, so a non-Windows build needs it too — add `const serviceName = "Retune"` to `service_other.go` if it is not already there, or guard the case.

Add the command to the `usage` const. While there, add the `cleanup` line, which is implemented but was never listed:

```
  cleanup [--data-dir D]                                              (Windows)
  supervise-update [--data-dir D]                                     (Windows)
```

- [ ] **Step 5: Run the tests**

Run: `go test ./internal/agent/... ./cmd/... -count=1 && go vet ./... && GOOS=linux go build ./...`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/agent/session/session.go internal/agent/runner/runner.go cmd/retune-agent/
git commit -m "feat(agent): wire self-update in, and report a rollback when one happened"
```

---

### Task 14: The Agent versions page

**Files:**
- Create: `web/src/pages/AgentVersions.tsx`, `AgentVersions.css`, `AgentVersions.test.tsx`
- Modify: `web/src/api/types.ts`, `web/src/App.tsx`, `web/src/components/Shell.tsx`

**Interfaces:**
- Consumes: the Task 6 admin routes.
- Produces: `AgentVersion` in `types.ts`; a default-exported `AgentVersions()` page.

- [ ] **Step 1: Write the failing test**

Create `web/src/pages/AgentVersions.test.tsx` following `web/src/pages/Apps.test.tsx`'s conventions — `vi.mock` for `SessionContext` and `react-router-dom`, a `json()` helper, `fetchMock` on `globalThis.fetch`. Cover:

- the listing shows the version, its size and who uploaded it;
- the assign dialog posts `item_kind: "agent"` with the chosen `deadline_seconds`;
- selecting a file and uploading posts to `/agent-versions?version=…` with the file as the body, not as JSON;
- the page states plainly what assigning a build does.

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm --prefix web run test -- --run AgentVersions`

Expected: FAIL — `./AgentVersions` cannot be resolved.

- [ ] **Step 3: Add the type**

In `web/src/api/types.ts`:

```ts
export interface AgentVersion {
  id: string;
  version: string;
  sha256: string;
  size_bytes: number;
  notes: string;
  created_at: string;
  created_by: string;
}
```

- [ ] **Step 4: Write the page**

Create `web/src/pages/AgentVersions.tsx` with `const ITEM_KIND = "agent"`, modelled on `Apps.tsx`, with its own classes in its own stylesheet — no cross-page CSS import.

- **Upload** takes a file and a version string. It posts the file as a raw body to `/agent-versions?version=…&notes=…`, because base64 in JSON would inflate a multi-megabyte binary by a third. `api.post` sends JSON, so this needs a direct `fetch` with the CSRF header — follow `api/client.ts` for how that header is set.
- **List** shows version, size, uploaded-by and date, with the SHA-256 available but not shouted.
- **Assign** offers a group, include/exclude, and a rollback deadline in seconds (60–14400, default 600). The hint says what the deadline means: *"If the new agent has not checked in by then, the previous build is put back."*
- **Detail** shows the rollup from `/items/agent/{id}/status`, so a pilot group reports before a wider one is assigned.

Copy should say plainly that assigning a build replaces the agent on every device in the group, and that a device which cannot check in afterwards goes back by itself.

Register the route in `App.tsx` and the nav entry in `Shell.tsx`, after Apps.

- [ ] **Step 5: Run the tests and the build**

Run: `npm --prefix web run test -- --run && npm --prefix web run build`

Expected: PASS and a clean build. `tsc -b` is stricter than the test run: unused parameters are errors, so prefix any with `_`.

- [ ] **Step 6: Commit**

```bash
git add web/src/pages/AgentVersions.tsx web/src/pages/AgentVersions.css web/src/pages/AgentVersions.test.tsx web/src/api/types.ts web/src/App.tsx web/src/components/Shell.tsx
git commit -m "feat(console): upload and assign agent builds"
```

---

### Task 15: End to end, and the documentation

**Files:**
- Modify: `test/e2e/e2e_test.go`
- Modify: `README.md`
- Modify: `docs/superpowers/plans/2026-09-12-roadmap.md`

- [ ] **Step 1: Write the end-to-end test**

Read `test/e2e/e2e_test.go` first and copy its setup from the neighbouring tests. The flow: upload a build, assign it, check in as an enrolled device, fetch the definition, download the binary and confirm the bytes and hash, then read the rollup.

The assertions, which are the point:

```go
	// The build reaches the agent.
	items := decodeJSON[protocol.CheckinResponse](t, body).Items
	if len(items) != 1 || items[0].Kind != protocol.ItemKindAgent {
		t.Fatalf("the build should be offered once, got %+v", items)
	}

	// The definition promises a hash, and the bytes honour it.
	def := decodeJSON[protocol.AgentVersionResponse](t, defBody)
	sum := sha256.Sum256(binaryBody)
	if hex.EncodeToString(sum[:]) != def.SHA256 {
		t.Fatalf("the downloaded bytes do not match the promised hash")
	}
	if def.SizeBytes != int64(len(binaryBody)) {
		t.Errorf("size = %d, downloaded %d", def.SizeBytes, len(binaryBody))
	}

	// A device that was never assigned the build cannot fetch it.
	if status, _ := send(t, other, http.MethodGet, binaryURL, nil); status != http.StatusNotFound {
		t.Errorf("an unassigned device must not download a build, got %d", status)
	}
```

Do not leave any part of the body as a comment.

- [ ] **Step 2: Run it**

Run: `go test ./test/e2e/ -run AgentSelfUpdate -count=1`

Expected: FAIL first, then PASS once written correctly against the finished code. Nothing in the product should need changing; if it does, that is a real gap and worth stopping over.

- [ ] **Step 3: Document it**

Add an **Updating the agent** section to `README.md` after the Applications section:

```markdown
## Updating the agent

Agent builds live under **Agent versions**. Upload a build, assign it to a
group, and the agents in that group replace themselves with it.

A build is stamped with its version at compile time. An agent built without
that stamp refuses to self-update and says so, because it would otherwise
report the same version after updating, be told to update again, and do that
on every check-in for ever.

**A bad build costs one check-in cycle, not a truck roll.** After swapping, the
new agent must check in successfully within the assignment's deadline (ten
minutes by default). If it does not, the previous build is put back and the
device reports which version failed — so a pilot group tells you something
before a wider one is assigned.

The managed binary lives in `C:\ProgramData\Retune\bin\<version>\`, and the
service points at it. The copy the MSI installed in `Program Files` is a
bootstrap and is never modified, so a repair or an upgrade cannot disturb a
running agent. Only the current and previous versions are kept.

Assigning an older build is a deliberate downgrade and works — it is how a
fleet is recovered from a bad build without touching every machine.

Uploaded builds are stored in `DATA_DIR/agents`, so **back that directory up
with the CA**, and size the volume for it.
```

Add a bullet to **What works today**:

```markdown
- **Agent self-update.** Agent builds assigned to groups, verified by hash,
  swapped under supervision, and rolled back automatically if the new build
  cannot check in.
```

Update `docs/superpowers/plans/2026-09-12-roadmap.md`: add the M10 row and change the status line to M1 through M10.

- [ ] **Step 4: Run everything**

```bash
gofmt -l internal/ cmd/ test/ && go vet ./... && GOOS=linux go build ./... && go test ./... -count=1
npm --prefix web run test -- --run && npm --prefix web run build
```

Expected: all green; `gofmt -l` silent for every file this branch touched.

- [ ] **Step 5: Commit**

```bash
git add test/e2e/e2e_test.go README.md docs/superpowers/plans/2026-09-12-roadmap.md
git commit -m "test: agent self-update end to end, and document it"
```

---

## Verification on this machine

After Task 15, prove it through the installed service. This is not a task in the plan because it is not code; it is the acceptance check, and the spec's §10 is the authority. **The rollback is exercised deliberately — it is the whole safety story, and M9 taught us that a path nobody runs is a path that does not work.**

1. Build and install the agent from the MSI with a stamped version; confirm it enrols and the console shows that version.
2. Upload a genuine newer build, assign it, and confirm the service repoints into `bin\<version>\`, the new agent checks in, and the console shows the new version.
3. Confirm `Program Files` is untouched and older version directories are pruned.
4. **Upload a deliberately broken build** — one that starts and exits, or cannot reach the server — assign it, and confirm the supervisor puts the previous build back, the restored agent resumes checking in, and the console reports the failed version.
5. Assign the older build deliberately and confirm the downgrade works.
6. Uninstall, remove the data directory, and confirm the machine is as it was.
