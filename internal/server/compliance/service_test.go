package compliance_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/compliance"
	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

func service(st *store.Store) *compliance.Service {
	return &compliance.Service{Store: st, Now: time.Now}
}

func device(t *testing.T, st *store.Store, hostname string) store.Device {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	d := store.Device{
		ID: uuid.Must(uuid.NewV7()), Hostname: hostname, Status: store.DeviceActive,
		CertSerial: hostname, CertExpiresAt: now.Add(time.Hour), EnrolledAt: now,
	}
	if err := st.Q().CreateDevice(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	return d
}

// assign attaches a policy to a device through a fresh static group, the way
// an administrator's group assignment reaches EffectiveItems.
func assign(t *testing.T, st *store.Store, policyID, deviceID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	g := store.Group{ID: uuid.Must(uuid.NewV7()), Name: "g-" + policyID.String(), Kind: store.GroupStatic, CreatedAt: now, UpdatedAt: now}
	if err := st.Q().CreateGroup(ctx, g); err != nil {
		t.Fatal(err)
	}
	if err := st.Q().AddGroupMember(ctx, g.ID, deviceID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Q().CreateAssignment(ctx, store.Assignment{
		ID: uuid.Must(uuid.NewV7()), ItemKind: compliance.ItemKindCompliance, ItemID: policyID,
		GroupID: g.ID, Mode: store.ModeInclude, CreatedAt: now, CreatedBy: "t",
	}); err != nil {
		t.Fatal(err)
	}
}

func createPolicy(t *testing.T, svc *compliance.Service, name, rules string) store.CompliancePolicy {
	t.Helper()
	p, err := svc.Create(context.Background(), compliance.NewPolicy{Name: name, Rules: []byte(rules), Actor: "ops"})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestEvaluateDeviceWritesBothTablesWithTheMapping checks the design's state
// mapping (compliant/non_compliant/unknown -> succeeded/failed/pending) for
// all three states at once, produced from a single EvaluateDevice call.
func TestEvaluateDeviceWritesBothTablesWithTheMapping(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)

	d := device(t, st, "h1")
	lastSeen := time.Now().Add(-2 * time.Hour)
	if err := st.Q().RecordCheckin(ctx, store.DefaultTenantID, d.ID, "1.0.0", lastSeen); err != nil {
		t.Fatal(err)
	}

	compliant := createPolicy(t, svc, "Compliant", `[{"type":"checked_in_within","hours":8760}]`)
	nonCompliant := createPolicy(t, svc, "NonCompliant", `[{"type":"checked_in_within","hours":1}]`)
	// bitlocker needs inventory this device never reported, so it can only
	// come back unknown.
	unknown := createPolicy(t, svc, "Unknown", `[{"type":"bitlocker","volumes":"system"}]`)

	for _, p := range []store.CompliancePolicy{compliant, nonCompliant, unknown} {
		assign(t, st, p.ID, d.ID)
	}

	if err := svc.EvaluateDevice(ctx, d.ID); err != nil {
		t.Fatal(err)
	}

	results, err := st.Q().ListDeviceCompliance(ctx, d.ID)
	if err != nil || len(results) != 3 {
		t.Fatalf("results: %v %+v", err, results)
	}
	byPolicy := map[uuid.UUID]store.DeviceCompliance{}
	for _, r := range results {
		byPolicy[r.PolicyID] = r
	}
	if byPolicy[compliant.ID].State != compliance.StateCompliant {
		t.Errorf("compliant policy state = %s", byPolicy[compliant.ID].State)
	}
	if byPolicy[nonCompliant.ID].State != compliance.StateNonCompliant {
		t.Errorf("non-compliant policy state = %s", byPolicy[nonCompliant.ID].State)
	}
	if byPolicy[unknown.ID].State != compliance.StateUnknown {
		t.Errorf("unknown policy state = %s", byPolicy[unknown.ID].State)
	}

	statuses, err := st.Q().ListDeviceItemStatus(ctx, d.ID, compliance.ItemKindCompliance)
	if err != nil {
		t.Fatal(err)
	}
	if statuses[compliant.ID] != store.ItemSucceeded {
		t.Errorf("compliant mirrors to %s, want succeeded", statuses[compliant.ID])
	}
	if statuses[nonCompliant.ID] != store.ItemFailed {
		t.Errorf("non-compliant mirrors to %s, want failed", statuses[nonCompliant.ID])
	}
	if statuses[unknown.ID] != store.ItemPending {
		t.Errorf("unknown mirrors to %s, want pending", statuses[unknown.ID])
	}
}

// TestEvaluateDeviceRemovesStaleResultsWhenUnassigned checks the other half
// of EvaluateDevice: a policy that no longer applies loses its rows in both
// tables rather than lingering with a stale verdict.
func TestEvaluateDeviceRemovesStaleResultsWhenUnassigned(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)

	d := device(t, st, "h1")
	p := createPolicy(t, svc, "P", `[{"type":"no_pending_reboot"}]`)
	assign(t, st, p.ID, d.ID)

	if err := svc.EvaluateDevice(ctx, d.ID); err != nil {
		t.Fatal(err)
	}
	if results, err := st.Q().ListDeviceCompliance(ctx, d.ID); err != nil || len(results) != 1 {
		t.Fatalf("before unassign: %v %+v", err, results)
	}

	// Unassign by removing the group assignment, exactly what an
	// administrator's group edit does under the hood.
	if err := st.Q().DeleteAssignmentsForItem(ctx, compliance.ItemKindCompliance, p.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.EvaluateDevice(ctx, d.ID); err != nil {
		t.Fatal(err)
	}

	results, err := st.Q().ListDeviceCompliance(ctx, d.ID)
	if err != nil || len(results) != 0 {
		t.Fatalf("after unassign: %v %+v", err, results)
	}
	statuses, err := st.Q().ListDeviceItemStatus(ctx, d.ID, compliance.ItemKindCompliance)
	if err != nil || len(statuses) != 0 {
		t.Fatalf("item status after unassign: %v %v", err, statuses)
	}
}

// TestEvaluateDeviceSkipsAnAssignmentWithNoPolicy covers the state
// createAssignment can leave behind: it validates an assignment's kind and
// options but not that the item exists, so a group can carry an assignment
// naming a policy id that is not there. That must not stop the device's real
// policies being scored, and the missing policy must not keep a stale
// device_compliance row alive through the cleanup.
func TestEvaluateDeviceSkipsAnAssignmentWithNoPolicy(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)

	d := device(t, st, "h1")
	live := createPolicy(t, svc, "Live", `[{"type":"no_pending_reboot"}]`)
	assign(t, st, live.ID, d.ID)

	// A second policy, evaluated once, then deleted straight out of the
	// policy table so only its assignment and its stale result remain.
	doomed := createPolicy(t, svc, "Doomed", `[{"type":"no_pending_reboot"}]`)
	assign(t, st, doomed.ID, d.ID)
	if err := svc.EvaluateDevice(ctx, d.ID); err != nil {
		t.Fatal(err)
	}
	if results, err := st.Q().ListDeviceCompliance(ctx, d.ID); err != nil || len(results) != 2 {
		t.Fatalf("before the policy vanishes: %v %+v", err, results)
	}
	if err := st.Q().DeleteCompliancePolicy(ctx, store.DefaultTenantID, doomed.ID); err != nil {
		t.Fatal(err)
	}

	if err := svc.EvaluateDevice(ctx, d.ID); err != nil {
		t.Fatalf("a dangling assignment must not fail the whole evaluation: %v", err)
	}

	results, err := st.Q().ListDeviceCompliance(ctx, d.ID)
	if err != nil || len(results) != 1 {
		t.Fatalf("results: %v %+v", err, results)
	}
	if results[0].PolicyID != live.ID {
		t.Errorf("surviving result is for %s, want the live policy %s", results[0].PolicyID, live.ID)
	}
	// device_compliance cascades off the deleted policy row, but
	// device_item_status has no foreign key to cascade through: the skipped
	// policy has to be dropped from the keep list for its mirrored row to go.
	statuses, err := st.Q().ListDeviceItemStatus(ctx, d.ID, compliance.ItemKindCompliance)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := statuses[live.ID]; len(statuses) != 1 || !ok {
		t.Errorf("item status = %v, want only the live policy's row", statuses)
	}
}

// TestComplianceOverallDerivesFromEvaluatedPolicies exercises ComplianceOverall
// through real evaluation output instead of hand-built rows, so a mismatch
// between the mapping and the derivation would show up here.
func TestComplianceOverallDerivesFromEvaluatedPolicies(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)

	compliantDev := device(t, st, "compliant")
	nonCompliantDev := device(t, st, "non-compliant")
	notEvaluatedDev := device(t, st, "not-evaluated")
	for _, d := range []store.Device{compliantDev, nonCompliantDev} {
		if err := st.Q().RecordCheckin(ctx, store.DefaultTenantID, d.ID, "1.0.0", time.Now()); err != nil {
			t.Fatal(err)
		}
	}

	fastPolicy := createPolicy(t, svc, "Fast", `[{"type":"checked_in_within","hours":8760}]`)
	assign(t, st, fastPolicy.ID, compliantDev.ID)
	// A policy this device cannot possibly satisfy: hours is at ParseRules'
	// minimum bound, against a check-in from well before that.
	strictPolicy := createPolicy(t, svc, "Strict", `[{"type":"checked_in_within","hours":1}]`)
	if err := st.Q().RecordCheckin(ctx, store.DefaultTenantID, nonCompliantDev.ID, "1.0.0", time.Now().Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	assign(t, st, strictPolicy.ID, nonCompliantDev.ID)

	if err := svc.EvaluateDevice(ctx, compliantDev.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.EvaluateDevice(ctx, nonCompliantDev.ID); err != nil {
		t.Fatal(err)
	}

	overall, err := st.Q().ComplianceOverall(ctx, []uuid.UUID{compliantDev.ID, nonCompliantDev.ID, notEvaluatedDev.ID})
	if err != nil {
		t.Fatal(err)
	}
	if overall[compliantDev.ID] != store.ComplianceCompliant {
		t.Errorf("compliant device overall = %s", overall[compliantDev.ID])
	}
	if overall[nonCompliantDev.ID] != store.ComplianceNonCompliant {
		t.Errorf("non-compliant device overall = %s", overall[nonCompliantDev.ID])
	}
	if overall[notEvaluatedDev.ID] != store.ComplianceNotEvaluated {
		t.Errorf("unevaluated device overall = %s", overall[notEvaluatedDev.ID])
	}
}

// TestDeleteClearsEverythingAndAudits checks Delete's whole-transaction sweep:
// the policy, its assignment, its device_compliance rows, its mirrored
// item-status rows, and that the deletion itself is on the record.
func TestDeleteClearsEverythingAndAudits(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)

	d := device(t, st, "h1")
	p := createPolicy(t, svc, "Doomed", `[{"type":"no_pending_reboot"}]`)
	assign(t, st, p.ID, d.ID)
	if err := svc.EvaluateDevice(ctx, d.ID); err != nil {
		t.Fatal(err)
	}

	if err := svc.Delete(ctx, p.ID, "ops"); err != nil {
		t.Fatal(err)
	}

	if _, err := svc.Get(ctx, p.ID); !errors.Is(err, compliance.ErrNotFound) {
		t.Errorf("policy should be gone, got %v", err)
	}
	if assignments, err := st.Q().ListAssignments(ctx, compliance.ItemKindCompliance, p.ID); err != nil || len(assignments) != 0 {
		t.Errorf("assignments should be gone: %v %+v", err, assignments)
	}
	if results, err := st.Q().ListDeviceCompliance(ctx, d.ID); err != nil || len(results) != 0 {
		t.Errorf("device_compliance rows should be gone: %v %+v", err, results)
	}
	if statuses, err := st.Q().ListDeviceItemStatus(ctx, d.ID, compliance.ItemKindCompliance); err != nil || len(statuses) != 0 {
		t.Errorf("item status rows should be gone: %v %v", err, statuses)
	}

	audit, _, err := st.Q().ListAuditPage(ctx, store.Page{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range audit {
		if a.Action == "compliance_policy.deleted" && a.TargetID == p.ID.String() {
			found = true
		}
	}
	if !found {
		t.Errorf("no audit entry for the deletion: %+v", audit)
	}
}

func TestCreateNameClashIsErrNameTaken(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)

	createPolicy(t, svc, "Baseline", `[{"type":"no_pending_reboot"}]`)
	if _, err := svc.Create(ctx, compliance.NewPolicy{Name: "Baseline", Rules: []byte(`[{"type":"tpm"}]`), Actor: "ops"}); !errors.Is(err, compliance.ErrNameTaken) {
		t.Errorf("want ErrNameTaken, got %v", err)
	}

	other := createPolicy(t, svc, "Other", `[{"type":"tpm"}]`)
	if _, err := svc.Update(ctx, other.ID, compliance.NewPolicy{Name: "Baseline", Rules: []byte(`[{"type":"tpm"}]`), Actor: "ops"}); !errors.Is(err, compliance.ErrNameTaken) {
		t.Errorf("want ErrNameTaken on rename clash, got %v", err)
	}
}

func TestCreateBadRulesIsErrBadRequest(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)

	if _, err := svc.Create(ctx, compliance.NewPolicy{Name: "Bad", Rules: []byte(`[{"type":"not_a_real_type"}]`), Actor: "ops"}); !errors.Is(err, compliance.ErrBadRequest) {
		t.Errorf("want ErrBadRequest, got %v", err)
	}
	// Zero rules is also out of ParseRules' bound.
	if _, err := svc.Create(ctx, compliance.NewPolicy{Name: "Empty", Rules: []byte(`[]`), Actor: "ops"}); !errors.Is(err, compliance.ErrBadRequest) {
		t.Errorf("want ErrBadRequest for an empty rule set, got %v", err)
	}
}

// TestEvaluatePolicyOnlyTouchesDevicesItAppliesTo checks the set the policy
// resolves to: it must count and evaluate the device the policy is assigned
// to, and leave an unrelated active device alone.
func TestEvaluatePolicyOnlyTouchesDevicesItAppliesTo(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)

	assigned := device(t, st, "assigned")
	unrelated := device(t, st, "unrelated")
	p := createPolicy(t, svc, "P", `[{"type":"no_pending_reboot"}]`)
	assign(t, st, p.ID, assigned.ID)

	n, err := svc.EvaluatePolicy(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("evaluated %d devices, want 1", n)
	}
	if results, err := st.Q().ListDeviceCompliance(ctx, assigned.ID); err != nil || len(results) != 1 {
		t.Errorf("assigned device: %v %+v", err, results)
	}
	if results, err := st.Q().ListDeviceCompliance(ctx, unrelated.ID); err != nil || len(results) != 0 {
		t.Errorf("unrelated device should be untouched: %v %+v", err, results)
	}
}

// TestEvaluateActiveMatchesSweeperSignature exercises EvaluateActive the way
// the sweeper will call it: as a sweeper.Job.Run function.
func TestEvaluateActiveMatchesSweeperSignature(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := service(st)

	d := device(t, st, "h1")
	p := createPolicy(t, svc, "P", `[{"type":"no_pending_reboot"}]`)
	assign(t, st, p.ID, d.ID)

	var run func(ctx context.Context, q *store.Queries, now time.Time) (int64, error) = svc.EvaluateActive
	n, err := run(ctx, st.Q(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("evaluated %d active devices, want 1", n)
	}
	if results, err := st.Q().ListDeviceCompliance(ctx, d.ID); err != nil || len(results) != 1 {
		t.Errorf("device_compliance after sweep: %v %+v", err, results)
	}
}
