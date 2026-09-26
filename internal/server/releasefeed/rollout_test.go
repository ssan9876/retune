package releasefeed_test

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/releasefeed"
	"retune/internal/server/store"
)

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

type rolloutFixture struct {
	*fixture
	rollout *releasefeed.Rollout
	pilot   uuid.UUID
	device  uuid.UUID
}

// newRolloutFixture turns automatic rollout on, with a one-device pilot group.
func newRolloutFixture(t *testing.T) *rolloutFixture {
	t.Helper()
	ctx := context.Background()
	f := newFixture(t)
	r := &rolloutFixture{fixture: f, rollout: &releasefeed.Rollout{Store: f.st, Now: func() time.Time { return f.now }}}
	f.feed.Rollout = r.rollout
	q := f.st.Q()
	r.device = uuid.New()
	if err := q.CreateDevice(ctx, store.Device{
		ID: r.device, Hostname: "PILOT-01", Status: store.DeviceActive,
		CertSerial: "s1", CertExpiresAt: f.now.Add(time.Hour), EnrolledAt: f.now,
	}); err != nil {
		t.Fatal(err)
	}
	r.pilot = uuid.New()
	if err := q.CreateGroup(ctx, store.Group{ID: r.pilot, Name: "Pilot", Kind: store.GroupStatic, CreatedAt: f.now, UpdatedAt: f.now}); err != nil {
		t.Fatal(err)
	}
	if err := q.AddGroupMember(ctx, r.pilot, r.device, f.now); err != nil {
		t.Fatal(err)
	}
	if err := q.SetAgentRolloutPolicy(ctx, store.AgentRolloutPolicy{
		Enabled: true, PilotGroupID: &r.pilot, DelayHours: 24, UpdatedAt: f.now, UpdatedBy: "admin@example.com",
	}); err != nil {
		t.Fatal(err)
	}
	return r
}

// release publishes and imports a version, and returns its build and rollout.
func (r *rolloutFixture) release(t *testing.T, version string) (store.AgentVersion, store.AgentRollout) {
	t.Helper()
	ctx := context.Background()
	r.server.publish(buildRelease(t, r.key, version, false))
	if _, err := r.feed.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	v, err := r.st.Q().GetAgentVersionByVersion(ctx, version)
	if err != nil {
		t.Fatal(err)
	}
	return v, r.rolloutFor(t, v.ID)
}

func (r *rolloutFixture) rolloutFor(t *testing.T, build uuid.UUID) store.AgentRollout {
	t.Helper()
	all, err := r.st.Q().ListAgentRollouts(context.Background(), 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, ro := range all {
		if ro.AgentVersionID == build {
			return ro
		}
	}
	t.Fatalf("no rollout for %s", build)
	return store.AgentRollout{}
}

func (r *rolloutFixture) report(t *testing.T, build uuid.UUID, status, detail string) {
	t.Helper()
	if err := r.st.Q().SetItemStatus(context.Background(), store.ItemStatus{
		DeviceID: r.device, ItemKind: protocol.ItemKindAgent, ItemID: build,
		Status: status, Detail: detail, Version: 1, UpdatedAt: r.now,
	}); err != nil {
		t.Fatal(err)
	}
}

func (r *rolloutFixture) assigned(t *testing.T, build, group uuid.UUID, mode string) bool {
	t.Helper()
	_, err := r.st.Q().GetAssignmentFor(context.Background(), protocol.ItemKindAgent, build, group, mode)
	return err == nil
}

func TestRolloutPilotsThenReachesEveryDevice(t *testing.T) {
	ctx := context.Background()
	r := newRolloutFixture(t)

	v1, ro := r.release(t, "1.2.0")
	if ro.State != store.RolloutPilot || !r.assigned(t, v1.ID, r.pilot, store.ModeInclude) {
		t.Fatalf("a new build goes to the pilot group first: %+v", ro)
	}
	if r.assigned(t, v1.ID, store.BuiltinGroupID, store.ModeInclude) {
		t.Fatal("nothing reaches All devices before the pilot has run")
	}

	// Healthy, but the delay has not passed.
	r.report(t, v1.ID, store.ItemSucceeded, "running this version")
	r.now = r.now.Add(23 * time.Hour)
	if _, err := r.rollout.Advance(ctx); err != nil {
		t.Fatal(err)
	}
	if ro = r.rolloutFor(t, v1.ID); ro.State != store.RolloutPilot || !strings.Contains(ro.Detail, "piloting until") {
		t.Fatalf("still piloting: %+v", ro)
	}

	r.now = r.now.Add(2 * time.Hour)
	if _, err := r.rollout.Advance(ctx); err != nil {
		t.Fatal(err)
	}
	ro = r.rolloutFor(t, v1.ID)
	if ro.State != store.RolloutPromoted || !r.assigned(t, v1.ID, store.BuiltinGroupID, store.ModeInclude) {
		t.Fatalf("after the delay it reaches everyone: %+v", ro)
	}
	if r.assigned(t, v1.ID, r.pilot, store.ModeInclude) {
		t.Fatal("the pilot assignment is cleared once All devices has it")
	}

	// The next release pilots while the fleet stays on 1.2.0, and the pilot
	// group is kept off 1.2.0 meanwhile, so it is offered one build.
	v2, ro2 := r.release(t, "1.3.0")
	if ro2.State != store.RolloutPilot || !r.assigned(t, v2.ID, r.pilot, store.ModeInclude) {
		t.Fatalf("second build pilots: %+v", ro2)
	}
	if !r.assigned(t, v1.ID, r.pilot, store.ModeExclude) {
		t.Fatal("the pilot group must be excluded from the fleet's build while it pilots the next one")
	}
	r.report(t, v2.ID, store.ItemSucceeded, "running this version")
	r.now = r.now.Add(25 * time.Hour)
	if _, err := r.rollout.Advance(ctx); err != nil {
		t.Fatal(err)
	}
	if ro2 = r.rolloutFor(t, v2.ID); ro2.State != store.RolloutPromoted {
		t.Fatalf("second build promoted: %+v", ro2)
	}
	if r.assigned(t, v1.ID, store.BuiltinGroupID, store.ModeInclude) || r.assigned(t, v1.ID, r.pilot, store.ModeExclude) {
		t.Fatal("the old build's assignments are replaced, not piled up")
	}
	if old := r.rolloutFor(t, v1.ID); old.State != store.RolloutSuperseded {
		t.Fatalf("old rollout = %+v", old)
	}
}

func TestRolloutHaltsWhenAPilotDeviceRollsBack(t *testing.T) {
	ctx := context.Background()
	r := newRolloutFixture(t)
	v, _ := r.release(t, "1.2.0")

	r.report(t, v.ID, store.ItemFailed, "rolled back from 1.2.0 to 1.1.0")
	if _, err := r.rollout.Advance(ctx); err != nil {
		t.Fatal(err)
	}
	ro := r.rolloutFor(t, v.ID)
	if ro.State != store.RolloutHalted || !strings.Contains(ro.Detail, "PILOT-01") || !strings.Contains(ro.Detail, "rolled back") {
		t.Fatalf("a rollback halts the rollout and says where: %+v", ro)
	}
	r.now = r.now.Add(48 * time.Hour)
	if _, err := r.rollout.Advance(ctx); err != nil {
		t.Fatal(err)
	}
	if r.assigned(t, v.ID, store.BuiltinGroupID, store.ModeInclude) {
		t.Fatal("a halted rollout never reaches All devices")
	}
	firing, err := r.st.Q().FiringHaltedRollouts(ctx)
	if err != nil || len(firing) != 1 || !strings.Contains(firing[0].Subject, "1.2.0") {
		t.Fatalf("the halt should fire an alert: %+v %v", firing, err)
	}

	// Resuming with the failure still reported halts again.
	if err := r.rollout.Resume(ctx, ro.ID, "admin@example.com"); err != nil {
		t.Fatal(err)
	}
	if ro = r.rolloutFor(t, v.ID); ro.State != store.RolloutHalted {
		t.Fatalf("still failing: %+v", ro)
	}
	// Once the device reports the build running, resuming carries on.
	r.report(t, v.ID, store.ItemSucceeded, "running this version")
	if err := r.rollout.Resume(ctx, ro.ID, "admin@example.com"); err != nil {
		t.Fatal(err)
	}
	if ro = r.rolloutFor(t, v.ID); ro.State != store.RolloutPromoted {
		t.Fatalf("resumed after the delay, it is promoted: %+v", ro)
	}
}

// With two-person approval on, All devices waits for a second administrator,
// and a refusal halts the rollout.
func TestRolloutWaitsForApproval(t *testing.T) {
	ctx := context.Background()
	r := newRolloutFixture(t)
	r.rollout.ApprovalsRequired, r.rollout.ApprovalThreshold = true, 50

	v, ro := r.release(t, "1.2.0")
	if ro.State != store.RolloutPilot || ro.PilotApprovalID != nil {
		t.Fatalf("a one-device pilot group is under the threshold: %+v", ro)
	}
	r.report(t, v.ID, store.ItemSucceeded, "running this version")
	r.now = r.now.Add(25 * time.Hour)
	if _, err := r.rollout.Advance(ctx); err != nil {
		t.Fatal(err)
	}
	ro = r.rolloutFor(t, v.ID)
	if ro.State != store.RolloutPromoting || ro.FleetApprovalID == nil {
		t.Fatalf("All devices must wait for approval: %+v", ro)
	}
	if r.assigned(t, v.ID, store.BuiltinGroupID, store.ModeInclude) {
		t.Fatal("nothing is assigned before approval")
	}
	a, err := r.st.Q().GetApproval(ctx, *ro.FleetApprovalID)
	if err != nil || a.Kind != store.ApprovalAssignment || a.RequestedBy != releasefeed.RolloutActor {
		t.Fatalf("approval = %+v %v", a, err)
	}

	// Approved: the admin API replays it as an assignment by the rollout.
	if _, err := r.st.Q().DecideApproval(ctx, a.ID, store.ApprovalApproved, "second@example.com", "", r.now); err != nil {
		t.Fatal(err)
	}
	if _, err := r.st.Q().CreateAssignment(ctx, store.Assignment{
		ID: uuid.Must(uuid.NewV7()), ItemKind: protocol.ItemKindAgent, ItemID: v.ID, GroupID: store.BuiltinGroupID,
		Mode: store.ModeInclude, CreatedAt: r.now, CreatedBy: releasefeed.RolloutActor, Options: []byte(`{"deadline_seconds":600}`),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.rollout.Advance(ctx); err != nil {
		t.Fatal(err)
	}
	if ro = r.rolloutFor(t, v.ID); ro.State != store.RolloutPromoted {
		t.Fatalf("approved, it is promoted: %+v", ro)
	}
}

func TestRolloutHaltsWhenApprovalIsRefused(t *testing.T) {
	ctx := context.Background()
	r := newRolloutFixture(t)
	r.rollout.ApprovalsRequired, r.rollout.ApprovalThreshold = true, 50
	v, _ := r.release(t, "1.2.0")
	r.report(t, v.ID, store.ItemSucceeded, "")
	r.now = r.now.Add(25 * time.Hour)
	if _, err := r.rollout.Advance(ctx); err != nil {
		t.Fatal(err)
	}
	ro := r.rolloutFor(t, v.ID)
	if _, err := r.st.Q().DecideApproval(ctx, *ro.FleetApprovalID, store.ApprovalRejected, "second@example.com", "not today", r.now); err != nil {
		t.Fatal(err)
	}
	if _, err := r.rollout.Advance(ctx); err != nil {
		t.Fatal(err)
	}
	if ro = r.rolloutFor(t, v.ID); ro.State != store.RolloutHalted || !strings.Contains(ro.Detail, "rejected") {
		t.Fatalf("a refusal halts: %+v", ro)
	}
}

// A newer build overtakes one still piloting, and its pending approval is
// withdrawn so it can't be approved later over the newer one.
func TestNewerBuildSupersedesOneInProgress(t *testing.T) {
	ctx := context.Background()
	r := newRolloutFixture(t)
	r.rollout.ApprovalsRequired, r.rollout.ApprovalThreshold = true, 50
	v1, _ := r.release(t, "1.2.0")
	r.report(t, v1.ID, store.ItemSucceeded, "")
	r.now = r.now.Add(25 * time.Hour)
	if _, err := r.rollout.Advance(ctx); err != nil {
		t.Fatal(err)
	}
	pending := r.rolloutFor(t, v1.ID).FleetApprovalID

	v2, ro2 := r.release(t, "1.3.0")
	if ro2.State != store.RolloutPilot {
		t.Fatalf("new rollout = %+v", ro2)
	}
	old := r.rolloutFor(t, v1.ID)
	if old.State != store.RolloutSuperseded || r.assigned(t, v1.ID, r.pilot, store.ModeInclude) {
		t.Fatalf("old rollout = %+v", old)
	}
	a, _ := r.st.Q().GetApproval(ctx, *pending)
	if a.Status != store.ApprovalRejected {
		t.Fatalf("the superseded rollout's approval should be withdrawn: %s", a.Status)
	}
	if !r.assigned(t, v2.ID, r.pilot, store.ModeInclude) {
		t.Fatal("the new build pilots")
	}
}

// With the policy off, a release is imported and left for an administrator.
func TestNoRolloutWhenThePolicyIsOff(t *testing.T) {
	ctx := context.Background()
	r := newRolloutFixture(t)
	if err := r.st.Q().SetAgentRolloutPolicy(ctx, store.AgentRolloutPolicy{DelayHours: 24, UpdatedAt: r.now, UpdatedBy: "x"}); err != nil {
		t.Fatal(err)
	}
	r.server.publish(buildRelease(t, r.key, "1.2.0", false))
	if _, err := r.feed.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	all, _ := r.st.Q().ListAgentRollouts(ctx, 10)
	if len(all) != 0 {
		t.Fatalf("no rollout expected: %+v", all)
	}
}

// A deleted pilot group halts a rollout rather than leaving it stuck.
func TestRolloutHaltsWhenThePilotGroupGoes(t *testing.T) {
	ctx := context.Background()
	r := newRolloutFixture(t)
	v, _ := r.release(t, "1.2.0")
	if err := r.st.Q().DeleteGroup(ctx, store.DefaultTenantID, r.pilot); err != nil {
		t.Fatal(err)
	}
	if _, err := r.rollout.Advance(ctx); err != nil {
		t.Fatal(err)
	}
	if ro := r.rolloutFor(t, v.ID); ro.State != store.RolloutHalted {
		t.Fatalf("rollout = %+v", ro)
	}
}
