package releasefeed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/release"
	"retune/internal/server/store"
	"retune/internal/server/sweeper"
)

// RolloutActor is who the audit log says made an automatic rollout's changes.
const RolloutActor = "system:agent-rollout"

// RolloutLockID is the rollout job's advisory lock.
const RolloutLockID = 5274013

// approvalTTL matches the admin API's: a held request lapses after a day.
const approvalTTL = 24 * time.Hour

// ErrNotHalted is resuming a rollout that is not halted.
var ErrNotHalted = errors.New("only a halted rollout can be resumed")

// Rollout moves imported agent builds through the pilot group to the fleet.
//
// Each rollout owns its assignments: it includes its build in the pilot
// group, excludes the pilot group from the build the fleet is on meanwhile,
// and on promotion includes its build in All devices and removes the
// previous build's fleet assignment. A device is therefore offered exactly
// one agent build at every step, which is what self-update needs - two
// assigned builds would have a device switch between them.
type Rollout struct {
	Store *store.Store
	Now   func() time.Time
	Log   *slog.Logger
	// ApprovalsRequired and ApprovalThreshold are two-person approval's
	// settings. An automatic rollout waits for approval exactly where an
	// administrator's assignment would.
	ApprovalsRequired bool
	ApprovalThreshold int
}

func (r *Rollout) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Rollout) log() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.New(slog.DiscardHandler)
}

// Job advances every rollout in progress, every five minutes.
func (r *Rollout) Job() sweeper.Job {
	return sweeper.Job{
		Name: "agent_rollouts.advance", LockID: RolloutLockID, Interval: 5 * time.Minute,
		Run: func(ctx context.Context, _ *store.Queries, _ time.Time) (int64, error) {
			return r.Advance(ctx)
		},
	}
}

// Start begins rolling out a build, if the policy says to. A build no newer
// than the one the fleet is on is not rolled out: an automatic rollout never
// goes backwards.
func (r *Rollout) Start(ctx context.Context, v store.AgentVersion) error {
	q := r.Store.Q()
	p, err := q.GetAgentRolloutPolicy(ctx)
	if err != nil || !p.Enabled || p.PilotGroupID == nil {
		return err
	}
	promoted, err := q.ListRolloutsInState(ctx, store.RolloutPromoted)
	if err != nil {
		return err
	}
	for _, old := range promoted {
		if !release.Newer(v.Version, old.Version) {
			return nil
		}
	}
	now := r.now()
	ro := store.AgentRollout{
		ID: uuid.Must(uuid.NewV7()), AgentVersionID: v.ID, State: store.RolloutPilot,
		PilotGroupID: p.PilotGroupID, DelayHours: p.DelayHours, CreatedAt: now,
	}
	created := false
	err = r.Store.InTx(ctx, func(q *store.Queries) error {
		var err error
		if created, err = q.CreateAgentRollout(ctx, ro); err != nil || !created {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: RolloutActor, Action: "agent_rollout.started", TargetKind: "agent_rollout", TargetID: ro.ID.String(),
			Details: map[string]any{"version": v.Version, "pilot_group_id": p.PilotGroupID.String(), "delay_hours": p.DelayHours},
		})
	})
	if err != nil || !created {
		return err
	}
	// Anything still in progress is overtaken by this build.
	active, err := q.ListRolloutsInState(ctx, store.RolloutPilot, store.RolloutPromoting)
	if err != nil {
		return err
	}
	for _, old := range active {
		if old.ID != ro.ID {
			if err := r.supersede(ctx, old, v.Version); err != nil {
				return err
			}
		}
	}
	started, err := q.GetAgentRollout(ctx, ro.ID)
	if err != nil {
		return err
	}
	_, err = r.step(ctx, started)
	return err
}

// Advance takes every rollout in progress one step, and reports how many moved.
func (r *Rollout) Advance(ctx context.Context) (int64, error) {
	active, err := r.Store.Q().ListRolloutsInState(ctx, store.RolloutPilot, store.RolloutPromoting)
	if err != nil {
		return 0, err
	}
	var moved int64
	var errs []error
	for _, ro := range active {
		changed, err := r.step(ctx, ro)
		if err != nil {
			errs = append(errs, fmt.Errorf("rollout of %s: %w", ro.Version, err))
			continue
		}
		if changed {
			moved++
		}
	}
	return moved, errors.Join(errs...)
}

// Resume restarts a halted rollout from where it stopped. A refused or lapsed
// approval is asked for again; a pilot device that failed still fails the
// pilot until its status changes.
func (r *Rollout) Resume(ctx context.Context, id uuid.UUID, actor string) error {
	ro, err := r.Store.Q().GetAgentRollout(ctx, id)
	if err != nil {
		return err
	}
	if ro.State != store.RolloutHalted {
		return ErrNotHalted
	}
	// Back to the pilot step, which checks the pilot again and asks afresh for
	// whichever approval it still needs.
	ro.State, ro.PilotApprovalID, ro.FleetApprovalID, ro.Detail = store.RolloutPilot, nil, nil, ""
	if err := r.save(ctx, ro, actor, "agent_rollout.resumed", nil); err != nil {
		return err
	}
	_, err = r.step(ctx, ro)
	return err
}

// step moves one rollout as far as it can go now, and reports whether it
// changed.
func (r *Rollout) step(ctx context.Context, ro store.AgentRollout) (bool, error) {
	before := ro
	var err error
	switch ro.State {
	case store.RolloutPilot:
		ro, err = r.stepPilot(ctx, ro)
	case store.RolloutPromoting:
		ro, err = r.stepPromoting(ctx, ro)
	default:
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if rolloutUnchanged(before, ro) {
		return false, nil
	}
	return true, nil
}

func rolloutUnchanged(a, b store.AgentRollout) bool {
	return a.State == b.State && a.Detail == b.Detail && eqID(a.PilotAssignmentID, b.PilotAssignmentID) &&
		eqID(a.PilotApprovalID, b.PilotApprovalID) && eqID(a.FleetApprovalID, b.FleetApprovalID) &&
		eqID(a.FleetAssignmentID, b.FleetAssignmentID) && eqID(a.ExcludeAssignmentID, b.ExcludeAssignmentID)
}

func eqID(a, b *uuid.UUID) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func (r *Rollout) stepPilot(ctx context.Context, ro store.AgentRollout) (store.AgentRollout, error) {
	q := r.Store.Q()
	if ro.PilotGroupID == nil {
		return r.halt(ctx, ro, "the pilot group was deleted")
	}
	pilot := *ro.PilotGroupID

	if ro.PilotAssignmentID == nil {
		if ro.PilotApprovalID != nil {
			a, err := q.GetApproval(ctx, *ro.PilotApprovalID)
			if err != nil {
				return ro, err
			}
			switch a.Status {
			case store.ApprovalPending:
				if a.ExpiresAt.After(r.now()) {
					return r.wait(ctx, ro, "waiting for a second administrator to approve the pilot")
				}
				return r.halt(ctx, ro, "nobody approved the pilot assignment before it lapsed")
			case store.ApprovalApproved:
				as, err := q.GetAssignmentFor(ctx, protocol.ItemKindAgent, ro.AgentVersionID, pilot, store.ModeInclude)
				if errors.Is(err, store.ErrNotFound) {
					return r.halt(ctx, ro, "the pilot assignment was approved but is not there")
				} else if err != nil {
					return ro, err
				}
				now := r.now()
				ro.PilotAssignmentID, ro.PilotStartedAt = &as.ID, &now
				ro.Detail = ""
				return ro, r.save(ctx, ro, RolloutActor, "agent_rollout.piloting", nil)
			default:
				return r.halt(ctx, ro, "the pilot assignment was "+approvalOutcome(a.Status))
			}
		}
		// While the pilot runs, the pilot group is kept off the build the
		// rest of the fleet is on, so its devices are offered only this one.
		if ro.ExcludeAssignmentID == nil {
			if current, ok, err := r.fleetBuild(ctx); err != nil {
				return ro, err
			} else if ok && current.AgentVersionID != ro.AgentVersionID {
				id, err := r.assignExclude(ctx, current.AgentVersionID, pilot)
				if err != nil {
					return ro, err
				}
				ro.ExcludeAssignmentID = &id
			}
		}
		assignment, approval, err := r.include(ctx, ro, pilot, "the pilot group")
		if err != nil {
			return ro, err
		}
		if approval != nil {
			ro.PilotApprovalID = approval
			ro.Detail = "waiting for a second administrator to approve the pilot"
			return ro, r.save(ctx, ro, RolloutActor, "agent_rollout.approval_requested", map[string]any{"step": "pilot"})
		}
		now := r.now()
		ro.PilotAssignmentID, ro.PilotStartedAt = assignment, &now
		ro.Detail = ""
		return ro, r.save(ctx, ro, RolloutActor, "agent_rollout.piloting", nil)
	}

	health, err := q.AgentBuildHealth(ctx, pilot, ro.AgentVersionID)
	if err != nil {
		return ro, err
	}
	if health.Failed > 0 {
		return r.halt(ctx, ro, fmt.Sprintf("%d pilot device(s) failed to run it: %s",
			health.Failed, strings.Join(health.Failures, "; ")))
	}
	promoteAt := ro.PilotStartedAt.Add(time.Duration(ro.DelayHours) * time.Hour)
	if r.now().Before(promoteAt) {
		return r.wait(ctx, ro, fmt.Sprintf("piloting until %s; %d pilot device(s) run it so far",
			promoteAt.UTC().Format(time.RFC3339), health.Succeeded))
	}
	if health.Succeeded == 0 {
		return r.wait(ctx, ro, "the pilot period is over, but no pilot device runs it yet")
	}
	assignment, approval, err := r.include(ctx, ro, store.BuiltinGroupID, "All devices")
	if err != nil {
		return ro, err
	}
	if approval != nil {
		ro.State, ro.FleetApprovalID = store.RolloutPromoting, approval
		ro.Detail = "the pilot passed; waiting for a second administrator to approve All devices"
		return ro, r.save(ctx, ro, RolloutActor, "agent_rollout.approval_requested", map[string]any{"step": "fleet"})
	}
	return r.promote(ctx, ro, *assignment)
}

func (r *Rollout) stepPromoting(ctx context.Context, ro store.AgentRollout) (store.AgentRollout, error) {
	q := r.Store.Q()
	if ro.PilotGroupID != nil {
		health, err := q.AgentBuildHealth(ctx, *ro.PilotGroupID, ro.AgentVersionID)
		if err != nil {
			return ro, err
		}
		if health.Failed > 0 {
			return r.halt(ctx, ro, fmt.Sprintf("%d pilot device(s) failed to run it: %s",
				health.Failed, strings.Join(health.Failures, "; ")))
		}
	}
	if ro.FleetApprovalID == nil {
		return r.halt(ctx, ro, "promotion lost track of its approval")
	}
	a, err := q.GetApproval(ctx, *ro.FleetApprovalID)
	if err != nil {
		return ro, err
	}
	switch a.Status {
	case store.ApprovalPending:
		if a.ExpiresAt.After(r.now()) {
			return r.wait(ctx, ro, "the pilot passed; waiting for a second administrator to approve All devices")
		}
		return r.halt(ctx, ro, "nobody approved All devices before the request lapsed")
	case store.ApprovalApproved:
		as, err := q.GetAssignmentFor(ctx, protocol.ItemKindAgent, ro.AgentVersionID, store.BuiltinGroupID, store.ModeInclude)
		if errors.Is(err, store.ErrNotFound) {
			return r.halt(ctx, ro, "All devices was approved but the assignment is not there")
		} else if err != nil {
			return ro, err
		}
		return r.promote(ctx, ro, as.ID)
	default:
		return r.halt(ctx, ro, "All devices was "+approvalOutcome(a.Status))
	}
}

// promote records that every device now has the build, and clears away what
// got it there: its own pilot assignment and exclusion, and the fleet
// assignments of the builds it replaces.
func (r *Rollout) promote(ctx context.Context, ro store.AgentRollout, fleetAssignment uuid.UUID) (store.AgentRollout, error) {
	now := r.now()
	ro.State, ro.FleetAssignmentID, ro.PromotedAt, ro.Detail = store.RolloutPromoted, &fleetAssignment, &now, ""
	older, err := r.Store.Q().ListRolloutsInState(ctx, store.RolloutPromoted)
	if err != nil {
		return ro, err
	}
	err = r.Store.InTx(ctx, func(q *store.Queries) error {
		for _, id := range []*uuid.UUID{ro.PilotAssignmentID, ro.ExcludeAssignmentID} {
			if err := removeAssignment(ctx, q, id); err != nil {
				return err
			}
		}
		ro.PilotAssignmentID, ro.ExcludeAssignmentID = nil, nil
		for _, old := range older {
			if old.ID == ro.ID {
				continue
			}
			for _, id := range []*uuid.UUID{old.FleetAssignmentID, old.PilotAssignmentID, old.ExcludeAssignmentID} {
				if err := removeAssignment(ctx, q, id); err != nil {
					return err
				}
			}
			old.FleetAssignmentID, old.PilotAssignmentID, old.ExcludeAssignmentID = nil, nil, nil
			old.State, old.Detail, old.UpdatedAt = store.RolloutSuperseded, "replaced by "+ro.Version, now
			if err := q.UpdateAgentRollout(ctx, old); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return ro, err
	}
	r.log().Info("an agent build reached every device", "version", ro.Version)
	return ro, r.save(ctx, ro, RolloutActor, "agent_rollout.promoted", nil)
}

// supersede stops a rollout that a newer build has overtaken: its pilot
// assignment and exclusion go, and anything it was waiting on is refused so it
// can't be approved later over the newer build.
func (r *Rollout) supersede(ctx context.Context, ro store.AgentRollout, by string) error {
	now := r.now()
	return r.Store.InTx(ctx, func(q *store.Queries) error {
		for _, id := range []*uuid.UUID{ro.PilotAssignmentID, ro.ExcludeAssignmentID} {
			if err := removeAssignment(ctx, q, id); err != nil {
				return err
			}
		}
		for _, id := range []*uuid.UUID{ro.PilotApprovalID, ro.FleetApprovalID} {
			if id == nil {
				continue
			}
			_, err := q.DecideApproval(ctx, *id, store.ApprovalRejected, RolloutActor, "superseded by agent "+by, now)
			if err != nil && !errors.Is(err, store.ErrNotPending) && !errors.Is(err, store.ErrNotFound) {
				return err
			}
		}
		ro.PilotAssignmentID, ro.ExcludeAssignmentID, ro.PilotApprovalID, ro.FleetApprovalID = nil, nil, nil, nil
		ro.State, ro.Detail, ro.UpdatedAt = store.RolloutSuperseded, "replaced by "+by, now
		if err := q.UpdateAgentRollout(ctx, ro); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: RolloutActor, Action: "agent_rollout.superseded", TargetKind: "agent_rollout", TargetID: ro.ID.String(),
			Details: map[string]any{"version": ro.Version, "by": by},
		})
	})
}

// fleetBuild is the rollout whose build every device is on now, if any.
func (r *Rollout) fleetBuild(ctx context.Context) (store.AgentRollout, bool, error) {
	promoted, err := r.Store.Q().ListRolloutsInState(ctx, store.RolloutPromoted)
	if err != nil || len(promoted) == 0 {
		return store.AgentRollout{}, false, err
	}
	return promoted[len(promoted)-1], true, nil
}

// include assigns the build to a group, or asks for approval where an
// administrator's assignment would have to.
func (r *Rollout) include(ctx context.Context, ro store.AgentRollout, group uuid.UUID, groupName string) (assignment, approval *uuid.UUID, err error) {
	opts, err := protocol.DefaultAgentOptions().Marshal()
	if err != nil {
		return nil, nil, err
	}
	now := r.now()
	a := store.Assignment{
		ID: uuid.Must(uuid.NewV7()), ItemKind: protocol.ItemKindAgent, ItemID: ro.AgentVersionID,
		GroupID: group, Mode: store.ModeInclude, CreatedAt: now, CreatedBy: RolloutActor, Options: opts,
	}
	held, err := r.needsApproval(ctx, group)
	if err != nil {
		return nil, nil, err
	}
	if held {
		body, err := json.Marshal(map[string]any{
			"item_kind": a.ItemKind, "item_id": a.ItemID.String(), "group_id": group.String(),
			"mode": a.Mode, "options": json.RawMessage(opts),
		})
		if err != nil {
			return nil, nil, err
		}
		ap := store.Approval{
			ID: uuid.Must(uuid.NewV7()), Kind: store.ApprovalAssignment, Request: body,
			Summary:     fmt.Sprintf("automatic rollout: assign agent %s to %s", ro.Version, groupName),
			RequestedBy: RolloutActor, RequesterID: uuid.Nil,
			CreatedAt: now, ExpiresAt: now.Add(approvalTTL), Status: store.ApprovalPending,
		}
		err = r.Store.InTx(ctx, func(q *store.Queries) error {
			if err := q.CreateApproval(ctx, ap); err != nil {
				return err
			}
			return q.InsertAudit(ctx, store.AuditEntry{
				Actor: RolloutActor, Action: "approval.requested", TargetKind: "approval", TargetID: ap.ID.String(),
				Details: map[string]any{"kind": ap.Kind, "summary": ap.Summary},
			})
		})
		if err != nil {
			return nil, nil, err
		}
		return nil, &ap.ID, nil
	}
	id, err := r.saveAssignment(ctx, a)
	if err != nil {
		return nil, nil, err
	}
	return &id, nil, nil
}

// assignExclude keeps a group off a build. An exclusion never waits for
// approval: it only takes something away.
func (r *Rollout) assignExclude(ctx context.Context, buildID, group uuid.UUID) (uuid.UUID, error) {
	return r.saveAssignment(ctx, store.Assignment{
		ID: uuid.Must(uuid.NewV7()), ItemKind: protocol.ItemKindAgent, ItemID: buildID,
		GroupID: group, Mode: store.ModeExclude, CreatedAt: r.now(), CreatedBy: RolloutActor,
	})
}

func (r *Rollout) saveAssignment(ctx context.Context, a store.Assignment) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.Store.InTx(ctx, func(q *store.Queries) error {
		var err error
		if id, err = q.CreateAssignment(ctx, a); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: RolloutActor, Action: "assignment.created", TargetKind: "assignment", TargetID: id.String(),
			Details: map[string]any{
				"item_kind": a.ItemKind, "item_id": a.ItemID.String(), "group_id": a.GroupID.String(), "mode": a.Mode,
			},
		})
	})
	return id, err
}

func removeAssignment(ctx context.Context, q *store.Queries, id *uuid.UUID) error {
	if id == nil {
		return nil
	}
	if err := q.DeleteAssignment(ctx, store.DefaultTenantID, *id); err != nil {
		return err
	}
	return q.InsertAudit(ctx, store.AuditEntry{
		Actor: RolloutActor, Action: "assignment.deleted", TargetKind: "assignment", TargetID: id.String(),
	})
}

// needsApproval is the admin API's rule for an include: with approvals on, a
// group of more devices than the threshold, or any group that can grow - a
// dynamic group or All devices - waits for a second administrator.
func (r *Rollout) needsApproval(ctx context.Context, group uuid.UUID) (bool, error) {
	if !r.ApprovalsRequired {
		return false, nil
	}
	q := r.Store.Q()
	g, err := q.GetGroup(ctx, store.DefaultTenantID, group)
	if err != nil {
		return false, err
	}
	if g.Kind != store.GroupStatic {
		return true, nil
	}
	n, err := q.GroupMemberCount(ctx, group)
	return n > r.ApprovalThreshold, err
}

// wait records what a rollout is waiting for, without changing its state.
func (r *Rollout) wait(ctx context.Context, ro store.AgentRollout, detail string) (store.AgentRollout, error) {
	if ro.Detail == detail {
		return ro, nil
	}
	ro.Detail = detail
	ro.UpdatedAt = r.now()
	return ro, r.Store.Q().UpdateAgentRollout(ctx, ro)
}

// halt stops a rollout. The pilot devices that took the build keep it until an
// administrator decides; but if the pilot never got the build, the pilot group
// goes back onto the fleet's build rather than being left with none.
func (r *Rollout) halt(ctx context.Context, ro store.AgentRollout, why string) (store.AgentRollout, error) {
	if ro.PilotAssignmentID == nil && ro.ExcludeAssignmentID != nil {
		if err := r.Store.InTx(ctx, func(q *store.Queries) error {
			return removeAssignment(ctx, q, ro.ExcludeAssignmentID)
		}); err != nil {
			return ro, err
		}
		ro.ExcludeAssignmentID = nil
	}
	ro.State, ro.Detail = store.RolloutHalted, why
	r.log().Warn("an automatic agent rollout halted", "version", ro.Version, "reason", why)
	return ro, r.save(ctx, ro, RolloutActor, "agent_rollout.halted", map[string]any{"reason": why})
}

func (r *Rollout) save(ctx context.Context, ro store.AgentRollout, actor, action string, details map[string]any) error {
	ro.UpdatedAt = r.now()
	if details == nil {
		details = map[string]any{}
	}
	details["version"], details["state"] = ro.Version, ro.State
	return r.Store.InTx(ctx, func(q *store.Queries) error {
		if err := q.UpdateAgentRollout(ctx, ro); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: actor, Action: action, TargetKind: "agent_rollout", TargetID: ro.ID.String(), Details: details,
		})
	})
}

func approvalOutcome(status string) string {
	switch status {
	case store.ApprovalRejected:
		return "rejected"
	case store.ApprovalExpired:
		return "not approved before it lapsed"
	case store.ApprovalFailed:
		return "approved, but could not be carried out"
	}
	return status
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
