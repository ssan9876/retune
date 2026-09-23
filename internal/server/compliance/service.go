package compliance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/store"
)

// ItemKindCompliance is the assignment kind for compliance policies: what a
// policy is assigned to a group as, the same way profiles are "profile" and
// scripts are "script".
const ItemKindCompliance = "compliance"

var (
	// ErrNotFound is returned when a policy does not exist.
	ErrNotFound = errors.New("compliance policy not found")
	// ErrBadRequest is returned for input the caller can fix, including rules
	// that fail to parse.
	ErrBadRequest = errors.New("bad request")
	// ErrNameTaken is returned when a policy name is already in use.
	ErrNameTaken = errors.New("a compliance policy with that name already exists")
)

// Service owns the compliance policy library and evaluates policies against
// devices, joining the pure rule engine above to the store.
type Service struct {
	Store *store.Store
	Now   func() time.Time
	Log   *slog.Logger
	// Background bounds work that outlives the request that asked for it: the
	// server's own lifetime context, so a re-evaluation stops when the server
	// is shutting down instead of writing into a pool that is closing. Unset,
	// it falls back to context.Background(), which is what a test that never
	// shuts anything down wants.
	Background context.Context

	// mu guards evaluating, the set of policies with a re-evaluation already
	// running here. It only stops one server from stacking passes over the
	// same policy when an administrator clicks twice; two replicas evaluating
	// the same policy at once is not worth a shared lock, because every write
	// the pass makes is an upsert of the same verdict.
	mu         sync.Mutex
	evaluating map[uuid.UUID]bool
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) background() context.Context {
	if s.Background != nil {
		return s.Background
	}
	return context.Background()
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// NewPolicy describes a policy to create or update.
type NewPolicy struct {
	Name        string
	Description string
	Rules       json.RawMessage
	Actor       string
}

// validate checks a policy's fields and returns its rules in canonical form,
// the same way profiles.NewProfile.validate re-encodes settings: an edit
// that only reorders JSON keys should not look like a change.
func (in NewPolicy) validate() ([]byte, error) {
	if strings.TrimSpace(in.Name) == "" {
		return nil, fmt.Errorf("%w: a policy needs a name", ErrBadRequest)
	}
	rules, err := ParseRules(in.Rules)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadRequest, err)
	}
	raw, err := MarshalRules(rules)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// Create adds a policy.
func (s *Service) Create(ctx context.Context, in NewPolicy) (store.CompliancePolicy, error) {
	rules, err := in.validate()
	if err != nil {
		return store.CompliancePolicy{}, err
	}
	now := s.now()
	p := store.CompliancePolicy{
		ID: uuid.Must(uuid.NewV7()), Name: strings.TrimSpace(in.Name), Description: in.Description,
		Rules: rules, CreatedAt: now, UpdatedAt: now, CreatedBy: in.Actor,
	}
	err = s.Store.InTx(ctx, func(q *store.Queries) error {
		if err := q.CreateCompliancePolicy(ctx, p); err != nil {
			if errors.Is(err, store.ErrDuplicate) {
				return ErrNameTaken
			}
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: in.Actor, Action: "compliance_policy.created", TargetKind: "compliance_policy", TargetID: p.ID.String(),
			Details: map[string]any{"name": p.Name},
		})
	})
	if err != nil {
		return store.CompliancePolicy{}, err
	}
	return p, nil
}

// Update replaces a policy's fields in place. There are no versions: unlike a
// profile, a policy is simply re-evaluated after an edit.
func (s *Service) Update(ctx context.Context, id uuid.UUID, in NewPolicy) (store.CompliancePolicy, error) {
	rules, err := in.validate()
	if err != nil {
		return store.CompliancePolicy{}, err
	}
	now := s.now()
	var out store.CompliancePolicy
	err = s.Store.InTx(ctx, func(q *store.Queries) error {
		p, err := q.GetCompliancePolicy(ctx, store.DefaultTenantID, id)
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		p.Name, p.Description, p.Rules, p.UpdatedAt = strings.TrimSpace(in.Name), in.Description, rules, now
		if err := q.UpdateCompliancePolicy(ctx, store.DefaultTenantID, p); err != nil {
			if errors.Is(err, store.ErrDuplicate) {
				return ErrNameTaken
			}
			return err
		}
		out = p
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: in.Actor, Action: "compliance_policy.updated", TargetKind: "compliance_policy", TargetID: id.String(),
			Details: map[string]any{"name": p.Name},
		})
	})
	if err != nil {
		return store.CompliancePolicy{}, err
	}
	return out, nil
}

// Delete removes a policy along with everything that points at it: its group
// assignments, every device's result for it and the mirrored item-status
// rows, all in one transaction so a crash mid-delete never leaves a result
// pointing at a policy that no longer exists.
func (s *Service) Delete(ctx context.Context, id uuid.UUID, actor string) error {
	return s.Store.InTx(ctx, func(q *store.Queries) error {
		p, err := q.GetCompliancePolicy(ctx, store.DefaultTenantID, id)
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if err := q.DeleteAssignmentsForItem(ctx, ItemKindCompliance, id); err != nil {
			return err
		}
		if err := q.DeleteComplianceForPolicy(ctx, id); err != nil {
			return err
		}
		if err := q.DeleteItemStatusForItem(ctx, ItemKindCompliance, id); err != nil {
			return err
		}
		if err := q.DeleteCompliancePolicy(ctx, store.DefaultTenantID, id); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: actor, Action: "compliance_policy.deleted", TargetKind: "compliance_policy", TargetID: id.String(),
			Details: map[string]any{"name": p.Name},
		})
	})
}

func (s *Service) Get(ctx context.Context, id uuid.UUID) (store.CompliancePolicy, error) {
	p, err := s.Store.Q().GetCompliancePolicy(ctx, store.DefaultTenantID, id)
	if errors.Is(err, store.ErrNotFound) {
		return store.CompliancePolicy{}, ErrNotFound
	}
	return p, err
}

func (s *Service) List(ctx context.Context, page store.Page) ([]store.CompliancePolicy, int, error) {
	return s.Store.Q().ListCompliancePolicies(ctx, page)
}

// EvaluateDevice scores every compliance policy currently assigned to a
// device (through EffectiveItems, the same include/exclude resolution every
// other assignable item goes through) and records the result: a
// device_compliance row per policy, mirrored into device_item_status so the
// device's item list reads the same way a profile or script's does. Policies
// no longer assigned lose their rows in both tables, the same cleanup
// EffectiveItems-driven reconciliation does elsewhere.
func (s *Service) EvaluateDevice(ctx context.Context, deviceID uuid.UUID) error {
	now := s.now()
	return s.Store.InTx(ctx, func(q *store.Queries) error {
		device, err := q.GetDevice(ctx, store.DefaultTenantID, deviceID)
		if err != nil {
			return err
		}
		items, err := q.EffectiveItems(ctx, deviceID, now)
		if err != nil {
			return err
		}
		var policyIDs []uuid.UUID
		for _, it := range items {
			if it.Kind == ItemKindCompliance {
				policyIDs = append(policyIDs, it.ID)
			}
		}
		if len(policyIDs) == 0 {
			if err := q.DeleteDeviceComplianceExcept(ctx, deviceID, nil); err != nil {
				return err
			}
			return q.DeleteItemStatusExcept(ctx, deviceID, ItemKindCompliance, nil)
		}

		facts, err := s.buildFacts(ctx, q, device)
		if err != nil {
			return err
		}

		// scored is policyIDs minus the ones evaluateOne had to skip, so the
		// cleanup below drops a vanished policy's stale rows instead of
		// keeping them alive on the strength of an assignment that outlived
		// the policy it points at.
		scored := make([]uuid.UUID, 0, len(policyIDs))
		for _, policyID := range policyIDs {
			result, failures, err := s.evaluateOne(ctx, q, policyID, facts, now)
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			if err := q.UpsertDeviceCompliance(ctx, store.DeviceCompliance{
				DeviceID: deviceID, PolicyID: policyID, State: result.State,
				Failures: failures, EvaluatedAt: now,
			}); err != nil {
				return err
			}
			status, detail := mirrorItemStatus(result)
			if err := q.SetItemStatus(ctx, store.ItemStatus{
				DeviceID: deviceID, ItemKind: ItemKindCompliance, ItemID: policyID,
				Status: status, Detail: detail, Version: 1, UpdatedAt: now,
			}); err != nil {
				return err
			}
			scored = append(scored, policyID)
		}
		if err := q.DeleteDeviceComplianceExcept(ctx, deviceID, scored); err != nil {
			return err
		}
		return q.DeleteItemStatusExcept(ctx, deviceID, ItemKindCompliance, scored)
	})
}

// buildFacts assembles what Evaluate needs for one device, once, so that
// scoring several policies against the same device does not re-read its
// inventory and profile statuses for each one.
func (s *Service) buildFacts(ctx context.Context, q *store.Queries, device store.Device) (Facts, error) {
	facts := Facts{Device: device}

	inv, err := q.GetInventory(ctx, store.DefaultTenantID, device.ID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		// No inventory yet; every inventory-backed rule reports unknown.
	case err != nil:
		return Facts{}, err
	default:
		var parsed protocol.Inventory
		if err := json.Unmarshal(inv.Data, &parsed); err != nil {
			return Facts{}, fmt.Errorf("decode stored inventory: %w", err)
		}
		facts.Inventory = &parsed
		receivedAt := inv.ReceivedAt
		facts.InventoryReceivedAt = &receivedAt
	}

	statuses, err := q.ListDeviceItemStatus(ctx, device.ID, protocol.ItemKindProfile)
	if err != nil {
		return Facts{}, err
	}
	facts.ProfileStatus = statuses
	return facts, nil
}

// evaluateOne scores one policy against facts already built for the device.
// A policy whose stored rules no longer parse - e.g. hand-edited in the
// database, or written by a future version of this server - does not stop
// evaluating the device's other policies; it is logged and reported as
// unknown, the same as any other fact this evaluator cannot make sense of.
//
// A policy that is not there at all is different, and returns store.ErrNotFound
// for the caller to skip: an assignment can name an item that does not exist
// (createAssignment validates the kind and its options, not the item), and
// letting that abort the transaction would freeze compliance for every device
// in the group - no policy scored, nothing written, and only a Warn from the
// check-in hook to say so.
func (s *Service) evaluateOne(ctx context.Context, q *store.Queries, policyID uuid.UUID, facts Facts, now time.Time) (Result, []byte, error) {
	policy, err := q.GetCompliancePolicy(ctx, store.DefaultTenantID, policyID)
	if errors.Is(err, store.ErrNotFound) {
		s.log().Warn("compliance policy assigned but missing; skipping it", "policy_id", policyID)
		return Result{}, nil, err
	}
	if err != nil {
		return Result{}, nil, err
	}
	rules, err := ParseRules(policy.Rules)
	if err != nil {
		s.log().Warn("compliance policy rules no longer parse", "policy_id", policyID, "policy", policy.Name, "error", err)
		result := Result{State: StateUnknown, Failures: []Failure{
			{Rule: "rules", State: StateUnknown, Detail: "this policy's rules could not be read"},
		}}
		raw, err := json.Marshal(result.Failures)
		return result, raw, err
	}
	result := Evaluate(rules, facts, now)
	failures := result.Failures
	if failures == nil {
		failures = []Failure{}
	}
	raw, err := json.Marshal(failures)
	return result, raw, err
}

// mirrorItemStatus maps a policy's result onto the device_item_status
// vocabulary every other assignable item uses (design §2's mapping):
// compliant -> succeeded, non_compliant -> failed, unknown -> pending. detail
// is every failure's own detail, joined, so the item list reads like a
// one-line reason without needing to open the policy's full result.
func mirrorItemStatus(result Result) (status, detail string) {
	switch result.State {
	case StateNonCompliant:
		status = store.ItemFailed
	case StateUnknown:
		status = store.ItemPending
	default:
		status = store.ItemSucceeded
	}
	details := make([]string, 0, len(result.Failures))
	for _, f := range result.Failures {
		details = append(details, f.Detail)
	}
	return status, strings.Join(details, "; ")
}

// StartPolicyEvaluation re-scores a policy's devices without holding the
// request open for it. Resolving the set is one query, so the caller learns
// straight away how many devices the pass will cover; the scoring itself is
// one transaction per device, which for a policy assigned to the whole fleet
// is more than any administrator should wait on an HTTP request for - and
// more than most proxies would allow before giving up on a request whose work
// would then carry on unwatched anyway.
//
// It reports how many devices the pass covers, and whether it started one: a
// second call while the first is still running is not an error and not a
// queued second pass, because the pass already running will read the same
// edited policy this one would have.
//
// The outcome lands in the audit log rather than in a response nobody is
// waiting for, so "did my re-evaluation finish, and did it manage every
// device" is answerable after the fact.
func (s *Service) StartPolicyEvaluation(ctx context.Context, policyID uuid.UUID, actor string) (int, bool, error) {
	ids, err := s.Store.Q().ActiveDevicesForItem(ctx, ItemKindCompliance, policyID)
	if err != nil {
		return 0, false, err
	}
	s.mu.Lock()
	if s.evaluating[policyID] {
		s.mu.Unlock()
		return len(ids), false, nil
	}
	if s.evaluating == nil {
		s.evaluating = make(map[uuid.UUID]bool)
	}
	s.evaluating[policyID] = true
	s.mu.Unlock()

	go func() {
		defer func() {
			s.mu.Lock()
			delete(s.evaluating, policyID)
			s.mu.Unlock()
		}()
		s.runPolicyEvaluation(s.background(), policyID, actor, ids)
	}()
	return len(ids), true, nil
}

// EvaluatingPolicy reports whether a re-evaluation of this policy is running
// on this server.
func (s *Service) EvaluatingPolicy(policyID uuid.UUID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.evaluating[policyID]
}

// runPolicyEvaluation is the pass itself. A device that fails is logged and
// skipped rather than abandoning the rest, the same way the sweeper treats
// one bad device, and the count of failures goes into the audit entry so a
// pass that limped is not indistinguishable from one that did not.
func (s *Service) runPolicyEvaluation(ctx context.Context, policyID uuid.UUID, actor string, ids []uuid.UUID) {
	started := s.now()
	done, failed := 0, 0
	for _, id := range ids {
		if ctx.Err() != nil {
			s.log().Warn("policy evaluation stopped early", "policy_id", policyID,
				"evaluated", done, "remaining", len(ids)-done-failed, "error", ctx.Err())
			break
		}
		if err := s.EvaluateDevice(ctx, id); err != nil {
			s.log().Warn("evaluate device for policy", "device_id", id, "policy_id", policyID, "error", err)
			failed++
			continue
		}
		done++
	}
	if err := s.Store.Q().InsertAudit(ctx, store.AuditEntry{
		Actor: actor, Action: "compliance_policy.evaluated",
		TargetKind: "compliance_policy", TargetID: policyID.String(),
		Details: map[string]any{
			"devices":   len(ids),
			"evaluated": done,
			"failed":    failed,
			"duration":  s.now().Sub(started).String(),
		},
	}); err != nil {
		s.log().Warn("audit policy evaluation", "policy_id", policyID, "error", err)
	}
}

// EvaluateActive re-evaluates every active device's compliance. Its signature
// matches sweeper.Job.Run so it can be registered as a periodic job directly;
// q is the job's own connection (held under its advisory lock) and is used
// only to list active devices - each device's own scoring still goes through
// the Store the same way EvaluateDevice always does, whether called from here
// or after a check-in, so one device's failure cannot leave another mid
// transaction.
func (s *Service) EvaluateActive(ctx context.Context, q *store.Queries, _ time.Time) (int64, error) {
	ids, err := q.ActiveDeviceIDs(ctx)
	if err != nil {
		return 0, err
	}
	var n int64
	for _, id := range ids {
		if err := s.EvaluateDevice(ctx, id); err != nil {
			s.log().Warn("evaluate device", "device_id", id, "error", err)
			continue
		}
		n++
	}
	return n, nil
}
