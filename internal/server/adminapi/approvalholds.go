package adminapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/compliance"
	"retune/internal/server/groups"
	"retune/internal/server/store"
)

// Two-person approval holds more than the request that first sends code to
// many devices. Without these, whatever was approved once could be changed
// afterwards by one person: a new version of an approved script reaches every
// device it was assigned to, a small static group can be grown to the whole
// fleet under an assignment nobody held, and PowerShell to a thousand devices
// can be sent fifty at a time.

// powerShellWindow is how far back ad-hoc PowerShell is counted per
// administrator: to more devices than the threshold within it, the next
// request waits.
const powerShellWindow = time.Hour

// unheldKinds are item kinds that never wait for approval: a compliance
// policy only reports, and a maintenance window only holds changes back.
var unheldKinds = []string{compliance.ItemKindCompliance, protocol.ItemKindWindow}

// versionApproval is a held new version of a script, profile or app. The
// version is already stored, with any secrets sealed; approving it makes it
// the one devices receive.
type versionApproval struct {
	ItemKind string `json:"item_kind"`
	ItemID   string `json:"item_id"`
	Version  int    `json:"version"`
}

// groupMemberApproval is a held addition to a static group.
type groupMemberApproval struct {
	GroupID  string `json:"group_id"`
	DeviceID string `json:"device_id"`
}

// groupRuleApproval is a held change to a dynamic group's rule.
type groupRuleApproval struct {
	GroupID string `json:"group_id"`
	groupRequest
}

// itemNeedsApproval: with approvals on, a new version of something whose
// include assignments reach more devices than the threshold - or any
// dynamic group or All devices - waits, as the assignment itself did.
func (h *Handler) itemNeedsApproval(ctx context.Context, kind string, id uuid.UUID) (bool, error) {
	if !h.ApprovalsRequired {
		return false, nil
	}
	devices, unbounded, err := h.Store.Q().ItemReach(ctx, kind, id)
	if err != nil {
		return false, err
	}
	return unbounded || devices > h.ApprovalThreshold, nil
}

// holdVersion answers an update whose new version was stored but not made
// current, holding its promotion for a second administrator.
func (h *Handler) holdVersion(w http.ResponseWriter, r *http.Request, kind string, id uuid.UUID, name string, version int) {
	h.holdForApproval(w, r, store.ApprovalVersion,
		versionApproval{ItemKind: kind, ItemID: id.String(), Version: version},
		fmt.Sprintf("make version %d of %s %q current", version, kind, name))
}

// groupHasCode reports whether a group has something included in it that
// would have waited for approval when assigned.
func (h *Handler) groupHasCode(ctx context.Context, id uuid.UUID) (bool, error) {
	return h.Store.Q().GroupIncludesAnyOf(ctx, id, unheldKinds)
}

// memberNeedsApproval: with approvals on, adding a device to a static group
// with code included in it waits once the group would hold more devices than
// the threshold. A group of any size can be grown one device at a time, so
// the size it would reach is what counts, not the size of one request.
func (h *Handler) memberNeedsApproval(ctx context.Context, g store.Group, deviceID uuid.UUID) (held bool, size int, err error) {
	if !h.ApprovalsRequired || g.Kind != store.GroupStatic {
		return false, 0, nil
	}
	q := h.Store.Q()
	code, err := h.groupHasCode(ctx, g.ID)
	if err != nil || !code {
		return false, 0, err
	}
	in, err := q.IsGroupMember(ctx, g.ID, deviceID)
	if err != nil || in {
		return false, 0, err
	}
	n, err := q.GroupMemberCount(ctx, g.ID)
	if err != nil {
		return false, 0, err
	}
	return n+1 > h.ApprovalThreshold, n + 1, nil
}

// ruleNeedsApproval: with approvals on, changing the rule of a dynamic group
// with code included in it waits. Including code in a dynamic group always
// waits, because it can grow to any size; changing the rule chooses which
// devices it grows to.
func (h *Handler) ruleNeedsApproval(ctx context.Context, g store.Group, rule string) (bool, error) {
	if !h.ApprovalsRequired || g.Kind != store.GroupDynamic || rule == g.Rule {
		return false, nil
	}
	return h.groupHasCode(ctx, g.ID)
}

// replayVersion promotes an approved held version.
func (h *Handler) replayVersion(ctx context.Context, a store.Approval, req versionApproval) (map[string]any, error) {
	id, err := uuid.Parse(req.ItemID)
	if err != nil {
		return nil, err
	}
	var current int
	switch req.ItemKind {
	case protocol.ItemKindScript:
		sc, err := h.Scripts.Promote(ctx, id, req.Version, a.RequestedBy)
		if err != nil {
			return nil, err
		}
		current = sc.CurrentVersion
	case protocol.ItemKindProfile:
		p, err := h.Profiles.Promote(ctx, id, req.Version, a.RequestedBy)
		if err != nil {
			return nil, err
		}
		current = p.CurrentVersion
	case protocol.ItemKindApp:
		ap, err := h.Apps.Promote(ctx, id, req.Version, a.RequestedBy)
		if err != nil {
			return nil, err
		}
		current = ap.CurrentVersion
	default:
		return nil, errors.New("there is no such item kind as " + req.ItemKind)
	}
	return map[string]any{"version": map[string]any{
		"item_kind": req.ItemKind, "item_id": req.ItemID, "current_version": current,
	}}, nil
}

// replayGroupMember adds an approved device to its group.
func (h *Handler) replayGroupMember(ctx context.Context, a store.Approval, req groupMemberApproval) (map[string]any, error) {
	groupID, err := uuid.Parse(req.GroupID)
	if err != nil {
		return nil, err
	}
	deviceID, err := uuid.Parse(req.DeviceID)
	if err != nil {
		return nil, err
	}
	if err := h.Groups.AddMember(ctx, groupID, deviceID, a.RequestedBy); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			err = errors.New("the group or the device no longer exists")
		}
		return nil, err
	}
	return map[string]any{"group_member": req}, nil
}

// replayGroupRule applies an approved rule change.
func (h *Handler) replayGroupRule(ctx context.Context, a store.Approval, req groupRuleApproval) (map[string]any, error) {
	id, err := uuid.Parse(req.GroupID)
	if err != nil {
		return nil, err
	}
	g, err := h.Groups.Update(ctx, id, groups.NewGroup{
		Name: req.Name, Description: req.Description, Rule: req.Rule, Actor: a.RequestedBy,
	})
	if errors.Is(err, store.ErrNotFound) {
		err = errors.New("the group no longer exists")
	}
	if err != nil {
		return nil, err
	}
	return map[string]any{"group": map[string]any{"id": g.ID.String(), "name": g.Name, "rule": g.Rule}}, nil
}
