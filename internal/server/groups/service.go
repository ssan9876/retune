package groups

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/store"
)

// ErrDerivedMembership is returned when something tries to edit the membership
// of a group whose membership comes from a rule.
var ErrDerivedMembership = errors.New("this group's membership is derived from its rule")

// ErrBuiltinGroup is returned when something tries to change or delete the
// built-in group.
var ErrBuiltinGroup = errors.New("the built-in group cannot be changed")

// ErrBadGroup is returned for a group the caller can fix: no name, or a kind
// that is neither static nor dynamic.
var ErrBadGroup = errors.New("invalid group")

// ErrNameTaken is returned when a group name is already in use.
var ErrNameTaken = errors.New("a group with that name already exists")

// Service owns groups and keeps derived membership up to date.
type Service struct {
	Store *store.Store
	Now   func() time.Time
	Log   *slog.Logger
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// NewGroup describes a group to create.
type NewGroup struct {
	Name        string
	Description string
	Kind        string
	Rule        string
	Actor       string
}

// Create makes a group and, if it is dynamic, evaluates it immediately so the
// caller sees its membership straight away.
func (s *Service) Create(ctx context.Context, in NewGroup) (store.Group, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return store.Group{}, fmt.Errorf("%w: a group needs a name", ErrBadGroup)
	}
	switch in.Kind {
	case store.GroupStatic:
		in.Rule = ""
	case store.GroupDynamic:
		if _, err := Parse(in.Rule); err != nil {
			return store.Group{}, err
		}
	default:
		return store.Group{}, fmt.Errorf("%w: a group is static or dynamic, not %q", ErrBadGroup, in.Kind)
	}

	g := store.Group{
		ID: uuid.Must(uuid.NewV7()), Name: name, Description: in.Description,
		Kind: in.Kind, Rule: in.Rule, CreatedAt: s.now(), UpdatedAt: s.now(),
	}
	err := s.Store.InTx(ctx, func(q *store.Queries) error {
		if _, err := q.GetGroupByName(ctx, name); err == nil {
			return ErrNameTaken
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if err := q.CreateGroup(ctx, g); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: in.Actor, Action: "group.created", TargetKind: "group", TargetID: g.ID.String(),
			Details: map[string]any{"name": g.Name, "kind": g.Kind},
		})
	})
	if err != nil {
		return store.Group{}, err
	}
	if g.Kind == store.GroupDynamic {
		if _, err := s.EvaluateGroup(ctx, g); err != nil {
			return store.Group{}, err
		}
	}
	return s.Get(ctx, g.ID)
}

// Update changes a group's name, description or rule, re-evaluating it when
// the rule changed so the caller sees the new membership.
func (s *Service) Update(ctx context.Context, id uuid.UUID, in NewGroup) (store.Group, error) {
	g, err := s.Get(ctx, id)
	if err != nil {
		return store.Group{}, err
	}
	if g.Kind == store.GroupBuiltin {
		return store.Group{}, ErrBuiltinGroup
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return store.Group{}, fmt.Errorf("%w: a group needs a name", ErrBadGroup)
	}
	ruleChanged := false
	if g.Kind == store.GroupDynamic {
		if _, err := Parse(in.Rule); err != nil {
			return store.Group{}, err
		}
		ruleChanged = in.Rule != g.Rule
		g.Rule = in.Rule
	}
	g.Name, g.Description, g.UpdatedAt = name, in.Description, s.now()

	err = s.Store.InTx(ctx, func(q *store.Queries) error {
		if other, err := q.GetGroupByName(ctx, name); err == nil && other.ID != id {
			return ErrNameTaken
		} else if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if err := q.UpdateGroup(ctx, store.DefaultTenantID, g); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: in.Actor, Action: "group.updated", TargetKind: "group", TargetID: id.String(),
			Details: map[string]any{"name": g.Name, "rule_changed": ruleChanged},
		})
	})
	if err != nil {
		return store.Group{}, err
	}
	if ruleChanged {
		if _, err := s.EvaluateGroup(ctx, g); err != nil {
			return store.Group{}, err
		}
	}
	return s.Get(ctx, id)
}

// Delete removes a group, its membership and its assignments.
func (s *Service) Delete(ctx context.Context, id uuid.UUID, actor string) error {
	g, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if g.Kind == store.GroupBuiltin {
		return ErrBuiltinGroup
	}
	return s.Store.InTx(ctx, func(q *store.Queries) error {
		if err := q.DeleteGroup(ctx, store.DefaultTenantID, id); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: actor, Action: "group.deleted", TargetKind: "group", TargetID: id.String(),
			Details: map[string]any{"name": g.Name},
		})
	})
}

func (s *Service) Get(ctx context.Context, id uuid.UUID) (store.Group, error) {
	return s.Store.Q().GetGroup(ctx, store.DefaultTenantID, id)
}

func (s *Service) List(ctx context.Context) ([]store.GroupWithCount, error) {
	return s.Store.Q().ListGroups(ctx)
}

// AddMember puts a device in a static group.
func (s *Service) AddMember(ctx context.Context, groupID, deviceID uuid.UUID, actor string) error {
	g, err := s.Get(ctx, groupID)
	if err != nil {
		return err
	}
	if g.Kind != store.GroupStatic {
		return ErrDerivedMembership
	}
	return s.Store.InTx(ctx, func(q *store.Queries) error {
		if _, err := q.GetDevice(ctx, store.DefaultTenantID, deviceID); err != nil {
			return err
		}
		if err := q.AddGroupMember(ctx, groupID, deviceID, s.now()); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: actor, Action: "group.member_added", TargetKind: "group", TargetID: groupID.String(),
			Details: map[string]any{"device_id": deviceID.String()},
		})
	})
}

// RemoveMember takes a device out of a static group.
func (s *Service) RemoveMember(ctx context.Context, groupID, deviceID uuid.UUID, actor string) error {
	g, err := s.Get(ctx, groupID)
	if err != nil {
		return err
	}
	if g.Kind != store.GroupStatic {
		return ErrDerivedMembership
	}
	return s.Store.InTx(ctx, func(q *store.Queries) error {
		if err := q.RemoveGroupMember(ctx, groupID, deviceID); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: actor, Action: "group.member_removed", TargetKind: "group", TargetID: groupID.String(),
			Details: map[string]any{"device_id": deviceID.String()},
		})
	})
}

// Preview reports which devices a rule would match, without saving anything.
func (s *Service) Preview(ctx context.Context, rule string, page store.Page) ([]store.Device, int, error) {
	ids, err := s.match(ctx, rule)
	if err != nil {
		return nil, 0, err
	}
	if len(ids) == 0 {
		return nil, 0, nil
	}
	devices, err := s.Store.Q().DevicesByIDs(ctx, ids, page.Normalized())
	if err != nil {
		return nil, 0, err
	}
	return devices, len(ids), nil
}

// match compiles a rule and runs it, returning the matching device IDs.
func (s *Service) match(ctx context.Context, rule string) ([]uuid.UUID, error) {
	n, err := Parse(rule)
	if err != nil {
		return nil, err
	}
	sql, args, err := Compile(n, store.DefaultTenantID, s.now())
	if err != nil {
		return nil, err
	}
	return s.Store.Q().MatchDevices(ctx, sql, args)
}

// EvaluateGroup recomputes one derived group's membership and returns its size.
// The replacement happens in one transaction, so the group is never seen
// half-evaluated.
func (s *Service) EvaluateGroup(ctx context.Context, g store.Group) (int, error) {
	var ids []uuid.UUID
	var err error
	switch g.Kind {
	case store.GroupBuiltin:
		ids, err = s.Store.Q().ActiveDeviceIDs(ctx)
	case store.GroupDynamic:
		ids, err = s.match(ctx, g.Rule)
	default:
		return 0, nil // a static group's membership is not derived
	}
	if err != nil {
		return 0, err
	}
	if ids == nil {
		ids = []uuid.UUID{}
	}
	now := s.now()
	if err := s.Store.InTx(ctx, func(q *store.Queries) error {
		return q.SetGroupMembers(ctx, g.ID, ids, now)
	}); err != nil {
		return 0, err
	}
	return len(ids), nil
}

// EvaluateAll recomputes every derived group, and is what the sweeper runs.
// One group whose rule no longer parses does not stop the others.
func (s *Service) EvaluateAll(ctx context.Context) (int, error) {
	gs, err := s.Store.Q().DynamicGroups(ctx)
	if err != nil {
		return 0, err
	}
	changed := 0
	for _, g := range gs {
		n, err := s.EvaluateGroup(ctx, g)
		if err != nil {
			// Leave the membership as it was: emptying a group because its
			// rule stopped parsing would silently unassign everything.
			s.log().Warn("evaluate group", "group", g.Name, "group_id", g.ID, "error", err)
			continue
		}
		changed += n
	}
	return changed, nil
}

// EvaluateDevice re-evaluates one device's place in every derived group, after
// its inventory or status changed.
func (s *Service) EvaluateDevice(ctx context.Context, deviceID uuid.UUID) error {
	gs, err := s.Store.Q().DynamicGroups(ctx)
	if err != nil {
		return err
	}
	now := s.now()
	for _, g := range gs {
		member, err := s.deviceMatches(ctx, g, deviceID)
		if err != nil {
			s.log().Warn("evaluate group for device", "group", g.Name, "device_id", deviceID, "error", err)
			continue
		}
		if err := s.Store.Q().SetDeviceGroupMembership(ctx, g.ID, deviceID, member, now); err != nil {
			return err
		}
	}
	return nil
}

// deviceMatches reports whether one device belongs in one derived group.
func (s *Service) deviceMatches(ctx context.Context, g store.Group, deviceID uuid.UUID) (bool, error) {
	if g.Kind == store.GroupBuiltin {
		d, err := s.Store.Q().GetDevice(ctx, store.DefaultTenantID, deviceID)
		if err != nil {
			return false, err
		}
		return d.Status == store.DeviceActive, nil
	}
	ids, err := s.match(ctx, g.Rule)
	if err != nil {
		return false, err
	}
	for _, id := range ids {
		if id == deviceID {
			return true, nil
		}
	}
	return false, nil
}
