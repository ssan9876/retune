package adminapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/groups"
	"retune/internal/server/store"
)

type groupJSON struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Kind        string     `json:"kind"`
	Rule        string     `json:"rule"`
	MemberCount int        `json:"member_count"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	EvaluatedAt *time.Time `json:"evaluated_at"`
}

func newGroupJSON(g store.Group, members int) groupJSON {
	return groupJSON{
		ID: g.ID.String(), Name: g.Name, Description: g.Description, Kind: g.Kind,
		Rule: g.Rule, MemberCount: members,
		CreatedAt: g.CreatedAt, UpdatedAt: g.UpdatedAt, EvaluatedAt: g.EvaluatedAt,
	}
}

type groupRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Kind        string `json:"kind"`
	Rule        string `json:"rule"`
}

// writeGroupError maps the group service's errors onto responses. A rule that
// does not parse is a 400 carrying the offset, because the console points at
// it in the editor.
func (h *Handler) writeGroupError(w http.ResponseWriter, what string, err error) {
	var pe groups.ParseError
	switch {
	case errors.As(err, &pe):
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"code": "invalid_rule", "message": pe.Message, "offset": pe.Offset,
		})
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such group")
	case errors.Is(err, groups.ErrNameTaken):
		writeError(w, http.StatusConflict, "name_taken", err.Error())
	case errors.Is(err, groups.ErrDerivedMembership):
		writeError(w, http.StatusConflict, "derived_membership", err.Error())
	case errors.Is(err, groups.ErrBuiltinGroup):
		writeError(w, http.StatusConflict, "builtin_group", err.Error())
	default:
		h.internal(w, what, err)
	}
}

func (h *Handler) listGroups(w http.ResponseWriter, r *http.Request) {
	rows, err := h.Groups.List(r.Context())
	if err != nil {
		h.internal(w, "list groups", err)
		return
	}
	items := make([]groupJSON, 0, len(rows))
	for _, g := range rows {
		items = append(items, newGroupJSON(g.Group, g.MemberCount))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h *Handler) createGroup(w http.ResponseWriter, r *http.Request) {
	var req groupRequest
	if !decode(w, r, &req) {
		return
	}
	g, err := h.Groups.Create(r.Context(), groups.NewGroup{
		Name: req.Name, Description: req.Description, Kind: req.Kind, Rule: req.Rule,
		Actor: caller(r).Admin.Email,
	})
	if err != nil {
		h.writeGroupError(w, "create group", err)
		return
	}
	writeJSON(w, http.StatusCreated, newGroupJSON(g, h.memberCount(r, g.ID)))
}

func (h *Handler) getGroup(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such group")
	if !ok {
		return
	}
	g, err := h.Groups.Get(r.Context(), id)
	if err != nil {
		h.writeGroupError(w, "get group", err)
		return
	}
	writeJSON(w, http.StatusOK, newGroupJSON(g, h.memberCount(r, g.ID)))
}

func (h *Handler) updateGroup(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such group")
	if !ok {
		return
	}
	var req groupRequest
	if !decode(w, r, &req) {
		return
	}
	g, err := h.Groups.Update(r.Context(), id, groups.NewGroup{
		Name: req.Name, Description: req.Description, Rule: req.Rule,
		Actor: caller(r).Admin.Email,
	})
	if err != nil {
		h.writeGroupError(w, "update group", err)
		return
	}
	writeJSON(w, http.StatusOK, newGroupJSON(g, h.memberCount(r, g.ID)))
}

func (h *Handler) deleteGroup(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such group")
	if !ok {
		return
	}
	if err := h.Groups.Delete(r.Context(), id, caller(r).Admin.Email); err != nil {
		h.writeGroupError(w, "delete group", err)
		return
	}
	writeNoContent(w)
}

func (h *Handler) listGroupMembers(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such group")
	if !ok {
		return
	}
	page := pageFrom(r)
	rows, total, err := h.Store.Q().ListGroupMembers(r.Context(), id, page)
	if err != nil {
		h.internal(w, "list group members", err)
		return
	}
	items := make([]deviceJSON, 0, len(rows))
	for _, d := range rows {
		items = append(items, h.newDeviceJSON(d))
	}
	writeJSON(w, http.StatusOK, newListResponse(items, total, page))
}

type memberRequest struct {
	DeviceID string `json:"device_id"`
}

func (h *Handler) addGroupMember(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such group")
	if !ok {
		return
	}
	var req memberRequest
	if !decode(w, r, &req) {
		return
	}
	deviceID, err := uuid.Parse(req.DeviceID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "device_id must be a UUID")
		return
	}
	if err := h.Groups.AddMember(r.Context(), id, deviceID, caller(r).Admin.Email); err != nil {
		h.writeGroupError(w, "add group member", err)
		return
	}
	writeNoContent(w)
}

func (h *Handler) removeGroupMember(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such group")
	if !ok {
		return
	}
	deviceID, err := uuid.Parse(r.PathValue("deviceID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "device_id must be a UUID")
		return
	}
	if err := h.Groups.RemoveMember(r.Context(), id, deviceID, caller(r).Admin.Email); err != nil {
		h.writeGroupError(w, "remove group member", err)
		return
	}
	writeNoContent(w)
}

type previewRequest struct {
	Rule string `json:"rule"`
}

// previewRule reports what a rule would match without saving anything, so the
// console can show a count while an administrator types.
func (h *Handler) previewRule(w http.ResponseWriter, r *http.Request) {
	var req previewRequest
	if !decode(w, r, &req) {
		return
	}
	page := pageFrom(r)
	devices, total, err := h.Groups.Preview(r.Context(), req.Rule, page)
	if err != nil {
		h.writeGroupError(w, "preview rule", err)
		return
	}
	items := make([]deviceJSON, 0, len(devices))
	for _, d := range devices {
		items = append(items, h.newDeviceJSON(d))
	}
	writeJSON(w, http.StatusOK, newListResponse(items, total, page))
}

// evaluateGroup recomputes a derived group's membership on demand.
func (h *Handler) evaluateGroup(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such group")
	if !ok {
		return
	}
	g, err := h.Groups.Get(r.Context(), id)
	if err != nil {
		h.writeGroupError(w, "get group", err)
		return
	}
	n, err := h.Groups.EvaluateGroup(r.Context(), g)
	if err != nil {
		h.writeGroupError(w, "evaluate group", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"member_count": n})
}

func (h *Handler) memberCount(r *http.Request, id uuid.UUID) int {
	_, total, err := h.Store.Q().ListGroupMembers(r.Context(), id, store.Page{Limit: 1})
	if err != nil {
		return 0
	}
	return total
}

type assignmentJSON struct {
	ID        string          `json:"id"`
	ItemKind  string          `json:"item_kind"`
	ItemID    string          `json:"item_id"`
	GroupID   string          `json:"group_id"`
	GroupName string          `json:"group_name"`
	Mode      string          `json:"mode"`
	Options   json.RawMessage `json:"options,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
	CreatedBy string          `json:"created_by"`
}

type assignmentRequest struct {
	ItemKind string          `json:"item_kind"`
	ItemID   string          `json:"item_id"`
	GroupID  string          `json:"group_id"`
	Mode     string          `json:"mode"`
	Options  json.RawMessage `json:"options"`
}

func (h *Handler) listAssignments(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("item_kind")
	itemID, err := uuid.Parse(r.URL.Query().Get("item_id"))
	if kind == "" || err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "item_kind and a UUID item_id are required")
		return
	}
	ctx := r.Context()
	rows, err := h.Store.Q().ListAssignments(ctx, kind, itemID)
	if err != nil {
		h.internal(w, "list assignments", err)
		return
	}
	items := make([]assignmentJSON, 0, len(rows))
	for _, a := range rows {
		name := ""
		if g, err := h.Store.Q().GetGroup(ctx, a.GroupID); err == nil {
			name = g.Name
		}
		items = append(items, assignmentJSON{
			ID: a.ID.String(), ItemKind: a.ItemKind, ItemID: a.ItemID.String(),
			GroupID: a.GroupID.String(), GroupName: name, Mode: a.Mode,
			Options:   json.RawMessage(a.Options),
			CreatedAt: a.CreatedAt, CreatedBy: a.CreatedBy,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h *Handler) createAssignment(w http.ResponseWriter, r *http.Request) {
	var req assignmentRequest
	if !decode(w, r, &req) {
		return
	}
	itemID, err := uuid.Parse(req.ItemID)
	if err != nil || req.ItemKind == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "item_kind and a UUID item_id are required")
		return
	}
	groupID, err := uuid.Parse(req.GroupID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "group_id must be a UUID")
		return
	}
	if req.Mode != store.ModeInclude && req.Mode != store.ModeExclude {
		writeError(w, http.StatusBadRequest, "bad_request", "mode must be include or exclude")
		return
	}

	// Options are validated here so an agent never has to defend itself
	// against nonsense. An exclude assignment carries none: it only takes
	// something away, whatever the kind.
	var options []byte
	if req.Mode == store.ModeInclude {
		parse, known := optionsParsers[req.ItemKind]
		if !known {
			writeError(w, http.StatusBadRequest, "bad_request",
				fmt.Sprintf("there is no such item kind as %q", req.ItemKind))
			return
		}
		encoded, err := parse(req.Options)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_options", err.Error())
			return
		}
		options = encoded
	}

	a := store.Assignment{
		ID: uuid.Must(uuid.NewV7()), ItemKind: req.ItemKind, ItemID: itemID,
		GroupID: groupID, Mode: req.Mode, CreatedAt: h.Now(), CreatedBy: caller(r).Admin.Email,
		Options: options,
	}
	groupName := ""
	ctx := r.Context()
	err = h.Store.InTx(ctx, func(q *store.Queries) error {
		g, err := q.GetGroup(ctx, groupID)
		if err != nil {
			return err
		}
		groupName = g.Name
		if err := q.CreateAssignment(ctx, a); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: a.CreatedBy, Action: "assignment.created", TargetKind: "assignment",
			TargetID: a.ID.String(),
			Details: map[string]any{
				"item_kind": a.ItemKind, "item_id": a.ItemID.String(),
				"group_id": a.GroupID.String(), "mode": a.Mode,
			},
		})
	})
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "no such group")
		return
	}
	if err != nil {
		h.internal(w, "create assignment", err)
		return
	}
	writeJSON(w, http.StatusCreated, assignmentJSON{
		ID: a.ID.String(), ItemKind: a.ItemKind, ItemID: a.ItemID.String(),
		GroupID: a.GroupID.String(), GroupName: groupName, Mode: a.Mode,
		Options:   json.RawMessage(a.Options),
		CreatedAt: a.CreatedAt, CreatedBy: a.CreatedBy,
	})
}

func (h *Handler) deleteAssignment(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such assignment")
	if !ok {
		return
	}
	ctx := r.Context()
	err := h.Store.InTx(ctx, func(q *store.Queries) error {
		a, err := q.GetAssignment(ctx, id)
		if err != nil {
			return err
		}
		if err := q.DeleteAssignment(ctx, id); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: caller(r).Admin.Email, Action: "assignment.deleted", TargetKind: "assignment",
			TargetID: id.String(),
			Details:  map[string]any{"item_kind": a.ItemKind, "item_id": a.ItemID.String()},
		})
	})
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "no such assignment")
		return
	}
	if err != nil {
		h.internal(w, "delete assignment", err)
		return
	}
	writeNoContent(w)
}

// itemStatus returns the rollup for one item, with an optional drill-down to
// the devices in one status.
func (h *Handler) itemStatus(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	itemID, err := uuid.Parse(r.PathValue("id"))
	if kind == "" || err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "a kind and a UUID id are required")
		return
	}
	ctx := r.Context()
	rollup, err := h.Store.Q().ItemStatusRollup(ctx, kind, itemID)
	if err != nil {
		h.internal(w, "item status rollup", err)
		return
	}
	page := pageFrom(r)
	rows, total, err := h.Store.Q().ListItemStatus(ctx, kind, itemID, r.URL.Query().Get("status"), page)
	if err != nil {
		h.internal(w, "list item status", err)
		return
	}
	type row struct {
		DeviceID string `json:"device_id"`
		Hostname string `json:"hostname"`
		Status   string `json:"status"`
		Detail   string `json:"detail"`
		// Version says which version of the item the status refers to, so the
		// console can report "succeeded on version 3".
		Version   int       `json:"version"`
		UpdatedAt time.Time `json:"updated_at"`
	}
	items := make([]row, 0, len(rows))
	for _, s := range rows {
		items = append(items, row{
			DeviceID: s.DeviceID.String(), Hostname: s.Hostname,
			Status: s.Status, Detail: s.Detail, Version: s.Version, UpdatedAt: s.UpdatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"rollup": rollup,
		"items":  items,
		"total":  total,
		"limit":  page.Normalized().Limit,
		"offset": page.Normalized().Offset,
	})
}
