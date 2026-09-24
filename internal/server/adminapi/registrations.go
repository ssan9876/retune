package adminapi

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/store"
)

// maxImportRows bounds one CSV import.
const maxImportRows = 5000

type registrationJSON struct {
	ID         string     `json:"id"`
	Serial     string     `json:"serial"`
	DeviceName string     `json:"device_name,omitempty"`
	GroupIDs   []string   `json:"group_ids"`
	Notes      string     `json:"notes,omitempty"`
	DeviceID   string     `json:"device_id,omitempty"`
	EnrolledAt *time.Time `json:"enrolled_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	CreatedBy  string     `json:"created_by"`
}

func newRegistrationJSON(r store.DeviceRegistration) registrationJSON {
	out := registrationJSON{
		ID: r.ID.String(), Serial: r.Serial, DeviceName: r.DeviceName, GroupIDs: []string{}, Notes: r.Notes,
		EnrolledAt: r.EnrolledAt, CreatedAt: r.CreatedAt, CreatedBy: r.CreatedBy,
	}
	for _, g := range r.GroupIDs {
		out.GroupIDs = append(out.GroupIDs, g.String())
	}
	if r.DeviceID != nil {
		out.DeviceID = r.DeviceID.String()
	}
	return out
}

type registrationRequest struct {
	Serial     string   `json:"serial"`
	DeviceName string   `json:"device_name"`
	GroupIDs   []string `json:"group_ids"`
	Notes      string   `json:"notes"`
}

// registrationImport is a CSV of registrations: serial, then optionally the
// computer name and the static groups to join, by name, separated by
// semicolons. A header row is recognised and skipped.
type registrationImport struct {
	CSV string `json:"csv"`
}

type importProblem struct {
	Line    int    `json:"line"`
	Message string `json:"message"`
}

type importResult struct {
	Created  int             `json:"created"`
	Problems []importProblem `json:"problems,omitempty"`
}

// buildRegistration checks one registration. groups resolves a group by id
// or, from a CSV, by name.
func buildRegistration(serial, name, notes string, groups []store.Group) (store.DeviceRegistration, error) {
	serial = strings.TrimSpace(serial)
	if serial == "" || len(serial) > 64 || strings.IndexFunc(serial, unicode.IsControl) >= 0 {
		return store.DeviceRegistration{}, errors.New("serial must be 1 to 64 characters")
	}
	name = strings.TrimSpace(name)
	if name != "" && !protocol.ValidComputerName(name) {
		return store.DeviceRegistration{}, fmt.Errorf("%q is not a computer name: 1 to 15 letters, digits and hyphens, not all digits", name)
	}
	if len(notes) > 500 {
		return store.DeviceRegistration{}, errors.New("notes must be at most 500 characters")
	}
	r := store.DeviceRegistration{ID: uuid.Must(uuid.NewV7()), Serial: serial, DeviceName: name, Notes: notes, GroupIDs: []uuid.UUID{}}
	for _, g := range groups {
		if g.Kind != store.GroupStatic {
			return store.DeviceRegistration{}, fmt.Errorf("%s is not a static group: a dynamic group's rule decides who is in it", g.Name)
		}
		r.GroupIDs = append(r.GroupIDs, g.ID)
	}
	return r, nil
}

func (h *Handler) listRegistrations(w http.ResponseWriter, r *http.Request) {
	page := pageFrom(r)
	rows, total, err := h.Store.Q().ListRegistrations(r.Context(), page)
	if err != nil {
		h.internal(w, "list registrations", err)
		return
	}
	items := make([]registrationJSON, 0, len(rows))
	for _, row := range rows {
		items = append(items, newRegistrationJSON(row))
	}
	writeJSON(w, http.StatusOK, newListResponse(items, total, page))
}

func (h *Handler) createRegistration(w http.ResponseWriter, r *http.Request) {
	var req registrationRequest
	if !decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	var groups []store.Group
	for _, raw := range req.GroupIDs {
		id, err := uuid.Parse(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "group_ids must be group IDs")
			return
		}
		g, err := h.Store.Q().GetGroup(ctx, store.DefaultTenantID, id)
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusBadRequest, "bad_request", "there is no group "+raw)
			return
		} else if err != nil {
			h.internal(w, "get group", err)
			return
		}
		groups = append(groups, g)
	}
	reg, err := buildRegistration(req.Serial, req.DeviceName, req.Notes, groups)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	reg.CreatedAt, reg.CreatedBy = h.Now(), caller(r).Admin.Email
	err = h.Store.InTx(ctx, func(q *store.Queries) error {
		return h.saveRegistrations(ctx, q, []store.DeviceRegistration{reg}, reg.CreatedBy)
	})
	switch {
	case err == nil:
		writeJSON(w, http.StatusCreated, newRegistrationJSON(reg))
	case errors.Is(err, store.ErrDuplicate):
		writeError(w, http.StatusConflict, "duplicate", "that serial number is already registered")
	default:
		h.internal(w, "create registration", err)
	}
}

// importRegistrations registers many devices from a CSV, all or none: a file
// with any problem registers nothing, and says what every problem is.
func (h *Handler) importRegistrations(w http.ResponseWriter, r *http.Request) {
	var req registrationImport
	if !decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	allGroups, err := h.Store.Q().ListGroups(ctx)
	if err != nil {
		h.internal(w, "list groups", err)
		return
	}
	byName := map[string]store.Group{}
	for _, g := range allGroups {
		byName[strings.ToLower(g.Name)] = g.Group
	}

	cr := csv.NewReader(strings.NewReader(req.CSV))
	cr.FieldsPerRecord = -1
	cr.TrimLeadingSpace = true
	var regs []store.DeviceRegistration
	var problems []importProblem
	seen := map[string]int{}
	now, actor := h.Now(), caller(r).Admin.Email
	for line := 1; ; line++ {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			problems = append(problems, importProblem{Line: line, Message: err.Error()})
			break
		}
		if len(rec) == 0 || (len(rec) == 1 && strings.TrimSpace(rec[0]) == "") {
			continue
		}
		if line == 1 && strings.EqualFold(strings.TrimSpace(rec[0]), "serial") {
			continue
		}
		if len(regs)+len(problems) >= maxImportRows {
			problems = append(problems, importProblem{Line: line, Message: fmt.Sprintf("at most %d devices per import", maxImportRows)})
			break
		}
		field := func(i int) string {
			if i < len(rec) {
				return strings.TrimSpace(rec[i])
			}
			return ""
		}
		var groups []store.Group
		bad := false
		for _, name := range strings.Split(field(2), ";") {
			if name = strings.TrimSpace(name); name == "" {
				continue
			}
			g, ok := byName[strings.ToLower(name)]
			if !ok {
				problems = append(problems, importProblem{Line: line, Message: "there is no group called " + name})
				bad = true
				break
			}
			groups = append(groups, g)
		}
		if bad {
			continue
		}
		reg, err := buildRegistration(field(0), field(1), field(3), groups)
		if err != nil {
			problems = append(problems, importProblem{Line: line, Message: err.Error()})
			continue
		}
		key := strings.ToUpper(reg.Serial)
		if first, dup := seen[key]; dup {
			problems = append(problems, importProblem{Line: line, Message: fmt.Sprintf("serial %s is already on line %d", reg.Serial, first)})
			continue
		}
		seen[key] = line
		reg.CreatedAt, reg.CreatedBy = now, actor
		regs = append(regs, reg)
	}
	if len(problems) > 0 {
		writeJSON(w, http.StatusBadRequest, importResult{Problems: problems})
		return
	}
	if len(regs) == 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "the CSV has no devices in it")
		return
	}
	err = h.Store.InTx(ctx, func(q *store.Queries) error { return h.saveRegistrations(ctx, q, regs, actor) })
	switch {
	case err == nil:
		writeJSON(w, http.StatusCreated, importResult{Created: len(regs)})
	case errors.Is(err, store.ErrDuplicate):
		writeError(w, http.StatusConflict, "duplicate", "a serial number in the CSV is already registered; nothing was imported")
	default:
		h.internal(w, "import registrations", err)
	}
}

func (h *Handler) saveRegistrations(ctx context.Context, q *store.Queries, regs []store.DeviceRegistration, actor string) error {
	serials := make([]string, 0, len(regs))
	for _, reg := range regs {
		if err := q.CreateRegistration(ctx, reg); err != nil {
			return err
		}
		serials = append(serials, reg.Serial)
	}
	details := map[string]any{"count": len(regs)}
	if len(serials) <= 20 {
		details["serials"] = serials
	}
	target := ""
	if len(regs) == 1 {
		target = regs[0].ID.String()
	}
	return q.InsertAudit(ctx, store.AuditEntry{
		Actor: actor, Action: "device_registration.created", TargetKind: "device_registration", TargetID: target, Details: details,
	})
}

func (h *Handler) deleteRegistration(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such registration")
	if !ok {
		return
	}
	ctx := r.Context()
	err := h.Store.InTx(ctx, func(q *store.Queries) error {
		reg, err := q.GetRegistration(ctx, id)
		if err != nil {
			return err
		}
		if err := q.DeleteRegistration(ctx, id); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: caller(r).Admin.Email, Action: "device_registration.deleted", TargetKind: "device_registration",
			TargetID: id.String(), Details: map[string]any{"serial": reg.Serial},
		})
	})
	switch {
	case err == nil:
		writeNoContent(w)
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such registration")
	default:
		h.internal(w, "delete registration", err)
	}
}
