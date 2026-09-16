package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/compliance"
	"retune/internal/server/store"
)

type compliancePolicyJSON struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Rules       json.RawMessage `json:"rules"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	CreatedBy   string          `json:"created_by"`
}

func newCompliancePolicyJSON(p store.CompliancePolicy) compliancePolicyJSON {
	return compliancePolicyJSON{
		ID: p.ID.String(), Name: p.Name, Description: p.Description, Rules: json.RawMessage(p.Rules),
		CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt, CreatedBy: p.CreatedBy,
	}
}

type compliancePolicyRequest struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Rules       json.RawMessage `json:"rules"`
}

func (h *Handler) writeComplianceError(w http.ResponseWriter, what string, err error) {
	switch {
	case errors.Is(err, compliance.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such compliance policy")
	case errors.Is(err, compliance.ErrNameTaken):
		writeError(w, http.StatusConflict, "name_taken", err.Error())
	case errors.Is(err, compliance.ErrBadRequest):
		// The message names which rule is wrong and why, which is what the
		// policy editor shows.
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	default:
		h.internal(w, what, err)
	}
}

func (h *Handler) listCompliancePolicies(w http.ResponseWriter, r *http.Request) {
	page := pageFrom(r)
	rows, total, err := h.Compliance.List(r.Context(), page)
	if err != nil {
		h.internal(w, "list compliance policies", err)
		return
	}
	items := make([]compliancePolicyJSON, 0, len(rows))
	for _, p := range rows {
		items = append(items, newCompliancePolicyJSON(p))
	}
	writeJSON(w, http.StatusOK, newListResponse(items, total, page))
}

func (h *Handler) createCompliancePolicy(w http.ResponseWriter, r *http.Request) {
	var req compliancePolicyRequest
	if !decode(w, r, &req) {
		return
	}
	p, err := h.Compliance.Create(r.Context(), compliance.NewPolicy{
		Name: req.Name, Description: req.Description, Rules: req.Rules, Actor: caller(r).Admin.Email,
	})
	if err != nil {
		h.writeComplianceError(w, "create compliance policy", err)
		return
	}
	writeJSON(w, http.StatusCreated, newCompliancePolicyJSON(p))
}

func (h *Handler) getCompliancePolicy(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such compliance policy")
	if !ok {
		return
	}
	p, err := h.Compliance.Get(r.Context(), id)
	if err != nil {
		h.writeComplianceError(w, "get compliance policy", err)
		return
	}
	writeJSON(w, http.StatusOK, newCompliancePolicyJSON(p))
}

// updateCompliancePolicy is POST on the id, the same way profiles and scripts
// route their edits: there is no PUT anywhere else in this API, and a policy
// has no versions to disambiguate "create a new one" from "change this one".
func (h *Handler) updateCompliancePolicy(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such compliance policy")
	if !ok {
		return
	}
	var req compliancePolicyRequest
	if !decode(w, r, &req) {
		return
	}
	p, err := h.Compliance.Update(r.Context(), id, compliance.NewPolicy{
		Name: req.Name, Description: req.Description, Rules: req.Rules, Actor: caller(r).Admin.Email,
	})
	if err != nil {
		h.writeComplianceError(w, "update compliance policy", err)
		return
	}
	writeJSON(w, http.StatusOK, newCompliancePolicyJSON(p))
}

func (h *Handler) deleteCompliancePolicy(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such compliance policy")
	if !ok {
		return
	}
	if err := h.Compliance.Delete(r.Context(), id, caller(r).Admin.Email); err != nil {
		h.writeComplianceError(w, "delete compliance policy", err)
		return
	}
	writeNoContent(w)
}

// evaluateCompliancePolicy re-scores every device the policy currently
// applies to, so an edit does not have to wait for the next sweep to reach
// its devices.
func (h *Handler) evaluateCompliancePolicy(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such compliance policy")
	if !ok {
		return
	}
	if _, err := h.Compliance.Get(r.Context(), id); err != nil {
		h.writeComplianceError(w, "get compliance policy", err)
		return
	}
	n, err := h.Compliance.EvaluatePolicy(r.Context(), id)
	if err != nil {
		h.writeComplianceError(w, "evaluate compliance policy", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"evaluated_count": n})
}

// decodeFailures turns a device_compliance row's stored failures back into
// the typed shape the rule engine produced them in, rather than passing the
// raw JSON through: a nil/empty column (a compliant result has none) becomes
// an empty slice, not a JSON null, so the console never has to special-case it.
func decodeFailures(raw []byte) ([]compliance.Failure, error) {
	failures := []compliance.Failure{}
	if len(raw) == 0 {
		return failures, nil
	}
	if err := json.Unmarshal(raw, &failures); err != nil {
		return nil, err
	}
	return failures, nil
}

type policyDeviceComplianceJSON struct {
	DeviceID    string               `json:"device_id"`
	Hostname    string               `json:"hostname"`
	State       string               `json:"state"`
	Failures    []compliance.Failure `json:"failures"`
	EvaluatedAt time.Time            `json:"evaluated_at"`
}

// listPolicyDevices returns one page of a policy's device results, optionally
// narrowed to a single state, for the policy's device list (spec §5).
func (h *Handler) listPolicyDevices(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such compliance policy")
	if !ok {
		return
	}
	page := pageFrom(r)
	rows, total, err := h.Store.Q().ListPolicyCompliance(r.Context(), id, r.URL.Query().Get("state"), page)
	if err != nil {
		h.internal(w, "list policy compliance", err)
		return
	}
	items := make([]policyDeviceComplianceJSON, 0, len(rows))
	for _, dc := range rows {
		failures, err := decodeFailures(dc.Failures)
		if err != nil {
			h.internal(w, "decode compliance failures", err)
			return
		}
		items = append(items, policyDeviceComplianceJSON{
			DeviceID: dc.DeviceID.String(), Hostname: dc.Hostname, State: dc.State,
			Failures: failures, EvaluatedAt: dc.EvaluatedAt,
		})
	}
	writeJSON(w, http.StatusOK, newListResponse(items, total, page))
}

type deviceCompliancePolicyJSON struct {
	PolicyID    string               `json:"policy_id"`
	State       string               `json:"state"`
	Failures    []compliance.Failure `json:"failures"`
	EvaluatedAt time.Time            `json:"evaluated_at"`
}

type deviceComplianceJSON struct {
	Overall  string                       `json:"overall"`
	Policies []deviceCompliancePolicyJSON `json:"policies"`
}

// deviceCompliance returns one device's overall compliance state plus every
// applicable policy's own state and failures (spec §5).
func (h *Handler) deviceCompliance(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such device")
	if !ok {
		return
	}
	ctx := r.Context()
	if _, err := h.Store.Q().GetDevice(ctx, store.DefaultTenantID, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "no such device")
			return
		}
		h.internal(w, "get device", err)
		return
	}
	rows, err := h.Store.Q().ListDeviceCompliance(ctx, id)
	if err != nil {
		h.internal(w, "list device compliance", err)
		return
	}
	overall, err := h.Store.Q().ComplianceOverall(ctx, []uuid.UUID{id})
	if err != nil {
		h.internal(w, "compliance overall", err)
		return
	}
	policies := make([]deviceCompliancePolicyJSON, 0, len(rows))
	for _, dc := range rows {
		failures, err := decodeFailures(dc.Failures)
		if err != nil {
			h.internal(w, "decode compliance failures", err)
			return
		}
		policies = append(policies, deviceCompliancePolicyJSON{
			PolicyID: dc.PolicyID.String(), State: dc.State, Failures: failures, EvaluatedAt: dc.EvaluatedAt,
		})
	}
	writeJSON(w, http.StatusOK, deviceComplianceJSON{Overall: overall[id], Policies: policies})
}
