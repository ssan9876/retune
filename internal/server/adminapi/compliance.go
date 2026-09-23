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
	// DeviceCounts is only ever populated by the list endpoint (spec §6's
	// "list with rollups"): it is one batched query over the whole page
	// rather than a per-policy round trip, so it is left nil - and so
	// omitted - everywhere else a policy is returned.
	DeviceCounts map[string]int `json:"device_counts,omitempty"`
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
	ctx := r.Context()
	rows, total, err := h.Compliance.List(ctx, page)
	if err != nil {
		h.internal(w, "list compliance policies", err)
		return
	}
	ids := make([]uuid.UUID, len(rows))
	for i, p := range rows {
		ids[i] = p.ID
	}
	// One query for the whole page's rollup, not one per policy: the same
	// shape as exportDevices batching ComplianceOverall over its page of
	// devices, so listing policies never fans out into N extra round trips.
	counts, err := h.Store.Q().PolicyStateCounts(ctx, ids, caller(r).Scope)
	if err != nil {
		h.internal(w, "policy state counts", err)
		return
	}
	items := make([]compliancePolicyJSON, 0, len(rows))
	for _, p := range rows {
		item := newCompliancePolicyJSON(p)
		item.DeviceCounts = counts[p.ID]
		items = append(items, item)
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
// its devices. The pass runs after the response: it is one transaction per
// device, and a policy assigned to the whole fleet would otherwise hold a
// request open for as long as the fleet is large. The reply says how many
// devices the pass covers and whether it started one - `started` is false
// when a pass for this policy is already running, which is not an error,
// since that pass reads the same policy this one would have.
func (h *Handler) evaluateCompliancePolicy(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such compliance policy")
	if !ok {
		return
	}
	if _, err := h.Compliance.Get(r.Context(), id); err != nil {
		h.writeComplianceError(w, "get compliance policy", err)
		return
	}
	n, started, err := h.Compliance.StartPolicyEvaluation(r.Context(), id, caller(r).Admin.Email)
	if err != nil {
		h.writeComplianceError(w, "evaluate compliance policy", err)
		return
	}
	writeJSON(w, http.StatusAccepted, evaluationStarted{DeviceCount: n, Started: started})
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
	rows, total, err := h.Store.Q().ListPolicyCompliance(r.Context(), id, r.URL.Query().Get("state"), page, caller(r).Scope)
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
	PolicyID string `json:"policy_id"`
	// PolicyName saves the console a second request for the whole policy
	// library just to caption these rows - a request that was also capped at
	// a page, so a fleet with more policies than that page held would have
	// shown bare ids.
	PolicyName  string               `json:"policy_name"`
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
	if !h.deviceVisible(w, r, id) {
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
			PolicyID: dc.PolicyID.String(), PolicyName: dc.PolicyName, State: dc.State,
			Failures: failures, EvaluatedAt: dc.EvaluatedAt,
		})
	}
	writeJSON(w, http.StatusOK, deviceComplianceJSON{Overall: overall[id], Policies: policies})
}
