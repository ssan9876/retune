package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/store"
)

// approvalTTL is how long a held request waits for a decision.
const approvalTTL = 24 * time.Hour

type approvalJSON struct {
	ID          string          `json:"id"`
	Kind        string          `json:"kind"`
	Request     json.RawMessage `json:"request"`
	Summary     string          `json:"summary"`
	RequestedBy string          `json:"requested_by"`
	CreatedAt   time.Time       `json:"created_at"`
	ExpiresAt   time.Time       `json:"expires_at"`
	Status      string          `json:"status"`
	DecidedBy   string          `json:"decided_by,omitempty"`
	DecidedAt   *time.Time      `json:"decided_at,omitempty"`
	Reason      string          `json:"reason,omitempty"`
	Result      json.RawMessage `json:"result,omitempty"`
}

func newApprovalJSON(a store.Approval) approvalJSON {
	return approvalJSON{
		ID: a.ID.String(), Kind: a.Kind, Request: json.RawMessage(a.Request), Summary: a.Summary,
		RequestedBy: a.RequestedBy, CreatedAt: a.CreatedAt, ExpiresAt: a.ExpiresAt, Status: a.Status,
		DecidedBy: a.DecidedBy, DecidedAt: a.DecidedAt, Reason: a.Reason, Result: json.RawMessage(a.Result),
	}
}

// holdForApproval stores a checked request for a second administrator and
// answers 202 with the approval.
func (h *Handler) holdForApproval(w http.ResponseWriter, r *http.Request, kind string, req any, summary string) {
	body, err := json.Marshal(req)
	if err != nil {
		h.internal(w, "encode request", err)
		return
	}
	c := caller(r)
	// The person behind a token is the admin who made it: nobody approves
	// their own request by sending it with a token.
	requester := c.Admin.ID
	if c.Token != nil {
		requester = c.Token.CreatedByID
	}
	now := h.Now()
	a := store.Approval{
		ID: uuid.Must(uuid.NewV7()), Kind: kind, Request: body, Summary: summary,
		RequestedBy: c.Admin.Email, RequesterID: requester,
		CreatedAt: now, ExpiresAt: now.Add(approvalTTL), Status: store.ApprovalPending,
	}
	ctx := r.Context()
	err = h.Store.InTx(ctx, func(q *store.Queries) error {
		if err := q.CreateApproval(ctx, a); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: a.RequestedBy, Action: "approval.requested", TargetKind: "approval",
			TargetID: a.ID.String(), Details: map[string]any{"kind": kind, "summary": summary},
		})
	})
	if err != nil {
		h.internal(w, "create approval", err)
		return
	}
	writeJSON(w, http.StatusAccepted, approvalEnvelope{Approval: newApprovalJSON(a)})
}

func (h *Handler) listApprovals(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	switch status {
	case "", store.ApprovalPending, store.ApprovalApproved, store.ApprovalRejected, store.ApprovalExpired, store.ApprovalFailed:
	default:
		writeError(w, http.StatusBadRequest, "bad_request", "status must be pending, approved, rejected, expired or failed")
		return
	}
	q := h.Store.Q()
	if err := q.ExpireApprovals(r.Context(), h.Now()); err != nil {
		h.internal(w, "expire approvals", err)
		return
	}
	page := pageFrom(r)
	rows, total, err := q.ListApprovals(r.Context(), status, page)
	if err != nil {
		h.internal(w, "list approvals", err)
		return
	}
	items := make([]approvalJSON, 0, len(rows))
	for _, a := range rows {
		items = append(items, newApprovalJSON(a))
	}
	writeJSON(w, http.StatusOK, newListResponse(items, total, page))
}

func (h *Handler) approveApproval(w http.ResponseWriter, r *http.Request) {
	h.decideApproval(w, r, true)
}
func (h *Handler) rejectApproval(w http.ResponseWriter, r *http.Request) {
	h.decideApproval(w, r, false)
}

// decideApproval approves or rejects a held request. Approving replays it as
// the person who asked, so the command or assignment is theirs in the audit
// log and the approval says who let it through. The requester may reject -
// withdraw - their own request, but never approve it.
func (h *Handler) decideApproval(w http.ResponseWriter, r *http.Request, approve bool) {
	id, ok := pathUUID(w, r, "no such approval")
	if !ok {
		return
	}
	var req decisionRequest
	if !decode(w, r, &req) {
		return
	}
	if len(req.Reason) > 500 {
		writeError(w, http.StatusBadRequest, "bad_request", "reason must be at most 500 characters")
		return
	}
	ctx := r.Context()
	now := h.Now()
	q := h.Store.Q()
	if err := q.ExpireApprovals(ctx, now); err != nil {
		h.internal(w, "expire approvals", err)
		return
	}
	a, err := q.GetApproval(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "no such approval")
		return
	} else if err != nil {
		h.internal(w, "get approval", err)
		return
	}
	actor := caller(r).Admin
	if approve && a.RequesterID == actor.ID {
		writeError(w, http.StatusForbidden, "forbidden", "a request must be approved by someone other than the person who made it")
		return
	}

	status, action := store.ApprovalRejected, "approval.rejected"
	if approve {
		status, action = store.ApprovalApproved, "approval.approved"
	}
	err = h.Store.InTx(ctx, func(q *store.Queries) error {
		decided, err := q.DecideApproval(ctx, id, status, actor.Email, req.Reason, now)
		if err != nil {
			return err
		}
		a = decided
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: actor.Email, Action: action, TargetKind: "approval", TargetID: id.String(),
			Details: map[string]any{"kind": a.Kind, "summary": a.Summary, "requested_by": a.RequestedBy, "reason": req.Reason},
		})
	})
	switch {
	case err == nil:
	case errors.Is(err, store.ErrNotPending):
		writeError(w, http.StatusConflict, "not_pending", "this request has already been decided, or has expired")
		return
	default:
		h.internal(w, "decide approval", err)
		return
	}

	if approve {
		// Carried out after the decision is committed, so two approvers at
		// once can't both run it.
		result, failed := h.replayApproval(ctx, a)
		a.Status = store.ApprovalApproved
		if failed {
			a.Status = store.ApprovalFailed
		}
		a.Result, err = json.Marshal(result)
		if err != nil {
			h.internal(w, "encode approval result", err)
			return
		}
		if err := q.SetApprovalResult(ctx, id, a.Status, a.Result); err != nil {
			h.internal(w, "record approval result", err)
			return
		}
	}
	writeJSON(w, http.StatusOK, approvalEnvelope{Approval: newApprovalJSON(a)})
}

// replayApproval carries out an approved request as its requester. failed
// says it could not be done; the result says why, and what was done first.
func (h *Handler) replayApproval(ctx context.Context, a store.Approval) (result map[string]any, failed bool) {
	fail := func(result map[string]any, err error) (map[string]any, bool) {
		if result == nil {
			result = map[string]any{}
		}
		result["error"] = err.Error()
		return result, true
	}
	switch a.Kind {
	case store.ApprovalCommand:
		var req queueRequest
		if err := json.Unmarshal(a.Request, &req); err != nil {
			return fail(nil, err)
		}
		payload, err := payloadFor(req)
		if err != nil {
			return fail(nil, err)
		}
		ids := make([]uuid.UUID, 0, len(req.DeviceIDs))
		for _, raw := range req.DeviceIDs {
			id, err := uuid.Parse(raw)
			if err != nil {
				return fail(nil, err)
			}
			ids = append(ids, id)
		}
		out, err := h.queueCommands(ctx, req, payload, ids, a.RequestedBy)
		if err != nil {
			return fail(map[string]any{"commands": out}, err)
		}
		return map[string]any{"commands": out}, false
	case store.ApprovalAssignment:
		var req assignmentRequest
		if err := json.Unmarshal(a.Request, &req); err != nil {
			return fail(nil, err)
		}
		as, rerr := parseAssignment(req, a.RequestedBy, h.Now())
		if rerr != nil {
			return fail(nil, errors.New(rerr.message))
		}
		out, err := h.saveAssignment(ctx, as)
		if errors.Is(err, store.ErrNotFound) {
			err = errors.New("the group no longer exists")
		}
		if err != nil {
			return fail(nil, err)
		}
		return map[string]any{"assignment": out}, false
	case store.ApprovalVersion:
		var req versionApproval
		if err := json.Unmarshal(a.Request, &req); err != nil {
			return fail(nil, err)
		}
		out, err := h.replayVersion(ctx, a, req)
		if err != nil {
			return fail(nil, err)
		}
		return out, false
	case store.ApprovalGroupMember:
		var req groupMemberApproval
		if err := json.Unmarshal(a.Request, &req); err != nil {
			return fail(nil, err)
		}
		out, err := h.replayGroupMember(ctx, a, req)
		if err != nil {
			return fail(nil, err)
		}
		return out, false
	case store.ApprovalGroupRule:
		var req groupRuleApproval
		if err := json.Unmarshal(a.Request, &req); err != nil {
			return fail(nil, err)
		}
		out, err := h.replayGroupRule(ctx, a, req)
		if err != nil {
			return fail(nil, err)
		}
		return out, false
	case store.ApprovalServerUpdate:
		var req serverUpdateRequest
		if err := json.Unmarshal(a.Request, &req); err != nil {
			return fail(nil, err)
		}
		st, err := h.startServerUpdate(ctx, req.Version, a.RequestedBy)
		if err != nil {
			return fail(map[string]any{"version": req.Version}, err)
		}
		return map[string]any{"version": req.Version, "state": st}, false
	default:
		return fail(nil, errors.New("unknown approval kind "+a.Kind))
	}
}
