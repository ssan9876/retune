package adminapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/releasefeed"
	"retune/internal/server/store"
)

// releaseFeedJSON says where the server looks for releases and how the last
// look went.
type releaseFeedJSON struct {
	Enabled       bool       `json:"enabled"`
	URL           string     `json:"url"`
	IntervalHours int        `json:"interval_hours"`
	Prereleases   bool       `json:"prereleases"`
	CheckedAt     *time.Time `json:"checked_at,omitempty"`
	Error         string     `json:"error,omitempty"`
}

type releaseJSON struct {
	Version     string    `json:"version"`
	Prerelease  bool      `json:"prerelease"`
	PublishedAt time.Time `json:"published_at"`
	Notes       string    `json:"notes"`
	KeyID       string    `json:"key_id"`
	VerifiedAt  time.Time `json:"verified_at"`
	// AgentVersionID is the agent build imported from it, once imported.
	AgentVersionID string `json:"agent_version_id,omitempty"`
	ImportError    string `json:"import_error,omitempty"`
}

type releasesResponse struct {
	Feed  releaseFeedJSON `json:"feed"`
	Items []releaseJSON   `json:"items"`
}

func (h *Handler) releasesResponse(ctx context.Context) (releasesResponse, error) {
	q := h.Store.Q()
	state, err := q.GetReleaseFeedState(ctx)
	if err != nil {
		return releasesResponse{}, err
	}
	rels, err := q.ListReleases(ctx)
	if err != nil {
		return releasesResponse{}, err
	}
	out := releasesResponse{
		Feed: releaseFeedJSON{
			Enabled: h.ReleaseFeedConfig.Enabled, URL: h.ReleaseFeedConfig.URL,
			IntervalHours: int(h.ReleaseFeedConfig.Interval / time.Hour), Prereleases: h.ReleaseFeedConfig.Prereleases,
			CheckedAt: state.CheckedAt, Error: state.Error,
		},
		Items: make([]releaseJSON, 0, len(rels)),
	}
	for _, r := range rels {
		j := releaseJSON{
			Version: r.Version, Prerelease: r.Prerelease, PublishedAt: r.PublishedAt, Notes: r.Notes,
			KeyID: r.KeyID, VerifiedAt: r.VerifiedAt, ImportError: r.ImportError,
		}
		if r.AgentVersionID != nil {
			j.AgentVersionID = r.AgentVersionID.String()
		}
		out.Items = append(out.Items, j)
	}
	return out, nil
}

// listReleases returns the releases the feed has verified, newest first.
func (h *Handler) listReleases(w http.ResponseWriter, r *http.Request) {
	out, err := h.releasesResponse(r.Context())
	if err != nil {
		h.internal(w, "list releases", err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// checkReleases looks for a new release now. A failed check is not an error
// response: it is recorded, and the response shows it the way the console
// shows any other.
func (h *Handler) checkReleases(w http.ResponseWriter, r *http.Request) {
	if !h.ReleaseFeedConfig.Enabled || h.ReleaseFeed == nil {
		writeError(w, http.StatusConflict, "feed_disabled",
			"this server does not look for releases (RELEASE_FEED_ENABLED=false)")
		return
	}
	ctx := r.Context()
	err := h.ReleaseFeed.CheckNow(ctx)
	if errors.Is(err, releasefeed.ErrBusy) {
		writeError(w, http.StatusConflict, "busy", err.Error())
		return
	}
	if err := h.Store.Q().InsertAudit(ctx, store.AuditEntry{
		Actor: caller(r).Admin.Email, Action: "release.checked", TargetKind: "release",
		Details: map[string]any{"ok": err == nil},
	}); err != nil {
		h.internal(w, "audit release check", err)
		return
	}
	out, err := h.releasesResponse(ctx)
	if err != nil {
		h.internal(w, "list releases", err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type rolloutPolicyJSON struct {
	Enabled        bool       `json:"enabled"`
	PilotGroupID   string     `json:"pilot_group_id,omitempty"`
	PilotGroupName string     `json:"pilot_group_name,omitempty"`
	DelayHours     int        `json:"delay_hours"`
	UpdatedAt      *time.Time `json:"updated_at,omitempty"`
	UpdatedBy      string     `json:"updated_by,omitempty"`
}

type agentRolloutJSON struct {
	ID             string     `json:"id"`
	AgentVersionID string     `json:"agent_version_id"`
	Version        string     `json:"version"`
	State          string     `json:"state"`
	PilotGroupID   string     `json:"pilot_group_id,omitempty"`
	PilotGroupName string     `json:"pilot_group_name,omitempty"`
	DelayHours     int        `json:"delay_hours"`
	PilotStartedAt *time.Time `json:"pilot_started_at,omitempty"`
	// PromoteAfter is when the pilot's delay is over.
	PromoteAfter *time.Time `json:"promote_after,omitempty"`
	PromotedAt   *time.Time `json:"promoted_at,omitempty"`
	// ApprovalID is the approval the rollout is waiting on, if any.
	ApprovalID string    `json:"approval_id,omitempty"`
	Detail     string    `json:"detail"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type agentRolloutResponse struct {
	Policy   rolloutPolicyJSON  `json:"policy"`
	Rollouts []agentRolloutJSON `json:"rollouts"`
}

func (h *Handler) agentRolloutResponse(ctx context.Context) (agentRolloutResponse, error) {
	q := h.Store.Q()
	p, err := q.GetAgentRolloutPolicy(ctx)
	if err != nil {
		return agentRolloutResponse{}, err
	}
	names := map[uuid.UUID]string{}
	groupName := func(id *uuid.UUID) (string, string) {
		if id == nil {
			return "", ""
		}
		if _, ok := names[*id]; !ok {
			if g, err := q.GetGroup(ctx, store.DefaultTenantID, *id); err == nil {
				names[*id] = g.Name
			} else {
				names[*id] = ""
			}
		}
		return id.String(), names[*id]
	}
	out := agentRolloutResponse{Policy: rolloutPolicyJSON{Enabled: p.Enabled, DelayHours: p.DelayHours, UpdatedBy: p.UpdatedBy}}
	out.Policy.PilotGroupID, out.Policy.PilotGroupName = groupName(p.PilotGroupID)
	if !p.UpdatedAt.IsZero() {
		out.Policy.UpdatedAt = &p.UpdatedAt
	}
	rows, err := q.ListAgentRollouts(ctx, 20)
	if err != nil {
		return agentRolloutResponse{}, err
	}
	out.Rollouts = make([]agentRolloutJSON, 0, len(rows))
	for _, ro := range rows {
		j := agentRolloutJSON{
			ID: ro.ID.String(), AgentVersionID: ro.AgentVersionID.String(), Version: ro.Version, State: ro.State,
			DelayHours: ro.DelayHours, PilotStartedAt: ro.PilotStartedAt, PromotedAt: ro.PromotedAt,
			Detail: ro.Detail, CreatedAt: ro.CreatedAt, UpdatedAt: ro.UpdatedAt,
		}
		j.PilotGroupID, j.PilotGroupName = groupName(ro.PilotGroupID)
		if ro.PilotStartedAt != nil && ro.State == store.RolloutPilot {
			after := ro.PilotStartedAt.Add(time.Duration(ro.DelayHours) * time.Hour)
			j.PromoteAfter = &after
		}
		switch {
		case ro.State == store.RolloutPromoting && ro.FleetApprovalID != nil:
			j.ApprovalID = ro.FleetApprovalID.String()
		case ro.State == store.RolloutPilot && ro.PilotApprovalID != nil && ro.PilotAssignmentID == nil:
			j.ApprovalID = ro.PilotApprovalID.String()
		}
		out.Rollouts = append(out.Rollouts, j)
	}
	return out, nil
}

// getAgentRollout returns the automatic rollout policy and recent rollouts.
func (h *Handler) getAgentRollout(w http.ResponseWriter, r *http.Request) {
	out, err := h.agentRolloutResponse(r.Context())
	if err != nil {
		h.internal(w, "get agent rollout", err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type rolloutPolicyRequest struct {
	Enabled      bool   `json:"enabled"`
	PilotGroupID string `json:"pilot_group_id"`
	DelayHours   int    `json:"delay_hours"`
}

// setAgentRolloutPolicy turns automatic rollout on or off. On needs a pilot
// group: the whole point is that a build reaches a few machines first.
func (h *Handler) setAgentRolloutPolicy(w http.ResponseWriter, r *http.Request) {
	var req rolloutPolicyRequest
	if !decode(w, r, &req) {
		return
	}
	if req.DelayHours == 0 {
		req.DelayHours = store.DefaultRolloutDelayHours
	}
	if req.DelayHours < 1 || req.DelayHours > 720 {
		writeError(w, http.StatusBadRequest, "bad_request", "delay_hours must be between 1 and 720")
		return
	}
	ctx := r.Context()
	p := store.AgentRolloutPolicy{
		Enabled: req.Enabled, DelayHours: req.DelayHours, UpdatedAt: h.Now(), UpdatedBy: caller(r).Admin.Email,
	}
	if req.PilotGroupID != "" {
		id, err := uuid.Parse(req.PilotGroupID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "pilot_group_id must be a UUID")
			return
		}
		if id == store.BuiltinGroupID {
			writeError(w, http.StatusBadRequest, "bad_request", "the pilot group must be a smaller group than All devices")
			return
		}
		if _, err := h.Store.Q().GetGroup(ctx, store.DefaultTenantID, id); errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusBadRequest, "bad_request", "no such group")
			return
		} else if err != nil {
			h.internal(w, "get group", err)
			return
		}
		p.PilotGroupID = &id
	}
	if p.Enabled && p.PilotGroupID == nil {
		writeError(w, http.StatusBadRequest, "bad_request", "automatic rollout needs a pilot group")
		return
	}
	details := map[string]any{"enabled": p.Enabled, "delay_hours": p.DelayHours, "pilot_group_id": req.PilotGroupID}
	err := h.Store.InTx(ctx, func(q *store.Queries) error {
		if err := q.SetAgentRolloutPolicy(ctx, p); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: caller(r).Admin.Email, Action: "agent_rollout.policy_changed", TargetKind: "agent_rollout_policy",
			Details: details,
		})
	})
	if err != nil {
		h.internal(w, "set agent rollout policy", err)
		return
	}
	h.getAgentRollout(w, r)
}

// resumeAgentRollout restarts a halted rollout.
func (h *Handler) resumeAgentRollout(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such rollout")
	if !ok {
		return
	}
	err := h.AgentRollout.Resume(r.Context(), id, caller(r).Admin.Email)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such rollout")
		return
	case errors.Is(err, releasefeed.ErrNotHalted):
		writeError(w, http.StatusConflict, "not_halted", err.Error())
		return
	case err != nil:
		h.internal(w, "resume agent rollout", err)
		return
	}
	h.getAgentRollout(w, r)
}
