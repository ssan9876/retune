package adminapi

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"retune/internal/protocol"
	"retune/internal/server/remote"
	"retune/internal/server/store"
)

type remoteSessionJSON struct {
	ID        string     `json:"id"`
	DeviceID  string     `json:"device_id"`
	StartedBy string     `json:"started_by"`
	Reason    string     `json:"reason"`
	Status    string     `json:"status"`
	CreatedAt time.Time  `json:"created_at"`
	StartedAt *time.Time `json:"started_at,omitempty"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
	EndReason string     `json:"end_reason,omitempty"`
}

func newRemoteSessionJSON(r store.RemoteSession) remoteSessionJSON {
	return remoteSessionJSON{
		ID: r.ID.String(), DeviceID: r.DeviceID.String(), StartedBy: r.StartedBy, Reason: r.Reason,
		Status: r.Status, CreatedAt: r.CreatedAt, StartedAt: r.StartedAt, EndedAt: r.EndedAt, EndReason: r.EndReason,
	}
}

type remoteStartRequest struct {
	Reason string `json:"reason"`
}

type remoteInputRequest struct {
	Data string `json:"data"`
}

// remoteTranscript is a session and its chunks after a point.
type remoteTranscript struct {
	Session remoteSessionJSON      `json:"session"`
	Chunks  []protocol.RemoteChunk `json:"chunks"`
}

func (h *Handler) writeRemoteError(w http.ResponseWriter, what string, err error) {
	switch {
	case errors.Is(err, remote.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such remote session")
	case errors.Is(err, remote.ErrEnded):
		writeError(w, http.StatusConflict, "ended", err.Error())
	case errors.Is(err, remote.ErrDeviceNotActive):
		writeError(w, http.StatusConflict, "device_not_active", err.Error())
	case errors.Is(err, remote.ErrBadRequest):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	case errors.Is(err, remote.ErrNotYours):
		writeError(w, http.StatusForbidden, "not_session_owner", err.Error())
	default:
		h.internal(w, what, err)
	}
}

// startRemoteSession opens a remote shell on a device. It is an
// administrator's, signed in, with a reason: whatever is typed runs as SYSTEM.
func (h *Handler) startRemoteSession(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := pathUUID(w, r, "no such device")
	if !ok || !h.deviceVisible(w, r, deviceID) {
		return
	}
	var req remoteStartRequest
	if !decode(w, r, &req) {
		return
	}
	s, err := h.Remote.Start(r.Context(), deviceID, caller(r).Admin.Email, req.Reason)
	if err != nil {
		h.writeRemoteError(w, "start remote session", err)
		return
	}
	writeJSON(w, http.StatusCreated, newRemoteSessionJSON(s))
}

func (h *Handler) listRemoteSessions(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := pathUUID(w, r, "no such device")
	if !ok || !h.deviceVisible(w, r, deviceID) {
		return
	}
	page := pageFrom(r)
	rows, total, err := h.Store.Q().ListRemoteSessions(r.Context(), deviceID, page)
	if err != nil {
		h.internal(w, "list remote sessions", err)
		return
	}
	items := make([]remoteSessionJSON, 0, len(rows))
	for _, s := range rows {
		items = append(items, newRemoteSessionJSON(s))
	}
	writeJSON(w, http.StatusOK, newListResponse(items, total, page))
}

// remoteSessionFromPath loads a session the caller may see.
func (h *Handler) remoteSessionFromPath(w http.ResponseWriter, r *http.Request) (store.RemoteSession, bool) {
	id, ok := pathUUID(w, r, "no such remote session")
	if !ok {
		return store.RemoteSession{}, false
	}
	s, err := h.Remote.Get(r.Context(), id)
	if err != nil {
		h.writeRemoteError(w, "get remote session", err)
		return s, false
	}
	// A session on a device out of the caller's scope is, to them, none.
	if visible, err := h.Store.Q().DeviceInScope(r.Context(), store.DefaultTenantID, s.DeviceID, caller(r).Scope); err != nil {
		h.internal(w, "check device scope", err)
		return s, false
	} else if !visible {
		writeError(w, http.StatusNotFound, "not_found", "no such remote session")
		return s, false
	}
	return s, true
}

// getRemoteSession returns a session and its transcript after ?after=, and
// with ?wait=1 holds the request until there is more or it ends.
func (h *Handler) getRemoteSession(w http.ResponseWriter, r *http.Request) {
	s, ok := h.remoteSessionFromPath(w, r)
	if !ok {
		return
	}
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	var wait time.Duration
	if r.URL.Query().Get("wait") == "1" {
		wait = protocol.RemotePollSeconds * time.Second
	}
	s, chunks, err := h.Remote.Poll(r.Context(), s.ID, after, nil, wait)
	if err != nil {
		h.writeRemoteError(w, "poll remote session", err)
		return
	}
	writeJSON(w, http.StatusOK, remoteTranscript{Session: newRemoteSessionJSON(s), Chunks: chunks})
}

func (h *Handler) remoteSessionInput(w http.ResponseWriter, r *http.Request) {
	s, ok := h.remoteSessionFromPath(w, r)
	if !ok {
		return
	}
	var req remoteInputRequest
	if !decode(w, r, &req) {
		return
	}
	if err := h.Remote.Input(r.Context(), s.ID, caller(r).Admin.Email, req.Data); err != nil {
		h.writeRemoteError(w, "remote session input", err)
		return
	}
	writeNoContent(w)
}

func (h *Handler) endRemoteSession(w http.ResponseWriter, r *http.Request) {
	s, ok := h.remoteSessionFromPath(w, r)
	if !ok {
		return
	}
	if err := h.Remote.End(r.Context(), s.ID, caller(r).Admin.Email); err != nil {
		h.writeRemoteError(w, "end remote session", err)
		return
	}
	writeNoContent(w)
}
