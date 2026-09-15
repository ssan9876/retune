package adminapi

import (
	"errors"
	"net/http"
	"time"

	"retune/internal/server/agentversions"
	"retune/internal/server/store"
)

// SignatureHeader carries the build's release signature: the base64 of its
// .sig sidecar. The body is the binary itself, so the signature cannot travel
// in it, and a query parameter is the wrong place for a hundred bytes of
// base64 that must survive untouched. It is agentversions.SignatureHeader
// re-exported: the service needs the header's name in its own audited
// rejection messages, so it owns the constant, and this handler and its
// tests refer to it under the name they already use.
const SignatureHeader = agentversions.SignatureHeader

type agentVersionJSON struct {
	ID        string    `json:"id"`
	Version   string    `json:"version"`
	SHA256    string    `json:"sha256"`
	SizeBytes int64     `json:"size_bytes"`
	KeyID     string    `json:"key_id"`
	Signature string    `json:"signature"`
	Notes     string    `json:"notes"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
}

func newAgentVersionJSON(v store.AgentVersion) agentVersionJSON {
	return agentVersionJSON{
		ID: v.ID.String(), Version: v.Version, SHA256: v.SHA256, SizeBytes: v.SizeBytes,
		KeyID: v.KeyID, Signature: v.Signature, Notes: v.Notes, CreatedAt: v.CreatedAt, CreatedBy: v.CreatedBy,
	}
}

func (h *Handler) writeAgentVersionError(w http.ResponseWriter, what string, err error) {
	switch {
	case errors.Is(err, agentversions.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such agent version")
	case errors.Is(err, agentversions.ErrVersionTaken):
		writeError(w, http.StatusConflict, "version_taken", err.Error())
	case errors.Is(err, agentversions.ErrNoReleaseKeys):
		writeError(w, http.StatusServiceUnavailable, "release_keys_unset",
			"set AGENT_RELEASE_KEYS to the public keys that sign agent builds")
	case errors.Is(err, agentversions.ErrBadRequest):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	default:
		h.internal(w, what, err)
	}
}

// listAgentVersions returns one page of uploaded builds, newest first.
func (h *Handler) listAgentVersions(w http.ResponseWriter, r *http.Request) {
	page := pageFrom(r)
	rows, total, err := h.AgentVersions.List(r.Context(), page)
	if err != nil {
		h.internal(w, "list agent versions", err)
		return
	}
	items := make([]agentVersionJSON, 0, len(rows))
	for _, v := range rows {
		items = append(items, newAgentVersionJSON(v))
	}
	writeJSON(w, http.StatusOK, newListResponse(items, total, page))
}

func (h *Handler) getAgentVersion(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such agent version")
	if !ok {
		return
	}
	v, err := h.AgentVersions.Get(r.Context(), id)
	if err != nil {
		h.writeAgentVersionError(w, "get agent version", err)
		return
	}
	writeJSON(w, http.StatusOK, newAgentVersionJSON(v))
}

// uploadAgentVersion takes the build as a raw body rather than JSON. Base64 in
// a JSON object would inflate a multi-megabyte binary by a third and force the
// whole thing into memory; the version and notes travel as query parameters
// instead.
func (h *Handler) uploadAgentVersion(w http.ResponseWriter, r *http.Request) {
	v, err := h.AgentVersions.Upload(r.Context(), agentversions.NewVersion{
		Version:         r.URL.Query().Get("version"),
		Notes:           r.URL.Query().Get("notes"),
		Actor:           caller(r).Admin.Email,
		SignatureHeader: r.Header.Get(SignatureHeader),
	}, http.MaxBytesReader(w, r.Body, agentversions.MaxUploadBytes))
	if err != nil {
		h.writeAgentVersionError(w, "upload agent version", err)
		return
	}
	writeJSON(w, http.StatusCreated, newAgentVersionJSON(v))
}

func (h *Handler) deleteAgentVersion(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such agent version")
	if !ok {
		return
	}
	if err := h.AgentVersions.Delete(r.Context(), id, caller(r).Admin.Email); err != nil {
		h.writeAgentVersionError(w, "delete agent version", err)
		return
	}
	writeNoContent(w)
}
