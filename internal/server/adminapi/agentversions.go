package adminapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

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
	ID      string `json:"id"`
	Version string `json:"version"`
	// SHA256, SizeBytes, KeyID and Signature describe the version's first
	// build, as they did when a version had only one. Builds lists them all.
	SHA256    string           `json:"sha256"`
	SizeBytes int64            `json:"size_bytes"`
	KeyID     string           `json:"key_id"`
	Signature string           `json:"signature"`
	Notes     string           `json:"notes"`
	CreatedAt time.Time        `json:"created_at"`
	CreatedBy string           `json:"created_by"`
	Builds    []agentBuildJSON `json:"builds"`
}

// agentBuildJSON is one platform's build of a version.
type agentBuildJSON struct {
	Platform  string    `json:"platform"`
	SHA256    string    `json:"sha256"`
	SizeBytes int64     `json:"size_bytes"`
	KeyID     string    `json:"key_id"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
}

func newAgentVersionJSON(v store.AgentVersion, builds []store.AgentVersionBuild) agentVersionJSON {
	out := agentVersionJSON{
		ID: v.ID.String(), Version: v.Version, SHA256: v.SHA256, SizeBytes: v.SizeBytes,
		KeyID: v.KeyID, Signature: v.Signature, Notes: v.Notes, CreatedAt: v.CreatedAt, CreatedBy: v.CreatedBy,
		Builds: make([]agentBuildJSON, 0, len(builds)),
	}
	for _, b := range builds {
		out.Builds = append(out.Builds, agentBuildJSON{
			Platform: b.Platform, SHA256: b.SHA256, SizeBytes: b.SizeBytes, KeyID: b.KeyID,
			CreatedAt: b.CreatedAt, CreatedBy: b.CreatedBy,
		})
	}
	return out
}

// agentVersionsJSON renders versions with their builds, fetched in one query.
func (h *Handler) agentVersionsJSON(ctx context.Context, rows []store.AgentVersion) ([]agentVersionJSON, error) {
	ids := make([]uuid.UUID, 0, len(rows))
	for _, v := range rows {
		ids = append(ids, v.ID)
	}
	builds, err := h.AgentVersions.Builds(ctx, ids)
	if err != nil {
		return nil, err
	}
	out := make([]agentVersionJSON, 0, len(rows))
	for _, v := range rows {
		out = append(out, newAgentVersionJSON(v, builds[v.ID]))
	}
	return out, nil
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
	items, err := h.agentVersionsJSON(r.Context(), rows)
	if err != nil {
		h.internal(w, "list agent builds", err)
		return
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
	h.writeAgentVersion(w, r, http.StatusOK, v)
}

// writeAgentVersion answers with one version and all of its builds.
func (h *Handler) writeAgentVersion(w http.ResponseWriter, r *http.Request, status int, v store.AgentVersion) {
	items, err := h.agentVersionsJSON(r.Context(), []store.AgentVersion{v})
	if err != nil {
		h.internal(w, "read agent builds", err)
		return
	}
	writeJSON(w, status, items[0])
}

// uploadAgentVersion takes the build as a raw body rather than JSON. Base64 in
// a JSON object would inflate a multi-megabyte binary by a third and force the
// whole thing into memory; the version, platform and notes travel as query
// parameters instead. A build for a platform the version does not have yet
// joins it.
func (h *Handler) uploadAgentVersion(w http.ResponseWriter, r *http.Request) {
	v, err := h.AgentVersions.Upload(r.Context(), agentversions.NewVersion{
		Version:         r.URL.Query().Get("version"),
		Platform:        r.URL.Query().Get("platform"),
		Notes:           r.URL.Query().Get("notes"),
		Actor:           caller(r).Admin.Email,
		SignatureHeader: r.Header.Get(SignatureHeader),
	}, http.MaxBytesReader(w, r.Body, agentversions.MaxUploadBytes))
	if err != nil {
		h.writeAgentVersionError(w, "upload agent version", err)
		return
	}
	h.writeAgentVersion(w, r, http.StatusCreated, v)
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
