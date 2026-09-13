package adminapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/scripts"
	"retune/internal/server/store"
)

type scriptJSON struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	CurrentVersion int       `json:"current_version"`
	Body           string    `json:"body,omitempty"`
	DetectionBody  string    `json:"detection_body,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	CreatedBy      string    `json:"created_by"`
}

func newScriptJSON(s store.Script) scriptJSON {
	return scriptJSON{
		ID: s.ID.String(), Name: s.Name, Description: s.Description,
		CurrentVersion: s.CurrentVersion, CreatedAt: s.CreatedAt,
		UpdatedAt: s.UpdatedAt, CreatedBy: s.CreatedBy,
	}
}

type scriptRequest struct {
	Name          string `json:"name"`
	Description   string `json:"description"`
	Body          string `json:"body"`
	DetectionBody string `json:"detection_body"`
}

func (h *Handler) writeScriptError(w http.ResponseWriter, what string, err error) {
	switch {
	case errors.Is(err, scripts.ErrNotFound), errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such script")
	case errors.Is(err, scripts.ErrNameTaken):
		writeError(w, http.StatusConflict, "name_taken", err.Error())
	case errors.Is(err, scripts.ErrBadRequest), errors.Is(err, scripts.ErrBadOptions):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	default:
		h.internal(w, what, err)
	}
}

func (h *Handler) listScripts(w http.ResponseWriter, r *http.Request) {
	page := pageFrom(r)
	rows, total, err := h.Scripts.List(r.Context(), page)
	if err != nil {
		h.internal(w, "list scripts", err)
		return
	}
	items := make([]scriptJSON, 0, len(rows))
	for _, s := range rows {
		items = append(items, newScriptJSON(s))
	}
	writeJSON(w, http.StatusOK, newListResponse(items, total, page))
}

func (h *Handler) createScript(w http.ResponseWriter, r *http.Request) {
	var req scriptRequest
	if !decode(w, r, &req) {
		return
	}
	s, err := h.Scripts.Create(r.Context(), scripts.NewScript{
		Name: req.Name, Description: req.Description, Body: req.Body,
		DetectionBody: req.DetectionBody, Actor: caller(r).Admin.Email,
	})
	if err != nil {
		h.writeScriptError(w, "create script", err)
		return
	}
	out := newScriptJSON(s)
	out.Body, out.DetectionBody = req.Body, req.DetectionBody
	writeJSON(w, http.StatusCreated, out)
}

// getScript returns the script with the body of its current version, which is
// what the editor opens.
func (h *Handler) getScript(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such script")
	if !ok {
		return
	}
	ctx := r.Context()
	s, err := h.Scripts.Get(ctx, id)
	if err != nil {
		h.writeScriptError(w, "get script", err)
		return
	}
	out := newScriptJSON(s)
	if v, err := h.Scripts.Version(ctx, id, s.CurrentVersion); err == nil {
		out.Body, out.DetectionBody = v.Body, v.DetectionBody
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) updateScript(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such script")
	if !ok {
		return
	}
	var req scriptRequest
	if !decode(w, r, &req) {
		return
	}
	s, err := h.Scripts.Update(r.Context(), id, scripts.NewScript{
		Name: req.Name, Description: req.Description, Body: req.Body,
		DetectionBody: req.DetectionBody, Actor: caller(r).Admin.Email,
	})
	if err != nil {
		h.writeScriptError(w, "update script", err)
		return
	}
	out := newScriptJSON(s)
	out.Body, out.DetectionBody = req.Body, req.DetectionBody
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) deleteScript(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such script")
	if !ok {
		return
	}
	if err := h.Scripts.Delete(r.Context(), id, caller(r).Admin.Email); err != nil {
		h.writeScriptError(w, "delete script", err)
		return
	}
	writeNoContent(w)
}

type scriptVersionJSON struct {
	Version       int       `json:"version"`
	Body          string    `json:"body"`
	DetectionBody string    `json:"detection_body"`
	Hash          string    `json:"hash"`
	CreatedAt     time.Time `json:"created_at"`
	CreatedBy     string    `json:"created_by"`
}

func (h *Handler) listScriptVersions(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such script")
	if !ok {
		return
	}
	rows, err := h.Scripts.ListVersions(r.Context(), id)
	if err != nil {
		h.writeScriptError(w, "list script versions", err)
		return
	}
	items := make([]scriptVersionJSON, 0, len(rows))
	for _, v := range rows {
		items = append(items, scriptVersionJSON{
			Version: v.Version, Body: v.Body, DetectionBody: v.DetectionBody,
			Hash: v.Hash, CreatedAt: v.CreatedAt, CreatedBy: v.CreatedBy,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

type scriptRunJSON struct {
	ID              string    `json:"id"`
	DeviceID        string    `json:"device_id"`
	Hostname        string    `json:"hostname"`
	Version         int       `json:"version"`
	Status          string    `json:"status"`
	Phase           string    `json:"phase"`
	Remediated      bool      `json:"remediated"`
	ExitCode        int       `json:"exit_code"`
	Stdout          string    `json:"stdout"`
	Stderr          string    `json:"stderr"`
	StdoutTruncated bool      `json:"stdout_truncated"`
	StderrTruncated bool      `json:"stderr_truncated"`
	Error           string    `json:"error"`
	StartedAt       time.Time `json:"started_at"`
	FinishedAt      time.Time `json:"finished_at"`
}

func (h *Handler) listScriptRuns(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such script")
	if !ok {
		return
	}
	var deviceID *uuid.UUID
	if raw := r.URL.Query().Get("device_id"); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "device_id must be a UUID")
			return
		}
		deviceID = &parsed
	}
	page := pageFrom(r)
	rows, total, err := h.Store.Q().ListScriptRuns(r.Context(), id, deviceID, page)
	if err != nil {
		h.internal(w, "list script runs", err)
		return
	}
	items := make([]scriptRunJSON, 0, len(rows))
	for _, run := range rows {
		items = append(items, scriptRunJSON{
			ID: run.ID.String(), DeviceID: run.DeviceID.String(), Hostname: run.Hostname,
			Version: run.Version, Status: run.Status, Phase: run.Phase, Remediated: run.Remediated,
			ExitCode: run.ExitCode, Stdout: run.Stdout, Stderr: run.Stderr,
			StdoutTruncated: run.StdoutTruncated, StderrTruncated: run.StderrTruncated,
			Error: run.Error, StartedAt: run.StartedAt, FinishedAt: run.FinishedAt,
		})
	}
	writeJSON(w, http.StatusOK, newListResponse(items, total, page))
}
