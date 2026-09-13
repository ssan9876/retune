package adminapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/apps"
	"retune/internal/server/store"
)

type appJSON struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	CurrentVersion int       `json:"current_version"`
	PackageID      string    `json:"package_id,omitempty"`
	PinnedVersion  string    `json:"pinned_version,omitempty"`
	Scope          string    `json:"scope,omitempty"`
	InstallArgs    string    `json:"install_args,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	CreatedBy      string    `json:"created_by"`
}

func newAppJSON(a store.App) appJSON {
	return appJSON{
		ID: a.ID.String(), Name: a.Name, Description: a.Description,
		CurrentVersion: a.CurrentVersion, CreatedAt: a.CreatedAt,
		UpdatedAt: a.UpdatedAt, CreatedBy: a.CreatedBy,
	}
}

type appRequest struct {
	Name          string `json:"name"`
	Description   string `json:"description"`
	PackageID     string `json:"package_id"`
	PinnedVersion string `json:"pinned_version"`
	Scope         string `json:"scope"`
	InstallArgs   string `json:"install_args"`
}

func (h *Handler) writeAppError(w http.ResponseWriter, what string, err error) {
	switch {
	case errors.Is(err, apps.ErrNotFound), errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such app")
	case errors.Is(err, apps.ErrNameTaken):
		writeError(w, http.StatusConflict, "name_taken", err.Error())
	case errors.Is(err, apps.ErrBadRequest):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	default:
		h.internal(w, what, err)
	}
}

// listApps includes each app's package id, since it identifies an app at a
// glance in a way its name may not.
func (h *Handler) listApps(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	page := pageFrom(r)
	rows, total, err := h.Apps.List(ctx, page)
	if err != nil {
		h.internal(w, "list apps", err)
		return
	}
	items := make([]appJSON, 0, len(rows))
	for _, a := range rows {
		out := newAppJSON(a)
		if v, err := h.Apps.Version(ctx, a.ID, a.CurrentVersion); err == nil {
			out.PackageID, out.PinnedVersion = v.PackageID, v.PinnedVersion
			out.Scope, out.InstallArgs = v.Scope, v.InstallArgs
		}
		items = append(items, out)
	}
	writeJSON(w, http.StatusOK, newListResponse(items, total, page))
}

func (h *Handler) createApp(w http.ResponseWriter, r *http.Request) {
	var req appRequest
	if !decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	a, err := h.Apps.Create(ctx, apps.NewApp{
		Name: req.Name, Description: req.Description, PackageID: req.PackageID,
		PinnedVersion: req.PinnedVersion, Scope: req.Scope, InstallArgs: req.InstallArgs,
		Actor: caller(r).Admin.Email,
	})
	if err != nil {
		h.writeAppError(w, "create app", err)
		return
	}
	out := newAppJSON(a)
	// Scope defaults to "machine" inside the service, so the response reflects
	// what was actually stored rather than the possibly-empty request field.
	if v, err := h.Apps.Version(ctx, a.ID, a.CurrentVersion); err == nil {
		out.PackageID, out.PinnedVersion = v.PackageID, v.PinnedVersion
		out.Scope, out.InstallArgs = v.Scope, v.InstallArgs
	}
	writeJSON(w, http.StatusCreated, out)
}

// getApp returns the app with the definition of its current version, which is
// what the editor opens.
func (h *Handler) getApp(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such app")
	if !ok {
		return
	}
	ctx := r.Context()
	a, err := h.Apps.Get(ctx, id)
	if err != nil {
		h.writeAppError(w, "get app", err)
		return
	}
	out := newAppJSON(a)
	if v, err := h.Apps.Version(ctx, id, a.CurrentVersion); err == nil {
		out.PackageID, out.PinnedVersion = v.PackageID, v.PinnedVersion
		out.Scope, out.InstallArgs = v.Scope, v.InstallArgs
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) updateApp(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such app")
	if !ok {
		return
	}
	var req appRequest
	if !decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	a, err := h.Apps.Update(ctx, id, apps.NewApp{
		Name: req.Name, Description: req.Description, PackageID: req.PackageID,
		PinnedVersion: req.PinnedVersion, Scope: req.Scope, InstallArgs: req.InstallArgs,
		Actor: caller(r).Admin.Email,
	})
	if err != nil {
		h.writeAppError(w, "update app", err)
		return
	}
	out := newAppJSON(a)
	if v, err := h.Apps.Version(ctx, id, a.CurrentVersion); err == nil {
		out.PackageID, out.PinnedVersion = v.PackageID, v.PinnedVersion
		out.Scope, out.InstallArgs = v.Scope, v.InstallArgs
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) deleteApp(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such app")
	if !ok {
		return
	}
	if err := h.Apps.Delete(r.Context(), id, caller(r).Admin.Email); err != nil {
		h.writeAppError(w, "delete app", err)
		return
	}
	writeNoContent(w)
}

type appVersionJSON struct {
	Version       int       `json:"version"`
	PackageID     string    `json:"package_id"`
	PinnedVersion string    `json:"pinned_version"`
	Scope         string    `json:"scope"`
	InstallArgs   string    `json:"install_args"`
	Hash          string    `json:"hash"`
	CreatedAt     time.Time `json:"created_at"`
	CreatedBy     string    `json:"created_by"`
}

func (h *Handler) listAppVersions(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such app")
	if !ok {
		return
	}
	rows, err := h.Apps.ListVersions(r.Context(), id)
	if err != nil {
		h.writeAppError(w, "list app versions", err)
		return
	}
	items := make([]appVersionJSON, 0, len(rows))
	for _, v := range rows {
		items = append(items, appVersionJSON{
			Version: v.Version, PackageID: v.PackageID, PinnedVersion: v.PinnedVersion,
			Scope: v.Scope, InstallArgs: v.InstallArgs, Hash: v.Hash,
			CreatedAt: v.CreatedAt, CreatedBy: v.CreatedBy,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

type appInstallJSON struct {
	ID               string    `json:"id"`
	DeviceID         string    `json:"device_id"`
	Hostname         string    `json:"hostname"`
	Version          int       `json:"version"`
	Intent           string    `json:"intent"`
	Status           string    `json:"status"`
	InstalledVersion string    `json:"installed_version"`
	ExitCode         int       `json:"exit_code"`
	Stdout           string    `json:"stdout"`
	Stderr           string    `json:"stderr"`
	StdoutTruncated  bool      `json:"stdout_truncated"`
	StderrTruncated  bool      `json:"stderr_truncated"`
	Error            string    `json:"error"`
	Detail           string    `json:"detail"`
	StartedAt        time.Time `json:"started_at"`
	FinishedAt       time.Time `json:"finished_at"`
}

func (h *Handler) listAppInstalls(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such app")
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
	rows, total, err := h.Store.Q().ListAppInstalls(r.Context(), id, deviceID, page)
	if err != nil {
		h.internal(w, "list app installs", err)
		return
	}
	items := make([]appInstallJSON, 0, len(rows))
	for _, in := range rows {
		items = append(items, appInstallJSON{
			ID: in.ID.String(), DeviceID: in.DeviceID.String(), Hostname: in.Hostname,
			Version: in.Version, Intent: in.Intent, Status: in.Status, InstalledVersion: in.InstalledVersion,
			ExitCode: in.ExitCode, Stdout: in.Stdout, Stderr: in.Stderr,
			StdoutTruncated: in.StdoutTruncated, StderrTruncated: in.StderrTruncated,
			Error: in.Error, Detail: in.Detail, StartedAt: in.StartedAt, FinishedAt: in.FinishedAt,
		})
	}
	writeJSON(w, http.StatusOK, newListResponse(items, total, page))
}
