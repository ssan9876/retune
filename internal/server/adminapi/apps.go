package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/apps"
	"retune/internal/server/store"
)

type appJSON struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Description    string `json:"description"`
	CurrentVersion int    `json:"current_version"`
	PackageID      string `json:"package_id,omitempty"`
	PinnedVersion  string `json:"pinned_version,omitempty"`
	Scope          string `json:"scope,omitempty"`
	InstallArgs    string `json:"install_args,omitempty"`
	packageJSON
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	CreatedBy string    `json:"created_by"`
}

// packageJSON is the uploaded-package half of an app version.
type packageJSON struct {
	Source            string                  `json:"source"`
	InstallerType     string                  `json:"installer_type,omitempty"`
	FileName          string                  `json:"file_name,omitempty"`
	FileSHA256        string                  `json:"file_sha256,omitempty"`
	FileSize          int64                   `json:"file_size,omitempty"`
	UninstallCommand  string                  `json:"uninstall_command,omitempty"`
	SuccessExitCodes  []int                   `json:"success_exit_codes,omitempty"`
	Detection         *protocol.DetectionRule `json:"detection,omitempty"`
	UninstallPrevious bool                    `json:"uninstall_previous,omitempty"`
}

func newPackageJSON(v store.AppVersion) packageJSON {
	out := packageJSON{
		Source: v.Source, InstallerType: v.InstallerType, FileName: v.FileName, FileSHA256: v.FileSHA256,
		FileSize: v.FileSize, UninstallCommand: v.UninstallCommand, UninstallPrevious: v.UninstallPrevious,
	}
	for _, c := range v.SuccessExitCodes {
		out.SuccessExitCodes = append(out.SuccessExitCodes, int(c))
	}
	if len(v.Detection) > 0 {
		var d protocol.DetectionRule
		if json.Unmarshal(v.Detection, &d) == nil {
			out.Detection = &d
		}
	}
	return out
}

// withVersion fills in the definition of the app's current version.
func (h *Handler) withVersion(ctx context.Context, out *appJSON, a store.App) {
	if v, err := h.Apps.Version(ctx, a.ID, a.CurrentVersion); err == nil {
		out.PackageID, out.PinnedVersion = v.PackageID, v.PinnedVersion
		out.Scope, out.InstallArgs = v.Scope, v.InstallArgs
		out.packageJSON = newPackageJSON(v)
	}
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

	Source            string                  `json:"source"`
	InstallerType     string                  `json:"installer_type"`
	FileSHA256        string                  `json:"file_sha256"`
	FileName          string                  `json:"file_name"`
	UninstallCommand  string                  `json:"uninstall_command"`
	SuccessExitCodes  []int                   `json:"success_exit_codes"`
	Detection         *protocol.DetectionRule `json:"detection"`
	UninstallPrevious bool                    `json:"uninstall_previous"`
}

func (req appRequest) newApp(actor string) apps.NewApp {
	return apps.NewApp{
		Name: req.Name, Description: req.Description, PackageID: req.PackageID,
		PinnedVersion: req.PinnedVersion, Scope: req.Scope, InstallArgs: req.InstallArgs, Actor: actor,
		Source: req.Source, InstallerType: req.InstallerType, FileSHA256: req.FileSHA256, FileName: req.FileName,
		UninstallCommand: req.UninstallCommand, SuccessExitCodes: req.SuccessExitCodes,
		Detection: req.Detection, UninstallPrevious: req.UninstallPrevious,
	}
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
		h.withVersion(ctx, &out, a)
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
	a, err := h.Apps.Create(ctx, req.newApp(caller(r).Admin.Email))
	if err != nil {
		h.writeAppError(w, "create app", err)
		return
	}
	out := newAppJSON(a)
	// Scope defaults to "machine" inside the service, so the response reflects
	// what was actually stored rather than the possibly-empty request field.
	h.withVersion(ctx, &out, a)
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
	h.withVersion(ctx, &out, a)
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
	a, err := h.Apps.Update(ctx, id, req.newApp(caller(r).Admin.Email))
	if err != nil {
		h.writeAppError(w, "update app", err)
		return
	}
	out := newAppJSON(a)
	h.withVersion(ctx, &out, a)
	writeJSON(w, http.StatusOK, out)
}

// uploadAppPackage stores an installer sent as the raw request body, named by
// ?file_name=, and returns the hash an app version then refers to it by.
func (h *Handler) uploadAppPackage(w http.ResponseWriter, r *http.Request) {
	// The server gives a whole request ten minutes; 2 GiB over an ordinary
	// office link needs longer. Only this signed-in, admin-only request
	// gets it.
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(2 * time.Hour))
	body := http.MaxBytesReader(w, r.Body, protocol.MaxPackageBytes)
	sha, size, err := h.Apps.UploadPackage(r.Context(), body, r.URL.Query().Get("file_name"), caller(r).Admin.Email)
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		writeError(w, http.StatusRequestEntityTooLarge, "too_large", "a package can be at most 2 GiB")
		return
	}
	if err != nil {
		h.writeAppError(w, "upload app package", err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"file_sha256": sha, "size_bytes": size})
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
	Version       int    `json:"version"`
	PackageID     string `json:"package_id"`
	PinnedVersion string `json:"pinned_version"`
	Scope         string `json:"scope"`
	InstallArgs   string `json:"install_args"`
	packageJSON
	Hash      string    `json:"hash"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
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
			Scope: v.Scope, InstallArgs: v.InstallArgs, packageJSON: newPackageJSON(v), Hash: v.Hash,
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
	rows, total, err := h.Store.Q().ListAppInstalls(r.Context(), id, deviceID, page, caller(r).Scope)
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
