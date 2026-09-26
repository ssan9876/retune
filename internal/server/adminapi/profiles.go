package adminapi

import (
	"errors"
	"net/http"
	"time"

	"retune/internal/opsign"
	"retune/internal/protocol"
	"retune/internal/server/profiles"
	"retune/internal/server/store"
)

type profileJSON struct {
	ID             string             `json:"id"`
	Name           string             `json:"name"`
	Description    string             `json:"description"`
	CurrentVersion int                `json:"current_version"`
	Settings       []protocol.Setting `json:"settings,omitempty"`
	Signed         bool               `json:"signed"` // the current version has an operations signature
	CreatedAt      time.Time          `json:"created_at"`
	UpdatedAt      time.Time          `json:"updated_at"`
	CreatedBy      string             `json:"created_by"`
}

func newProfileJSON(p store.Profile) profileJSON {
	return profileJSON{
		ID: p.ID.String(), Name: p.Name, Description: p.Description,
		CurrentVersion: p.CurrentVersion, CreatedAt: p.CreatedAt,
		UpdatedAt: p.UpdatedAt, CreatedBy: p.CreatedBy,
	}
}

type profileRequest struct {
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Settings    []protocol.Setting `json:"settings"`
	// Signature is the operations signature from retune-sign sign-profile.
	Signature *opsign.Signature `json:"signature,omitempty"`
}

func (h *Handler) writeProfileError(w http.ResponseWriter, what string, err error) {
	switch {
	case errors.Is(err, profiles.ErrNotFound), errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such profile")
	case errors.Is(err, profiles.ErrNameTaken):
		writeError(w, http.StatusConflict, "name_taken", err.Error())
	case errors.Is(err, profiles.ErrBadRequest), errors.Is(err, protocol.ErrBadSetting):
		// The message names which setting is wrong and why, which is what the
		// editor shows.
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	default:
		h.internal(w, what, err)
	}
}

func (h *Handler) listProfiles(w http.ResponseWriter, r *http.Request) {
	page := pageFrom(r)
	rows, total, err := h.Profiles.List(r.Context(), page)
	if err != nil {
		h.internal(w, "list profiles", err)
		return
	}
	items := make([]profileJSON, 0, len(rows))
	for _, p := range rows {
		items = append(items, newProfileJSON(p))
	}
	writeJSON(w, http.StatusOK, newListResponse(items, total, page))
}

func (h *Handler) createProfile(w http.ResponseWriter, r *http.Request) {
	var req profileRequest
	if !decode(w, r, &req) {
		return
	}
	p, err := h.Profiles.Create(r.Context(), profiles.NewProfile{
		Name: req.Name, Description: req.Description, Settings: req.Settings,
		Actor: caller(r).Admin.Email, Signature: req.Signature,
	})
	if err != nil {
		h.writeProfileError(w, "create profile", err)
		return
	}
	out := newProfileJSON(p)
	out.Settings, out.Signed = profiles.Redact(req.Settings), req.Signature != nil
	writeJSON(w, http.StatusCreated, out)
}

// getProfile returns the profile with the settings of its current version,
// which is what the editor opens.
func (h *Handler) getProfile(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such profile")
	if !ok {
		return
	}
	ctx := r.Context()
	p, err := h.Profiles.Get(ctx, id)
	if err != nil {
		h.writeProfileError(w, "get profile", err)
		return
	}
	out := newProfileJSON(p)
	if v, settings, err := h.Profiles.Version(ctx, id, p.CurrentVersion); err == nil {
		out.Settings, out.Signed = profiles.Redact(settings), len(v.Signature) > 0
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) updateProfile(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such profile")
	if !ok {
		return
	}
	var req profileRequest
	if !decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	in := profiles.NewProfile{
		Name: req.Name, Description: req.Description, Settings: req.Settings,
		Actor: caller(r).Admin.Email, Signature: req.Signature,
	}
	hold, err := h.itemNeedsApproval(ctx, protocol.ItemKindProfile, id)
	if err != nil {
		h.internal(w, "check profile reach", err)
		return
	}
	var p store.Profile
	held := 0
	if hold {
		p, held, err = h.Profiles.UpdateHeld(ctx, id, in)
	} else {
		p, err = h.Profiles.Update(ctx, id, in)
	}
	if err != nil {
		h.writeProfileError(w, "update profile", err)
		return
	}
	if held > 0 {
		h.holdVersion(w, r, protocol.ItemKindProfile, id, p.Name, held)
		return
	}
	out := newProfileJSON(p)
	out.Settings = profiles.Redact(req.Settings)
	// A rename keeps the signature without resending it, so ask the version.
	if v, _, err := h.Profiles.Version(r.Context(), id, p.CurrentVersion); err == nil {
		out.Signed = len(v.Signature) > 0
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) deleteProfile(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such profile")
	if !ok {
		return
	}
	if err := h.Profiles.Delete(r.Context(), id, caller(r).Admin.Email); err != nil {
		h.writeProfileError(w, "delete profile", err)
		return
	}
	writeNoContent(w)
}

type profileVersionJSON struct {
	Version   int                `json:"version"`
	Settings  []protocol.Setting `json:"settings"`
	Hash      string             `json:"hash"`
	Signed    bool               `json:"signed"`
	CreatedAt time.Time          `json:"created_at"`
	CreatedBy string             `json:"created_by"`
}

func (h *Handler) listProfileVersions(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such profile")
	if !ok {
		return
	}
	ctx := r.Context()
	rows, err := h.Profiles.ListVersions(ctx, id)
	if err != nil {
		h.writeProfileError(w, "list profile versions", err)
		return
	}
	items := make([]profileVersionJSON, 0, len(rows))
	for _, v := range rows {
		entry := profileVersionJSON{
			Version: v.Version, Hash: v.Hash, Signed: len(v.Signature) > 0,
			CreatedAt: v.CreatedAt, CreatedBy: v.CreatedBy,
		}
		if _, settings, err := h.Profiles.Version(ctx, id, v.Version); err == nil {
			entry.Settings = profiles.Redact(settings)
		}
		items = append(items, entry)
	}
	writeJSON(w, http.StatusOK, itemsOf(items))
}

// profileStatus returns the per-setting results for a profile, so an
// administrator can go straight to which setting is failing where.
func (h *Handler) profileSettingStatus(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such profile")
	if !ok {
		return
	}
	ctx := r.Context()
	rollup, err := h.Store.Q().SettingStatusRollup(ctx, id, caller(r).Scope)
	if err != nil {
		h.internal(w, "setting status rollup", err)
		return
	}
	page := pageFrom(r)
	rows, total, err := h.Store.Q().ListSettingStatus(ctx, id, r.URL.Query().Get("status"), page, caller(r).Scope)
	if err != nil {
		h.internal(w, "list setting status", err)
		return
	}
	items := make([]settingStatusRowJSON, 0, len(rows))
	for _, s := range rows {
		items = append(items, settingStatusRowJSON{
			DeviceID: s.DeviceID.String(), Hostname: s.Hostname, Identity: s.Identity,
			Version: s.Version, Status: s.Status, Detail: s.Detail, UpdatedAt: s.UpdatedAt,
		})
	}
	writeJSON(w, http.StatusOK, statusRollupResponse[settingStatusRowJSON]{
		Rollup: rollup, Items: items, Total: total,
		Limit: page.Normalized().Limit, Offset: page.Normalized().Offset,
	})
}

// settingStatusRowJSON is one device's status for one profile setting.
type settingStatusRowJSON struct {
	DeviceID  string    `json:"device_id"`
	Hostname  string    `json:"hostname"`
	Identity  string    `json:"identity"`
	Version   int       `json:"version"`
	Status    string    `json:"status"`
	Detail    string    `json:"detail"`
	UpdatedAt time.Time `json:"updated_at"`
}
