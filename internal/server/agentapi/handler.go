// Package agentapi serves the endpoints agents call.
package agentapi

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/agentversions"
	"retune/internal/server/apps"
	"retune/internal/server/bitlocker"
	"retune/internal/server/ca"
	"retune/internal/server/commands"
	"retune/internal/server/enroll"
	"retune/internal/server/inventory"
	"retune/internal/server/profiles"
	"retune/internal/server/scripts"
	"retune/internal/server/store"
)

// Handler serves /api/agent/v1.
type Handler struct {
	Enroll          *enroll.Service
	Inventory       *inventory.Service
	Commands        *commands.Service
	Scripts         *scripts.Service
	Profiles        *profiles.Service
	Apps            *apps.Service
	AgentVersions   *agentversions.Service
	BitLocker       *bitlocker.Service
	Store           *store.Store
	Now             func() time.Time
	CheckinInterval time.Duration
	Log             *slog.Logger
	// ClientCert returns the device certificate for a request, already
	// verified against the internal CA, or (nil, nil) if the request
	// presented none. It is TLSClientCert unless a proxy terminates TLS.
	ClientCert func(*http.Request) (*x509.Certificate, error)
}

type authKey struct{}

// authInfo is the authenticated device plus the certificate serial it used.
type authInfo struct {
	Device     store.Device
	CertSerial string
}

// Routes returns the agent API mux.
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/agent/v1/enroll", h.enroll)
	mux.Handle("POST /api/agent/v1/checkin", h.requireDevice(h.checkin))
	mux.Handle("POST /api/agent/v1/renew", h.requireDevice(h.renew))
	mux.Handle("PUT /api/agent/v1/inventory", h.requireDevice(h.putInventory))
	mux.Handle("POST /api/agent/v1/commands/{id}/start", h.requireDevice(h.startCommand))
	mux.Handle("POST /api/agent/v1/commands/{id}/result", h.requireDevice(h.commandResult))
	mux.Handle("GET /api/agent/v1/scripts/{id}/versions/{version}", h.requireDevice(h.scriptVersion))
	mux.Handle("POST /api/agent/v1/scripts/{id}/runs", h.requireDevice(h.scriptRun))
	mux.Handle("GET /api/agent/v1/profiles/{id}/versions/{version}", h.requireDevice(h.profileVersion))
	mux.Handle("POST /api/agent/v1/profiles/{id}/status", h.requireDevice(h.profileStatus))
	mux.Handle("GET /api/agent/v1/apps/{id}/versions/{version}", h.requireDevice(h.appVersion))
	mux.Handle("POST /api/agent/v1/apps/{id}/result", h.requireDevice(h.appResult))
	mux.Handle("GET /api/agent/v1/agent-versions/{id}", h.requireDevice(h.agentVersion))
	mux.Handle("GET /api/agent/v1/agent-versions/{id}/binary", h.requireDevice(h.agentVersionBinary))
	mux.Handle("POST /api/agent/v1/agent-versions/{id}/result", h.requireDevice(h.agentVersionResult))
	mux.Handle("GET /api/agent/v1/bitlocker", h.requireDevice(h.bitlockerStatus))
	mux.Handle("POST /api/agent/v1/bitlocker", h.requireDevice(h.escrowBitLocker))
	return mux
}

func (h *Handler) enroll(w http.ResponseWriter, r *http.Request) {
	var req protocol.EnrollRequest
	if !decode(w, r, &req, maxCheckinBody) {
		return
	}
	resp, err := h.Enroll.Enroll(r.Context(), req)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, resp)
	case errors.Is(err, enroll.ErrTokenNotFound), errors.Is(err, enroll.ErrTokenRevoked),
		errors.Is(err, enroll.ErrTokenExpired), errors.Is(err, enroll.ErrTokenExhausted):
		writeError(w, http.StatusForbidden, "enrollment_token_invalid", err.Error())
	case errors.Is(err, ca.ErrBadCSR), errors.Is(err, enroll.ErrBadRequest):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	default:
		h.Log.Error("enroll failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
	}
}

// requireDevice authenticates the mTLS client certificate. The certificate must
// be the device's current one, or the one it presented at its last renewal;
// using the current one clears the superseded serial.
func (h *Handler) requireDevice(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaf, certErr := h.ClientCert(r)
		if certErr != nil {
			var ce CertError
			if errors.As(certErr, &ce) {
				writeError(w, ce.Status, ce.Code, ce.Message)
				return
			}
			h.Log.Error("read client certificate", "error", certErr)
			writeError(w, http.StatusInternalServerError, "internal", "internal server error")
			return
		}
		if leaf == nil {
			writeError(w, http.StatusUnauthorized, "client_cert_required", "a device client certificate is required")
			return
		}
		serial := leaf.SerialNumber.Text(16)
		id, err := uuid.Parse(leaf.Subject.CommonName)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "device_not_active", "unrecognized device certificate")
			return
		}
		ctx := r.Context()
		d, err := h.Store.Q().GetDevice(ctx, store.DefaultTenantID, id)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			h.Log.Error("load device", "device_id", id, "error", err)
			writeError(w, http.StatusInternalServerError, "internal", "internal server error")
			return
		}
		known := err == nil && (serial == d.CertSerial || (d.PrevCertSerial != "" && serial == d.PrevCertSerial))
		if !known {
			writeError(w, http.StatusUnauthorized, "device_not_active", "unrecognized device certificate")
			return
		}
		switch d.Status {
		case store.DeviceUnenrolled:
			writeError(w, http.StatusGone, "device_unenrolled", "device was unenrolled; remove the local identity")
			return
		case store.DeviceActive:
		default:
			writeError(w, http.StatusUnauthorized, "device_not_active", "device is retired or replaced")
			return
		}
		if serial == d.CertSerial && d.PrevCertSerial != "" {
			if err := h.Store.Q().ClearPrevCertSerial(ctx, store.DefaultTenantID, d.ID); err != nil {
				h.Log.Error("clear superseded certificate serial", "device_id", d.ID, "error", err)
			} else {
				d.PrevCertSerial = ""
			}
		}
		next(w, r.WithContext(context.WithValue(ctx, authKey{}, authInfo{Device: d, CertSerial: serial})))
	})
}

func auth(r *http.Request) authInfo { return r.Context().Value(authKey{}).(authInfo) }

func (h *Handler) checkin(w http.ResponseWriter, r *http.Request) {
	a := auth(r)
	var req protocol.CheckinRequest
	if !decode(w, r, &req, maxCheckinBody) {
		return
	}
	ctx := r.Context()
	if err := h.Store.Q().RecordCheckin(ctx, store.DefaultTenantID, a.Device.ID, req.AgentVersion, h.Now()); err != nil {
		h.Log.Error("record checkin", "device_id", a.Device.ID, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	due, err := h.Inventory.Due(ctx, a.Device.ID, req.InventoryHash)
	if err != nil {
		h.Log.Error("inventory due check", "device_id", a.Device.ID, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	cmds, err := h.Commands.Deliver(ctx, a.Device.ID)
	if err != nil {
		h.Log.Error("deliver commands", "device_id", a.Device.ID, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	// The effective set is computed per check-in rather than cached, so a
	// membership or assignment change takes effect on the next check-in with
	// no invalidation to get wrong.
	assigned, err := h.Store.Q().EffectiveItems(ctx, a.Device.ID)
	if err != nil {
		h.Log.Error("effective items", "device_id", a.Device.ID, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	items := make([]protocol.Item, 0, len(assigned))
	for _, it := range assigned {
		version, agentVersion, exists := h.itemVersion(ctx, it)
		if !exists {
			continue
		}
		items = append(items, protocol.Item{
			Kind: it.Kind, ID: it.ID.String(), Version: version, Options: it.Options,
		})

		// A device that reports the version of an assigned build is running
		// it, however it got there: by self-update, or by an MSI that already
		// carried this version. That is the only proof of success there is,
		// and recording it here is what lets a build's status page show the
		// devices it reached beside the ones it failed on.
		if it.Kind == protocol.ItemKindAgent && agentVersion == req.AgentVersion {
			if err := h.Store.Q().MarkItemSucceededOnce(ctx, store.ItemStatus{
				DeviceID: a.Device.ID, ItemKind: protocol.ItemKindAgent, ItemID: it.ID,
				Detail: "running this version", Version: 1, UpdatedAt: h.Now(),
			}); err != nil {
				h.Log.Warn("record agent build success", "agent_version_id", it.ID, "error", err)
			}
		}

		// A deployment that needs a signed-in user cannot run on a machine
		// where nobody is. The check-in says who is signed in, so the server
		// records that as pending; the agent still receives it, and reports a
		// real result as soon as somebody signs in.
		if it.Kind != protocol.ItemKindScript || strings.TrimSpace(req.LoggedInUser) != "" {
			continue
		}
		opts, err := protocol.ParseDeploymentOptions(it.Options)
		if err != nil || !opts.NeedsUserSession() {
			continue
		}
		if err := h.Scripts.SetItemPending(ctx, a.Device.ID, it.ID, version,
			"waiting for somebody to sign in"); err != nil {
			h.Log.Warn("record pending deployment", "script_id", it.ID, "error", err)
		}
	}

	writeJSON(w, http.StatusOK, protocol.CheckinResponse{
		IntervalSeconds: int(h.CheckinInterval / time.Second),
		InventoryDue:    due,
		Commands:        cmds,
		Items:           items,
	})
}

// itemVersion reports the current version of an assigned item, and whether it
// still exists. A kind with no case here is one this server does not
// implement, and is never offered to an agent.
//
// agentVersion is the agent build's own version string, for ItemKindAgent
// only ("" for every other kind): the success-inference block in checkin
// needs it to compare against what the device reported, and returning it
// here spares checkin a second h.AgentVersions.Get for the very row this
// call already fetched.
func (h *Handler) itemVersion(ctx context.Context, it store.Item) (version int, agentVersion string, exists bool) {
	switch it.Kind {
	case protocol.ItemKindScript:
		// The agent needs the version to know whether its cached copy is
		// current; it fetches the body separately, once per version.
		sc, err := h.Store.Q().GetScript(ctx, store.DefaultTenantID, it.ID)
		if err != nil {
			// A script that has gone missing is simply not offered.
			h.Log.Warn("assigned script is missing", "script_id", it.ID, "error", err)
			return 0, "", false
		}
		return sc.CurrentVersion, "", true
	case protocol.ItemKindProfile:
		pr, err := h.Profiles.Get(ctx, it.ID)
		if err != nil {
			h.Log.Warn("assigned profile is missing", "profile_id", it.ID, "error", err)
			return 0, "", false
		}
		return pr.CurrentVersion, "", true
	case protocol.ItemKindApp:
		app, err := h.Apps.Get(ctx, it.ID)
		if err != nil {
			h.Log.Warn("assigned app is missing", "app_id", it.ID, "error", err)
			return 0, "", false
		}
		return app.CurrentVersion, "", true
	case protocol.ItemKindAgent:
		v, err := h.AgentVersions.Get(ctx, it.ID)
		if err != nil {
			h.Log.Warn("assigned agent build is missing", "agent_version_id", it.ID, "error", err)
			return 0, "", false
		}
		// A build is immutable, so there is only ever version 1 of it; the
		// version string an agent compares against travels in the definition.
		return 1, v.Version, true
	}
	return 0, "", false
}

func (h *Handler) renew(w http.ResponseWriter, r *http.Request) {
	a := auth(r)
	var req protocol.RenewRequest
	if !decode(w, r, &req, maxCheckinBody) {
		return
	}
	resp, err := h.Enroll.Renew(r.Context(), a.Device.ID, a.CertSerial, req)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, resp)
	case errors.Is(err, ca.ErrBadCSR):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	default:
		h.Log.Error("renew failed", "device_id", a.Device.ID, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
	}
}

func (h *Handler) putInventory(w http.ResponseWriter, r *http.Request) {
	a := auth(r)
	var inv protocol.Inventory
	if !decode(w, r, &inv, maxInventoryBody) {
		return
	}
	hash, err := h.Inventory.Ingest(r.Context(), a.Device.ID, inv)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, protocol.InventoryResponse{Hash: hash})
	case errors.Is(err, inventory.ErrBadRequest):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	default:
		h.Log.Error("ingest inventory", "device_id", a.Device.ID, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
	}
}

func (h *Handler) startCommand(w http.ResponseWriter, r *http.Request) {
	a := auth(r)
	id, ok := commandID(w, r)
	if !ok {
		return
	}
	err := h.Commands.Start(r.Context(), a.Device.ID, id)
	switch {
	case err == nil:
		writeNoContent(w)
	case errors.Is(err, commands.ErrNotFound):
		writeError(w, http.StatusNotFound, "command_not_found", err.Error())
	default:
		h.Log.Error("start command", "device_id", a.Device.ID, "command_id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
	}
}

func (h *Handler) commandResult(w http.ResponseWriter, r *http.Request) {
	a := auth(r)
	id, ok := commandID(w, r)
	if !ok {
		return
	}
	var res protocol.CommandResult
	if !decode(w, r, &res, maxResultBody) {
		return
	}
	err := h.Commands.Complete(r.Context(), a.Device.ID, id, res)
	switch {
	case err == nil:
		writeNoContent(w)
	case errors.Is(err, commands.ErrNotFound):
		writeError(w, http.StatusNotFound, "command_not_found", err.Error())
	case errors.Is(err, commands.ErrBadRequest):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	default:
		h.Log.Error("complete command", "device_id", a.Device.ID, "command_id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
	}
}

func commandID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "command_not_found", "unknown command")
		return uuid.UUID{}, false
	}
	return id, true
}

// scriptVersion hands a device the contents of an assigned script. A device
// may only read what it has been given, so an unassigned script is a 404 —
// the same answer as one that does not exist, which is all an agent needs.
func (h *Handler) scriptVersion(w http.ResponseWriter, r *http.Request) {
	a := auth(r)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "script_not_found", "unknown script")
		return
	}
	version, err := strconv.Atoi(r.PathValue("version"))
	if err != nil || version < 1 {
		writeError(w, http.StatusNotFound, "script_not_found", "unknown script version")
		return
	}
	ctx := r.Context()
	allowed, err := h.Store.Q().DeviceHasItem(ctx, a.Device.ID, protocol.ItemKindScript, id)
	if err != nil {
		h.Log.Error("check script assignment", "device_id", a.Device.ID, "script_id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	if !allowed {
		writeError(w, http.StatusNotFound, "script_not_found", "unknown script")
		return
	}
	v, err := h.Scripts.Version(ctx, id, version)
	if errors.Is(err, scripts.ErrNotFound) {
		writeError(w, http.StatusNotFound, "script_not_found", "unknown script version")
		return
	}
	if err != nil {
		h.Log.Error("read script version", "script_id", id, "version", version, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, protocol.ScriptVersionResponse{
		Version: v.Version, Body: v.Body, DetectionBody: v.DetectionBody, Hash: v.Hash,
	})
}

// scriptRun records one execution reported by a device.
func (h *Handler) scriptRun(w http.ResponseWriter, r *http.Request) {
	a := auth(r)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "script_not_found", "unknown script")
		return
	}
	// Gating the write side the same as the read side means a device whose
	// assignment is revoked between a run starting and its result arriving
	// gets a 404 and the result is dropped rather than recorded. That is the
	// correct trade -- an agent must never be able to write history for
	// something it was never given -- but it does mean a result can be lost
	// to a race with revocation, not just rejected outright.
	ctx := r.Context()
	allowed, err := h.Store.Q().DeviceHasItem(ctx, a.Device.ID, protocol.ItemKindScript, id)
	if err != nil {
		h.Log.Error("check script assignment", "device_id", a.Device.ID, "script_id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	if !allowed {
		writeError(w, http.StatusNotFound, "script_not_found", "unknown script")
		return
	}
	var run protocol.ScriptRun
	if !decode(w, r, &run, maxResultBody) {
		return
	}
	err = h.Scripts.RecordRun(ctx, a.Device.ID, id, run)
	switch {
	case err == nil:
		writeNoContent(w)
	case errors.Is(err, scripts.ErrBadRequest):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	default:
		h.Log.Error("record script run", "device_id", a.Device.ID, "script_id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
	}
}

// profileVersion hands a device the settings of an assigned profile. As with
// scripts, a device may only read what it has been given.
func (h *Handler) profileVersion(w http.ResponseWriter, r *http.Request) {
	a := auth(r)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "profile_not_found", "unknown profile")
		return
	}
	version, err := strconv.Atoi(r.PathValue("version"))
	if err != nil || version < 1 {
		writeError(w, http.StatusNotFound, "profile_not_found", "unknown profile version")
		return
	}
	ctx := r.Context()
	allowed, err := h.Store.Q().DeviceHasItem(ctx, a.Device.ID, protocol.ItemKindProfile, id)
	if err != nil {
		h.Log.Error("check profile assignment", "device_id", a.Device.ID, "profile_id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	if !allowed {
		writeError(w, http.StatusNotFound, "profile_not_found", "unknown profile")
		return
	}
	v, settings, err := h.Profiles.Version(ctx, id, version)
	if errors.Is(err, profiles.ErrNotFound) {
		writeError(w, http.StatusNotFound, "profile_not_found", "unknown profile version")
		return
	}
	if err != nil {
		h.Log.Error("read profile version", "profile_id", id, "version", version, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, protocol.ProfileVersionResponse{
		Version: v.Version, Settings: settings, Hash: v.Hash,
	})
}

// profileStatus records what a device found for every setting of a profile.
func (h *Handler) profileStatus(w http.ResponseWriter, r *http.Request) {
	a := auth(r)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "profile_not_found", "unknown profile")
		return
	}
	// Gating the write side the same as the read side means a device whose
	// assignment is revoked between a status check starting and its report
	// arriving gets a 404 and the report is dropped rather than recorded.
	// That is the correct trade -- an agent must never be able to write
	// history for something it was never given -- but it does mean a report
	// can be lost to a race with revocation, not just rejected outright.
	ctx := r.Context()
	allowed, err := h.Store.Q().DeviceHasItem(ctx, a.Device.ID, protocol.ItemKindProfile, id)
	if err != nil {
		h.Log.Error("check profile assignment", "device_id", a.Device.ID, "profile_id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	if !allowed {
		writeError(w, http.StatusNotFound, "profile_not_found", "unknown profile")
		return
	}
	var report protocol.ProfileStatus
	if !decode(w, r, &report, maxResultBody) {
		return
	}
	err = h.Profiles.RecordStatus(ctx, a.Device.ID, id, report)
	switch {
	case err == nil:
		writeNoContent(w)
	case errors.Is(err, profiles.ErrBadRequest):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	default:
		h.Log.Error("record profile status", "device_id", a.Device.ID, "profile_id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
	}
}

// bitlockerStatus answers whether the server already holds a recovery key for a
// volume, so a compliant machine does not send one on every check-in.
func (h *Handler) bitlockerStatus(w http.ResponseWriter, r *http.Request) {
	a := auth(r)
	volumeID := r.URL.Query().Get("volume_id")
	if strings.TrimSpace(volumeID) == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "volume_id is required")
		return
	}
	has, err := h.BitLocker.Has(r.Context(), a.Device.ID, volumeID)
	if err != nil {
		h.Log.Error("check escrowed key", "device_id", a.Device.ID, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, protocol.BitLockerHasResponse{Escrowed: has})
}

// appVersion hands a device the definition of an assigned app. As with
// scripts and profiles, a device may only read what it has been given, so an
// unassigned app is a 404 -- the same answer as one that does not exist.
func (h *Handler) appVersion(w http.ResponseWriter, r *http.Request) {
	a := auth(r)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "app_not_found", "unknown app")
		return
	}
	version, err := strconv.Atoi(r.PathValue("version"))
	if err != nil || version < 1 {
		writeError(w, http.StatusNotFound, "app_not_found", "unknown app version")
		return
	}
	ctx := r.Context()
	allowed, err := h.Store.Q().DeviceHasItem(ctx, a.Device.ID, protocol.ItemKindApp, id)
	if err != nil {
		h.Log.Error("check app assignment", "device_id", a.Device.ID, "app_id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	if !allowed {
		writeError(w, http.StatusNotFound, "app_not_found", "unknown app")
		return
	}
	v, err := h.Apps.Version(ctx, id, version)
	if errors.Is(err, apps.ErrNotFound) {
		writeError(w, http.StatusNotFound, "app_not_found", "unknown app version")
		return
	}
	if err != nil {
		h.Log.Error("read app version", "app_id", id, "version", version, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, protocol.AppVersionResponse{
		Version: v.Version, PackageID: v.PackageID, PinnedVersion: v.PinnedVersion,
		Scope: v.Scope, InstallArgs: v.InstallArgs, Hash: v.Hash,
	})
}

// appResult records one install or uninstall reported by a device. Unlike
// scriptRun, this endpoint too must gate on assignment: an app is not offered
// by ID alone anywhere else in the agent API, but the same 404-for-both-cases
// rule applies to writes as to reads.
func (h *Handler) appResult(w http.ResponseWriter, r *http.Request) {
	a := auth(r)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "app_not_found", "unknown app")
		return
	}
	// Gating the write side the same as the read side means a device whose
	// assignment is revoked between an install starting and its result
	// arriving gets a 404 and the result is dropped rather than recorded.
	// That is the correct trade -- an agent must never be able to write
	// history for something it was never given -- but it does mean a result
	// can be lost to a race with revocation, not just rejected outright.
	ctx := r.Context()
	allowed, err := h.Store.Q().DeviceHasItem(ctx, a.Device.ID, protocol.ItemKindApp, id)
	if err != nil {
		h.Log.Error("check app assignment", "device_id", a.Device.ID, "app_id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	if !allowed {
		writeError(w, http.StatusNotFound, "app_not_found", "unknown app")
		return
	}
	var res protocol.AppResult
	if !decode(w, r, &res, maxResultBody) {
		return
	}
	err = h.Apps.RecordInstall(ctx, a.Device.ID, id, res)
	switch {
	case err == nil:
		writeNoContent(w)
	case errors.Is(err, apps.ErrBadRequest):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	default:
		h.Log.Error("record app install", "device_id", a.Device.ID, "app_id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
	}
}

// agentVersion hands a device the definition of an assigned build. As with
// scripts, profiles and apps, a device may only read what it has been given,
// so an unassigned build is a 404 -- the same answer as one that does not
// exist, which is all an agent needs to know.
func (h *Handler) agentVersion(w http.ResponseWriter, r *http.Request) {
	a := auth(r)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "agent_version_not_found", "unknown agent build")
		return
	}
	ctx := r.Context()
	allowed, err := h.Store.Q().DeviceHasItem(ctx, a.Device.ID, protocol.ItemKindAgent, id)
	if err != nil {
		h.Log.Error("check agent build assignment", "device_id", a.Device.ID, "agent_version_id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	if !allowed {
		writeError(w, http.StatusNotFound, "agent_version_not_found", "unknown agent build")
		return
	}
	v, err := h.AgentVersions.Get(ctx, id)
	if errors.Is(err, agentversions.ErrNotFound) {
		writeError(w, http.StatusNotFound, "agent_version_not_found", "unknown agent build")
		return
	}
	if err != nil {
		h.Log.Error("read agent build", "agent_version_id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, protocol.AgentVersionResponse{
		Version: v.Version, SHA256: v.SHA256, SizeBytes: v.SizeBytes,
		KeyID: v.KeyID, Signature: v.Signature,
	})
}

// agentVersionBinary streams the bytes of an assigned build. This is the
// product's first non-JSON agent response: the payload is a binary of a few
// megabytes, and base64-in-JSON would inflate that by a third for no benefit.
func (h *Handler) agentVersionBinary(w http.ResponseWriter, r *http.Request) {
	a := auth(r)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "agent_version_not_found", "unknown agent build")
		return
	}
	ctx := r.Context()
	allowed, err := h.Store.Q().DeviceHasItem(ctx, a.Device.ID, protocol.ItemKindAgent, id)
	if err != nil {
		h.Log.Error("check agent build assignment", "device_id", a.Device.ID, "agent_version_id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	if !allowed {
		writeError(w, http.StatusNotFound, "agent_version_not_found", "unknown agent build")
		return
	}
	body, size, err := h.AgentVersions.Open(ctx, id)
	if errors.Is(err, agentversions.ErrNotFound) {
		writeError(w, http.StatusNotFound, "agent_version_not_found", "unknown agent build")
		return
	}
	if err != nil {
		h.Log.Error("open agent build", "agent_version_id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	defer body.Close()

	// The agent verifies the SHA-256 from the definition, so a truncated
	// transfer is caught there; Content-Length lets it fail sooner.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	if _, err := io.Copy(w, body); err != nil {
		// The response is already partly written, so there is nothing useful
		// to say to the client; the agent's hash check is what catches it.
		h.Log.Warn("agent build download was cut short", "device_id", a.Device.ID, "error", err)
	}
}

// agentVersionResult records the outcome of one device's attempt to install a
// build. As with appResult, the gate on assignment happens before anything is
// decoded: a device must never be able to forge a "succeeded" for a build it
// was never given.
func (h *Handler) agentVersionResult(w http.ResponseWriter, r *http.Request) {
	a := auth(r)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "agent_version_not_found", "unknown agent build")
		return
	}
	ctx := r.Context()
	allowed, err := h.Store.Q().DeviceHasItem(ctx, a.Device.ID, protocol.ItemKindAgent, id)
	if err != nil {
		h.Log.Error("check agent build assignment", "device_id", a.Device.ID, "agent_version_id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	if !allowed {
		writeError(w, http.StatusNotFound, "agent_version_not_found", "unknown agent build")
		return
	}
	var res protocol.AgentUpdateResult
	if !decode(w, r, &res, maxResultBody) {
		return
	}
	err = h.AgentVersions.RecordResult(ctx, a.Device.ID, id, res)
	switch {
	case err == nil:
		writeNoContent(w)
	case errors.Is(err, agentversions.ErrBadRequest):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	default:
		h.Log.Error("record agent update result", "device_id", a.Device.ID, "agent_version_id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
	}
}

// escrowBitLocker stores a recovery password. The key is never logged, here or
// anywhere else.
func (h *Handler) escrowBitLocker(w http.ResponseWriter, r *http.Request) {
	a := auth(r)
	var req protocol.BitLockerEscrowRequest
	if !decode(w, r, &req, maxCheckinBody) {
		return
	}
	err := h.BitLocker.Escrow(r.Context(), a.Device.ID, req.VolumeID, req.Method, req.RecoveryPassword)
	switch {
	case err == nil:
		writeNoContent(w)
	case errors.Is(err, bitlocker.ErrBadRequest):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	default:
		h.Log.Error("escrow recovery key", "device_id", a.Device.ID, "volume_id", req.VolumeID, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
	}
}
