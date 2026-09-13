// Package agentapi serves the endpoints agents call.
package agentapi

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/ca"
	"retune/internal/server/commands"
	"retune/internal/server/enroll"
	"retune/internal/server/inventory"
	"retune/internal/server/scripts"
	"retune/internal/server/store"
)

// Handler serves /api/agent/v1.
type Handler struct {
	Enroll          *enroll.Service
	Inventory       *inventory.Service
	Commands        *commands.Service
	Scripts         *scripts.Service
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
		d, err := h.Store.Q().GetDevice(ctx, id)
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
			if err := h.Store.Q().ClearPrevCertSerial(ctx, d.ID); err != nil {
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
	if err := h.Store.Q().RecordCheckin(ctx, a.Device.ID, req.AgentVersion, h.Now()); err != nil {
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
		item := protocol.Item{Kind: it.Kind, ID: it.ID.String(), Options: it.Options}
		if it.Kind == protocol.ItemKindScript {
			// The agent needs the version to know whether its cached copy is
			// current; it fetches the body separately, once per version.
			sc, err := h.Store.Q().GetScript(ctx, it.ID)
			if err != nil {
				// A script that has gone missing is simply not offered.
				h.Log.Warn("assigned script is missing", "script_id", it.ID, "error", err)
				continue
			}
			item.Version = sc.CurrentVersion
		}
		items = append(items, item)
	}

	writeJSON(w, http.StatusOK, protocol.CheckinResponse{
		IntervalSeconds: int(h.CheckinInterval / time.Second),
		InventoryDue:    due,
		Commands:        cmds,
		Items:           items,
	})
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
	var run protocol.ScriptRun
	if !decode(w, r, &run, maxResultBody) {
		return
	}
	err = h.Scripts.RecordRun(r.Context(), a.Device.ID, id, run)
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
