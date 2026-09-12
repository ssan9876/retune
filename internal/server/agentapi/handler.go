// Package agentapi serves the endpoints agents call.
package agentapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/ca"
	"retune/internal/server/commands"
	"retune/internal/server/enroll"
	"retune/internal/server/inventory"
	"retune/internal/server/store"
)

// Handler serves /api/agent/v1.
type Handler struct {
	Enroll          *enroll.Service
	Inventory       *inventory.Service
	Commands        *commands.Service
	Store           *store.Store
	Now             func() time.Time
	CheckinInterval time.Duration
	Log             *slog.Logger
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
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			writeError(w, http.StatusUnauthorized, "client_cert_required", "a device client certificate is required")
			return
		}
		leaf := r.TLS.VerifiedChains[0][0]
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
	writeJSON(w, http.StatusOK, protocol.CheckinResponse{
		IntervalSeconds: int(h.CheckinInterval / time.Second),
		InventoryDue:    due,
		Commands:        cmds,
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
