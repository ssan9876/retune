package adminapi

import (
	"errors"
	"net/http"
	"time"

	"retune/internal/server/bitlocker"
	"retune/internal/server/store"
)

// bitlockerKeyJSON describes an escrowed key. It deliberately has no field for
// the key itself: listing keys must never hand them out.
type bitlockerKeyJSON struct {
	ID        string    `json:"id"`
	DeviceID  string    `json:"device_id"`
	Hostname  string    `json:"hostname"`
	VolumeID  string    `json:"volume_id"`
	Method    string    `json:"method"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func newBitLockerKeyJSON(k store.BitLockerKey) bitlockerKeyJSON {
	return bitlockerKeyJSON{
		ID: k.ID.String(), DeviceID: k.DeviceID.String(), Hostname: k.Hostname,
		VolumeID: k.VolumeID, Method: k.Method, CreatedAt: k.CreatedAt, UpdatedAt: k.UpdatedAt,
	}
}

// listBitLockerKeys shows which volumes of a device have an escrowed key.
func (h *Handler) listBitLockerKeys(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such device")
	if !ok {
		return
	}
	keys, err := h.BitLocker.List(r.Context(), id)
	if err != nil {
		h.internal(w, "list recovery keys", err)
		return
	}
	items := make([]bitlockerKeyJSON, 0, len(keys))
	for _, k := range keys {
		items = append(items, newBitLockerKeyJSON(k))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

type revealRequest struct {
	// Reason is recorded in the audit entry. It is not required, because a
	// help desk under pressure should not be blocked from unlocking a laptop,
	// but it is asked for.
	Reason string `json:"reason"`
}

type revealResponse struct {
	bitlockerKeyJSON
	RecoveryPassword string `json:"recovery_password"`
}

// revealBitLockerKey hands back one recovery password and records who asked.
// It is a POST, behind the admin role, precisely so that it is a deliberate act
// with an audit entry rather than a field someone stumbles across.
func (h *Handler) revealBitLockerKey(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such recovery key")
	if !ok {
		return
	}
	var req revealRequest
	if !decode(w, r, &req) {
		return
	}
	key, password, err := h.BitLocker.Reveal(r.Context(), id, caller(r).Admin.Email, req.Reason)
	switch {
	case err == nil:
	case errors.Is(err, bitlocker.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such recovery key")
		return
	default:
		h.internal(w, "reveal recovery key", err)
		return
	}
	writeJSON(w, http.StatusOK, revealResponse{
		bitlockerKeyJSON: newBitLockerKeyJSON(key),
		RecoveryPassword: password,
	})
}
