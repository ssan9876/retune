package adminapi

import (
	"net/http"
	"slices"

	"github.com/google/uuid"

	"retune/internal/server/store"
)

// deviceVisible reports whether the caller may see a device, answering 404
// when not: the same answer as a device that does not exist, so a scoped admin
// cannot probe for the ids of devices outside their groups.
func (h *Handler) deviceVisible(w http.ResponseWriter, r *http.Request, id uuid.UUID) bool {
	ok, err := h.Store.Q().DeviceInScope(r.Context(), store.DefaultTenantID, id, caller(r).Scope)
	if err != nil {
		h.internal(w, "check device scope", err, "device_id", id)
		return false
	}
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "no such device")
		return false
	}
	return true
}

// groupVisible reports whether the caller's scope includes a group.
func groupVisible(scope store.DeviceScope, id uuid.UUID) bool {
	return !scope.Limited() || slices.Contains(scope, id)
}
