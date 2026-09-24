package adminapi

import (
	"net/http"

	"retune/internal/server/attest"
	"retune/internal/server/store"
)

// complianceLookupJSON is the answer to a compliance lookup.
type complianceLookupJSON struct {
	Items []attest.DeviceCompliance `json:"items"`
}

// lookupCompliance answers whether the device an identifier names is
// compliant: for network access control asking about a MAC address, or an
// identity provider about a device ID. Exactly one identifier is given.
func (h *Handler) lookupCompliance(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	by, value := "", ""
	for _, key := range []string{store.LookupDeviceID, store.LookupSerial, store.LookupHostname, store.LookupMAC} {
		if v := q.Get(key); v != "" {
			if by != "" {
				writeError(w, http.StatusBadRequest, "bad_request", "give one of device_id, serial, hostname or mac")
				return
			}
			by, value = key, v
		}
	}
	if by == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "give one of device_id, serial, hostname or mac")
		return
	}
	items, err := h.Attest.Lookup(r.Context(), by, value, caller(r).Scope)
	if err != nil {
		h.internal(w, "look up compliance", err)
		return
	}
	if items == nil {
		items = []attest.DeviceCompliance{}
	}
	writeJSON(w, http.StatusOK, complianceLookupJSON{Items: items})
}

// complianceJWKS publishes the key compliance statements are signed with.
func (h *Handler) complianceJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=3600")
	writeJSON(w, http.StatusOK, h.Attest.CA.JWKS())
}
