package adminapi

import "net/http"

// mountResources registers the device, command, token, admin and audit routes.
func (h *Handler) mountResources(mux *http.ServeMux, base string) {
	mux.Handle("POST "+base+"/tokens", h.write(h.createToken))
}
