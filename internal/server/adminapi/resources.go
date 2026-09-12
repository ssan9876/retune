package adminapi

import "net/http"

// mountResources registers the device, command, token, admin and audit routes.
func (h *Handler) mountResources(mux *http.ServeMux, base string) {
	mux.Handle("GET "+base+"/devices", h.read(h.listDevices))
	mux.Handle("GET "+base+"/devices/{id}", h.read(h.getDevice))
	mux.Handle("GET "+base+"/devices/{id}/software", h.read(h.listDeviceSoftware))
	mux.Handle("POST "+base+"/devices/{id}/retire", h.write(h.retireDevice))
	mux.Handle("POST "+base+"/devices/{id}/unenroll", h.write(h.unenrollDevice))

	mux.Handle("GET "+base+"/commands", h.read(h.listCommands))
	mux.Handle("POST "+base+"/commands", h.write(h.queueCommand))
	mux.Handle("GET "+base+"/commands/{id}", h.read(h.getCommand))

	mux.Handle("GET "+base+"/tokens", h.read(h.listTokens))
	mux.Handle("POST "+base+"/tokens", h.write(h.createToken))
	mux.Handle("POST "+base+"/tokens/{id}/revoke", h.write(h.revokeToken))

	mux.Handle("GET "+base+"/admins", h.read(h.listAdmins))
	mux.Handle("POST "+base+"/admins", h.write(h.createAdmin))
	mux.Handle("POST "+base+"/admins/{id}/password", h.write(h.setAdminPassword))
	mux.Handle("POST "+base+"/admins/{id}/totp", h.write(h.setAdminTOTP))
	mux.Handle("POST "+base+"/admins/{id}/disabled", h.write(h.setAdminDisabled))

	mux.Handle("GET "+base+"/audit", h.read(h.listAudit))
}
