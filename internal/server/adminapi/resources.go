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

	mux.Handle("GET "+base+"/groups", h.read(h.listGroups))
	mux.Handle("POST "+base+"/groups", h.write(h.createGroup))
	// Rule preview reads nothing it changes, but it runs a rule, so it is
	// behind the write guard rather than being open to read-only accounts.
	mux.Handle("POST "+base+"/groups/preview", h.write(h.previewRule))
	mux.Handle("GET "+base+"/groups/{id}", h.read(h.getGroup))
	mux.Handle("POST "+base+"/groups/{id}", h.write(h.updateGroup))
	mux.Handle("DELETE "+base+"/groups/{id}", h.write(h.deleteGroup))
	mux.Handle("POST "+base+"/groups/{id}/evaluate", h.write(h.evaluateGroup))
	mux.Handle("GET "+base+"/groups/{id}/members", h.read(h.listGroupMembers))
	mux.Handle("POST "+base+"/groups/{id}/members", h.write(h.addGroupMember))
	mux.Handle("DELETE "+base+"/groups/{id}/members/{deviceID}", h.write(h.removeGroupMember))

	mux.Handle("GET "+base+"/scripts", h.read(h.listScripts))
	mux.Handle("POST "+base+"/scripts", h.write(h.createScript))
	mux.Handle("GET "+base+"/scripts/{id}", h.read(h.getScript))
	mux.Handle("POST "+base+"/scripts/{id}", h.write(h.updateScript))
	mux.Handle("DELETE "+base+"/scripts/{id}", h.write(h.deleteScript))
	mux.Handle("GET "+base+"/scripts/{id}/versions", h.read(h.listScriptVersions))
	mux.Handle("GET "+base+"/scripts/{id}/runs", h.read(h.listScriptRuns))

	mux.Handle("GET "+base+"/assignments", h.read(h.listAssignments))
	mux.Handle("POST "+base+"/assignments", h.write(h.createAssignment))
	mux.Handle("DELETE "+base+"/assignments/{id}", h.write(h.deleteAssignment))

	mux.Handle("GET "+base+"/items/{kind}/{id}/status", h.read(h.itemStatus))

	mux.Handle("GET "+base+"/audit", h.read(h.listAudit))
}
