package adminapi

import "net/http"

// mountResources registers the device, command, token, admin and audit routes.
func (h *Handler) mountResources(mux *http.ServeMux, base string) {
	h.handle(mux, "GET "+base+"/devices", h.read(h.listDevices))
	// ServeMux resolves this literal path ahead of /devices/{id} by pattern
	// specificity (not registration order), so export.csv never gets parsed
	// as a device ID.
	h.handle(mux, "GET "+base+"/devices/export.csv", h.read(h.exportDevices))
	h.handle(mux, "GET "+base+"/devices/{id}", h.read(h.getDevice))
	h.handle(mux, "GET "+base+"/devices/{id}/software", h.read(h.listDeviceSoftware))
	h.handle(mux, "POST "+base+"/devices/{id}/retire", h.write(h.retireDevice))
	h.handle(mux, "POST "+base+"/devices/{id}/unenroll", h.write(h.unenrollDevice))

	h.handle(mux, "GET "+base+"/commands", h.read(h.listCommands))
	h.handle(mux, "POST "+base+"/commands", h.operate(h.queueCommand))
	h.handle(mux, "GET "+base+"/commands/{id}", h.read(h.getCommand))
	h.handle(mux, "GET "+base+"/commands/{id}/artifact", h.operate(h.downloadCommandArtifact))

	h.handle(mux, "GET "+base+"/tokens", h.readFleet(h.listTokens))
	h.handle(mux, "POST "+base+"/tokens", h.writeFleet(h.createToken))
	h.handle(mux, "POST "+base+"/tokens/{id}/revoke", h.writeFleet(h.revokeToken))

	h.handle(mux, "GET "+base+"/admins", h.readAdmin(h.listAdmins))
	h.handle(mux, "POST "+base+"/admins", h.writeAdmin(h.createAdmin))
	h.handle(mux, "POST "+base+"/admins/{id}/password", h.writeAdmin(h.setAdminPassword))
	h.handle(mux, "POST "+base+"/admins/{id}/totp", h.writeAdmin(h.setAdminTOTP))
	h.handle(mux, "POST "+base+"/admins/{id}/disabled", h.writeAdmin(h.setAdminDisabled))
	h.handle(mux, "PUT "+base+"/admins/{id}/scope", h.writeAdmin(h.setAdminScope))

	h.handle(mux, "GET "+base+"/api-tokens", h.readAdmin(h.listAPITokens))
	h.handle(mux, "POST "+base+"/api-tokens", h.writeAdmin(h.createAPIToken))
	h.handle(mux, "POST "+base+"/api-tokens/{id}/revoke", h.writeAdmin(h.revokeAPIToken))

	h.handle(mux, "GET "+base+"/groups", h.read(h.listGroups))
	h.handle(mux, "POST "+base+"/groups", h.writeFleet(h.createGroup))
	// Rule preview reads nothing it changes, but it runs a rule, so it is
	// behind the write guard rather than being open to read-only accounts.
	h.handle(mux, "POST "+base+"/groups/preview", h.writeFleet(h.previewRule))
	h.handle(mux, "GET "+base+"/groups/{id}", h.read(h.getGroup))
	h.handle(mux, "POST "+base+"/groups/{id}", h.writeFleet(h.updateGroup))
	h.handle(mux, "DELETE "+base+"/groups/{id}", h.writeFleet(h.deleteGroup))
	h.handle(mux, "POST "+base+"/groups/{id}/evaluate", h.writeFleet(h.evaluateGroup))
	h.handle(mux, "GET "+base+"/groups/{id}/members", h.read(h.listGroupMembers))
	h.handle(mux, "POST "+base+"/groups/{id}/members", h.writeFleet(h.addGroupMember))
	h.handle(mux, "DELETE "+base+"/groups/{id}/members/{deviceID}", h.writeFleet(h.removeGroupMember))

	h.handle(mux, "GET "+base+"/scripts", h.read(h.listScripts))
	h.handle(mux, "POST "+base+"/scripts", h.writeFleet(h.createScript))
	h.handle(mux, "GET "+base+"/scripts/{id}", h.read(h.getScript))
	h.handle(mux, "POST "+base+"/scripts/{id}", h.writeFleet(h.updateScript))
	h.handle(mux, "DELETE "+base+"/scripts/{id}", h.writeFleet(h.deleteScript))
	h.handle(mux, "GET "+base+"/scripts/{id}/versions", h.read(h.listScriptVersions))
	h.handle(mux, "GET "+base+"/scripts/{id}/runs", h.read(h.listScriptRuns))

	h.handle(mux, "GET "+base+"/devices/{id}/bitlocker-keys", h.read(h.listBitLockerKeys))
	// Revealing a recovery key is a write: it is a deliberate act, restricted
	// to the admin role, and audited every time.
	h.handle(mux, "POST "+base+"/bitlocker-keys/{id}/reveal", h.operateSession(h.revealBitLockerKey))
	h.handle(mux, "GET "+base+"/devices/{id}/admin-passwords", h.read(h.listAdminPasswords))
	h.handle(mux, "POST "+base+"/admin-passwords/{id}/reveal", h.operateSession(h.revealAdminPassword))

	h.handle(mux, "GET "+base+"/profiles", h.read(h.listProfiles))
	h.handle(mux, "POST "+base+"/profiles", h.writeFleet(h.createProfile))
	h.handle(mux, "GET "+base+"/profiles/{id}", h.read(h.getProfile))
	h.handle(mux, "POST "+base+"/profiles/{id}", h.writeFleet(h.updateProfile))
	h.handle(mux, "DELETE "+base+"/profiles/{id}", h.writeFleet(h.deleteProfile))
	h.handle(mux, "GET "+base+"/profiles/{id}/versions", h.read(h.listProfileVersions))
	h.handle(mux, "GET "+base+"/profiles/{id}/settings", h.read(h.profileSettingStatus))

	h.handle(mux, "GET "+base+"/apps", h.read(h.listApps))
	h.handle(mux, "POST "+base+"/apps", h.writeFleet(h.createApp))
	h.handle(mux, "POST "+base+"/app-packages", h.writeFleet(h.uploadAppPackage))
	h.handle(mux, "GET "+base+"/apps/{id}", h.read(h.getApp))
	h.handle(mux, "POST "+base+"/apps/{id}", h.writeFleet(h.updateApp))
	h.handle(mux, "DELETE "+base+"/apps/{id}", h.writeFleet(h.deleteApp))
	h.handle(mux, "GET "+base+"/apps/{id}/versions", h.read(h.listAppVersions))
	h.handle(mux, "GET "+base+"/apps/{id}/installs", h.read(h.listAppInstalls))

	h.handle(mux, "GET "+base+"/agent-versions", h.read(h.listAgentVersions))
	h.handle(mux, "POST "+base+"/agent-versions", h.writeFleet(h.uploadAgentVersion))
	h.handle(mux, "GET "+base+"/agent-versions/{id}", h.read(h.getAgentVersion))
	h.handle(mux, "DELETE "+base+"/agent-versions/{id}", h.writeFleet(h.deleteAgentVersion))

	h.handle(mux, "GET "+base+"/notification-channels", h.readFleet(h.listNotificationChannels))
	h.handle(mux, "POST "+base+"/notification-channels", h.writeFleet(h.createNotificationChannel))
	h.handle(mux, "GET "+base+"/notification-channels/{id}", h.readFleet(h.getNotificationChannel))
	h.handle(mux, "POST "+base+"/notification-channels/{id}", h.writeFleet(h.updateNotificationChannel))
	h.handle(mux, "DELETE "+base+"/notification-channels/{id}", h.writeFleet(h.deleteNotificationChannel))
	// Sending a test makes the server talk to the outside world on request,
	// so it is a write rather than something a read-only account can trigger.
	h.handle(mux, "POST "+base+"/notification-channels/{id}/test", h.writeFleet(h.testNotificationChannel))

	h.handle(mux, "GET "+base+"/alert-rules", h.readFleet(h.listAlertRules))
	h.handle(mux, "POST "+base+"/alert-rules", h.writeFleet(h.createAlertRule))
	h.handle(mux, "GET "+base+"/alert-rules/{id}", h.readFleet(h.getAlertRule))
	h.handle(mux, "POST "+base+"/alert-rules/{id}", h.writeFleet(h.updateAlertRule))
	h.handle(mux, "DELETE "+base+"/alert-rules/{id}", h.writeFleet(h.deleteAlertRule))
	h.handle(mux, "GET "+base+"/alerts", h.readFleet(h.listFiringAlerts))
	h.handle(mux, "GET "+base+"/alert-deliveries", h.readFleet(h.listAlertDeliveries))

	h.handle(mux, "GET "+base+"/assignments", h.read(h.listAssignments))
	h.handle(mux, "POST "+base+"/assignments", h.write(h.createAssignment))
	h.handle(mux, "DELETE "+base+"/assignments/{id}", h.write(h.deleteAssignment))

	h.handle(mux, "GET "+base+"/items/{kind}/{id}/status", h.read(h.itemStatus))

	h.handle(mux, "GET "+base+"/compliance-policies", h.read(h.listCompliancePolicies))
	h.handle(mux, "POST "+base+"/compliance-policies", h.writeFleet(h.createCompliancePolicy))
	h.handle(mux, "GET "+base+"/compliance-policies/{id}", h.read(h.getCompliancePolicy))
	h.handle(mux, "POST "+base+"/compliance-policies/{id}", h.writeFleet(h.updateCompliancePolicy))
	h.handle(mux, "DELETE "+base+"/compliance-policies/{id}", h.writeFleet(h.deleteCompliancePolicy))
	h.handle(mux, "POST "+base+"/compliance-policies/{id}/evaluate", h.writeFleet(h.evaluateCompliancePolicy))
	h.handle(mux, "GET "+base+"/compliance-policies/{id}/devices", h.read(h.listPolicyDevices))
	h.handle(mux, "GET "+base+"/compliance-policies/{id}/devices/export.csv", h.read(h.exportPolicyDevices))

	h.handle(mux, "GET "+base+"/devices/{id}/compliance", h.read(h.deviceCompliance))

	h.handle(mux, "GET "+base+"/dashboard", h.read(h.dashboard))

	h.handle(mux, "GET "+base+"/audit", h.readFleet(h.listAudit))
	h.handle(mux, "GET "+base+"/audit/export.csv", h.readFleet(h.exportAudit))
}
