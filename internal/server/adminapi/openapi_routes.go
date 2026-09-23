package adminapi

import (
	"time"
)

// Request and response bodies with no other home, named so the OpenAPI
// document can describe them. The handlers decode and encode these types
// themselves.

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	TOTPCode string `json:"totp_code"`
}

type queuedCommands struct {
	Commands []queuedJSON `json:"commands"`
}

type commandDetail struct {
	Command commandJSON `json:"command"`
	// Result is present once the device has reported one.
	Result *resultJSON `json:"result,omitempty"`
}

type decisionRequest struct {
	Reason string `json:"reason"`
}

type createdEnrollmentToken struct {
	ID        string     `json:"id"`
	Token     string     `json:"token"`
	Label     string     `json:"label"`
	MaxUses   *int       `json:"max_uses"`
	ExpiresAt *time.Time `json:"expires_at"`
	CreatedAt time.Time  `json:"created_at"`
}

type createAdminRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type passwordRequest struct {
	Password string `json:"password"`
}

type totpRequest struct {
	Enabled bool `json:"enabled"`
}

type totpEnrollment struct {
	Secret     string `json:"secret"`
	OTPAuthURL string `json:"otpauth_url"`
}

type disabledRequest struct {
	Disabled bool `json:"disabled"`
}

type scopeRequest struct {
	// GroupIDs limits the admin to these device groups; null is the whole
	// fleet.
	GroupIDs *[]string `json:"group_ids"`
}

type apiTokenList struct {
	Items []apiTokenJSON `json:"items"`
	Total int            `json:"total"`
}

type createAPITokenRequest struct {
	Name          string `json:"name"`
	Role          string `json:"role"`
	ExpiresInDays int    `json:"expires_in_days"`
}

type createdAPIToken struct {
	Token    string       `json:"token"`
	APIToken apiTokenJSON `json:"api_token"`
}

// itemsResponse is a listing that is never paged.
type itemsResponse[T any] struct {
	Items []T `json:"items"`
}

func itemsOf[T any](items []T) itemsResponse[T] {
	if items == nil {
		items = []T{}
	}
	return itemsResponse[T]{Items: items}
}

type memberCount struct {
	MemberCount int `json:"member_count"`
}

type revealedPassword struct {
	Password      string            `json:"password"`
	AdminPassword adminPasswordJSON `json:"admin_password"`
}

type statusRollupResponse[T any] struct {
	Rollup map[string]int `json:"rollup"`
	Items  []T            `json:"items"`
	Total  int            `json:"total"`
	Limit  int            `json:"limit"`
	Offset int            `json:"offset"`
}

type uploadedPackage struct {
	FileSHA256 string `json:"file_sha256"`
	SizeBytes  int64  `json:"size_bytes"`
}

type channelTest struct {
	OK bool `json:"ok"`
}

type evaluationStarted struct {
	DeviceCount int  `json:"device_count"`
	Started     bool `json:"started"`
}

// approvalEnvelope is a request held for approval, or the decision on one.
type approvalEnvelope struct {
	Approval approvalJSON `json:"approval"`
}

var (
	paging = []param{
		{Name: "limit", In: "query", Type: "integer", Description: "At most this many (default 50, at most 500)."},
		{Name: "offset", In: "query", Type: "integer", Description: "Skip this many."},
	}
	byDevice   = param{Name: "device_id", In: "query", Description: "Only this device."}
	auditQuery = []param{
		{Name: "actor", In: "query", Description: "Only entries by this actor."},
		{Name: "action", In: "query", Description: "Only this action, e.g. command.queued."},
		{Name: "since", In: "query", Description: "RFC 3339; entries at or after."},
		{Name: "until", In: "query", Description: "RFC 3339; entries before."},
	}
)

func with(ps ...param) []param { return append(ps, paging...) }

// routeDocs describes every admin API route, keyed as registered.
var routeDocs = map[string]routeDoc{
	// Session
	"GET /api/admin/v1/setup":         {Tag: "Session", Summary: "Whether first-run setup is needed, and how people sign in", Response: setupResponse{}},
	"POST /api/admin/v1/session":      {Tag: "Session", Summary: "Sign in with a password (and authenticator code)", Request: loginRequest{}, Response: sessionResponse{}, Description: "Sets the " + SessionCookie + " cookie. The response carries the CSRF token to send as " + CSRFHeader + "."},
	"GET /api/admin/v1/oidc/start":    {Tag: "Session", Summary: "Start single sign-on", Status: 302, Description: "Redirects to the identity provider. 404 if SSO is not configured."},
	"GET /api/admin/v1/oidc/callback": {Tag: "Session", Summary: "Finish single sign-on", Status: 302, Query: []param{{Name: "code", In: "query"}, {Name: "state", In: "query"}, {Name: "error", In: "query"}, {Name: "error_description", In: "query"}}, Description: "The identity provider redirects here. Sets the session cookie and redirects to the console."},
	"GET /api/admin/v1/session":       {Tag: "Session", Summary: "The signed-in admin", Response: sessionResponse{}},
	"DELETE /api/admin/v1/session":    {Tag: "Session", Summary: "Sign out", Status: 204},

	// Devices
	"GET /api/admin/v1/devices":                      {Tag: "Devices", Summary: "List devices", Query: with(param{Name: "search", In: "query", Description: "Hostname or serial contains."}, param{Name: "status", In: "query", Description: "active, retired or unenrolled."}), Response: listResponse[deviceJSON]{}},
	"GET /api/admin/v1/devices/export.csv":           {Tag: "Devices", Summary: "Export devices as CSV", ResponseContent: "text/csv"},
	"GET /api/admin/v1/devices/{id}":                 {Tag: "Devices", Summary: "A device, its inventory and recent commands", Response: deviceDetailJSON{}},
	"GET /api/admin/v1/devices/{id}/software":        {Tag: "Devices", Summary: "A device's installed software", Response: listResponse[softwareJSON]{}},
	"POST /api/admin/v1/devices/{id}/retire":         {Tag: "Devices", Summary: "Retire a device: it stops checking in", Status: 204},
	"POST /api/admin/v1/devices/{id}/unenroll":       {Tag: "Devices", Summary: "Unenroll a device: the agent removes its identity", Status: 204},
	"GET /api/admin/v1/devices/{id}/compliance":      {Tag: "Compliance", Summary: "A device's compliance", Response: deviceComplianceJSON{}},
	"GET /api/admin/v1/devices/{id}/bitlocker-keys":  {Tag: "Recovery", Summary: "A device's BitLocker recovery keys (without the keys)", Response: itemsResponse[bitlockerKeyJSON]{}},
	"POST /api/admin/v1/bitlocker-keys/{id}/reveal":  {Tag: "Recovery", Summary: "Reveal a BitLocker recovery key", Request: revealRequest{}, Response: revealResponse{}, Description: "Audited, with the reason given."},
	"GET /api/admin/v1/devices/{id}/admin-passwords": {Tag: "Recovery", Summary: "A device's local admin passwords (without the passwords)", Response: itemsResponse[adminPasswordJSON]{}},
	"POST /api/admin/v1/admin-passwords/{id}/reveal": {Tag: "Recovery", Summary: "Reveal a local admin password", Request: revealRequest{}, Response: revealedPassword{}, Description: "Audited, with the reason given."},

	// Commands and approvals
	"GET /api/admin/v1/commands":                {Tag: "Commands", Summary: "List commands", Query: with(byDevice, param{Name: "status", In: "query"}), Response: listResponse[commandJSON]{}},
	"POST /api/admin/v1/commands":               {Tag: "Commands", Summary: "Queue a command on devices", Request: queueRequest{}, Status: 201, Response: queuedCommands{}, Held: true, Description: "Helpdesk may queue lock, restart, refresh_inventory, collect_logs and rotate_local_admin_password only. A wipe names one device, needs confirm_hostname and a reason, and can't be queued with a token."},
	"GET /api/admin/v1/commands/{id}":           {Tag: "Commands", Summary: "A command and its result", Response: commandDetail{}},
	"GET /api/admin/v1/commands/{id}/artifact":  {Tag: "Commands", Summary: "Download what a command produced, such as collected logs", ResponseContent: "application/zip"},
	"GET /api/admin/v1/approvals":               {Tag: "Approvals", Summary: "List requests held for approval", Query: with(param{Name: "status", In: "query", Description: "pending, approved, rejected, expired or failed."}), Response: listResponse[approvalJSON]{}},
	"POST /api/admin/v1/approvals/{id}/approve": {Tag: "Approvals", Summary: "Approve a held request, carrying it out", Request: decisionRequest{}, Response: approvalEnvelope{}, Description: "Not by the person who asked."},
	"POST /api/admin/v1/approvals/{id}/reject":  {Tag: "Approvals", Summary: "Reject or withdraw a held request", Request: decisionRequest{}, Response: approvalEnvelope{}},

	// Enrollment
	"GET /api/admin/v1/tokens":              {Tag: "Enrollment", Summary: "List enrollment tokens", Response: listResponse[tokenJSON]{}},
	"POST /api/admin/v1/tokens":             {Tag: "Enrollment", Summary: "Create an enrollment token", Request: createTokenRequest{}, Status: 201, Response: createdEnrollmentToken{}, Description: "The token is returned only here."},
	"POST /api/admin/v1/tokens/{id}/revoke": {Tag: "Enrollment", Summary: "Revoke an enrollment token", Status: 204},

	// Administration
	"GET /api/admin/v1/admins":                  {Tag: "Administration", Summary: "List admins", Response: listResponse[adminJSON]{}},
	"POST /api/admin/v1/admins":                 {Tag: "Administration", Summary: "Create an admin", Request: createAdminRequest{}, Status: 201, Response: adminJSON{}},
	"POST /api/admin/v1/admins/{id}/password":   {Tag: "Administration", Summary: "Set an admin's password", Request: passwordRequest{}, Status: 204},
	"POST /api/admin/v1/admins/{id}/totp":       {Tag: "Administration", Summary: "Turn authenticator codes on or off for an admin", Request: totpRequest{}, Response: totpEnrollment{}, Description: "Turning them on answers 200 with the secret to enroll; turning them off answers 204."},
	"POST /api/admin/v1/admins/{id}/disabled":   {Tag: "Administration", Summary: "Disable or re-enable an admin", Request: disabledRequest{}, Status: 204},
	"PUT /api/admin/v1/admins/{id}/scope":       {Tag: "Administration", Summary: "Limit an admin to some device groups", Request: scopeRequest{}, Status: 204},
	"GET /api/admin/v1/api-tokens":              {Tag: "Administration", Summary: "List API tokens", Response: apiTokenList{}},
	"POST /api/admin/v1/api-tokens":             {Tag: "Administration", Summary: "Create an API token", Request: createAPITokenRequest{}, Status: 201, Response: createdAPIToken{}, Description: "The token is returned only here. Its role can't be above your own."},
	"POST /api/admin/v1/api-tokens/{id}/revoke": {Tag: "Administration", Summary: "Revoke an API token", Status: 204},
	"GET /api/admin/v1/audit":                   {Tag: "Administration", Summary: "The audit log", Query: with(auditQuery...), Response: listResponse[auditJSON]{}},
	"GET /api/admin/v1/audit/export.csv":        {Tag: "Administration", Summary: "Export the audit log as CSV", Query: auditQuery, ResponseContent: "text/csv"},

	// Groups and assignments
	"GET /api/admin/v1/groups":                            {Tag: "Groups", Summary: "List groups", Response: itemsResponse[groupJSON]{}},
	"POST /api/admin/v1/groups":                           {Tag: "Groups", Summary: "Create a group", Request: groupRequest{}, Status: 201, Response: groupJSON{}, Description: "A rule that doesn't parse answers 400 with code invalid_rule and the offset of the problem."},
	"POST /api/admin/v1/groups/preview":                   {Tag: "Groups", Summary: "Preview which devices a rule matches", Request: previewRequest{}, Query: paging, Response: listResponse[deviceJSON]{}},
	"GET /api/admin/v1/groups/{id}":                       {Tag: "Groups", Summary: "A group", Response: groupJSON{}},
	"POST /api/admin/v1/groups/{id}":                      {Tag: "Groups", Summary: "Update a group", Request: groupRequest{}, Response: groupJSON{}, Description: "A group's kind can't change."},
	"DELETE /api/admin/v1/groups/{id}":                    {Tag: "Groups", Summary: "Delete a group", Status: 204},
	"POST /api/admin/v1/groups/{id}/evaluate":             {Tag: "Groups", Summary: "Re-evaluate a dynamic group now", Response: memberCount{}},
	"GET /api/admin/v1/groups/{id}/members":               {Tag: "Groups", Summary: "A group's devices", Query: paging, Response: listResponse[deviceJSON]{}},
	"POST /api/admin/v1/groups/{id}/members":              {Tag: "Groups", Summary: "Add a device to a static group", Request: memberRequest{}, Status: 204},
	"DELETE /api/admin/v1/groups/{id}/members/{deviceID}": {Tag: "Groups", Summary: "Remove a device from a static group", Status: 204},
	"GET /api/admin/v1/assignments":                       {Tag: "Groups", Summary: "Where an item is assigned", Query: []param{{Name: "item_kind", In: "query", Description: "script, profile, app, agent, compliance or window. Required."}, {Name: "item_id", In: "query", Description: "Required."}}, Response: itemsResponse[assignmentJSON]{}},
	"POST /api/admin/v1/assignments":                      {Tag: "Groups", Summary: "Assign an item to a group", Request: assignmentRequest{}, Status: 201, Response: assignmentJSON{}, Held: true, Description: "Assigning the same item, group and mode again replaces the assignment."},
	"DELETE /api/admin/v1/assignments/{id}":               {Tag: "Groups", Summary: "Remove an assignment", Status: 204},
	"GET /api/admin/v1/items/{kind}/{id}/status":          {Tag: "Groups", Summary: "How an assigned item is doing on each device", Query: with(param{Name: "status", In: "query"}), Response: statusRollupResponse[itemStatusRowJSON]{}},
	"GET /api/admin/v1/maintenance-windows":               {Tag: "Groups", Summary: "List maintenance windows", Response: listResponse[windowJSON]{}},
	"POST /api/admin/v1/maintenance-windows":              {Tag: "Groups", Summary: "Create a maintenance window", Request: windowRequest{}, Status: 201, Response: windowJSON{}},
	"GET /api/admin/v1/maintenance-windows/{id}":          {Tag: "Groups", Summary: "A maintenance window", Response: windowJSON{}},
	"POST /api/admin/v1/maintenance-windows/{id}":         {Tag: "Groups", Summary: "Update a maintenance window", Request: windowRequest{}, Response: windowJSON{}},
	"DELETE /api/admin/v1/maintenance-windows/{id}":       {Tag: "Groups", Summary: "Delete a maintenance window and its assignments", Status: 204},

	// Scripts
	"GET /api/admin/v1/scripts":               {Tag: "Scripts", Summary: "List scripts", Query: paging, Response: listResponse[scriptJSON]{}},
	"POST /api/admin/v1/scripts":              {Tag: "Scripts", Summary: "Create a script", Request: scriptRequest{}, Status: 201, Response: scriptJSON{}},
	"GET /api/admin/v1/scripts/{id}":          {Tag: "Scripts", Summary: "A script", Response: scriptJSON{}},
	"POST /api/admin/v1/scripts/{id}":         {Tag: "Scripts", Summary: "Update a script, making a new version if its code changed", Request: scriptRequest{}, Response: scriptJSON{}},
	"DELETE /api/admin/v1/scripts/{id}":       {Tag: "Scripts", Summary: "Delete a script and its assignments", Status: 204},
	"GET /api/admin/v1/scripts/{id}/versions": {Tag: "Scripts", Summary: "A script's versions", Response: itemsResponse[scriptVersionJSON]{}},
	"GET /api/admin/v1/scripts/{id}/runs":     {Tag: "Scripts", Summary: "A script's runs", Query: with(byDevice), Response: listResponse[scriptRunJSON]{}},

	// Profiles
	"GET /api/admin/v1/profiles":               {Tag: "Profiles", Summary: "List configuration profiles", Query: paging, Response: listResponse[profileJSON]{}},
	"POST /api/admin/v1/profiles":              {Tag: "Profiles", Summary: "Create a configuration profile", Request: profileRequest{}, Status: 201, Response: profileJSON{}},
	"GET /api/admin/v1/profiles/{id}":          {Tag: "Profiles", Summary: "A configuration profile", Response: profileJSON{}},
	"POST /api/admin/v1/profiles/{id}":         {Tag: "Profiles", Summary: "Update a configuration profile, making a new version", Request: profileRequest{}, Response: profileJSON{}},
	"DELETE /api/admin/v1/profiles/{id}":       {Tag: "Profiles", Summary: "Delete a configuration profile and its assignments", Status: 204},
	"GET /api/admin/v1/profiles/{id}/versions": {Tag: "Profiles", Summary: "A profile's versions", Response: itemsResponse[profileVersionJSON]{}},
	"GET /api/admin/v1/profiles/{id}/settings": {Tag: "Profiles", Summary: "How each of a profile's settings is doing on each device", Query: with(param{Name: "status", In: "query"}), Response: statusRollupResponse[settingStatusRowJSON]{}},

	// Apps
	"GET /api/admin/v1/apps":               {Tag: "Apps", Summary: "List apps", Query: paging, Response: listResponse[appJSON]{}},
	"POST /api/admin/v1/apps":              {Tag: "Apps", Summary: "Create an app: a winget package or an uploaded installer", Request: appRequest{}, Status: 201, Response: appJSON{}},
	"POST /api/admin/v1/app-packages":      {Tag: "Apps", Summary: "Upload an installer (MSI or EXE) for an app", RequestContent: "application/octet-stream", Query: []param{{Name: "file_name", In: "query", Description: "The installer's file name."}}, Status: 201, Response: uploadedPackage{}},
	"GET /api/admin/v1/apps/{id}":          {Tag: "Apps", Summary: "An app", Response: appJSON{}},
	"POST /api/admin/v1/apps/{id}":         {Tag: "Apps", Summary: "Update an app, making a new version", Request: appRequest{}, Response: appJSON{}},
	"DELETE /api/admin/v1/apps/{id}":       {Tag: "Apps", Summary: "Delete an app and its assignments", Status: 204},
	"GET /api/admin/v1/apps/{id}/versions": {Tag: "Apps", Summary: "An app's versions", Response: itemsResponse[appVersionJSON]{}},
	"GET /api/admin/v1/apps/{id}/installs": {Tag: "Apps", Summary: "An app's install history", Query: with(byDevice), Response: listResponse[appInstallJSON]{}},

	// Agent versions
	"GET /api/admin/v1/agent-versions":         {Tag: "Agent versions", Summary: "List agent builds", Query: paging, Response: listResponse[agentVersionJSON]{}},
	"POST /api/admin/v1/agent-versions":        {Tag: "Agent versions", Summary: "Upload a signed agent build", RequestContent: "application/octet-stream", Query: []param{{Name: "version", In: "query", Description: "The build's version. Required."}, {Name: "notes", In: "query"}}, Status: 201, Response: agentVersionJSON{}, Description: "The release signature travels in the X-Retune-Signature header."},
	"GET /api/admin/v1/agent-versions/{id}":    {Tag: "Agent versions", Summary: "An agent build", Response: agentVersionJSON{}},
	"DELETE /api/admin/v1/agent-versions/{id}": {Tag: "Agent versions", Summary: "Delete an agent build and its assignments", Status: 204},

	// Compliance
	"GET /api/admin/v1/compliance-policies":                         {Tag: "Compliance", Summary: "List compliance policies", Query: paging, Response: listResponse[compliancePolicyJSON]{}},
	"POST /api/admin/v1/compliance-policies":                        {Tag: "Compliance", Summary: "Create a compliance policy", Request: compliancePolicyRequest{}, Status: 201, Response: compliancePolicyJSON{}},
	"GET /api/admin/v1/compliance-policies/{id}":                    {Tag: "Compliance", Summary: "A compliance policy", Response: compliancePolicyJSON{}},
	"POST /api/admin/v1/compliance-policies/{id}":                   {Tag: "Compliance", Summary: "Update a compliance policy", Request: compliancePolicyRequest{}, Response: compliancePolicyJSON{}},
	"DELETE /api/admin/v1/compliance-policies/{id}":                 {Tag: "Compliance", Summary: "Delete a compliance policy, its assignments and results", Status: 204},
	"POST /api/admin/v1/compliance-policies/{id}/evaluate":          {Tag: "Compliance", Summary: "Re-evaluate a policy on every device it applies to", Status: 202, Response: evaluationStarted{}},
	"GET /api/admin/v1/compliance-policies/{id}/devices":            {Tag: "Compliance", Summary: "A policy's result on each device", Query: with(param{Name: "state", In: "query", Description: "compliant, non_compliant or unknown."}), Response: listResponse[policyDeviceComplianceJSON]{}},
	"GET /api/admin/v1/compliance-policies/{id}/devices/export.csv": {Tag: "Compliance", Summary: "Export a policy's results as CSV", Query: []param{{Name: "state", In: "query"}}, ResponseContent: "text/csv"},

	// Alerts
	"GET /api/admin/v1/notification-channels":            {Tag: "Alerts", Summary: "List notification channels", Response: itemsResponse[channelJSON]{}},
	"POST /api/admin/v1/notification-channels":           {Tag: "Alerts", Summary: "Create a notification channel (email or webhook)", Request: channelRequest{}, Status: 201, Response: channelJSON{}},
	"GET /api/admin/v1/notification-channels/{id}":       {Tag: "Alerts", Summary: "A notification channel", Response: channelJSON{}},
	"POST /api/admin/v1/notification-channels/{id}":      {Tag: "Alerts", Summary: "Update a notification channel", Request: channelRequest{}, Response: channelJSON{}},
	"DELETE /api/admin/v1/notification-channels/{id}":    {Tag: "Alerts", Summary: "Delete a notification channel", Status: 204},
	"POST /api/admin/v1/notification-channels/{id}/test": {Tag: "Alerts", Summary: "Send a test message", Response: channelTest{}, Description: "A failed send answers 502."},
	"GET /api/admin/v1/alert-rules":                      {Tag: "Alerts", Summary: "List alert rules", Response: itemsResponse[alertRuleJSON]{}},
	"POST /api/admin/v1/alert-rules":                     {Tag: "Alerts", Summary: "Create an alert rule", Request: alertRuleRequest{}, Status: 201, Response: alertRuleJSON{}},
	"GET /api/admin/v1/alert-rules/{id}":                 {Tag: "Alerts", Summary: "An alert rule", Response: alertRuleJSON{}},
	"POST /api/admin/v1/alert-rules/{id}":                {Tag: "Alerts", Summary: "Update an alert rule", Request: alertRuleRequest{}, Response: alertRuleJSON{}},
	"DELETE /api/admin/v1/alert-rules/{id}":              {Tag: "Alerts", Summary: "Delete an alert rule", Status: 204},
	"GET /api/admin/v1/alerts":                           {Tag: "Alerts", Summary: "Alerts firing now", Response: itemsResponse[firingAlertJSON]{}},
	"GET /api/admin/v1/alert-deliveries":                 {Tag: "Alerts", Summary: "Recent alert deliveries", Response: itemsResponse[deliveryJSON]{}},

	// Overview
	"GET /api/admin/v1/dashboard":    {Tag: "Overview", Summary: "Fleet-wide counts for the overview page", Response: dashboardJSON{}},
	"GET /api/admin/v1/openapi.json": {Tag: "Overview", Summary: "This document", Description: "OpenAPI 3.1.", Response: map[string]any{}},
}
