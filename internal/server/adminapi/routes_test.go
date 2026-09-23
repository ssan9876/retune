package adminapi

import (
	"sort"
	"testing"
)

// expectedRoutes is every admin API route and who may call it:
//
//	public   no sign-in: setup, sign-in, the SSO redirects
//	scoped   anyone signed in or holding a token; a scoped admin sees their devices only
//	fleet    as scoped, but a scoped admin is refused: it concerns the whole fleet
//	session  a person at the console, not an API token; scoped admins within their devices
//	admin    a person, unscoped: managing admins and API tokens
//
// and "+write" where the admin role is needed. A route added without an entry
// here fails the test, so nobody adds one without deciding who may call it.
var expectedRoutes = map[string]string{
	"DELETE /api/admin/v1/agent-versions/{id}":                      "fleet+write",
	"DELETE /api/admin/v1/alert-rules/{id}":                         "fleet+write",
	"DELETE /api/admin/v1/apps/{id}":                                "fleet+write",
	"DELETE /api/admin/v1/assignments/{id}":                         "scoped+write",
	"DELETE /api/admin/v1/compliance-policies/{id}":                 "fleet+write",
	"DELETE /api/admin/v1/groups/{id}":                              "fleet+write",
	"DELETE /api/admin/v1/groups/{id}/members/{deviceID}":           "fleet+write",
	"DELETE /api/admin/v1/notification-channels/{id}":               "fleet+write",
	"DELETE /api/admin/v1/profiles/{id}":                            "fleet+write",
	"DELETE /api/admin/v1/scripts/{id}":                             "fleet+write",
	"DELETE /api/admin/v1/session":                                  "session",
	"GET /api/admin/v1/admins":                                      "admin",
	"GET /api/admin/v1/agent-versions":                              "scoped",
	"GET /api/admin/v1/agent-versions/{id}":                         "scoped",
	"GET /api/admin/v1/alert-deliveries":                            "fleet",
	"GET /api/admin/v1/alert-rules":                                 "fleet",
	"GET /api/admin/v1/alert-rules/{id}":                            "fleet",
	"GET /api/admin/v1/alerts":                                      "fleet",
	"GET /api/admin/v1/api-tokens":                                  "admin",
	"GET /api/admin/v1/apps":                                        "scoped",
	"GET /api/admin/v1/apps/{id}":                                   "scoped",
	"GET /api/admin/v1/apps/{id}/installs":                          "scoped",
	"GET /api/admin/v1/apps/{id}/versions":                          "scoped",
	"GET /api/admin/v1/assignments":                                 "scoped",
	"GET /api/admin/v1/audit/export.csv":                            "fleet",
	"GET /api/admin/v1/audit":                                       "fleet",
	"GET /api/admin/v1/commands":                                    "scoped",
	"GET /api/admin/v1/commands/{id}":                               "scoped",
	"GET /api/admin/v1/commands/{id}/artifact":                      "scoped+write",
	"GET /api/admin/v1/compliance-policies":                         "scoped",
	"GET /api/admin/v1/compliance-policies/{id}":                    "scoped",
	"GET /api/admin/v1/compliance-policies/{id}/devices":            "scoped",
	"GET /api/admin/v1/compliance-policies/{id}/devices/export.csv": "scoped",
	"GET /api/admin/v1/dashboard":                                   "scoped",
	"GET /api/admin/v1/devices":                                     "scoped",
	"GET /api/admin/v1/devices/export.csv":                          "scoped",
	"GET /api/admin/v1/devices/{id}":                                "scoped",
	"GET /api/admin/v1/devices/{id}/bitlocker-keys":                 "scoped",
	"GET /api/admin/v1/devices/{id}/compliance":                     "scoped",
	"GET /api/admin/v1/devices/{id}/software":                       "scoped",
	"GET /api/admin/v1/groups":                                      "scoped",
	"GET /api/admin/v1/groups/{id}":                                 "scoped",
	"GET /api/admin/v1/groups/{id}/members":                         "scoped",
	"GET /api/admin/v1/items/{kind}/{id}/status":                    "scoped",
	"GET /api/admin/v1/notification-channels":                       "fleet",
	"GET /api/admin/v1/notification-channels/{id}":                  "fleet",
	"GET /api/admin/v1/oidc/callback":                               "public",
	"GET /api/admin/v1/oidc/start":                                  "public",
	"GET /api/admin/v1/profiles":                                    "scoped",
	"GET /api/admin/v1/profiles/{id}":                               "scoped",
	"GET /api/admin/v1/profiles/{id}/settings":                      "scoped",
	"GET /api/admin/v1/profiles/{id}/versions":                      "scoped",
	"GET /api/admin/v1/scripts":                                     "scoped",
	"GET /api/admin/v1/scripts/{id}":                                "scoped",
	"GET /api/admin/v1/scripts/{id}/runs":                           "scoped",
	"GET /api/admin/v1/scripts/{id}/versions":                       "scoped",
	"GET /api/admin/v1/session":                                     "session",
	"GET /api/admin/v1/setup":                                       "public",
	"GET /api/admin/v1/tokens":                                      "fleet",
	"POST /api/admin/v1/admins":                                     "admin+write",
	"POST /api/admin/v1/admins/{id}/disabled":                       "admin+write",
	"POST /api/admin/v1/admins/{id}/password":                       "admin+write",
	"POST /api/admin/v1/admins/{id}/totp":                           "admin+write",
	"POST /api/admin/v1/agent-versions":                             "fleet+write",
	"POST /api/admin/v1/alert-rules":                                "fleet+write",
	"POST /api/admin/v1/alert-rules/{id}":                           "fleet+write",
	"POST /api/admin/v1/api-tokens":                                 "admin+write",
	"POST /api/admin/v1/api-tokens/{id}/revoke":                     "admin+write",
	"POST /api/admin/v1/apps":                                       "fleet+write",
	"POST /api/admin/v1/app-packages":                               "fleet+write",
	"POST /api/admin/v1/apps/{id}":                                  "fleet+write",
	"POST /api/admin/v1/assignments":                                "scoped+write",
	"POST /api/admin/v1/bitlocker-keys/{id}/reveal":                 "session+write",
	"POST /api/admin/v1/commands":                                   "scoped+write",
	"POST /api/admin/v1/compliance-policies":                        "fleet+write",
	"POST /api/admin/v1/compliance-policies/{id}":                   "fleet+write",
	"POST /api/admin/v1/compliance-policies/{id}/evaluate":          "fleet+write",
	"POST /api/admin/v1/devices/{id}/retire":                        "scoped+write",
	"POST /api/admin/v1/devices/{id}/unenroll":                      "scoped+write",
	"POST /api/admin/v1/groups":                                     "fleet+write",
	"POST /api/admin/v1/groups/preview":                             "fleet+write",
	"POST /api/admin/v1/groups/{id}":                                "fleet+write",
	"POST /api/admin/v1/groups/{id}/evaluate":                       "fleet+write",
	"POST /api/admin/v1/groups/{id}/members":                        "fleet+write",
	"POST /api/admin/v1/notification-channels":                      "fleet+write",
	"POST /api/admin/v1/notification-channels/{id}":                 "fleet+write",
	"POST /api/admin/v1/notification-channels/{id}/test":            "fleet+write",
	"POST /api/admin/v1/profiles":                                   "fleet+write",
	"POST /api/admin/v1/profiles/{id}":                              "fleet+write",
	"POST /api/admin/v1/scripts":                                    "fleet+write",
	"POST /api/admin/v1/scripts/{id}":                               "fleet+write",
	"POST /api/admin/v1/session":                                    "public",
	"POST /api/admin/v1/tokens":                                     "fleet+write",
	"POST /api/admin/v1/tokens/{id}/revoke":                         "fleet+write",
	"PUT /api/admin/v1/admins/{id}/scope":                           "admin+write",
}

func routeClass(g guarded) string {
	if g.open {
		return "public"
	}
	c := "scoped"
	switch {
	case g.access.session && g.access.fleet:
		c = "admin"
	case g.access.session:
		c = "session"
	case g.access.fleet:
		c = "fleet"
	}
	if g.access.admin {
		c += "+write"
	}
	return c
}

func TestEveryRouteHasTheClassItShould(t *testing.T) {
	h := &Handler{}
	h.Routes()
	var patterns []string
	for p := range h.routes {
		patterns = append(patterns, p)
	}
	sort.Strings(patterns)
	for _, p := range patterns {
		want, ok := expectedRoutes[p]
		if !ok {
			t.Errorf("%s is not in expectedRoutes: decide who may call it, and add it", p)
			continue
		}
		if got := routeClass(h.routes[p]); got != want {
			t.Errorf("%s is %s, want %s", p, got, want)
		}
	}
	for p := range expectedRoutes {
		if _, ok := h.routes[p]; !ok {
			t.Errorf("%s is expected but not registered", p)
		}
	}
}
