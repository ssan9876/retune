package adminapi

import (
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestClientIPBelievesOnlyTrustedProxies(t *testing.T) {
	h := &Handler{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	for _, tc := range []struct {
		name, remote, xff, want string
	}{
		{"direct, no header", "198.51.100.7:5000", "", "198.51.100.7"},
		{"direct, forged header", "198.51.100.7:5000", "203.0.113.1", "198.51.100.7"},
		{"through the proxy", "10.0.0.2:443", "203.0.113.1", "203.0.113.1"},
		{"client prepends a lie", "10.0.0.2:443", "1.2.3.4, 203.0.113.1", "203.0.113.1"},
		{"two trusted hops", "10.0.0.2:443", "203.0.113.1, 10.0.0.9", "203.0.113.1"},
		{"proxy sent nothing", "10.0.0.2:443", "", "10.0.0.2"},
		{"garbage", "10.0.0.2:443", "not-an-address", "10.0.0.2"},
		{"IPv4-mapped", "10.0.0.2:443", "::ffff:203.0.113.1", "203.0.113.1"},
	} {
		r := httptest.NewRequest("POST", "/api/admin/v1/session", nil)
		r.RemoteAddr = tc.remote
		if tc.xff != "" {
			r.Header.Set("X-Forwarded-For", tc.xff)
		}
		if got := h.clientIP(r); got != tc.want {
			t.Errorf("%s: clientIP = %q, want %q", tc.name, got, tc.want)
		}
	}
}
