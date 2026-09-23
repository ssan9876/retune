package config

import (
	"strings"
	"testing"
	"time"

	"retune/internal/release"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadServerDefaults(t *testing.T) {
	c, err := LoadServer(env(map[string]string{
		"DATABASE_URL": "postgres://u:p@db/retune",
		"PUBLIC_URL":   "https://mdm.example.com",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.AgentListen != ":8443" || c.TLSMode != "self-signed" || c.DataDir != "data" || c.CheckinInterval != 5*time.Minute {
		t.Fatalf("unexpected defaults: %+v", c)
	}
	if c.PublicHost() != "mdm.example.com" {
		t.Fatalf("PublicHost = %q", c.PublicHost())
	}
}

func TestLoadServerErrors(t *testing.T) {
	base := map[string]string{"DATABASE_URL": "postgres://x", "PUBLIC_URL": "https://h"}
	cases := map[string]struct {
		override map[string]string
		wantErr  string
	}{
		"missing db":          {map[string]string{"DATABASE_URL": ""}, "DATABASE_URL"},
		"http public url":     {map[string]string{"PUBLIC_URL": "http://h"}, "PUBLIC_URL"},
		"missing public url":  {map[string]string{"PUBLIC_URL": ""}, "PUBLIC_URL"},
		"bad tls mode":        {map[string]string{"TLS_MODE": "passthrough"}, "TLS_MODE"},
		"bad ca key source":   {map[string]string{"CA_KEY_SOURCE": "kms"}, "CA_KEY_SOURCE"},
		"provided needs cert": {map[string]string{"TLS_MODE": "provided"}, "TLS_CERT_FILE"},
		"interval too small":  {map[string]string{"CHECKIN_INTERVAL_SECONDS": "5"}, "CHECKIN_INTERVAL_SECONDS"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			m := map[string]string{}
			for k, v := range base {
				m[k] = v
			}
			for k, v := range tc.override {
				m[k] = v
			}
			_, err := LoadServer(env(m))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want mention of %s", err, tc.wantErr)
			}
		})
	}
}

func TestSessionTTL(t *testing.T) {
	base := map[string]string{"DATABASE_URL": "postgres://x", "PUBLIC_URL": "https://h"}
	c, err := LoadServer(env(base))
	if err != nil || c.SessionTTL != 12*time.Hour {
		t.Fatalf("default SessionTTL = %s, err = %v", c.SessionTTL, err)
	}
	base["SESSION_TTL_HOURS"] = "36"
	if c, err = LoadServer(env(base)); err != nil || c.SessionTTL != 36*time.Hour {
		t.Fatalf("SessionTTL = %s, err = %v", c.SessionTTL, err)
	}
	for _, bad := range []string{"0", "-1", "200", "abc"} {
		base["SESSION_TTL_HOURS"] = bad
		if _, err := LoadServer(env(base)); err == nil {
			t.Errorf("SESSION_TTL_HOURS=%s must be rejected", bad)
		}
	}
}

func TestLoadServerProvidedAndInterval(t *testing.T) {
	c, err := LoadServer(env(map[string]string{
		"DATABASE_URL": "postgres://x", "PUBLIC_URL": "https://h",
		"TLS_MODE": "provided", "TLS_CERT_FILE": "c.pem", "TLS_KEY_FILE": "k.pem",
		"CHECKIN_INTERVAL_SECONDS": "60",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.TLSMode != "provided" || c.CheckinInterval != time.Minute {
		t.Fatalf("got %+v", c)
	}
}

func TestLoadServerBehindProxy(t *testing.T) {
	base := map[string]string{
		"DATABASE_URL": "postgres://x/y",
		"PUBLIC_URL":   "https://mdm.example.com",
		"TLS_MODE":     "behind-proxy",
	}
	with := func(extra map[string]string) func(string) string {
		m := map[string]string{}
		for k, v := range base {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return env(m)
	}

	t.Run("requires a trusted proxy list", func(t *testing.T) {
		_, err := LoadServer(with(nil))
		if err == nil || !strings.Contains(err.Error(), "TRUSTED_PROXIES") {
			t.Fatalf("want a TRUSTED_PROXIES error, got %v", err)
		}
	})

	t.Run("rejects an empty header name", func(t *testing.T) {
		_, err := LoadServer(with(map[string]string{
			"TRUSTED_PROXIES": "10.0.0.0/8", "CLIENT_CERT_HEADER": " ",
		}))
		if err == nil || !strings.Contains(err.Error(), "CLIENT_CERT_HEADER") {
			t.Fatalf("want a CLIENT_CERT_HEADER error, got %v", err)
		}
	})

	t.Run("accepts CIDRs and bare addresses", func(t *testing.T) {
		c, err := LoadServer(with(map[string]string{"TRUSTED_PROXIES": "10.0.0.0/8, 192.168.1.7"}))
		if err != nil {
			t.Fatal(err)
		}
		if len(c.TrustedProxies) != 2 {
			t.Fatalf("want 2 prefixes, got %d", len(c.TrustedProxies))
		}
		if !c.TrustedProxies[1].IsSingleIP() {
			t.Error("a bare address should become a single-IP prefix")
		}
		if c.ClientCertHeader != "X-Forwarded-Client-Cert" {
			t.Errorf("default header = %q", c.ClientCertHeader)
		}
	})

	t.Run("rejects an unparseable entry", func(t *testing.T) {
		_, err := LoadServer(with(map[string]string{"TRUSTED_PROXIES": "10.0.0.0/8, nonsense"}))
		if err == nil || !strings.Contains(err.Error(), "nonsense") {
			t.Fatalf("want the bad value named, got %v", err)
		}
	})
}

func TestSweepInterval(t *testing.T) {
	base := map[string]string{"DATABASE_URL": "postgres://x", "PUBLIC_URL": "https://h"}
	with := func(v string) func(string) string {
		m := map[string]string{}
		for k, val := range base {
			m[k] = val
		}
		if v != "" {
			m["SWEEP_INTERVAL_SECONDS"] = v
		}
		return env(m)
	}
	c, err := LoadServer(with(""))
	if err != nil || c.SweepInterval != 5*time.Minute {
		t.Fatalf("default sweep interval = %v, err %v", c.SweepInterval, err)
	}
	if c, err := LoadServer(with("30")); err != nil || c.SweepInterval != 30*time.Second {
		t.Fatalf("sweep interval = %v, err %v", c.SweepInterval, err)
	}
	if _, err := LoadServer(with("5")); err == nil {
		t.Error("want an error below the 10 second minimum")
	}
}

func TestAgentReleaseKeysParse(t *testing.T) {
	priv, _ := release.GenerateKey()
	env := map[string]string{
		"DATABASE_URL": "postgres://x", "PUBLIC_URL": "https://mdm.example.com",
		"AGENT_RELEASE_KEYS": priv.Public().Encode(),
	}
	cfg, err := LoadServer(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.AgentReleaseKeys) != 1 || cfg.AgentReleaseKeys[0].ID() != priv.Public().ID() {
		t.Fatalf("keys = %+v", cfg.AgentReleaseKeys)
	}
	env["AGENT_RELEASE_KEYS"] = "junk"
	if _, err := LoadServer(func(k string) string { return env[k] }); err == nil {
		t.Error("a malformed key list must refuse to start the server")
	}
	delete(env, "AGENT_RELEASE_KEYS")
	if cfg, err := LoadServer(func(k string) string { return env[k] }); err != nil || len(cfg.AgentReleaseKeys) != 0 {
		t.Error("no keys is allowed at startup; uploads are what refuse")
	}
}

func TestRetention(t *testing.T) {
	base := map[string]string{"DATABASE_URL": "postgres://x", "PUBLIC_URL": "https://h"}
	c, err := LoadServer(env(base))
	if err != nil {
		t.Fatal(err)
	}
	day := 24 * time.Hour
	want := Retention{Audit: 365 * day, Commands: 90 * day, ScriptRuns: 90 * day, AppInstalls: 90 * day}
	if c.Retention != want {
		t.Fatalf("defaults = %+v, want %+v", c.Retention, want)
	}

	m := map[string]string{
		"AUDIT_RETENTION_DAYS": "0", "COMMAND_RETENTION_DAYS": "7",
		"SCRIPT_RUN_RETENTION_DAYS": "3650", "APP_INSTALL_RETENTION_DAYS": "1",
	}
	for k, v := range base {
		m[k] = v
	}
	c, err = LoadServer(env(m))
	if err != nil {
		t.Fatal(err)
	}
	want = Retention{Audit: 0, Commands: 7 * day, ScriptRuns: 3650 * day, AppInstalls: day}
	if c.Retention != want {
		t.Fatalf("set = %+v, want %+v", c.Retention, want)
	}

	for _, bad := range []string{"-1", "3651", "ninety"} {
		m := map[string]string{"COMMAND_RETENTION_DAYS": bad}
		for k, v := range base {
			m[k] = v
		}
		if _, err := LoadServer(env(m)); err == nil || !strings.Contains(err.Error(), "COMMAND_RETENTION_DAYS") {
			t.Errorf("%q: want an error naming the setting, got %v", bad, err)
		}
	}
}

func TestMetricsToken(t *testing.T) {
	base := map[string]string{"DATABASE_URL": "postgres://x", "PUBLIC_URL": "https://h"}
	c, err := LoadServer(env(base))
	if err != nil || c.MetricsToken != "" {
		t.Fatalf("unset: %q %v", c.MetricsToken, err)
	}
	long := strings.Repeat("k", 32)
	base["METRICS_TOKEN"] = long
	if c, err = LoadServer(env(base)); err != nil || c.MetricsToken != long {
		t.Fatalf("set: %q %v", c.MetricsToken, err)
	}
	base["METRICS_TOKEN"] = strings.Repeat("k", 31)
	if _, err := LoadServer(env(base)); err == nil || !strings.Contains(err.Error(), "METRICS_TOKEN") {
		t.Fatalf("a short token should be refused, got %v", err)
	}
}

func TestOIDC(t *testing.T) {
	load := func(extra map[string]string) (Server, error) {
		m := map[string]string{"DATABASE_URL": "postgres://x", "PUBLIC_URL": "https://h"}
		for k, v := range extra {
			m[k] = v
		}
		return LoadServer(env(m))
	}
	full := map[string]string{
		"OIDC_ISSUER": "https://login.example.com/tenant/", "OIDC_CLIENT_ID": "retune",
		"OIDC_CLIENT_SECRET": "s3cret", "OIDC_ADMIN_GROUPS": "it-admins, helpdesk-leads",
	}
	c, err := load(nil)
	if err != nil || c.OIDC.Enabled() {
		t.Fatalf("unset: %+v %v", c.OIDC, err)
	}
	c, err = load(full)
	if err != nil {
		t.Fatal(err)
	}
	o := c.OIDC
	if !o.Enabled() || o.Issuer != "https://login.example.com/tenant" || o.GroupsClaim != "groups" ||
		len(o.AdminGroups) != 2 || o.AdminGroups[1] != "helpdesk-leads" || o.DisplayName != "Sign in with SSO" {
		t.Fatalf("config = %+v", o)
	}

	for name, tc := range map[string]struct {
		set     map[string]string
		mention string
	}{
		"half configured": {map[string]string{"OIDC_ISSUER": "https://idp"}, "all of OIDC_ISSUER"},
		"no groups": {map[string]string{"OIDC_ISSUER": "https://idp", "OIDC_CLIENT_ID": "a", "OIDC_CLIENT_SECRET": "b"},
			"OIDC_HELPDESK_GROUPS or OIDC_READONLY_GROUPS"},
		"plain http": {map[string]string{"OIDC_ISSUER": "http://idp.example.com", "OIDC_CLIENT_ID": "a",
			"OIDC_CLIENT_SECRET": "b", "OIDC_ADMIN_GROUPS": "x"}, "must be https"},
		"local login off without SSO": {map[string]string{"OIDC_DISABLE_LOCAL_LOGIN": "true"}, "nobody could sign in"},
	} {
		if _, err := load(tc.set); err == nil || !strings.Contains(err.Error(), tc.mention) {
			t.Errorf("%s: want an error mentioning %q, got %v", name, tc.mention, err)
		}
	}
	local := map[string]string{"OIDC_ISSUER": "http://localhost:5556", "OIDC_CLIENT_ID": "a",
		"OIDC_CLIENT_SECRET": "b", "OIDC_READONLY_GROUPS": "x", "OIDC_DISABLE_LOCAL_LOGIN": "true"}
	if c, err := load(local); err != nil || !c.OIDC.DisableLocalLogin {
		t.Fatalf("http on localhost is allowed for trying things out: %+v %v", c.OIDC, err)
	}
}

func TestSessionMaxLifetime(t *testing.T) {
	load := func(extra map[string]string) (Server, error) {
		m := map[string]string{"DATABASE_URL": "postgres://x", "PUBLIC_URL": "https://h"}
		for k, v := range extra {
			m[k] = v
		}
		return LoadServer(env(m))
	}
	if c, err := load(nil); err != nil || c.SessionMaxLifetime != 24*time.Hour {
		t.Fatalf("default = %s, %v", c.SessionMaxLifetime, err)
	}
	// An existing longer idle timeout keeps working after an upgrade.
	if c, err := load(map[string]string{"SESSION_TTL_HOURS": "36"}); err != nil || c.SessionMaxLifetime != 36*time.Hour {
		t.Fatalf("with a 36h idle timeout = %s, %v", c.SessionMaxLifetime, err)
	}
	if c, err := load(map[string]string{"SESSION_MAX_HOURS": "8", "SESSION_TTL_HOURS": "4"}); err != nil || c.SessionMaxLifetime != 8*time.Hour {
		t.Fatalf("set = %s, %v", c.SessionMaxLifetime, err)
	}
	for _, bad := range []map[string]string{
		{"SESSION_MAX_HOURS": "0"}, {"SESSION_MAX_HOURS": "721"},
		{"SESSION_MAX_HOURS": "6", "SESSION_TTL_HOURS": "12"},
	} {
		if _, err := load(bad); err == nil {
			t.Errorf("%v should be refused", bad)
		}
	}
}

func TestAuditStream(t *testing.T) {
	load := func(extra map[string]string) (Server, error) {
		m := map[string]string{"DATABASE_URL": "postgres://x", "PUBLIC_URL": "https://h"}
		for k, v := range extra {
			m[k] = v
		}
		return LoadServer(env(m))
	}
	if c, err := load(nil); err != nil || c.AuditStream.Enabled() {
		t.Fatalf("unset: %+v %v", c.AuditStream, err)
	}
	c, err := load(map[string]string{
		"AUDIT_SYSLOG_ADDRESS": "tls://siem.example.com:6514",
		"AUDIT_WEBHOOK_URL":    "https://http-inputs.example.splunkcloud.com/services/collector/raw",
		"AUDIT_WEBHOOK_HEADER": "Authorization: Splunk 0000",
	})
	if err != nil {
		t.Fatal(err)
	}
	a := c.AuditStream
	if a.SyslogNetwork != "tls" || a.SyslogAddress != "siem.example.com:6514" || a.WebhookHeader != "Authorization: Splunk 0000" {
		t.Fatalf("config = %+v", a)
	}
	for name, bad := range map[string]map[string]string{
		"no port":         {"AUDIT_SYSLOG_ADDRESS": "tcp://siem.example.com"},
		"wrong scheme":    {"AUDIT_SYSLOG_ADDRESS": "http://siem.example.com:514"},
		"plain http hook": {"AUDIT_WEBHOOK_URL": "http://siem.example.com/in"},
		"header no hook":  {"AUDIT_WEBHOOK_HEADER": "Authorization: x"},
		"header no colon": {"AUDIT_WEBHOOK_URL": "https://s/in", "AUDIT_WEBHOOK_HEADER": "Authorization x"},
	} {
		if _, err := load(bad); err == nil {
			t.Errorf("%s should be refused", name)
		}
	}
}

func TestOIDCScopeGroups(t *testing.T) {
	load := func(extra map[string]string) (Server, error) {
		m := map[string]string{
			"DATABASE_URL": "postgres://x", "PUBLIC_URL": "https://h",
			"OIDC_ISSUER": "https://idp.example.com", "OIDC_CLIENT_ID": "a", "OIDC_CLIENT_SECRET": "b",
			"OIDC_ADMIN_GROUPS": "it-admins",
		}
		for k, v := range extra {
			m[k] = v
		}
		return LoadServer(env(m))
	}
	c, err := load(map[string]string{
		"OIDC_SCOPE_GROUPS": " helpdesk-emea = EMEA laptops, desktops ; helpdesk-emea=Kiosks;helpdesk-us=US laptops; ",
		"OIDC_FLEET_GROUPS": "it-admins",
	})
	if err != nil {
		t.Fatal(err)
	}
	o := c.OIDC
	emea := o.ScopeGroups["helpdesk-emea"]
	if !o.ManagesScopes() || len(emea) != 2 || emea[0] != "EMEA laptops, desktops" || emea[1] != "Kiosks" ||
		len(o.ScopeGroups["helpdesk-us"]) != 1 || len(o.FleetGroups) != 1 {
		t.Fatalf("config = %+v", o)
	}
	if c, err := load(nil); err != nil || c.OIDC.ManagesScopes() {
		t.Fatalf("no mapping: %+v %v", c.OIDC, err)
	}

	for name, tc := range map[string]struct {
		set     map[string]string
		mention string
	}{
		"no equals":         {map[string]string{"OIDC_SCOPE_GROUPS": "helpdesk-emea"}, "idp-group=Device group"},
		"empty group":       {map[string]string{"OIDC_SCOPE_GROUPS": "helpdesk-emea="}, "idp-group=Device group"},
		"fleet without map": {map[string]string{"OIDC_FLEET_GROUPS": "it-admins"}, "OIDC_SCOPE_GROUPS"},
		"map without SSO": {map[string]string{
			"OIDC_ISSUER": "", "OIDC_CLIENT_ID": "", "OIDC_CLIENT_SECRET": "", "OIDC_SCOPE_GROUPS": "a=b",
		}, "needs SSO"},
	} {
		if _, err := load(tc.set); err == nil || !strings.Contains(err.Error(), tc.mention) {
			t.Errorf("%s: want an error mentioning %q, got %v", name, tc.mention, err)
		}
	}
}
