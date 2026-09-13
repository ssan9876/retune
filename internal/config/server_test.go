package config

import (
	"strings"
	"testing"
	"time"
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
