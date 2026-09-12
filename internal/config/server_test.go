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
		"bad tls mode":        {map[string]string{"TLS_MODE": "behind-proxy"}, "TLS_MODE"},
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
