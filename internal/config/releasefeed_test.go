package config

import (
	"testing"
	"time"
)

func TestReleaseFeed(t *testing.T) {
	env := map[string]string{"DATABASE_URL": "postgres://x", "PUBLIC_URL": "https://mdm.example.com"}
	load := func() (Server, error) { return LoadServer(func(k string) string { return env[k] }) }

	cfg, err := load()
	if err != nil {
		t.Fatal(err)
	}
	if f := cfg.ReleaseFeed; !f.Enabled || f.URL != DefaultReleaseFeedURL || f.Interval != 6*time.Hour || f.Prereleases {
		t.Fatalf("defaults = %+v", f)
	}

	env["RELEASE_FEED_ENABLED"] = "false"
	env["RELEASE_FEED_URL"] = "https://mirror.example.com/retune/releases.json"
	env["RELEASE_FEED_INTERVAL_HOURS"] = "24"
	env["RELEASE_FEED_PRERELEASES"] = "true"
	cfg, err = load()
	if err != nil {
		t.Fatal(err)
	}
	if f := cfg.ReleaseFeed; f.Enabled || f.URL != "https://mirror.example.com/retune/releases.json" || f.Interval != 24*time.Hour || !f.Prereleases {
		t.Fatalf("set = %+v", f)
	}

	for key, bad := range map[string]string{
		"RELEASE_FEED_ENABLED":        "sometimes",
		"RELEASE_FEED_URL":            "mirror.example.com",
		"RELEASE_FEED_INTERVAL_HOURS": "0",
		"RELEASE_FEED_PRERELEASES":    "maybe",
	} {
		was := env[key]
		env[key] = bad
		if _, err := load(); err == nil {
			t.Errorf("%s=%q must refuse to start the server", key, bad)
		}
		env[key] = was
	}
	env["RELEASE_FEED_INTERVAL_HOURS"] = "169"
	if _, err := load(); err == nil {
		t.Error("an interval over a week must be refused")
	}
}
