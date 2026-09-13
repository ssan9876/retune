package protocol_test

import (
	"errors"
	"testing"

	"retune/internal/protocol"
)

func TestParseOptionsDefaults(t *testing.T) {
	for _, raw := range []string{"", "{}", "null"} {
		o, err := protocol.ParseDeploymentOptions([]byte(raw))
		if err != nil {
			t.Fatalf("ParseOptions(%q): %v", raw, err)
		}
		if o != protocol.DefaultDeploymentOptions() {
			t.Errorf("ParseOptions(%q) = %+v, want the defaults", raw, o)
		}
	}
}

func TestParseOptionsAccepts(t *testing.T) {
	o, err := protocol.ParseDeploymentOptions([]byte(`{"frequency":"recurring","interval_hours":6,"max_retries":0}`))
	if err != nil {
		t.Fatal(err)
	}
	if o.Frequency != protocol.FrequencyRecurring || o.IntervalHours != 6 || o.MaxRetries != 0 {
		t.Fatalf("got %+v", o)
	}
	// Unmentioned fields keep their defaults.
	if o.TimeoutSeconds != 600 || !o.RerunOnNewVersion {
		t.Fatalf("defaults should survive a partial object, got %+v", o)
	}
}

// Running as the signed-in user needs somebody to be signed in; running as the
// system account never does.
func TestRunAsUserNeedsASession(t *testing.T) {
	o, err := protocol.ParseDeploymentOptions([]byte(`{"run_as":"logged_in_user"}`))
	if err != nil {
		t.Fatalf("run_as: logged_in_user must be accepted, got %v", err)
	}
	if !o.NeedsUserSession() {
		t.Error("a deployment set to run as the signed-in user needs a session")
	}
	if protocol.DefaultDeploymentOptions().NeedsUserSession() {
		t.Error("running as the system account does not need anybody signed in")
	}
}

func TestParseOptionsRejects(t *testing.T) {
	cases := map[string]string{
		"unknown frequency": `{"frequency":"hourly"}`,
		"unknown run_as":    `{"run_as":"admin"}`,
		"zero interval":     `{"frequency":"recurring","interval_hours":0}`,
		"timeout too small": `{"timeout_seconds":0}`,
		"timeout too large": `{"timeout_seconds":100000}`,
		"negative retries":  `{"max_retries":-1}`,
		"too many retries":  `{"max_retries":99}`,
		"unknown field":     `{"frequncy":"once"}`,
		"not an object":     `[1,2,3]`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := protocol.ParseDeploymentOptions([]byte(raw))
			if err == nil {
				t.Fatalf("ParseOptions(%s) should have failed", raw)
			}
			if !errors.Is(err, protocol.ErrBadOptions) {
				t.Errorf("error should wrap ErrBadOptions, got %v", err)
			}
		})
	}
}

func TestOptionsRoundTrip(t *testing.T) {
	want := protocol.DefaultDeploymentOptions()
	want.Frequency = protocol.FrequencyRecurring
	raw, err := want.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := protocol.ParseDeploymentOptions(raw)
	if err != nil || got != want {
		t.Fatalf("round trip: %+v err %v", got, err)
	}
}
