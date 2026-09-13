package protocol_test

import (
	"errors"
	"strings"
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

// Running as the signed-in user is accepted and stored; it is simply not
// executed yet, which Executable explains.
func TestRunAsUserIsStoredButNotExecutable(t *testing.T) {
	o, err := protocol.ParseDeploymentOptions([]byte(`{"run_as":"logged_in_user"}`))
	if err != nil {
		t.Fatalf("run_as: logged_in_user must be accepted, got %v", err)
	}
	ok, reason := o.Executable()
	if ok {
		t.Fatal("it must not be executable in this milestone")
	}
	if !strings.Contains(reason, "not supported yet") {
		t.Errorf("the reason should say so plainly, got %q", reason)
	}

	if ok, _ := protocol.DefaultDeploymentOptions().Executable(); !ok {
		t.Error("running as the system account should be executable")
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
