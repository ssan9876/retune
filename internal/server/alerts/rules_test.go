package alerts

import (
	"errors"
	"strings"
	"testing"

	"retune/internal/server/store"
)

func TestParseParams(t *testing.T) {
	cases := []struct {
		name    string
		kind    string
		raw     string
		wantErr string
	}{
		{"stale hours", store.AlertDeviceStale, `{"hours": 24}`, ""},
		{"stale needs hours", store.AlertDeviceStale, `{}`, "needs hours"},
		{"stale rejects zero", store.AlertDeviceStale, `{"hours": 0}`, "between 1 and 8760"},
		{"stale rejects a decade", store.AlertDeviceStale, `{"hours": 90000}`, "between 1 and 8760"},
		{"compliance takes no parameters", store.AlertDeviceNonCompliant, `{}`, ""},
		{"compliance narrows to a policy", store.AlertDeviceNonCompliant,
			`{"policy_id":"3f5c0f2e-0000-7000-8000-000000000001"}`, ""},
		{"compliance rejects a non-uuid", store.AlertDeviceNonCompliant, `{"policy_id":"baseline"}`, "must be a UUID"},
		{"deployment takes any kind", store.AlertDeploymentFailed, `{}`, ""},
		{"deployment narrows to one", store.AlertDeploymentFailed, `{"item_kind":"script"}`, ""},
		{"deployment rejects compliance", store.AlertDeploymentFailed, `{"item_kind":"compliance"}`, "unsupported item_kind"},
		// A parameter that belongs to another kind is a typo, not a setting
		// that silently does nothing.
		{"a foreign field is rejected by name", store.AlertDeviceStale, `{"item_kind":"script"}`, `field "item_kind"`},
		{"unknown kind", "device_on_fire", `{}`, "unsupported kind"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseParams(tc.kind, []byte(tc.raw))
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("ParseParams = %v, want no error", err)
			case tc.wantErr == "":
				return
			case err == nil:
				t.Fatalf("ParseParams = nil, want an error mentioning %q", tc.wantErr)
			case !errors.Is(err, ErrBadRule):
				t.Errorf("error %v does not wrap ErrBadRule", err)
			case !strings.Contains(err.Error(), tc.wantErr):
				t.Errorf("error = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestDescribeReadsAsASentence(t *testing.T) {
	params, err := ParseParams(store.AlertDeviceStale, []byte(`{"hours": 48}`))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := Describe(store.AlertDeviceStale, params), "a device has not checked in for 48 hours"; got != want {
		t.Errorf("Describe = %q, want %q", got, want)
	}
	// Singular, because "for 1 hours" is how software sounds when nobody read
	// it out loud.
	one, _ := ParseParams(store.AlertDeviceStale, []byte(`{"hours": 1}`))
	if got, want := Describe(store.AlertDeviceStale, one), "a device has not checked in for an hour"; got != want {
		t.Errorf("Describe = %q, want %q", got, want)
	}
}
