package protocol_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"retune/internal/protocol"
)

func TestAppOptionsDefaults(t *testing.T) {
	for _, raw := range []string{"", "{}", "null"} {
		o, err := protocol.ParseAppOptions([]byte(raw))
		if err != nil {
			t.Fatalf("ParseAppOptions(%q): %v", raw, err)
		}
		if o.Intent != protocol.IntentInstall {
			t.Errorf("intent = %q, want install: an assignment means put it there", o.Intent)
		}
		if o.TimeoutSeconds != 900 {
			t.Errorf("timeout = %d, want 900", o.TimeoutSeconds)
		}
		if o.Timeout() != 15*time.Minute {
			t.Errorf("Timeout() = %v, want 15m", o.Timeout())
		}
	}
}

func TestAppOptionsRejectsNonsense(t *testing.T) {
	cases := map[string]string{
		"an intent nobody implements": `{"intent":"upgrade"}`,
		"a timeout below the floor":   `{"timeout_seconds":1}`,
		"a timeout above the ceiling": `{"timeout_seconds":100000}`,
		"a misspelled field":          `{"intnet":"install"}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := protocol.ParseAppOptions([]byte(raw))
			if err == nil {
				t.Fatalf("%s should be refused", raw)
			}
			if !errors.Is(err, protocol.ErrBadOptions) {
				t.Errorf("error should wrap ErrBadOptions, got %v", err)
			}
		})
	}
}

// Uninstall is a deliberate instruction, not a consequence of leaving a group,
// so it is a first-class intent on the assignment.
func TestAppOptionsAcceptsUninstall(t *testing.T) {
	o, err := protocol.ParseAppOptions([]byte(`{"intent":"uninstall"}`))
	if err != nil {
		t.Fatal(err)
	}
	if o.Intent != protocol.IntentUninstall {
		t.Errorf("intent = %q, want uninstall", o.Intent)
	}
	raw, err := o.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"intent":"uninstall"`) {
		t.Errorf("the stored options should keep the intent, got %s", raw)
	}
}
