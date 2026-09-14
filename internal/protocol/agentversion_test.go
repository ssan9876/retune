package protocol_test

import (
	"errors"
	"testing"
	"time"

	"retune/internal/protocol"
)

func TestAgentOptionsDefaults(t *testing.T) {
	for _, raw := range []string{"", "{}", "null"} {
		o, err := protocol.ParseAgentOptions([]byte(raw))
		if err != nil {
			t.Fatalf("ParseAgentOptions(%q): %v", raw, err)
		}
		if o.DeadlineSeconds != 600 {
			t.Errorf("deadline = %d, want 600", o.DeadlineSeconds)
		}
		if o.Deadline() != 10*time.Minute {
			t.Errorf("Deadline() = %v, want 10m", o.Deadline())
		}
	}
}

func TestAgentOptionsRejectsNonsense(t *testing.T) {
	cases := map[string]string{
		"a deadline below the floor":   `{"deadline_seconds":30}`,
		"a deadline above the ceiling": `{"deadline_seconds":7200}`,
		"a misspelled field":           `{"deadline_secondz":600}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := protocol.ParseAgentOptions([]byte(raw))
			if err == nil {
				t.Fatalf("%s should be refused", raw)
			}
			if !errors.Is(err, protocol.ErrBadOptions) {
				t.Errorf("error should wrap ErrBadOptions, got %v", err)
			}
		})
	}
}
