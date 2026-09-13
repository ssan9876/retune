// Package scripts owns the script library: versions, assignment options, and
// the runs devices report back.
package scripts

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ErrBadOptions is returned when assignment options do not make sense.
var ErrBadOptions = errors.New("invalid deployment options")

// Frequencies a deployment can run at.
const (
	FrequencyOnce      = "once"
	FrequencyRecurring = "recurring"
)

// Accounts a script can run as. RunAsUser is accepted and stored, but M6 does
// not execute it: see Options.Executable.
const (
	RunAsSystem = "system"
	RunAsUser   = "logged_in_user"
)

// Limits on what an administrator may ask for.
const (
	MinTimeoutSeconds = 1
	MaxTimeoutSeconds = 86400
	MaxRetriesLimit   = 10
)

// Options are the per-assignment settings of a script deployment.
type Options struct {
	Frequency         string `json:"frequency"`
	IntervalHours     int    `json:"interval_hours"`
	RunAs             string `json:"run_as"`
	TimeoutSeconds    int    `json:"timeout_seconds"`
	MaxRetries        int    `json:"max_retries"`
	RerunOnNewVersion bool   `json:"rerun_on_new_version"`
}

// DefaultOptions are applied to anything the caller leaves out.
func DefaultOptions() Options {
	return Options{
		Frequency:         FrequencyOnce,
		IntervalHours:     24,
		RunAs:             RunAsSystem,
		TimeoutSeconds:    600,
		MaxRetries:        2,
		RerunOnNewVersion: true,
	}
}

// Timeout is the per-execution limit.
func (o Options) Timeout() time.Duration { return time.Duration(o.TimeoutSeconds) * time.Second }

// Interval is how long to wait between recurring runs.
func (o Options) Interval() time.Duration { return time.Duration(o.IntervalHours) * time.Hour }

// Executable reports whether the agent can actually run this deployment today.
// A deployment set to run as the signed-in user is stored and shown, but not
// executed, and says so rather than failing quietly.
func (o Options) Executable() (bool, string) {
	if o.RunAs == RunAsUser {
		return false, "running as the logged-in user is not supported yet"
	}
	return true, ""
}

// ParseOptions validates raw assignment options, filling in the defaults.
// Unknown fields are rejected so a typo is not silently ignored.
func ParseOptions(raw []byte) (Options, error) {
	o := DefaultOptions()
	if len(bytes.TrimSpace(raw)) > 0 && string(bytes.TrimSpace(raw)) != "null" {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&o); err != nil {
			return Options{}, fmt.Errorf("%w: %v", ErrBadOptions, err)
		}
	}
	if err := o.validate(); err != nil {
		return Options{}, err
	}
	return o, nil
}

func (o Options) validate() error {
	switch o.Frequency {
	case FrequencyOnce, FrequencyRecurring:
	default:
		return fmt.Errorf("%w: frequency must be %q or %q, not %q",
			ErrBadOptions, FrequencyOnce, FrequencyRecurring, o.Frequency)
	}
	switch o.RunAs {
	case RunAsSystem, RunAsUser:
	default:
		return fmt.Errorf("%w: run_as must be %q or %q, not %q",
			ErrBadOptions, RunAsSystem, RunAsUser, o.RunAs)
	}
	if o.Frequency == FrequencyRecurring && o.IntervalHours < 1 {
		return fmt.Errorf("%w: interval_hours must be at least 1 for a recurring deployment", ErrBadOptions)
	}
	if o.TimeoutSeconds < MinTimeoutSeconds || o.TimeoutSeconds > MaxTimeoutSeconds {
		return fmt.Errorf("%w: timeout_seconds must be between %d and %d",
			ErrBadOptions, MinTimeoutSeconds, MaxTimeoutSeconds)
	}
	if o.MaxRetries < 0 || o.MaxRetries > MaxRetriesLimit {
		return fmt.Errorf("%w: max_retries must be between 0 and %d", ErrBadOptions, MaxRetriesLimit)
	}
	return nil
}

// Marshal returns the canonical JSON for storing on an assignment.
func (o Options) Marshal() ([]byte, error) { return json.Marshal(o) }
