package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ErrBadOptions is returned when deployment options do not make sense.
var ErrBadOptions = errors.New("invalid deployment options")

// Frequencies a deployment can run at.
const (
	FrequencyOnce      = "once"
	FrequencyRecurring = "recurring"
)

// Accounts a script can run as.
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

// DeploymentOptions are the per-assignment settings of a script deployment.
// They travel to the agent on check-in, which is why they live here.
type DeploymentOptions struct {
	Frequency         string `json:"frequency"`
	IntervalHours     int    `json:"interval_hours"`
	RunAs             string `json:"run_as"`
	TimeoutSeconds    int    `json:"timeout_seconds"`
	MaxRetries        int    `json:"max_retries"`
	RerunOnNewVersion bool   `json:"rerun_on_new_version"`
}

// DefaultOptions are applied to anything the caller leaves out.
func DefaultDeploymentOptions() DeploymentOptions {
	return DeploymentOptions{
		Frequency:         FrequencyOnce,
		IntervalHours:     24,
		RunAs:             RunAsSystem,
		TimeoutSeconds:    600,
		MaxRetries:        2,
		RerunOnNewVersion: true,
	}
}

// Timeout is the per-execution limit.
func (o DeploymentOptions) Timeout() time.Duration {
	return time.Duration(o.TimeoutSeconds) * time.Second
}

// Interval is how long to wait between recurring runs.
func (o DeploymentOptions) Interval() time.Duration {
	return time.Duration(o.IntervalHours) * time.Hour
}

// NeedsUserSession reports whether this deployment can only run while somebody
// is signed in.
func (o DeploymentOptions) NeedsUserSession() bool { return o.RunAs == RunAsUser }

// ParseOptions validates raw assignment options, filling in the defaults.
// Unknown fields are rejected so a typo is not silently ignored.
func ParseDeploymentOptions(raw []byte) (DeploymentOptions, error) {
	o := DefaultDeploymentOptions()
	if len(bytes.TrimSpace(raw)) > 0 && string(bytes.TrimSpace(raw)) != "null" {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&o); err != nil {
			return DeploymentOptions{}, fmt.Errorf("%w: %v", ErrBadOptions, err)
		}
	}
	if err := o.validate(); err != nil {
		return DeploymentOptions{}, err
	}
	return o, nil
}

func (o DeploymentOptions) validate() error {
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
func (o DeploymentOptions) Marshal() ([]byte, error) { return json.Marshal(o) }
