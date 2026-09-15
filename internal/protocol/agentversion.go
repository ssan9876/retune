package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// ItemKindAgent is the assignment kind for agent builds.
const ItemKindAgent = "agent"

// How long the supervisor waits for a new agent to check in before putting the
// previous one back. Ten minutes comfortably spans a service restart plus a
// check-in interval; an hour would strand a device on a build that is never
// going to work.
const (
	MinUpdateDeadlineSeconds = 60
	MaxUpdateDeadlineSeconds = 3600
)

// AgentOptions are the per-assignment settings of an agent update.
type AgentOptions struct {
	DeadlineSeconds int `json:"deadline_seconds"`
}

// DefaultAgentOptions are applied to anything the caller leaves out.
func DefaultAgentOptions() AgentOptions {
	return AgentOptions{DeadlineSeconds: 600}
}

// Deadline is how long a new agent has to check in before it is rolled back.
func (o AgentOptions) Deadline() time.Duration {
	return time.Duration(o.DeadlineSeconds) * time.Second
}

// ParseAgentOptions validates raw assignment options, filling in the defaults.
// Unknown fields are rejected so a typo is not silently ignored.
func ParseAgentOptions(raw []byte) (AgentOptions, error) {
	o := DefaultAgentOptions()
	if len(bytes.TrimSpace(raw)) > 0 && string(bytes.TrimSpace(raw)) != "null" {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&o); err != nil {
			return AgentOptions{}, fmt.Errorf("%w: %v", ErrBadOptions, err)
		}
	}
	if err := o.validate(); err != nil {
		return AgentOptions{}, err
	}
	return o, nil
}

func (o AgentOptions) validate() error {
	if o.DeadlineSeconds < MinUpdateDeadlineSeconds || o.DeadlineSeconds > MaxUpdateDeadlineSeconds {
		return fmt.Errorf("%w: deadline_seconds must be between %d and %d",
			ErrBadOptions, MinUpdateDeadlineSeconds, MaxUpdateDeadlineSeconds)
	}
	return nil
}

// Marshal returns the canonical JSON for storing on an assignment.
func (o AgentOptions) Marshal() ([]byte, error) { return json.Marshal(o) }

// AgentVersionResponse is the body of GET /api/agent/v1/agent-versions/{id}.
// The binary itself is fetched separately; this is what the agent needs to
// decide whether to fetch it and how to check what it got.
type AgentVersionResponse struct {
	Version   string `json:"version"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
	// KeyID and Signature let the agent verify the build against the release
	// keys it was built to trust, after it has hashed the bytes itself.
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

// AgentUpdateResult is POSTed to /api/agent/v1/agent-versions/{id}/result.
// Only terminal outcomes are reported: an update that is still under way is
// the supervisor's business, not the console's.
type AgentUpdateResult struct {
	Version string `json:"version"`
	Status  string `json:"status"`
	// RolledBackFrom names the build that failed, when this report is a
	// restored agent saying what happened to it.
	RolledBackFrom string    `json:"rolled_back_from,omitempty"`
	Detail         string    `json:"detail"`
	ReportedAt     time.Time `json:"reported_at"`
}
