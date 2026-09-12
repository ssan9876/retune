package protocol

import (
	"encoding/json"
	"time"
)

// Command types.
const (
	CommandRunPowerShell    = "run_powershell"
	CommandRestart          = "restart"
	CommandRefreshInventory = "refresh_inventory"
)

// Terminal result statuses reported by the agent.
const (
	ResultSucceeded = "succeeded"
	ResultFailed    = "failed"
	ResultTimedOut  = "timed_out"
)

// MaxOutputBytes caps each of stdout and stderr.
const MaxOutputBytes = 1 << 20

// Command is one unit of work handed to an agent at check-in.
type Command struct {
	ID      string          `json:"id"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// RunPowerShellPayload configures CommandRunPowerShell.
type RunPowerShellPayload struct {
	Script         string `json:"script"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

// RestartPayload configures CommandRestart.
type RestartPayload struct {
	DelaySeconds int    `json:"delay_seconds"`
	Message      string `json:"message"`
}

// CommandResult is POSTed to /api/agent/v1/commands/{id}/result.
type CommandResult struct {
	Status          string    `json:"status"`
	ExitCode        int       `json:"exit_code"`
	Stdout          string    `json:"stdout"`
	Stderr          string    `json:"stderr"`
	StdoutTruncated bool      `json:"stdout_truncated"`
	StderrTruncated bool      `json:"stderr_truncated"`
	Error           string    `json:"error"`
	StartedAt       time.Time `json:"started_at"`
	FinishedAt      time.Time `json:"finished_at"`
}

// RenewRequest asks for a fresh client certificate.
type RenewRequest struct {
	CSRPEM string `json:"csr_pem"`
}

// RenewResponse carries the reissued client certificate.
type RenewResponse struct {
	CertPEM string `json:"cert_pem"`
}
