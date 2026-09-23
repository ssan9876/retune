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
	// CommandLock locks the signed-in user's session.
	CommandLock = "lock"
	// CommandCollectLogs uploads an archive of the agent's logs and recent
	// Windows event logs.
	CommandCollectLogs = "collect_logs"
	// CommandWipe resets the device to factory settings, removing everything.
	CommandWipe = "wipe"
)

// Bounds on collect_logs.
const (
	MinLogHours     = 1
	MaxLogHours     = 168
	DefaultLogHours = 24
	// MaxLogArchiveBytes caps the archive an agent may upload.
	MaxLogArchiveBytes = 50 << 20
)

// CollectLogsPayload configures CommandCollectLogs.
type CollectLogsPayload struct {
	// Hours is how far back the event logs go.
	Hours int `json:"hours"`
}

// WipePayload configures CommandWipe.
type WipePayload struct {
	// Protected also removes what a plain reset keeps for recovery, and
	// can leave a device that can't start until it is reinstalled.
	Protected bool `json:"protected"`
}

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
