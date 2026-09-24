package protocol

import (
	"encoding/json"
	"time"

	"retune/internal/opsign"
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
	// CommandRotateAdminPassword sets a new random password on a local
	// administrator account, escrowing it with the server first.
	CommandRotateAdminPassword = "rotate_local_admin_password"
	// CommandRenameComputer gives the device a new computer name, which
	// takes effect when it next restarts.
	CommandRenameComputer = "rename_computer"
)

// RenameComputerPayload configures CommandRenameComputer.
type RenameComputerPayload struct {
	Name string `json:"name"`
	// Restart restarts the device a minute after renaming it, so the name
	// takes effect now rather than at the next restart someone chooses.
	Restart bool `json:"restart,omitempty"`
}

// ValidComputerName reports whether a name is one Windows accepts as a
// computer (NetBIOS) name: 1 to 15 letters, digits and hyphens, not all
// digits, not starting or ending with a hyphen.
func ValidComputerName(name string) bool {
	if len(name) == 0 || len(name) > 15 || name[0] == '-' || name[len(name)-1] == '-' {
		return false
	}
	digits := true
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '-':
			digits = false
		default:
			return false
		}
	}
	return !digits
}

// Bounds on rotate_local_admin_password.
const (
	MinAdminPasswordLength     = 20
	MaxAdminPasswordLength     = 64
	DefaultAdminPasswordLength = 24
)

// RotateAdminPasswordPayload configures CommandRotateAdminPassword.
type RotateAdminPasswordPayload struct {
	// Account is a local account name; empty means the built-in
	// Administrator (RID 500), whatever it has been renamed to.
	Account string `json:"account,omitempty"`
	Length  int    `json:"length"`
}

// AdminPasswordEscrowRequest is POSTed to /api/agent/v1/admin-passwords
// before the password is set: a password set but never escrowed would lock
// everyone out of the account.
type AdminPasswordEscrowRequest struct {
	CommandID string `json:"command_id"`
	Account   string `json:"account"`
	Password  string `json:"password"`
}

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
	// Expires and Signature are a signed wipe order, for agents built to
	// require one: bound to this device, this choice of protected, and this
	// expiry.
	Expires   *time.Time        `json:"expires,omitempty"`
	Signature *opsign.Signature `json:"signature,omitempty"`
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
	// Signature, by an operations key, over the script. An agent built to
	// require one runs nothing without it.
	Signature *opsign.Signature `json:"signature,omitempty"`
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
