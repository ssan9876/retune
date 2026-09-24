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
	// CommandInstallUpdates installs what Windows Update offers now,
	// rather than when its own schedule gets round to it.
	CommandInstallUpdates = "install_updates"
	// CommandRemoteShell opens an interactive PowerShell session an
	// administrator types into from the console. Only the server creates it,
	// for a remote session an administrator started.
	CommandRemoteShell = "remote_shell"
)

// RemoteShellPayload names the remote session a remote_shell command is for.
type RemoteShellPayload struct {
	SessionID string `json:"session_id"`
}

// Remote session streams: what the administrator typed, and what the shell
// wrote to its output and error.
const (
	RemoteStreamIn  = "in"
	RemoteStreamOut = "out"
	RemoteStreamErr = "err"
)

// Remote session bounds, kept by the agent and the server alike.
const (
	// MaxRemoteChunk is the most one input or output post may carry.
	MaxRemoteChunk = 64 << 10
	// RemoteIdleTimeout ends a session nobody has typed into for a while.
	RemoteIdleTimeout = 15 * time.Minute
	// RemoteMaxDuration ends a session however busy it is.
	RemoteMaxDuration = time.Hour
	// RemotePollSeconds is how long a poll for input or output is held.
	RemotePollSeconds = 25
)

// RemoteChunk is one piece of a remote session, in order.
type RemoteChunk struct {
	Seq    int64     `json:"seq"`
	Stream string    `json:"stream"`
	Data   string    `json:"data"`
	At     time.Time `json:"at"`
}

// RemoteInputResponse is the input an agent polls for, and whether the
// session has ended.
type RemoteInputResponse struct {
	Chunks []RemoteChunk `json:"chunks"`
	Ended  bool          `json:"ended"`
}

// RemoteOutputRequest is output an agent sends.
type RemoteOutputRequest struct {
	Stream string `json:"stream"`
	Data   string `json:"data"`
}

// RemoteEndRequest says why the agent ended a session.
type RemoteEndRequest struct {
	Reason string `json:"reason"`
}

// install_updates scopes and restart choices.
const (
	UpdatesSecurity = "security"
	UpdatesAll      = "all"

	UpdateRestartNever      = "never"
	UpdateRestartIfRequired = "if_required"
)

// InstallUpdatesPayload configures CommandInstallUpdates.
type InstallUpdatesPayload struct {
	// Scope is security (security and critical updates) or all (every
	// software update offered, drivers included).
	Scope string `json:"scope"`
	// Restart is never, or if_required: restart five minutes after
	// installing, when an update needs it.
	Restart string `json:"restart"`
}

// InstallUpdatesResult is what the agent reports in a command's stdout.
type InstallUpdatesResult struct {
	Installed      int      `json:"installed"`
	Failed         int      `json:"failed"`
	RebootRequired bool     `json:"reboot_required"`
	Titles         []string `json:"titles,omitempty"`
}

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
