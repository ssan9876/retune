package protocol

import (
	"time"

	"retune/internal/opsign"
)

// ItemKindScript is the assignment kind for script deployments.
const ItemKindScript = "script"

// Phases a run can be decided in.
const (
	PhaseScript      = "script"
	PhaseDetection   = "detection"
	PhaseRemediation = "remediation"
)

// ScriptVersionResponse is the body of
// GET /api/agent/v1/scripts/{id}/versions/{version}.
type ScriptVersionResponse struct {
	Version int    `json:"version"`
	Body    string `json:"body"`
	// DetectionBody, when set, decides whether Body needs to run at all.
	DetectionBody string `json:"detection_body"`
	Hash          string `json:"hash"`
	// Signature, by an operations key, over Body and DetectionBody.
	Signature *opsign.Signature `json:"signature,omitempty"`
}

// ScriptRun is POSTed to /api/agent/v1/scripts/{id}/runs to report one
// execution.
type ScriptRun struct {
	Version int    `json:"version"`
	Status  string `json:"status"`
	// Phase says which execution decided the outcome.
	Phase string `json:"phase"`
	// Remediated reports that detection failed, the body ran, and detection
	// then passed.
	Remediated      bool      `json:"remediated"`
	ExitCode        int       `json:"exit_code"`
	Stdout          string    `json:"stdout"`
	Stderr          string    `json:"stderr"`
	StdoutTruncated bool      `json:"stdout_truncated"`
	StderrTruncated bool      `json:"stderr_truncated"`
	Error           string    `json:"error"`
	StartedAt       time.Time `json:"started_at"`
	FinishedAt      time.Time `json:"finished_at"`
}
