package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"retune/internal/opsign"
	"retune/internal/protocol"
	"retune/internal/server/commands"
	"retune/internal/server/store"
)

type commandJSON struct {
	ID          string          `json:"id"`
	DeviceID    string          `json:"device_id"`
	Type        string          `json:"type"`
	Status      string          `json:"status"`
	Payload     json.RawMessage `json:"payload"`
	CreatedBy   string          `json:"created_by"`
	CreatedAt   time.Time       `json:"created_at"`
	DeliveredAt *time.Time      `json:"delivered_at,omitempty"`
	StartedAt   *time.Time      `json:"started_at,omitempty"`
	CompletedAt *time.Time      `json:"completed_at,omitempty"`
	ExpiresAt   time.Time       `json:"expires_at"`
}

func newCommandJSON(c store.Command) commandJSON {
	return commandJSON{
		ID: c.ID.String(), DeviceID: c.DeviceID.String(), Type: c.Type, Status: c.Status,
		Payload: json.RawMessage(c.Payload), CreatedBy: c.CreatedBy, CreatedAt: c.CreatedAt,
		DeliveredAt: c.DeliveredAt, StartedAt: c.StartedAt, CompletedAt: c.CompletedAt, ExpiresAt: c.ExpiresAt,
	}
}

type resultJSON struct {
	ExitCode        int       `json:"exit_code"`
	Stdout          string    `json:"stdout"`
	Stderr          string    `json:"stderr"`
	StdoutTruncated bool      `json:"stdout_truncated"`
	StderrTruncated bool      `json:"stderr_truncated"`
	Error           string    `json:"error"`
	StartedAt       time.Time `json:"started_at"`
	FinishedAt      time.Time `json:"finished_at"`
}

type queueRequest struct {
	DeviceIDs      []string `json:"device_ids"`
	Type           string   `json:"type"`
	Script         string   `json:"script"`
	TimeoutSeconds int      `json:"timeout_seconds"`
	DelaySeconds   int      `json:"delay_seconds"`
	Message        string   `json:"message"`
	TTLHours       int      `json:"ttl_hours"`
	// collect_logs
	Hours int `json:"hours"`
	// wipe
	Protected       bool   `json:"protected"`
	ConfirmHostname string `json:"confirm_hostname"`
	Reason          string `json:"reason"`
	// Expires and Signature: a signed wipe order, or (Signature alone) a
	// signed script.
	Expires   *time.Time        `json:"expires,omitempty"`
	Signature *opsign.Signature `json:"signature,omitempty"`
	// rotate_local_admin_password
	Account string `json:"account"`
	Length  int    `json:"length"`
	// rename_computer
	Name    string `json:"name,omitempty"`
	Restart bool   `json:"restart,omitempty"`
	// install_updates: security or all, and never or if_required.
	Scope         string `json:"scope,omitempty"`
	RestartPolicy string `json:"restart_policy,omitempty"`
}

func (h *Handler) listCommands(w http.ResponseWriter, r *http.Request) {
	page := pageFrom(r)
	filter := store.CommandFilter{Status: r.URL.Query().Get("status"), Page: page, Scope: caller(r).Scope}
	if raw := r.URL.Query().Get("device_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "device_id must be a device ID")
			return
		}
		filter.DeviceID = &id
	}
	rows, total, err := h.Store.Q().ListCommandsPage(r.Context(), filter)
	if err != nil {
		h.internal(w, "list commands", err)
		return
	}
	items := make([]commandJSON, 0, len(rows))
	for _, c := range rows {
		items = append(items, newCommandJSON(c))
	}
	writeJSON(w, http.StatusOK, newListResponse(items, total, page))
}

func (h *Handler) queueCommand(w http.ResponseWriter, r *http.Request) {
	var req queueRequest
	if !decode(w, r, &req) {
		return
	}
	if len(req.DeviceIDs) == 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "device_ids must name at least one device")
		return
	}
	payload, err := payloadFor(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	// Helpdesk takes device actions that run no code and destroy nothing.
	if caller(r).Admin.Role != store.RoleAdmin && !helpdeskCommands[req.Type] {
		writeError(w, http.StatusForbidden, "forbidden", "a "+req.Type+" command needs the admin role")
		return
	}
	if req.Type == protocol.CommandWipe {
		// A wipe is one device at a time, confirmed by name, by a person:
		// not something a script with a token does.
		if caller(r).Token != nil {
			writeError(w, http.StatusForbidden, "forbidden", "a wipe must be queued by an administrator signed in to the console, not an API token")
			return
		}
		if len(req.DeviceIDs) != 1 {
			writeError(w, http.StatusBadRequest, "bad_request", "a wipe names exactly one device")
			return
		}
	}
	// Every device is parsed and checked against the caller's scope before
	// any command is queued, so a request that names one device out of reach
	// queues nothing rather than half of what it asked for.
	ids := make([]uuid.UUID, 0, len(req.DeviceIDs))
	for _, raw := range req.DeviceIDs {
		deviceID, err := uuid.Parse(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "device_ids must contain device IDs")
			return
		}
		if !h.deviceVisible(w, r, deviceID) {
			return
		}
		ids = append(ids, deviceID)
	}
	actor := caller(r).Admin.Email
	if h.commandNeedsApproval(req.Type, len(ids)) {
		// Held requests are checked in full now, so nobody is asked to
		// approve something that could never run.
		for _, deviceID := range ids {
			if err := h.Commands.Check(r.Context(), queueOptions(req, payload, deviceID, actor)); err != nil {
				h.writeQueueError(w, err)
				return
			}
		}
		h.holdForApproval(w, r, store.ApprovalCommand, req, commandSummary(req, len(ids)))
		return
	}
	out, err := h.queueCommands(r.Context(), req, payload, ids, actor)
	if err != nil {
		h.writeQueueError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, queuedCommands{Commands: out})
}

type queuedJSON struct {
	ID       string `json:"id"`
	DeviceID string `json:"device_id"`
}

func queueOptions(req queueRequest, payload json.RawMessage, deviceID uuid.UUID, actor string) commands.QueueOptions {
	return commands.QueueOptions{
		DeviceID: deviceID, Type: req.Type, Payload: payload, CreatedBy: actor,
		TTL:             time.Duration(req.TTLHours) * time.Hour,
		ConfirmHostname: req.ConfirmHostname, Reason: req.Reason,
	}
}

// queueCommands queues req for each device, stopping at the first error with
// what was queued before it.
func (h *Handler) queueCommands(ctx context.Context, req queueRequest, payload json.RawMessage, ids []uuid.UUID, actor string) ([]queuedJSON, error) {
	out := make([]queuedJSON, 0, len(ids))
	for _, deviceID := range ids {
		c, err := h.Commands.Queue(ctx, queueOptions(req, payload, deviceID, actor))
		if err != nil {
			return out, err
		}
		out = append(out, queuedJSON{ID: c.ID.String(), DeviceID: deviceID.String()})
	}
	return out, nil
}

func (h *Handler) writeQueueError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, commands.ErrBadRequest):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	case errors.Is(err, commands.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, commands.ErrDeviceNotActive):
		writeError(w, http.StatusConflict, "device_not_active", err.Error())
	default:
		h.internal(w, "queue command", err)
	}
}

// commandNeedsApproval: with approvals on, every wipe, and ad-hoc PowerShell
// to more devices than the threshold, waits for a second administrator.
func (h *Handler) commandNeedsApproval(typ string, devices int) bool {
	if !h.ApprovalsRequired {
		return false
	}
	return typ == protocol.CommandWipe || (typ == protocol.CommandRunPowerShell && devices > h.ApprovalThreshold)
}

func commandSummary(req queueRequest, devices int) string {
	if req.Type == protocol.CommandWipe {
		return fmt.Sprintf("wipe %s: %s", req.ConfirmHostname, req.Reason)
	}
	if devices == 1 {
		return req.Type + " on 1 device"
	}
	return fmt.Sprintf("%s on %d devices", req.Type, devices)
}

// payloadFor builds the typed payload the command service expects.
func payloadFor(req queueRequest) (json.RawMessage, error) {
	switch req.Type {
	case protocol.CommandRunPowerShell:
		return json.Marshal(protocol.RunPowerShellPayload{Script: req.Script, TimeoutSeconds: req.TimeoutSeconds, Signature: req.Signature})
	case protocol.CommandRestart:
		return json.Marshal(protocol.RestartPayload{DelaySeconds: req.DelaySeconds, Message: req.Message})
	case protocol.CommandRefreshInventory, protocol.CommandLock:
		return nil, nil
	case protocol.CommandCollectLogs:
		return json.Marshal(protocol.CollectLogsPayload{Hours: req.Hours})
	case protocol.CommandWipe:
		return json.Marshal(protocol.WipePayload{Protected: req.Protected, Expires: req.Expires, Signature: req.Signature})
	case protocol.CommandRotateAdminPassword:
		return json.Marshal(protocol.RotateAdminPasswordPayload{Account: req.Account, Length: req.Length})
	case protocol.CommandRenameComputer:
		return json.Marshal(protocol.RenameComputerPayload{Name: req.Name, Restart: req.Restart})
	case protocol.CommandInstallUpdates:
		return json.Marshal(protocol.InstallUpdatesPayload{Scope: req.Scope, Restart: req.RestartPolicy})
	default:
		return nil, errors.New("type must be run_powershell, restart, refresh_inventory, lock, collect_logs, wipe, rotate_local_admin_password, rename_computer or install_updates")
	}
}

func (h *Handler) getCommand(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such command")
	if !ok {
		return
	}
	c, res, err := h.Commands.Get(r.Context(), id)
	switch {
	case err == nil:
	case errors.Is(err, commands.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such command")
		return
	default:
		h.internal(w, "get command", err)
		return
	}
	// A command for a device outside the caller's scope is one they cannot
	// know about: the answer is the same as for no command at all.
	if visible, err := h.Store.Q().DeviceInScope(r.Context(), store.DefaultTenantID, c.DeviceID, caller(r).Scope); err != nil {
		h.internal(w, "check device scope", err)
		return
	} else if !visible {
		writeError(w, http.StatusNotFound, "not_found", "no such command")
		return
	}
	body := map[string]any{"command": newCommandJSON(c)}
	if res != nil {
		body["result"] = resultJSON{
			ExitCode: res.ExitCode, Stdout: res.Stdout, Stderr: res.Stderr,
			StdoutTruncated: res.StdoutTruncated, StderrTruncated: res.StderrTruncated,
			Error: res.Error, StartedAt: res.StartedAt, FinishedAt: res.FinishedAt,
		}
	}
	writeJSON(w, http.StatusOK, body)
}

// downloadCommandArtifact streams the file a command produced, such as a
// collect_logs archive. Logs can hold anything a machine wrote down, so each
// download is audited.
func (h *Handler) downloadCommandArtifact(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "no such command")
	if !ok {
		return
	}
	ctx := r.Context()
	c, _, err := h.Commands.Get(ctx, id)
	if errors.Is(err, commands.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "no such command")
		return
	}
	if err != nil {
		h.internal(w, "get command", err)
		return
	}
	if !h.deviceVisible(w, r, c.DeviceID) {
		return
	}
	f, a, err := h.Commands.OpenArtifact(ctx, id)
	if errors.Is(err, commands.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "this command has no file")
		return
	}
	if err != nil {
		h.internal(w, "open command file", err)
		return
	}
	defer f.Close()
	hostname := "device"
	if d, err := h.Store.Q().GetDevice(ctx, store.DefaultTenantID, c.DeviceID); err == nil {
		hostname = d.Hostname
	}
	if err := h.Store.Q().InsertAudit(ctx, store.AuditEntry{
		Actor: caller(r).Admin.Email, Action: "command.artifact_downloaded", TargetKind: "command",
		TargetID: id.String(), Details: map[string]any{"device_id": c.DeviceID.String(), "hostname": hostname},
	}); err != nil {
		h.internal(w, "audit command file download", err)
		return
	}
	name := fmt.Sprintf("logs-%s-%s.zip", safeFileName(hostname), a.CreatedAt.UTC().Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Length", strconv.FormatInt(a.SizeBytes, 10))
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	if _, err := io.Copy(w, f); err != nil {
		h.Log.Warn("command file download ended early", "command_id", id, "error", err)
	}
}

// safeFileName keeps letters, digits, dash, dot and underscore.
func safeFileName(s string) string {
	b := []byte(s)
	for i, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_') {
			b[i] = '_'
		}
	}
	return string(b)
}

// helpdeskCommands are the command types the helpdesk role may queue.
var helpdeskCommands = map[string]bool{
	protocol.CommandLock: true, protocol.CommandRestart: true, protocol.CommandRefreshInventory: true,
	protocol.CommandCollectLogs: true, protocol.CommandRotateAdminPassword: true,
	// Installing what Windows Update offers is routine patching, and restarts
	// only when asked to, as helpdesk can anyway.
	protocol.CommandInstallUpdates: true,
}
