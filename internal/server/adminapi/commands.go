package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

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
}

func (h *Handler) listCommands(w http.ResponseWriter, r *http.Request) {
	page := pageFrom(r)
	filter := store.CommandFilter{Status: r.URL.Query().Get("status"), Page: page}
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
	actor := caller(r).Admin.Email
	type queued struct {
		ID       string `json:"id"`
		DeviceID string `json:"device_id"`
	}
	out := make([]queued, 0, len(req.DeviceIDs))
	for _, raw := range req.DeviceIDs {
		deviceID, err := uuid.Parse(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "device_ids must contain device IDs")
			return
		}
		c, err := h.Commands.Queue(r.Context(), commands.QueueOptions{
			DeviceID: deviceID, Type: req.Type, Payload: payload, CreatedBy: actor,
			TTL: time.Duration(req.TTLHours) * time.Hour,
		})
		switch {
		case err == nil:
			out = append(out, queued{ID: c.ID.String(), DeviceID: deviceID.String()})
		case errors.Is(err, commands.ErrBadRequest):
			writeError(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		case errors.Is(err, commands.ErrNotFound):
			writeError(w, http.StatusNotFound, "not_found", err.Error())
			return
		case errors.Is(err, commands.ErrDeviceNotActive):
			writeError(w, http.StatusConflict, "device_not_active", err.Error())
			return
		default:
			h.internal(w, "queue command", err)
			return
		}
	}
	writeJSON(w, http.StatusCreated, map[string]any{"commands": out})
}

// payloadFor builds the typed payload the command service expects.
func payloadFor(req queueRequest) (json.RawMessage, error) {
	switch req.Type {
	case protocol.CommandRunPowerShell:
		return json.Marshal(protocol.RunPowerShellPayload{Script: req.Script, TimeoutSeconds: req.TimeoutSeconds})
	case protocol.CommandRestart:
		return json.Marshal(protocol.RestartPayload{DelaySeconds: req.DelaySeconds, Message: req.Message})
	case protocol.CommandRefreshInventory:
		return nil, nil
	default:
		return nil, errors.New("type must be run_powershell, restart or refresh_inventory")
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
