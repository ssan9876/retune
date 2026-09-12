package agentapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"retune/internal/protocol"
)

// Request body limits.
const (
	maxCheckinBody   = 1 << 20
	maxInventoryBody = 8 << 20
	maxResultBody    = 8 << 20
)

// decode reads a JSON body no larger than limit. Unknown fields are allowed so
// newer agents can talk to older servers.
func decode(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	err := json.NewDecoder(r.Body).Decode(v)
	if err == nil {
		return true
	}
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body is too large")
		return false
	}
	writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
	return false
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeNoContent(w http.ResponseWriter) { w.WriteHeader(http.StatusNoContent) }

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, protocol.Error{Code: code, Message: msg})
}
