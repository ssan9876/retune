package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"retune/internal/protocol"
	"retune/internal/server/store"
)

// maxBody is generous enough for a script payload but not unbounded.
const maxBody = 4 << 20

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
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

// pageFrom reads limit/offset query parameters.
func pageFrom(r *http.Request) store.Page {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	return store.Page{Limit: limit, Offset: offset}.Normalized()
}

// listResponse is the shape every listing returns.
type listResponse[T any] struct {
	Items  []T `json:"items"`
	Total  int `json:"total"`
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

func newListResponse[T any](items []T, total int, page store.Page) listResponse[T] {
	if items == nil {
		items = []T{}
	}
	return listResponse[T]{Items: items, Total: total, Limit: page.Limit, Offset: page.Offset}
}
