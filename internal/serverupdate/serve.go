package serverupdate

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Service is the updater's API. It listens only on a unix socket in a volume
// shared with the server, and every request must also carry the token both
// were given, so nothing else on the network or the host can drive it.
type Service struct {
	Token   string
	Updater *Updater
	States  FileStore
	Now     func() time.Time

	mu      sync.Mutex
	running bool
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Recover marks an update the updater did not live to finish as failed, so
// the console does not show it in progress for ever.
func (s *Service) Recover() error {
	st, err := s.States.Load()
	if err != nil || st == nil || st.Done() {
		return err
	}
	now := s.now()
	st.Phase, st.Error, st.UpdatedAt, st.FinishedAt = PhaseFailed,
		"the updater restarted before the update finished; check which version is running", now, &now
	return s.States.Save(*st)
}

// Handler serves POST /update and GET /status.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /update", s.update)
	mux.HandleFunc("GET /status", s.status)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if s.Token == "" || !ok || subtle.ConstantTimeCompare([]byte(got), []byte(s.Token)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		mux.ServeHTTP(w, r)
	})
}

type stateEnvelope struct {
	State *State `json:"state"`
}

func (s *Service) update(w http.ResponseWriter, r *http.Request) {
	var req Request
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || req.Version == "" || req.ID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "an update needs an id and a version"})
		return
	}
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		writeJSON(w, http.StatusConflict, map[string]string{"error": ErrBusy.Error()})
		return
	}
	s.running = true
	s.mu.Unlock()

	queued := State{ID: req.ID, Version: req.Version, RequestedBy: req.RequestedBy, Phase: PhaseQueued,
		StartedAt: s.now(), UpdatedAt: s.now()}
	if err := s.States.Save(queued); err != nil {
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	go func() {
		defer func() {
			s.mu.Lock()
			s.running = false
			s.mu.Unlock()
		}()
		// Not the request's context: the update outlives the request, and the
		// server that sent it is about to be restarted.
		s.Updater.Run(context.Background(), req)
	}()
	writeJSON(w, http.StatusAccepted, stateEnvelope{State: &queued})
}

func (s *Service) status(w http.ResponseWriter, _ *http.Request) {
	st, err := s.States.Load()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, stateEnvelope{State: st})
}

// Busy reports whether an update is running.
func (s *Service) Busy() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// ListenUnix listens on a unix socket, replacing a stale one left by an
// earlier run. The socket is world-writable because the server runs as
// another user; the volume it sits in, and the token, are what keep it
// private.
func ListenUnix(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o666); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
