package app

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"retune/internal/server/store"
)

// readyTimeout bounds the database check a readiness probe triggers. A probe
// is asked on a schedule and answered under one, so a server whose database
// has gone away must say so quickly rather than hold the connection open
// until the prober gives up and calls it a timeout - the two look the same to
// a load balancer, but only one of them tells an operator what is wrong.
const readyTimeout = 2 * time.Second

// mountHealth adds the two probes an orchestrator asks for, on the root mux so
// they answer before the console's catch-all and outside every authenticated
// route: a load balancer cannot sign in, and a probe that needs a session is a
// probe nobody can use.
//
// The two questions are deliberately different. /healthz asks whether this
// process is still running its own loop, and answers from memory - restarting
// a server because its database is briefly unreachable turns an outage into a
// longer one. /readyz asks whether it can do any work, which means reaching
// Postgres, so an instance that came up before its database did is kept out of
// rotation instead of serving errors.
func mountHealth(mux *http.ServeMux, st *store.Store, log *slog.Logger) {
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writePlain(w, http.StatusOK, "ok")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), readyTimeout)
		defer cancel()
		if err := st.Ping(ctx); err != nil {
			// The probe is unauthenticated, so the body says only that the
			// server is not ready; which host, which credential and which
			// driver error are the operator's business, and they go to the
			// log where a session is already required to read them.
			log.Error("readiness check failed", "err", err)
			writePlain(w, http.StatusServiceUnavailable, "database unavailable")
			return
		}
		writePlain(w, http.StatusOK, "ok")
	})
}

func writePlain(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	// Probes are polled every few seconds; a cached answer is not an answer.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body + "\n"))
}
