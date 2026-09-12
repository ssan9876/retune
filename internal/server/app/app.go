// Package app wires the server's components together.
package app

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"time"

	"retune/internal/config"
	"retune/internal/server/agentapi"
	"retune/internal/server/ca"
	"retune/internal/server/enroll"
	"retune/internal/server/store"
)

const clientCertValidity = 90 * 24 * time.Hour

// App is a fully wired server.
type App struct {
	Store     *store.Store
	CA        *ca.CA
	Enroll    *enroll.Service
	Handler   http.Handler
	TLSConfig *tls.Config
}

// New migrates the database, loads (or creates) the CA, and builds handlers.
func New(ctx context.Context, cfg config.Server, log *slog.Logger) (*App, error) {
	if err := store.Migrate(cfg.DatabaseURL); err != nil {
		return nil, err
	}
	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	authority, err := ca.LoadOrCreate(ctx, ca.FileKeyStore{Dir: filepath.Join(cfg.DataDir, "ca")}, time.Now())
	if err != nil {
		st.Close()
		return nil, err
	}
	serverCert, err := loadServerCert(cfg, authority)
	if err != nil {
		st.Close()
		return nil, err
	}

	svc := &enroll.Service{Store: st, CA: authority, Now: time.Now, CertValidity: clientCertValidity}
	h := &agentapi.Handler{Enroll: svc, Store: st, Now: time.Now, CheckinInterval: cfg.CheckinInterval, Log: log}
	return &App{
		Store:   st,
		CA:      authority,
		Enroll:  svc,
		Handler: h.Routes(),
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{serverCert},
			ClientAuth:   tls.VerifyClientCertIfGiven,
			ClientCAs:    authority.Pool(),
		},
	}, nil
}

// Close releases the database pool.
func (a *App) Close() { a.Store.Close() }

func loadServerCert(cfg config.Server, authority *ca.CA) (tls.Certificate, error) {
	switch cfg.TLSMode {
	case "self-signed":
		return authority.IssueServerCert(uniq(cfg.PublicHost(), "localhost", "127.0.0.1"), time.Now())
	case "provided":
		c, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("load TLS certificate: %w", err)
		}
		return c, nil
	default:
		return tls.Certificate{}, fmt.Errorf("unsupported TLS mode %q", cfg.TLSMode)
	}
}

func uniq(items ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range items {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
