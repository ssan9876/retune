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
	"retune/internal/server/adminapi"
	"retune/internal/server/agentapi"
	"retune/internal/server/auth"
	"retune/internal/server/ca"
	"retune/internal/server/commands"
	"retune/internal/server/console"
	"retune/internal/server/devices"
	"retune/internal/server/enroll"
	"retune/internal/server/inventory"
	"retune/internal/server/store"
)

const clientCertValidity = 90 * 24 * time.Hour

// App is a fully wired server.
type App struct {
	Store     *store.Store
	CA        *ca.CA
	Enroll    *enroll.Service
	Inventory *inventory.Service
	Commands  *commands.Service
	Devices   *devices.Service
	Auth      *auth.Service
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
	inv := &inventory.Service{Store: st, Now: time.Now}
	cmd := &commands.Service{Store: st, Now: time.Now}
	dev := &devices.Service{Store: st}
	authSvc := &auth.Service{
		Store: st, Now: time.Now, SessionTTL: cfg.SessionTTL,
		Limiter: auth.NewLimiter(10, 15*time.Minute, time.Now), Issuer: "Retune",
	}
	agent := &agentapi.Handler{
		Enroll: svc, Inventory: inv, Commands: cmd, Store: st,
		Now: time.Now, CheckinInterval: cfg.CheckinInterval, Log: log,
	}
	admin := &adminapi.Handler{
		Auth: authSvc, Store: st, Commands: cmd, Devices: dev, Enroll: svc,
		Now: time.Now, Log: log,
	}
	root := http.NewServeMux()
	root.Handle("/api/agent/v1/", agent.Routes())
	root.Handle("/api/admin/v1/", admin.Routes())
	root.Handle("/", console.Handler())

	return &App{
		Store:     st,
		CA:        authority,
		Enroll:    svc,
		Inventory: inv,
		Commands:  cmd,
		Devices:   dev,
		Auth:      authSvc,
		Handler:   root,
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
