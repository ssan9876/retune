// Package app wires the server's components together.
package app

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"retune/internal/config"
	"retune/internal/server/adminapi"
	"retune/internal/server/agentapi"
	"retune/internal/server/agentversions"
	"retune/internal/server/apps"
	"retune/internal/server/artifacts"
	"retune/internal/server/auth"
	"retune/internal/server/bitlocker"
	"retune/internal/server/ca"
	"retune/internal/server/commands"
	"retune/internal/server/console"
	"retune/internal/server/devices"
	"retune/internal/server/enroll"
	"retune/internal/server/groups"
	"retune/internal/server/inventory"
	"retune/internal/server/profiles"
	"retune/internal/server/scripts"
	"retune/internal/server/secrets"
	"retune/internal/server/store"
)

const clientCertValidity = 90 * 24 * time.Hour

// App is a fully wired server.
type App struct {
	Store         *store.Store
	CA            *ca.CA
	Enroll        *enroll.Service
	Inventory     *inventory.Service
	Commands      *commands.Service
	Scripts       *scripts.Service
	Profiles      *profiles.Service
	Apps          *apps.Service
	AgentVersions *agentversions.Service
	BitLocker     *bitlocker.Service
	Devices       *devices.Service
	Groups        *groups.Service
	Auth          *auth.Service
	Handler       http.Handler
	TLSConfig     *tls.Config
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
	var keys ca.KeyStore = ca.FileKeyStore{Dir: filepath.Join(cfg.DataDir, "ca")}
	if cfg.CAKeySource == "env" {
		keys = ca.EnvKeyStore{CertPEM: os.Getenv("CA_CERT_PEM"), KeyPEM: os.Getenv("CA_KEY_PEM")}
	}
	authority, err := ca.LoadOrCreate(ctx, keys, time.Now())
	if err != nil {
		st.Close()
		return nil, err
	}
	// Behind a proxy there is no handshake here, so the device certificate
	// arrives in a header and this server holds no TLS configuration at all.
	clientCert := agentapi.TLSClientCert
	var tlsCfg *tls.Config
	if cfg.TLSMode == "behind-proxy" {
		clientCert = agentapi.HeaderClientCert(cfg.ClientCertHeader, cfg.TrustedProxies, authority.Pool())
	} else {
		serverCert, err := loadServerCert(cfg, authority)
		if err != nil {
			st.Close()
			return nil, err
		}
		tlsCfg = &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{serverCert},
			ClientAuth:   tls.VerifyClientCertIfGiven,
			ClientCAs:    authority.Pool(),
		}
	}

	svc := &enroll.Service{Store: st, CA: authority, Now: time.Now, CertValidity: clientCertValidity}
	grp := &groups.Service{Store: st, Now: time.Now, Log: log}
	inv := &inventory.Service{Store: st, Now: time.Now, Groups: grp, Log: log}
	cmd := &commands.Service{Store: st, Now: time.Now}
	scr := &scripts.Service{Store: st, Now: time.Now}
	prof := &profiles.Service{Store: st, Now: time.Now}
	appSvc := &apps.Service{Store: st, Now: time.Now}
	agentVers := &agentversions.Service{
		Store: st, Now: time.Now,
		// Beside the CA and the secret key: DATA_DIR is already what the
		// README tells an operator to back up.
		Artifacts: artifacts.Store{Dir: filepath.Join(cfg.DataDir, "agents")},
	}
	secretKey, err := serverSecret(cfg)
	if err != nil {
		st.Close()
		return nil, err
	}
	locker := &bitlocker.Service{Store: st, Key: secretKey, Now: time.Now}
	dev := &devices.Service{Store: st}
	authSvc := &auth.Service{
		Store: st, Now: time.Now, SessionTTL: cfg.SessionTTL,
		Limiter: auth.NewLimiter(10, 15*time.Minute, time.Now), Issuer: "Retune",
	}
	agent := &agentapi.Handler{
		Enroll: svc, Inventory: inv, Commands: cmd, Scripts: scr, Profiles: prof, Apps: appSvc, AgentVersions: agentVers, BitLocker: locker, Store: st,
		Now: time.Now, CheckinInterval: cfg.CheckinInterval, Log: log,
		ClientCert: clientCert,
	}
	admin := &adminapi.Handler{
		Auth: authSvc, Store: st, Commands: cmd, Devices: dev, Enroll: svc, Groups: grp, Scripts: scr, Profiles: prof, Apps: appSvc, AgentVersions: agentVers, BitLocker: locker,
		Now: time.Now, Log: log,
	}
	root := http.NewServeMux()
	root.Handle("/api/agent/v1/", agent.Routes())
	root.Handle("/api/admin/v1/", admin.Routes())
	root.Handle("/", console.Handler())

	return &App{
		Store:         st,
		CA:            authority,
		Enroll:        svc,
		Inventory:     inv,
		Commands:      cmd,
		Scripts:       scr,
		Profiles:      prof,
		Apps:          appSvc,
		AgentVersions: agentVers,
		BitLocker:     locker,
		Devices:       dev,
		Groups:        grp,
		Auth:          authSvc,
		Handler:       root,
		TLSConfig:     tlsCfg,
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

// serverSecret loads the key that protects escrowed data at rest. It lives
// beside the CA, because losing either one is equally unrecoverable.
func serverSecret(cfg config.Server) (*secrets.Key, error) {
	if cfg.CAKeySource == "env" {
		return secrets.FromHex(os.Getenv("SECRET_KEY"))
	}
	return secrets.LoadOrCreateFile(cfg.DataDir)
}
