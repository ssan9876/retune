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
	"strings"
	"time"

	"retune/internal/config"
	"retune/internal/server/adminapi"
	"retune/internal/server/agentapi"
	"retune/internal/server/agentversions"
	"retune/internal/server/alerts"
	"retune/internal/server/apps"
	"retune/internal/server/artifacts"
	"retune/internal/server/auth"
	"retune/internal/server/bitlocker"
	"retune/internal/server/ca"
	"retune/internal/server/commands"
	"retune/internal/server/compliance"
	"retune/internal/server/console"
	"retune/internal/server/devices"
	"retune/internal/server/enroll"
	"retune/internal/server/groups"
	"retune/internal/server/inventory"
	"retune/internal/server/profiles"
	"retune/internal/server/scripts"
	"retune/internal/server/secrets"
	"retune/internal/server/store"
	"retune/internal/server/sweeper"
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
	Compliance    *compliance.Service
	Alerts        *alerts.Service
	Auth          *auth.Service
	Handler       http.Handler
	TLSConfig     *tls.Config
	// Sweeps records what the sweeper jobs do, for /metrics. The caller that
	// runs the sweeper passes it to sweeper.Runner.
	Sweeps *sweeper.Stats
	// SSO is nil unless single sign-on is configured.
	SSO *auth.OIDC
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
	// ctx is the server's lifetime: a re-evaluation started by "Evaluate now"
	// outlives its request but not the process it runs in.
	comp := &compliance.Service{Store: st, Now: time.Now, Log: log, Background: ctx}
	inv := &inventory.Service{Store: st, Now: time.Now, Groups: grp, Compliance: comp, Log: log}
	cmd := &commands.Service{Store: st, Now: time.Now}
	scr := &scripts.Service{Store: st, Now: time.Now}
	prof := &profiles.Service{Store: st, Now: time.Now}
	appSvc := &apps.Service{Store: st, Now: time.Now}
	agentVers := &agentversions.Service{
		Store: st, Now: time.Now,
		// Beside the CA and the secret key: DATA_DIR is already what the
		// README tells an operator to back up.
		Artifacts:   artifacts.Store{Dir: filepath.Join(cfg.DataDir, "agents")},
		ReleaseKeys: cfg.AgentReleaseKeys,
	}
	secretKey, err := serverSecret(cfg)
	if err != nil {
		st.Close()
		return nil, err
	}
	locker := &bitlocker.Service{Store: st, Key: secretKey, Now: time.Now}
	// Alerts share the key that protects escrowed recovery keys: a webhook's
	// shared secret is the same kind of thing, something the server must be
	// able to use and nobody should be able to read back out of the console.
	alerter := &alerts.Service{
		Store: st, Key: secretKey, Now: time.Now, Log: log,
		SMTP: alerts.SMTP{
			Host: cfg.SMTP.Host, Port: cfg.SMTP.Port, From: cfg.SMTP.From,
			Username: cfg.SMTP.Username, Password: cfg.SMTP.Password, StartTLS: cfg.SMTP.StartTLS,
		},
	}
	dev := &devices.Service{Store: st}
	authSvc := &auth.Service{
		Store: st, Now: time.Now, SessionTTL: cfg.SessionTTL, MaxSessionLifetime: cfg.SessionMaxLifetime,
		Limiter: auth.NewLimiter(10, 15*time.Minute, time.Now), Issuer: "Retune", Key: secretKey,
	}
	if n, err := authSvc.SealTOTPSecrets(ctx); err != nil {
		st.Close()
		return nil, fmt.Errorf("seal authenticator secrets: %w", err)
	} else if n > 0 {
		log.Info("sealed authenticator secrets stored by an earlier version", "count", n)
	}
	agent := &agentapi.Handler{
		Enroll: svc, Inventory: inv, Commands: cmd, Scripts: scr, Profiles: prof, Apps: appSvc, AgentVersions: agentVers, BitLocker: locker, Store: st,
		Now: time.Now, CheckinInterval: cfg.CheckinInterval, Log: log,
		ClientCert: clientCert,
	}
	authSvc.LocalLoginDisabled = cfg.OIDC.DisableLocalLogin
	var sso *auth.OIDC
	if cfg.OIDC.Enabled() {
		sso = &auth.OIDC{
			Config: cfg.OIDC, RedirectURL: strings.TrimRight(cfg.PublicURL, "/") + "/api/admin/v1/oidc/callback",
			Key: secretKey, Store: st, Now: time.Now,
		}
		log.Info("single sign-on is on; register this redirect URL with the identity provider",
			"issuer", cfg.OIDC.Issuer, "redirect_url", sso.RedirectURL)
	}
	admin := &adminapi.Handler{
		Auth: authSvc, Store: st, Commands: cmd, Devices: dev, Enroll: svc, Groups: grp, Scripts: scr, Profiles: prof, Apps: appSvc, Compliance: comp, AgentVersions: agentVers, BitLocker: locker, Alerts: alerter,
		SSO: sso, SSOName: cfg.OIDC.DisplayName,
		Now: time.Now, Log: log,
	}
	root := http.NewServeMux()
	mountHealth(root, st, log)
	sweeps := sweeper.NewStats()
	mountMetrics(root, st, cfg.MetricsToken, sweeps, time.Now, log)
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
		Compliance:    comp,
		Alerts:        alerter,
		Auth:          authSvc,
		Handler:       root,
		TLSConfig:     tlsCfg,
		Sweeps:        sweeps,
		SSO:           sso,
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
