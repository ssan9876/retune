// Package config loads process configuration.
package config

import (
	"errors"
	"fmt"
	"net/mail"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"retune/internal/release"
)

// Server is the retune-server configuration.
type Server struct {
	DatabaseURL     string
	PublicURL       string
	AgentListen     string
	TLSMode         string // "self-signed" | "provided" | "behind-proxy"
	TLSCertFile     string
	TLSKeyFile      string
	DataDir         string
	CheckinInterval time.Duration
	SessionTTL      time.Duration
	// ClientCertHeader carries the device certificate in behind-proxy mode.
	ClientCertHeader string
	// TrustedProxies may send ClientCertHeader; nobody else may.
	TrustedProxies []netip.Prefix
	CAKeySource    string // "file" | "env"
	SweepInterval  time.Duration
	// AgentReleaseKeys are the public keys agent builds must be signed by.
	// Optional at startup; an upload with none configured is refused.
	AgentReleaseKeys []release.PublicKey
	// SMTP is the relay alert email is sent through. Optional: without it,
	// creating an email notification channel is refused rather than accepted
	// and quietly never delivered.
	SMTP SMTPConfig
	// Retention says how long history is kept before the retention sweeper
	// deletes it.
	Retention Retention
	// MetricsToken turns on GET /metrics and is the bearer token a scraper
	// must send. Empty leaves the endpoint off.
	MetricsToken string
}

// Retention is how long each kind of history is kept. A zero duration keeps
// that history forever; the defaults are set in LoadServer.
type Retention struct {
	Audit       time.Duration
	Commands    time.Duration
	ScriptRuns  time.Duration
	AppInstalls time.Duration
}

// minMetricsToken is the shortest METRICS_TOKEN accepted. The endpoint is
// reachable by anything that can reach the server, so its token is a
// password, and one short enough to guess is worse than none because it
// looks like protection.
const minMetricsToken = 32

// SMTPConfig is the mail relay. It is process configuration rather than a
// notification channel's own settings because a deployment has one relay, and
// a password in a row the console can read back is a password nobody should
// have stored.
type SMTPConfig struct {
	Host     string
	Port     int
	From     string
	Username string
	Password string
	StartTLS bool
}

// LoadServer reads configuration from environment variables via getenv.
func LoadServer(getenv func(string) string) (Server, error) {
	fileValues, err := loadConfigFile(getenv)
	if err != nil {
		return Server{}, err
	}
	// The environment wins; the file fills in the rest.
	lookup := func(key string) string {
		if v := getenv(key); v != "" {
			return v
		}
		return fileValues[key]
	}
	c := Server{
		DatabaseURL:     lookup("DATABASE_URL"),
		PublicURL:       lookup("PUBLIC_URL"),
		AgentListen:     or(lookup("AGENT_API_LISTEN"), ":8443"),
		TLSMode:         or(lookup("TLS_MODE"), "self-signed"),
		TLSCertFile:     lookup("TLS_CERT_FILE"),
		TLSKeyFile:      lookup("TLS_KEY_FILE"),
		DataDir:         or(lookup("DATA_DIR"), "data"),
		CheckinInterval: 5 * time.Minute,
		SessionTTL:      12 * time.Hour,
	}
	if v := lookup("CHECKIN_INTERVAL_SECONDS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 30 {
			return Server{}, errors.New("CHECKIN_INTERVAL_SECONDS must be an integer >= 30")
		}
		c.CheckinInterval = time.Duration(n) * time.Second
	}
	if v := lookup("SESSION_TTL_HOURS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 168 {
			return Server{}, errors.New("SESSION_TTL_HOURS must be an integer between 1 and 168")
		}
		c.SessionTTL = time.Duration(n) * time.Hour
	}
	c.ClientCertHeader = or(lookup("CLIENT_CERT_HEADER"), "X-Forwarded-Client-Cert")
	c.CAKeySource = or(lookup("CA_KEY_SOURCE"), "file")
	c.SweepInterval = 5 * time.Minute
	if v := lookup("SWEEP_INTERVAL_SECONDS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 10 {
			return Server{}, errors.New("SWEEP_INTERVAL_SECONDS must be an integer >= 10")
		}
		c.SweepInterval = time.Duration(n) * time.Second
	}
	if v := lookup("AGENT_RELEASE_KEYS"); v != "" {
		keys, err := release.ParseTrustList(v)
		if err != nil {
			return Server{}, fmt.Errorf("AGENT_RELEASE_KEYS: %w", err)
		}
		c.AgentReleaseKeys = keys
	}
	smtpCfg, err := loadSMTP(lookup)
	if err != nil {
		return Server{}, err
	}
	c.SMTP = smtpCfg
	if c.Retention, err = loadRetention(lookup); err != nil {
		return Server{}, err
	}
	c.MetricsToken = strings.TrimSpace(lookup("METRICS_TOKEN"))
	if c.MetricsToken != "" && len(c.MetricsToken) < minMetricsToken {
		return Server{}, fmt.Errorf("METRICS_TOKEN must be at least %d characters", minMetricsToken)
	}
	if v := lookup("TRUSTED_PROXIES"); v != "" {
		proxies, err := parsePrefixes(v)
		if err != nil {
			return Server{}, err
		}
		c.TrustedProxies = proxies
	}
	switch c.CAKeySource {
	case "file", "env":
	default:
		return Server{}, fmt.Errorf("unsupported CA_KEY_SOURCE %q (supported: file, env)", c.CAKeySource)
	}
	if c.DatabaseURL == "" {
		return Server{}, errors.New("DATABASE_URL is required")
	}
	u, err := url.Parse(c.PublicURL)
	if c.PublicURL == "" || err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return Server{}, errors.New("PUBLIC_URL must be an https URL, e.g. https://mdm.example.com")
	}
	switch c.TLSMode {
	case "self-signed":
	case "provided":
		if c.TLSCertFile == "" || c.TLSKeyFile == "" {
			return Server{}, errors.New("TLS_MODE=provided requires TLS_CERT_FILE and TLS_KEY_FILE")
		}
	case "behind-proxy":
		// The proxy terminates TLS, so the device certificate arrives in a
		// header. Without a header name and a trusted sender the agent API
		// would be unauthenticated, so refuse to start rather than serve it.
		if strings.TrimSpace(c.ClientCertHeader) == "" {
			return Server{}, errors.New("TLS_MODE=behind-proxy requires a non-empty CLIENT_CERT_HEADER")
		}
		if len(c.TrustedProxies) == 0 {
			return Server{}, errors.New("TLS_MODE=behind-proxy requires TRUSTED_PROXIES (comma-separated IPs or CIDRs)")
		}
	default:
		return Server{}, fmt.Errorf("unsupported TLS_MODE %q (supported: self-signed, provided, behind-proxy)", c.TLSMode)
	}
	return c, nil
}

// loadSMTP reads the mail relay settings. All of them are optional together:
// a deployment that never sends email configures none of them, and one that
// does is told about a half-configured relay at startup rather than when the
// first alert fails.
func loadSMTP(lookup func(string) string) (SMTPConfig, error) {
	cfg := SMTPConfig{
		Host:     strings.TrimSpace(lookup("SMTP_HOST")),
		Port:     587,
		From:     strings.TrimSpace(lookup("SMTP_FROM")),
		Username: lookup("SMTP_USERNAME"),
		Password: lookup("SMTP_PASSWORD"),
		StartTLS: true,
	}
	if v := lookup("SMTP_PORT"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 65535 {
			return SMTPConfig{}, errors.New("SMTP_PORT must be a port number")
		}
		cfg.Port = n
	}
	if v := lookup("SMTP_STARTTLS"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return SMTPConfig{}, errors.New("SMTP_STARTTLS must be true or false")
		}
		cfg.StartTLS = b
	}
	if cfg.Host == "" && cfg.From == "" {
		return SMTPConfig{}, nil
	}
	if cfg.Host == "" || cfg.From == "" {
		return SMTPConfig{}, errors.New("SMTP_HOST and SMTP_FROM are both required to send email")
	}
	if _, err := mail.ParseAddress(cfg.From); err != nil {
		return SMTPConfig{}, errors.New("SMTP_FROM must be an email address")
	}
	if cfg.Password != "" && cfg.Username == "" {
		return SMTPConfig{}, errors.New("SMTP_PASSWORD needs SMTP_USERNAME")
	}
	return cfg, nil
}

// loadRetention reads the four history horizons. Each is a number of days:
// 0 keeps that history forever, anything else must be 1-3650, and unset
// takes the default. Audit history is kept longer than the rest because it
// is the record of who did what, not of what a machine happened to report.
func loadRetention(lookup func(string) string) (Retention, error) {
	var r Retention
	for _, h := range []struct {
		key         string
		defaultDays int
		dst         *time.Duration
	}{
		{"AUDIT_RETENTION_DAYS", 365, &r.Audit},
		{"COMMAND_RETENTION_DAYS", 90, &r.Commands},
		{"SCRIPT_RUN_RETENTION_DAYS", 90, &r.ScriptRuns},
		{"APP_INSTALL_RETENTION_DAYS", 90, &r.AppInstalls},
	} {
		days := h.defaultDays
		if v := lookup(h.key); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 || n > 3650 {
				return Retention{}, fmt.Errorf("%s must be 0 (keep forever) or a number of days up to 3650", h.key)
			}
			days = n
		}
		*h.dst = time.Duration(days) * 24 * time.Hour
	}
	return r, nil
}

// parsePrefixes reads a comma-separated list of CIDRs and bare addresses.
func parsePrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "/") {
			p, err := netip.ParsePrefix(part)
			if err != nil {
				return nil, fmt.Errorf("TRUSTED_PROXIES entry %q is not a valid CIDR", part)
			}
			out = append(out, p.Masked())
			continue
		}
		addr, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("TRUSTED_PROXIES entry %q is not a valid IP address or CIDR", part)
		}
		out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return out, nil
}

// PublicHost is the hostname (or IP) part of PublicURL.
func (c Server) PublicHost() string {
	u, err := url.Parse(c.PublicURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func or(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
