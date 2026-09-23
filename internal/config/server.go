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
	// SessionMaxLifetime is how long a session can live however busy it is.
	// SessionTTL slides with use; this does not.
	SessionMaxLifetime time.Duration
	// ClientCertHeader carries the device certificate in behind-proxy mode.
	ClientCertHeader string
	// TrustedProxies may send ClientCertHeader; nobody else may.
	TrustedProxies []netip.Prefix
	CAKeySource    string // "file" | "env"
	SweepInterval  time.Duration
	// AgentReleaseKeys are the public keys agent builds must be signed by.
	// Optional at startup; an upload with none configured is refused.
	AgentReleaseKeys []release.PublicKey
	// OperationsKeys are the keys scripts and wipe orders are signed with,
	// when agents are built to require them. The server only checks early
	// and tells the console to ask for signatures; the agent enforces.
	OperationsKeys []release.PublicKey
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
	// OIDC is single sign-on. Its zero value is SSO off.
	OIDC OIDCConfig
	// AuditStream is where the audit log is copied as it is written, for a
	// SIEM. Its zero value streams nowhere.
	AuditStream AuditStreamConfig
	// Approvals is two-person approval. Its zero value is off.
	Approvals ApprovalsConfig
}

// ApprovalsConfig says which requests wait for a second administrator.
type ApprovalsConfig struct {
	// Required holds every wipe, and ad-hoc PowerShell or an assignment that
	// reaches more than DeviceThreshold devices, until another admin approves.
	Required bool
	// DeviceThreshold is how many devices a request may reach without one.
	DeviceThreshold int
}

// defaultApprovalThreshold is APPROVAL_DEVICE_THRESHOLD unset.
const defaultApprovalThreshold = 50

// AuditStreamConfig names the audit log's destinations outside Retune. They
// are process configuration, set by whoever runs the server, not something
// the console can change: where the record of what admins did is sent must
// not be editable by those admins.
type AuditStreamConfig struct {
	// SyslogNetwork is "udp", "tcp" or "tls"; SyslogAddress is host:port.
	SyslogNetwork string
	SyslogAddress string
	// WebhookURL receives newline-delimited JSON; WebhookHeader, "Name:
	// value", is sent with it - an Authorization header, typically.
	WebhookURL    string
	WebhookHeader string
}

// Enabled reports whether the audit log goes anywhere.
func (a AuditStreamConfig) Enabled() bool { return a.SyslogAddress != "" || a.WebhookURL != "" }

// OIDCConfig is the identity provider the console signs people in with.
type OIDCConfig struct {
	Issuer         string
	ClientID       string
	ClientSecret   string
	GroupsClaim    string
	AdminGroups    []string
	HelpdeskGroups []string
	ReadOnlyGroups []string
	DisplayName    string
	// DisableLocalLogin refuses password sign-in, leaving SSO as the only
	// way into the console. bootstrap-admin still works from the command line.
	DisableLocalLogin bool
	// ScopeGroups maps an identity-provider group to the Retune device groups
	// its members may manage. When set, every SSO sign-in sets the person's
	// scope from their groups, and the console can no longer change it.
	ScopeGroups map[string][]string
	// FleetGroups are the identity-provider groups whose members manage the
	// whole fleet when ScopeGroups is set.
	FleetGroups []string
}

// ManagesScopes reports whether the identity provider decides SSO accounts'
// device scopes.
func (o OIDCConfig) ManagesScopes() bool { return len(o.ScopeGroups) > 0 }

// Enabled reports whether SSO is configured.
func (o OIDCConfig) Enabled() bool { return o.Issuer != "" }

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
	// Unset, the cap is a day or the idle timeout, whichever is longer, so a
	// deployment that already allowed longer idle sessions still starts after
	// an upgrade. Set, it must not undercut the idle timeout it caps.
	c.SessionMaxLifetime = max(24*time.Hour, c.SessionTTL)
	if v := lookup("SESSION_MAX_HOURS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 720 {
			return Server{}, errors.New("SESSION_MAX_HOURS must be an integer between 1 and 720")
		}
		c.SessionMaxLifetime = time.Duration(n) * time.Hour
		if c.SessionMaxLifetime < c.SessionTTL {
			return Server{}, errors.New("SESSION_MAX_HOURS cannot be shorter than SESSION_TTL_HOURS")
		}
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
	if v := lookup("APPROVALS_REQUIRED"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return Server{}, errors.New("APPROVALS_REQUIRED must be true or false")
		}
		c.Approvals.Required = b
	}
	c.Approvals.DeviceThreshold = defaultApprovalThreshold
	if v := lookup("APPROVAL_DEVICE_THRESHOLD"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return Server{}, errors.New("APPROVAL_DEVICE_THRESHOLD must be an integer >= 0")
		}
		c.Approvals.DeviceThreshold = n
	}
	if v := lookup("OPERATIONS_KEYS"); v != "" {
		keys, err := release.ParseTrustList(v)
		if err != nil {
			return Server{}, fmt.Errorf("OPERATIONS_KEYS: %w", err)
		}
		c.OperationsKeys = keys
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
	if c.OIDC, err = loadOIDC(lookup); err != nil {
		return Server{}, err
	}
	if c.AuditStream, err = loadAuditStream(lookup); err != nil {
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

// loadAuditStream reads the audit destinations. The syslog address is a URL
// (udp://, tcp:// or tls://host:port) so one setting says both how and where.
func loadAuditStream(lookup func(string) string) (AuditStreamConfig, error) {
	var a AuditStreamConfig
	if v := strings.TrimSpace(lookup("AUDIT_SYSLOG_ADDRESS")); v != "" {
		u, err := url.Parse(v)
		if err != nil || u.Host == "" || u.Port() == "" {
			return a, errors.New("AUDIT_SYSLOG_ADDRESS must look like tcp://host:514, udp://host:514 or tls://host:6514")
		}
		switch u.Scheme {
		case "udp", "tcp", "tls":
		default:
			return a, errors.New("AUDIT_SYSLOG_ADDRESS must use udp://, tcp:// or tls://")
		}
		a.SyslogNetwork, a.SyslogAddress = u.Scheme, u.Host
	}
	if v := strings.TrimSpace(lookup("AUDIT_WEBHOOK_URL")); v != "" {
		u, err := url.Parse(v)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return a, errors.New("AUDIT_WEBHOOK_URL must be an https URL")
		}
		a.WebhookURL = v
	}
	if v := strings.TrimSpace(lookup("AUDIT_WEBHOOK_HEADER")); v != "" {
		name, value, ok := strings.Cut(v, ":")
		if !ok || strings.TrimSpace(name) == "" || strings.TrimSpace(value) == "" || strings.ContainsAny(v, "\r\n") {
			return a, errors.New("AUDIT_WEBHOOK_HEADER must look like \"Name: value\"")
		}
		if a.WebhookURL == "" {
			return a, errors.New("AUDIT_WEBHOOK_HEADER needs AUDIT_WEBHOOK_URL")
		}
		a.WebhookHeader = v
	}
	return a, nil
}

// loadOIDC reads the SSO settings. They are all-or-nothing in the ways that
// matter: a half-configured client, a provider nobody can be mapped from, or
// local login switched off with nothing to replace it would each start a
// server nobody can sign in to, so each is refused at startup instead.
func loadOIDC(lookup func(string) string) (OIDCConfig, error) {
	o := OIDCConfig{
		Issuer:         strings.TrimRight(strings.TrimSpace(lookup("OIDC_ISSUER")), "/"),
		ClientID:       strings.TrimSpace(lookup("OIDC_CLIENT_ID")),
		ClientSecret:   lookup("OIDC_CLIENT_SECRET"),
		GroupsClaim:    or(strings.TrimSpace(lookup("OIDC_GROUPS_CLAIM")), "groups"),
		AdminGroups:    splitList(lookup("OIDC_ADMIN_GROUPS")),
		HelpdeskGroups: splitList(lookup("OIDC_HELPDESK_GROUPS")),
		ReadOnlyGroups: splitList(lookup("OIDC_READONLY_GROUPS")),
		DisplayName:    or(strings.TrimSpace(lookup("OIDC_DISPLAY_NAME")), "Sign in with SSO"),
	}
	scopes, err := parseScopeGroups(lookup("OIDC_SCOPE_GROUPS"))
	if err != nil {
		return OIDCConfig{}, err
	}
	o.ScopeGroups, o.FleetGroups = scopes, splitList(lookup("OIDC_FLEET_GROUPS"))
	if len(o.FleetGroups) > 0 && len(o.ScopeGroups) == 0 {
		return OIDCConfig{}, errors.New("OIDC_FLEET_GROUPS only means something with OIDC_SCOPE_GROUPS")
	}
	if v := lookup("OIDC_DISABLE_LOCAL_LOGIN"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return OIDCConfig{}, errors.New("OIDC_DISABLE_LOCAL_LOGIN must be true or false")
		}
		o.DisableLocalLogin = b
	}
	set := 0
	for _, v := range []string{o.Issuer, o.ClientID, o.ClientSecret} {
		if v != "" {
			set++
		}
	}
	switch {
	case set == 0:
		if o.DisableLocalLogin {
			return OIDCConfig{}, errors.New("OIDC_DISABLE_LOCAL_LOGIN needs SSO configured, or nobody could sign in")
		}
		if o.ManagesScopes() {
			return OIDCConfig{}, errors.New("OIDC_SCOPE_GROUPS needs SSO configured")
		}
		return OIDCConfig{DisplayName: o.DisplayName, GroupsClaim: o.GroupsClaim}, nil
	case set < 3:
		return OIDCConfig{}, errors.New("SSO needs all of OIDC_ISSUER, OIDC_CLIENT_ID and OIDC_CLIENT_SECRET")
	}
	u, err := url.Parse(o.Issuer)
	if err != nil || u.Host == "" {
		return OIDCConfig{}, errors.New("OIDC_ISSUER must be a URL")
	}
	local := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"
	if u.Scheme != "https" && !(u.Scheme == "http" && local) {
		return OIDCConfig{}, errors.New("OIDC_ISSUER must be https (http is allowed only for localhost)")
	}
	if len(o.AdminGroups) == 0 && len(o.HelpdeskGroups) == 0 && len(o.ReadOnlyGroups) == 0 {
		return OIDCConfig{}, errors.New("SSO needs OIDC_ADMIN_GROUPS, OIDC_HELPDESK_GROUPS or OIDC_READONLY_GROUPS, or nobody could ever be let in")
	}
	return o, nil
}

// parseScopeGroups reads "idp-group=Device group;other=Another, Third". Pairs
// are separated by semicolons, because device group names may contain commas;
// one identity-provider group may map to several device groups by repeating
// it.
func parseScopeGroups(s string) (map[string][]string, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	out := map[string][]string{}
	for _, pair := range strings.Split(s, ";") {
		if strings.TrimSpace(pair) == "" {
			continue
		}
		idp, group, ok := strings.Cut(pair, "=")
		idp, group = strings.TrimSpace(idp), strings.TrimSpace(group)
		if !ok || idp == "" || group == "" {
			return nil, fmt.Errorf("OIDC_SCOPE_GROUPS: %q should look like idp-group=Device group", strings.TrimSpace(pair))
		}
		out[idp] = append(out[idp], group)
	}
	return out, nil
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
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
