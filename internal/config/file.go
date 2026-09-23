package config

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

// DefaultConfigFile is read when it exists and RETUNE_CONFIG is unset.
const DefaultConfigFile = "retune-server.yaml"

// fileConfig mirrors the environment variables in YAML form.
type fileConfig struct {
	DatabaseURL            string `yaml:"database_url"`
	PublicURL              string `yaml:"public_url"`
	AgentAPIListen         string `yaml:"agent_api_listen"`
	TLSMode                string `yaml:"tls_mode"`
	TLSCertFile            string `yaml:"tls_cert_file"`
	TLSKeyFile             string `yaml:"tls_key_file"`
	DataDir                string `yaml:"data_dir"`
	CheckinIntervalSeconds int    `yaml:"checkin_interval_seconds"`
	SessionTTLHours        int    `yaml:"session_ttl_hours"`
	SessionMaxHours        int    `yaml:"session_max_hours"`
	ClientCertHeader       string `yaml:"client_cert_header"`
	TrustedProxies         string `yaml:"trusted_proxies"`
	CAKeySource            string `yaml:"ca_key_source"`
	SweepIntervalSeconds   int    `yaml:"sweep_interval_seconds"`
	AgentReleaseKeys       string `yaml:"agent_release_keys"`
	SMTPHost               string `yaml:"smtp_host"`
	SMTPPort               int    `yaml:"smtp_port"`
	SMTPFrom               string `yaml:"smtp_from"`
	SMTPUsername           string `yaml:"smtp_username"`
	SMTPPassword           string `yaml:"smtp_password"`
	SMTPStartTLS           *bool  `yaml:"smtp_starttls"`
	MetricsToken           string `yaml:"metrics_token"`
	OIDCIssuer             string `yaml:"oidc_issuer"`
	OIDCClientID           string `yaml:"oidc_client_id"`
	OIDCClientSecret       string `yaml:"oidc_client_secret"`
	OIDCGroupsClaim        string `yaml:"oidc_groups_claim"`
	OIDCAdminGroups        string `yaml:"oidc_admin_groups"`
	OIDCReadOnlyGroups     string `yaml:"oidc_readonly_groups"`
	OIDCDisplayName        string `yaml:"oidc_display_name"`
	OIDCDisableLocalLogin  *bool  `yaml:"oidc_disable_local_login"`
	AuditSyslogAddress     string `yaml:"audit_syslog_address"`
	AuditWebhookURL        string `yaml:"audit_webhook_url"`
	AuditWebhookHeader     string `yaml:"audit_webhook_header"`
	// Pointers, because 0 is a meaningful value here (keep forever) and has
	// to be told apart from a key that was never written.
	AuditRetentionDays      *int `yaml:"audit_retention_days"`
	CommandRetentionDays    *int `yaml:"command_retention_days"`
	ScriptRunRetentionDays  *int `yaml:"script_run_retention_days"`
	AppInstallRetentionDays *int `yaml:"app_install_retention_days"`
}

// DatabaseURL resolves the database connection string for commands that need
// only that, such as migrate and the admin commands. The environment wins over
// the config file.
func DatabaseURL(getenv func(string) string) (string, error) {
	value, err := lookupValue(getenv, "DATABASE_URL")
	if err != nil {
		return "", err
	}
	if value == "" {
		return "", errors.New("DATABASE_URL is required (set the environment variable or database_url in the config file)")
	}
	return value, nil
}

// DataDir resolves the data directory, defaulting to "data".
func DataDir(getenv func(string) string) (string, error) {
	value, err := lookupValue(getenv, "DATA_DIR")
	if err != nil {
		return "", err
	}
	return or(value, "data"), nil
}

// Value reads one setting by its environment name, from the environment or
// else the config file, for commands that need only a setting or two.
func Value(getenv func(string) string, key string) (string, error) {
	return lookupValue(getenv, key)
}

// lookupValue reads one setting from the environment, then the config file.
func lookupValue(getenv func(string) string, key string) (string, error) {
	if v := getenv(key); v != "" {
		return v, nil
	}
	fileValues, err := loadConfigFile(getenv)
	if err != nil {
		return "", err
	}
	return fileValues[key], nil
}

// loadConfigFile turns the YAML file, if any, into environment-style values.
func loadConfigFile(getenv func(string) string) (map[string]string, error) {
	path := getenv("RETUNE_CONFIG")
	named := path != ""
	if !named {
		path = DefaultConfigFile
	}
	body, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist) && !named:
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("read config file %s: %w", path, err)
	}

	var f fileConfig
	dec := yaml.NewDecoder(bytes.NewReader(body))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("parse config file %s: %w", path, err)
	}
	out := map[string]string{}
	set := func(key, value string) {
		if value != "" {
			out[key] = value
		}
	}
	set("DATABASE_URL", f.DatabaseURL)
	set("PUBLIC_URL", f.PublicURL)
	set("AGENT_API_LISTEN", f.AgentAPIListen)
	set("TLS_MODE", f.TLSMode)
	set("TLS_CERT_FILE", f.TLSCertFile)
	set("TLS_KEY_FILE", f.TLSKeyFile)
	set("DATA_DIR", f.DataDir)
	set("CLIENT_CERT_HEADER", f.ClientCertHeader)
	set("TRUSTED_PROXIES", f.TrustedProxies)
	set("CA_KEY_SOURCE", f.CAKeySource)
	if f.SweepIntervalSeconds != 0 {
		set("SWEEP_INTERVAL_SECONDS", strconv.Itoa(f.SweepIntervalSeconds))
	}
	if f.CheckinIntervalSeconds != 0 {
		set("CHECKIN_INTERVAL_SECONDS", strconv.Itoa(f.CheckinIntervalSeconds))
	}
	if f.SessionTTLHours != 0 {
		set("SESSION_TTL_HOURS", strconv.Itoa(f.SessionTTLHours))
	}
	if f.SessionMaxHours != 0 {
		set("SESSION_MAX_HOURS", strconv.Itoa(f.SessionMaxHours))
	}
	set("AGENT_RELEASE_KEYS", f.AgentReleaseKeys)
	set("SMTP_HOST", f.SMTPHost)
	if f.SMTPPort != 0 {
		set("SMTP_PORT", strconv.Itoa(f.SMTPPort))
	}
	set("SMTP_FROM", f.SMTPFrom)
	set("SMTP_USERNAME", f.SMTPUsername)
	set("SMTP_PASSWORD", f.SMTPPassword)
	if f.SMTPStartTLS != nil {
		set("SMTP_STARTTLS", strconv.FormatBool(*f.SMTPStartTLS))
	}
	set("METRICS_TOKEN", f.MetricsToken)
	set("AUDIT_SYSLOG_ADDRESS", f.AuditSyslogAddress)
	set("AUDIT_WEBHOOK_URL", f.AuditWebhookURL)
	set("AUDIT_WEBHOOK_HEADER", f.AuditWebhookHeader)
	set("OIDC_ISSUER", f.OIDCIssuer)
	set("OIDC_CLIENT_ID", f.OIDCClientID)
	set("OIDC_CLIENT_SECRET", f.OIDCClientSecret)
	set("OIDC_GROUPS_CLAIM", f.OIDCGroupsClaim)
	set("OIDC_ADMIN_GROUPS", f.OIDCAdminGroups)
	set("OIDC_READONLY_GROUPS", f.OIDCReadOnlyGroups)
	set("OIDC_DISPLAY_NAME", f.OIDCDisplayName)
	if f.OIDCDisableLocalLogin != nil {
		set("OIDC_DISABLE_LOCAL_LOGIN", strconv.FormatBool(*f.OIDCDisableLocalLogin))
	}
	for key, days := range map[string]*int{
		"AUDIT_RETENTION_DAYS":       f.AuditRetentionDays,
		"COMMAND_RETENTION_DAYS":     f.CommandRetentionDays,
		"SCRIPT_RUN_RETENTION_DAYS":  f.ScriptRunRetentionDays,
		"APP_INSTALL_RETENTION_DAYS": f.AppInstallRetentionDays,
	} {
		if days != nil {
			set(key, strconv.Itoa(*days))
		}
	}
	return out, nil
}
