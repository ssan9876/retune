package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "retune-server.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadServerFromFile(t *testing.T) {
	path := writeFile(t, `
database_url: postgres://file/retune
public_url: https://mdm.file.example
agent_api_listen: 127.0.0.1:9443
data_dir: /var/lib/retune
checkin_interval_seconds: 120
session_ttl_hours: 24
`)
	c, err := LoadServer(env(map[string]string{"RETUNE_CONFIG": path}))
	if err != nil {
		t.Fatal(err)
	}
	if c.DatabaseURL != "postgres://file/retune" || c.PublicURL != "https://mdm.file.example" ||
		c.AgentListen != "127.0.0.1:9443" || c.DataDir != "/var/lib/retune" ||
		c.CheckinInterval != 2*time.Minute || c.SessionTTL != 24*time.Hour {
		t.Fatalf("config = %+v", c)
	}
}

func TestEnvironmentBeatsFile(t *testing.T) {
	path := writeFile(t, "database_url: postgres://file/retune\npublic_url: https://file.example\n")
	c, err := LoadServer(env(map[string]string{
		"RETUNE_CONFIG": path,
		"PUBLIC_URL":    "https://env.example",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.PublicURL != "https://env.example" || c.DatabaseURL != "postgres://file/retune" {
		t.Fatalf("config = %+v", c)
	}
}

func TestDatabaseURLAndDataDir(t *testing.T) {
	path := writeFile(t, "database_url: postgres://file/retune\ndata_dir: /srv/retune\n")
	fileOnly := env(map[string]string{"RETUNE_CONFIG": path})

	// Commands that need only these settings must read the file too.
	got, err := DatabaseURL(fileOnly)
	if err != nil || got != "postgres://file/retune" {
		t.Fatalf("DatabaseURL = %q, err = %v", got, err)
	}
	if dir, err := DataDir(fileOnly); err != nil || dir != "/srv/retune" {
		t.Fatalf("DataDir = %q, err = %v", dir, err)
	}

	withEnv := env(map[string]string{"RETUNE_CONFIG": path, "DATABASE_URL": "postgres://env/retune", "DATA_DIR": "/env/dir"})
	if got, _ = DatabaseURL(withEnv); got != "postgres://env/retune" {
		t.Fatalf("the environment must win: %q", got)
	}
	if dir, _ := DataDir(withEnv); dir != "/env/dir" {
		t.Fatalf("the environment must win: %q", dir)
	}

	if _, err := DatabaseURL(env(nil)); err == nil {
		t.Fatal("a missing database URL must be an error")
	}
	if dir, err := DataDir(env(nil)); err != nil || dir != "data" {
		t.Fatalf("default DataDir = %q, err = %v", dir, err)
	}
}

func TestConfigFileErrors(t *testing.T) {
	if _, err := LoadServer(env(map[string]string{"RETUNE_CONFIG": "does-not-exist.yaml"})); err == nil {
		t.Fatal("a named config file that is missing must be an error")
	}
	bad := writeFile(t, "database_url: postgres://x\npublic_url: https://h\nnonsense_key: 1\n")
	_, err := LoadServer(env(map[string]string{"RETUNE_CONFIG": bad}))
	if err == nil || !strings.Contains(err.Error(), "nonsense_key") {
		t.Fatalf("unknown key err = %v", err)
	}
	broken := writeFile(t, "database_url: [unclosed\n")
	if _, err := LoadServer(env(map[string]string{"RETUNE_CONFIG": broken})); err == nil {
		t.Fatal("malformed YAML must be an error")
	}
}

func TestConfigFileNewKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "retune-server.yaml")
	body := "database_url: postgres://x/y\n" +
		"public_url: https://mdm.example.com\n" +
		"tls_mode: behind-proxy\n" +
		"client_cert_header: X-Client-Cert\n" +
		"trusted_proxies: 10.0.0.0/8\n" +
		"ca_key_source: env\n" +
		"sweep_interval_seconds: 60\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadServer(env(map[string]string{"RETUNE_CONFIG": path}))
	if err != nil {
		t.Fatal(err)
	}
	if c.ClientCertHeader != "X-Client-Cert" {
		t.Errorf("ClientCertHeader = %q", c.ClientCertHeader)
	}
	if len(c.TrustedProxies) != 1 || c.TrustedProxies[0].String() != "10.0.0.0/8" {
		t.Errorf("TrustedProxies = %v", c.TrustedProxies)
	}
	if c.CAKeySource != "env" || c.SweepInterval != time.Minute {
		t.Errorf("CAKeySource = %q, SweepInterval = %v", c.CAKeySource, c.SweepInterval)
	}
}

// Every setting the README lists can be written in the file, not only in the
// environment: the decoder refuses unknown keys, so a documented key missing
// here is a config file that will not load.
func TestConfigFileRetentionMetricsAndSMTP(t *testing.T) {
	path := writeFile(t, `
database_url: postgres://file/retune
public_url: https://mdm.file.example
audit_retention_days: 0
command_retention_days: 30
metrics_token: `+strings.Repeat("t", 40)+`
smtp_host: mail.example.com
smtp_port: 2525
smtp_from: retune@example.com
smtp_starttls: false
`)
	c, err := LoadServer(env(map[string]string{"RETUNE_CONFIG": path}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Retention.Audit != 0 {
		t.Errorf("audit_retention_days: 0 should keep audit forever, got %v", c.Retention.Audit)
	}
	if c.Retention.Commands != 30*24*time.Hour || c.Retention.ScriptRuns != 90*24*time.Hour {
		t.Errorf("retention = %+v", c.Retention)
	}
	if len(c.MetricsToken) != 40 {
		t.Errorf("metrics_token = %q", c.MetricsToken)
	}
	if c.SMTP.Host != "mail.example.com" || c.SMTP.Port != 2525 || c.SMTP.From != "retune@example.com" || c.SMTP.StartTLS {
		t.Errorf("smtp = %+v", c.SMTP)
	}
}

func TestConfigFileApprovals(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "retune-server.yaml")
	body := "database_url: postgres://x/y\n" +
		"public_url: https://mdm.example.com\n" +
		"approvals_required: true\n" +
		"approval_device_threshold: 0\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadServer(env(map[string]string{"RETUNE_CONFIG": path}))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Approvals.Required || c.Approvals.DeviceThreshold != 0 {
		t.Errorf("Approvals = %+v", c.Approvals)
	}
}
