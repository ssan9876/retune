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
	if f.CheckinIntervalSeconds != 0 {
		set("CHECKIN_INTERVAL_SECONDS", strconv.Itoa(f.CheckinIntervalSeconds))
	}
	if f.SessionTTLHours != 0 {
		set("SESSION_TTL_HOURS", strconv.Itoa(f.SessionTTLHours))
	}
	return out, nil
}
