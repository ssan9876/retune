// Package agentcfg reads the agent's local settings, written by the installer
// so that the service can enroll itself on first start.
package agentcfg

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// FileName is the settings file inside the agent's data directory.
const FileName = "agent.yaml"

// ErrNoConfig is returned by Load when no settings file exists.
var ErrNoConfig = errors.New("no agent configuration")

// Config is what the installer knows and the agent needs.
type Config struct {
	ServerURL string `yaml:"server_url"`
	// EnrollToken is cleared once it has been spent.
	EnrollToken           string `yaml:"enroll_token,omitempty"`
	ServerCertFingerprint string `yaml:"server_cert_fingerprint,omitempty"`
}

// Load reads the settings file from dir.
func Load(dir string) (Config, error) {
	body, err := os.ReadFile(filepath.Join(dir, FileName))
	if errors.Is(err, fs.ErrNotExist) {
		return Config{}, ErrNoConfig
	}
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err := yaml.Unmarshal(body, &c); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", FileName, err)
	}
	return c, nil
}

// Save writes the settings file, readable only by the account that owns the
// data directory, because it can hold an enrollment token.
func Save(dir string, c Config) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	body, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, FileName), body, 0o600)
}

// ClearToken removes a spent enrollment token, leaving the rest in place.
func ClearToken(dir string) error {
	c, err := Load(dir)
	if err != nil {
		return err
	}
	if c.EnrollToken == "" {
		return nil
	}
	c.EnrollToken = ""
	return Save(dir, c)
}
