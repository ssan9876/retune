// Package config loads process configuration.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"
)

// Server is the retune-server configuration.
type Server struct {
	DatabaseURL     string
	PublicURL       string
	AgentListen     string
	TLSMode         string // "self-signed" | "provided"
	TLSCertFile     string
	TLSKeyFile      string
	DataDir         string
	CheckinInterval time.Duration
}

// LoadServer reads configuration from environment variables via getenv.
func LoadServer(getenv func(string) string) (Server, error) {
	c := Server{
		DatabaseURL:     getenv("DATABASE_URL"),
		PublicURL:       getenv("PUBLIC_URL"),
		AgentListen:     or(getenv("AGENT_API_LISTEN"), ":8443"),
		TLSMode:         or(getenv("TLS_MODE"), "self-signed"),
		TLSCertFile:     getenv("TLS_CERT_FILE"),
		TLSKeyFile:      getenv("TLS_KEY_FILE"),
		DataDir:         or(getenv("DATA_DIR"), "data"),
		CheckinInterval: 5 * time.Minute,
	}
	if v := getenv("CHECKIN_INTERVAL_SECONDS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 30 {
			return Server{}, errors.New("CHECKIN_INTERVAL_SECONDS must be an integer >= 30")
		}
		c.CheckinInterval = time.Duration(n) * time.Second
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
	default:
		return Server{}, fmt.Errorf("unsupported TLS_MODE %q (supported: self-signed, provided)", c.TLSMode)
	}
	return c, nil
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
