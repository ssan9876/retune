// Package config loads process configuration.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
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
