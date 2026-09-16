package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"retune/internal/config"
)

// healthcheckTimeout is the whole budget for the probe, request and all. It is
// shorter than the interval a container runtime polls on, so a hung check
// fails on its own rather than piling up behind the previous one.
const healthcheckTimeout = 5 * time.Second

// healthcheckCmd asks the server running in this container whether it is ready
// and exits non-zero if it is not. The container image is distroless, so there
// is no shell and no curl for a HEALTHCHECK to call: the only executable
// present is this binary, which therefore has to be able to probe itself.
func healthcheckCmd(ctx context.Context, getenv func(string) string, out io.Writer) error {
	cfg, err := config.LoadServer(getenv)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, healthcheckTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthcheckURL(cfg), nil)
	if err != nil {
		return err
	}
	client := &http.Client{
		Transport: &http.Transport{
			// The probe dials this container's own loopback and talks to the
			// process that issued the certificate it is being shown, so
			// verifying that certificate would only re-answer a question
			// nobody asked. What is being checked is whether the server
			// answers at all, and whether it can still reach its database.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("not serving: %w", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 256))
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("not ready: %s: %s", res.Status, strings.TrimSpace(string(body)))
	}
	fmt.Fprintln(out, "ready")
	return nil
}

// healthcheckURL turns the listen address into one a client can dial. A listen
// address is usually just a port, which names every interface to a listener
// and none to a dialler, so the host defaults to loopback - the probe runs
// beside the server, not across the network.
func healthcheckURL(cfg config.Server) string {
	scheme := "https"
	if cfg.TLSMode == "behind-proxy" {
		scheme = "http"
	}
	host, port, err := net.SplitHostPort(cfg.AgentListen)
	if err != nil || host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	if err != nil {
		port = strings.TrimPrefix(cfg.AgentListen, ":")
	}
	return scheme + "://" + net.JoinHostPort(host, port) + "/readyz"
}
