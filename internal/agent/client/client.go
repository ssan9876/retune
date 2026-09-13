// Package client is the agent's HTTP client for the Retune server.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"retune/internal/pki"
	"retune/internal/protocol"
)

// HTTPError is a non-2xx response from the server.
type HTTPError struct {
	Status  int
	Code    string
	Message string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("server returned %d %s: %s", e.Status, e.Code, e.Message)
}

// Retryable reports whether the request may succeed if retried later.
func (e *HTTPError) Retryable() bool {
	return e.Status >= 500 || e.Status == http.StatusTooManyRequests
}

// Client calls the agent API.
type Client struct {
	base string
	http *http.Client
}

// New builds a client. If pin is set ("sha256:<hex>"), the server chain must
// contain a certificate with that fingerprint; otherwise system roots are
// used. clientCert enables mTLS.
func New(serverURL, pin string, clientCert *tls.Certificate) (*Client, error) {
	u, err := url.Parse(serverURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return nil, fmt.Errorf("server URL must be https, got %q", serverURL)
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if pin != "" {
		// Standard verification is replaced (not skipped) by verifyPinned.
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = verifyPinned(pin, u.Hostname())
	}
	if clientCert != nil {
		cfg.Certificates = []tls.Certificate{*clientCert}
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = cfg
	return &Client{
		base: strings.TrimRight(serverURL, "/"),
		http: &http.Client{Transport: tr, Timeout: 60 * time.Second},
	}, nil
}

func (c *Client) Enroll(ctx context.Context, req protocol.EnrollRequest) (protocol.EnrollResponse, error) {
	var resp protocol.EnrollResponse
	err := c.post(ctx, "/api/agent/v1/enroll", req, &resp)
	return resp, err
}

func (c *Client) Checkin(ctx context.Context, req protocol.CheckinRequest) (protocol.CheckinResponse, error) {
	var resp protocol.CheckinResponse
	err := c.post(ctx, "/api/agent/v1/checkin", req, &resp)
	return resp, err
}

func (c *Client) post(ctx context.Context, path string, in, out any) error {
	return c.do(ctx, http.MethodPost, path, in, out)
}

// PutInventory uploads a full inventory document and returns the hash the
// server stored.
func (c *Client) PutInventory(ctx context.Context, inv protocol.Inventory) (protocol.InventoryResponse, error) {
	var resp protocol.InventoryResponse
	err := c.do(ctx, http.MethodPut, "/api/agent/v1/inventory", inv, &resp)
	return resp, err
}

// StartCommand reports that execution has begun.
func (c *Client) StartCommand(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPost, "/api/agent/v1/commands/"+url.PathEscape(id)+"/start", nil, nil)
}

// SubmitResult reports a finished command.
func (c *Client) SubmitResult(ctx context.Context, id string, r protocol.CommandResult) error {
	return c.do(ctx, http.MethodPost, "/api/agent/v1/commands/"+url.PathEscape(id)+"/result", r, nil)
}

// Renew exchanges a CSR for a fresh client certificate.
func (c *Client) Renew(ctx context.Context, req protocol.RenewRequest) (protocol.RenewResponse, error) {
	var resp protocol.RenewResponse
	err := c.do(ctx, http.MethodPost, "/api/agent/v1/renew", req, &resp)
	return resp, err
}

// do sends a JSON request and decodes a JSON response. in may be nil for an
// empty body; out may be nil when no response body is expected.
func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusNoContent {
		var e protocol.Error
		_ = json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&e)
		return &HTTPError{Status: res.StatusCode, Code: e.Code, Message: e.Message}
	}
	if out == nil || res.StatusCode == http.StatusNoContent {
		_, _ = io.Copy(io.Discard, res.Body)
		return nil
	}
	if err := json.NewDecoder(res.Body).Decode(out); err != nil {
		return fmt.Errorf("decode %s response: %w", path, err)
	}
	return nil
}

// verifyPinned trusts the presented chain only if one of its certificates
// matches pin, and the leaf verifies for host against that certificate.
func verifyPinned(pin, host string) func([][]byte, [][]*x509.Certificate) error {
	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) == 0 {
			return errors.New("server presented no certificate")
		}
		roots, inter := x509.NewCertPool(), x509.NewCertPool()
		var leaf *x509.Certificate
		found := false
		for i, r := range raw {
			c, err := x509.ParseCertificate(r)
			if err != nil {
				return fmt.Errorf("parse server certificate: %w", err)
			}
			if i == 0 {
				leaf = c
			}
			if strings.EqualFold(pki.Fingerprint(c.Raw), pin) {
				roots.AddCert(c)
				found = true
			} else {
				inter.AddCert(c)
			}
		}
		if !found {
			return fmt.Errorf("server certificate chain does not match pinned fingerprint %s", pin)
		}
		_, err := leaf.Verify(x509.VerifyOptions{
			DNSName:       host,
			Roots:         roots,
			Intermediates: inter,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		return err
	}
}

// FetchScript downloads one version of an assigned script. Bodies are fetched
// once per version and cached, rather than resent on every check-in.
func (c *Client) FetchScript(ctx context.Context, id string, version int) (protocol.ScriptVersionResponse, error) {
	var resp protocol.ScriptVersionResponse
	path := "/api/agent/v1/scripts/" + url.PathEscape(id) + "/versions/" + strconv.Itoa(version)
	err := c.do(ctx, http.MethodGet, path, nil, &resp)
	return resp, err
}

// ReportScriptRun tells the server what one execution did.
func (c *Client) ReportScriptRun(ctx context.Context, id string, run protocol.ScriptRun) error {
	return c.do(ctx, http.MethodPost, "/api/agent/v1/scripts/"+url.PathEscape(id)+"/runs", run, nil)
}
