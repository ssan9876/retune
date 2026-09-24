// Package client is the agent's HTTP client for the Retune server.
package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
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

// downloadTimeout is the budget for fetching a build. The JSON client's flat
// 60 seconds covers a whole request including the body, which is plenty for
// an object and nowhere near enough for a multi-megabyte binary over a slow
// link.
const downloadTimeout = 30 * time.Minute

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
	// download is used only for fetching a build payload: same transport (so
	// the same client certificate), but no whole-request Timeout, because a
	// binary download's budget is sized by its own context instead.
	download *http.Client
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
		// A payload download has no whole-request deadline: its context
		// carries one sized for a binary rather than for an object.
		download: &http.Client{Transport: tr},
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

// EscrowAdminPassword stores a local admin password with the server before
// the agent sets it.
func (c *Client) EscrowAdminPassword(ctx context.Context, req protocol.AdminPasswordEscrowRequest) error {
	return c.do(ctx, http.MethodPost, "/api/agent/v1/admin-passwords", req, nil)
}

// UploadCommandArtifact sends the file a command produced, such as a logs
// archive, as the raw body. It uses the download client, which has no
// whole-request deadline, since 50 MiB can take a while on a slow link.
func (c *Client) UploadCommandArtifact(ctx context.Context, id string, body io.Reader, size int64) error {
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()
	path := "/api/agent/v1/commands/" + url.PathEscape(id) + "/artifact"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, body)
	if err != nil {
		return err
	}
	req.ContentLength = size
	req.Header.Set("Content-Type", "application/zip")
	res, err := c.download.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", path, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNoContent && res.StatusCode != http.StatusOK {
		var e protocol.Error
		_ = json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&e)
		return &HTTPError{Status: res.StatusCode, Code: e.Code, Message: e.Message}
	}
	return nil
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

// ComplianceStatement fetches a signed statement of this device's
// compliance.
func (c *Client) ComplianceStatement(ctx context.Context) (protocol.ComplianceStatementResponse, error) {
	var resp protocol.ComplianceStatementResponse
	err := c.do(ctx, http.MethodGet, "/api/agent/v1/compliance-statement", nil, &resp)
	return resp, err
}

// ReportScriptRun tells the server what one execution did.
func (c *Client) ReportScriptRun(ctx context.Context, id string, run protocol.ScriptRun) error {
	return c.do(ctx, http.MethodPost, "/api/agent/v1/scripts/"+url.PathEscape(id)+"/runs", run, nil)
}

// FetchApp downloads one version of an assigned app deployment.
func (c *Client) FetchApp(ctx context.Context, id string, version int) (protocol.AppVersionResponse, error) {
	var resp protocol.AppVersionResponse
	path := "/api/agent/v1/apps/" + url.PathEscape(id) + "/versions/" + strconv.Itoa(version)
	err := c.do(ctx, http.MethodGet, path, nil, &resp)
	return resp, err
}

// ReportAppResult tells the server what one install or uninstall did.
func (c *Client) ReportAppResult(ctx context.Context, id string, r protocol.AppResult) error {
	return c.do(ctx, http.MethodPost, "/api/agent/v1/apps/"+url.PathEscape(id)+"/result", r, nil)
}

// FetchProfile downloads one version of an assigned configuration profile.
func (c *Client) FetchProfile(ctx context.Context, id string, version int) (protocol.ProfileVersionResponse, error) {
	var resp protocol.ProfileVersionResponse
	path := "/api/agent/v1/profiles/" + url.PathEscape(id) + "/versions/" + strconv.Itoa(version)
	err := c.do(ctx, http.MethodGet, path, nil, &resp)
	return resp, err
}

// ReportProfileStatus tells the server what every setting of a profile did.
func (c *Client) ReportProfileStatus(ctx context.Context, id string, status protocol.ProfileStatus) error {
	return c.do(ctx, http.MethodPost, "/api/agent/v1/profiles/"+url.PathEscape(id)+"/status", status, nil)
}

// HasRecoveryKey asks whether the server already holds a recovery key for a
// volume, so a compliant machine does not send one on every check-in.
func (c *Client) HasRecoveryKey(ctx context.Context, volumeID string) (bool, error) {
	var resp protocol.BitLockerHasResponse
	path := "/api/agent/v1/bitlocker?volume_id=" + url.QueryEscape(volumeID)
	err := c.do(ctx, http.MethodGet, path, nil, &resp)
	return resp.Escrowed, err
}

// EscrowRecoveryKey sends a BitLocker recovery password to the server, which
// stores it encrypted.
func (c *Client) EscrowRecoveryKey(ctx context.Context, volumeID, method, recoveryPassword string) error {
	return c.do(ctx, http.MethodPost, "/api/agent/v1/bitlocker", protocol.BitLockerEscrowRequest{
		VolumeID: volumeID, Method: method, RecoveryPassword: recoveryPassword,
	}, nil)
}

// FetchAgentVersion downloads the definition of an assigned agent build: what
// version it is, how big it should be, and what it should hash to.
func (c *Client) FetchAgentVersion(ctx context.Context, id string) (protocol.AgentVersionResponse, error) {
	var resp protocol.AgentVersionResponse
	err := c.do(ctx, http.MethodGet, "/api/agent/v1/agent-versions/"+url.PathEscape(id), nil, &resp)
	return resp, err
}

// ReportAgentUpdate tells the server how an update turned out.
func (c *Client) ReportAgentUpdate(ctx context.Context, id string, r protocol.AgentUpdateResult) error {
	return c.do(ctx, http.MethodPost,
		"/api/agent/v1/agent-versions/"+url.PathEscape(id)+"/result", r, nil)
}

// DownloadTimeout is the budget for a payload download, exposed so a test can
// assert it is not the JSON client's much shorter one.
func (c *Client) DownloadTimeout() time.Duration { return downloadTimeout }

// DownloadAgentBinary streams a build to dst, hashing as it goes, and refuses
// anything whose SHA-256 is not what the definition promised. It does not use
// the JSON client: that one decodes bodies and would cut a large download off
// at its own timeout.
//
// The hash can only be checked once the last byte has been written, so on a
// mismatch dst already holds the wrong bytes. Discarding them is the caller's
// job, and not an optional one: a wrong binary left on disk is worse than no
// binary at all.
// maxAgentBinary bounds an agent build download.
const maxAgentBinary = 256 << 20

func (c *Client) DownloadAgentBinary(ctx context.Context, id, wantSHA256 string, dst io.Writer) error {
	path := "/api/agent/v1/agent-versions/" + url.PathEscape(id) + "/binary"
	return c.downloadVerified(ctx, path, wantSHA256, maxAgentBinary, downloadTimeout, dst)
}

// packageDownloadTimeout allows for a 2 GiB installer over a slow link.
const packageDownloadTimeout = 2 * time.Hour

// DownloadAppPackage streams an assigned app version's installer to dst,
// under the same rules as DownloadAgentBinary: on an error, including a hash
// mismatch, whatever dst holds must be thrown away.
func (c *Client) DownloadAppPackage(ctx context.Context, id string, version int, wantSHA256 string, dst io.Writer) error {
	path := "/api/agent/v1/apps/" + url.PathEscape(id) + "/versions/" + strconv.Itoa(version) + "/package"
	return c.downloadVerified(ctx, path, wantSHA256, protocol.MaxPackageBytes, packageDownloadTimeout, dst)
}

// downloadVerified streams path to dst, refusing more than max bytes or
// anything that doesn't hash to wantSHA256.
func (c *Client) downloadVerified(ctx context.Context, path, wantSHA256 string, max int64,
	timeout time.Duration, dst io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return err
	}
	// The same transport -- and so the same mutual TLS identity -- with no
	// whole-request deadline of its own.
	res, err := c.download.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", path, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		var e protocol.Error
		_ = json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&e)
		return &HTTPError{Status: res.StatusCode, Code: e.Code, Message: e.Message}
	}

	// Hashed while it streams, so verification never requires buffering the
	// whole binary or re-reading it from dst.
	// Capped, so a server that sends forever cannot fill the disk.
	sum := sha256.New()
	n, err := io.Copy(io.MultiWriter(dst, sum), io.LimitReader(res.Body, max+1))
	if err == nil && n > max {
		return fmt.Errorf("GET %s: the download is larger than %d bytes", path, max)
	}
	if err != nil {
		return fmt.Errorf("download %s: %w", path, err)
	}
	got := hex.EncodeToString(sum.Sum(nil))
	// Hex can arrive in either case, so compare case-insensitively rather than
	// rejecting a technically-valid hash over letter case.
	if !strings.EqualFold(got, wantSHA256) {
		return fmt.Errorf("sha256 mismatch: the server promised %s and sent %s", wantSHA256, got)
	}
	return nil
}
