# M4 — Packaging and Deployment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Retune deployable — a container image and Compose stack for the server, a `behind-proxy` TLS mode, background sweepers, and the agent as a Windows service installed by an MSI.

**Architecture:** No protocol changes. The server grows a seam for "where does the verified device certificate come from" so a proxy header can supply it, a sweeper package that runs timed jobs under Postgres advisory locks, and a distroless image. The agent's run loop is extracted from `main.go` so both a terminal and the Windows Service Control Manager can host it.

**Tech Stack:** Go 1.27, pgx/v5, `golang.org/x/sys/windows/svc` (already a direct dependency), WiX 5 CLI, Docker, distroless.

**Spec:** `docs/superpowers/specs/2026-09-12-m4-packaging-design.md`

## Global Constraints

- Go 1.27, module `retune`. No new Go module dependencies — `golang.org/x/sys` and `gopkg.in/yaml.v3` are already direct requires and cover the service host and agent config.
- Every new server config key must be added to **both** the `fileConfig` struct and the `set()` map in `internal/config/file.go`; `dec.KnownFields(true)` makes an omission a YAML parse error.
- Windows-only code goes behind `//go:build windows` with a stub for other platforms, matching `internal/agent/facts`, `identity` and `inventory`. `go build ./...` and `go vet ./...` must pass on Linux.
- Tests that need Postgres use `storetest` and must be skipped by `-short`, because the Windows CI job runs `go test -short ./...`.
- The agent's data directory is `C:\ProgramData\Retune` on Windows, ACLs restricted to SYSTEM and Administrators.
- The MSI is unsigned. No signing step anywhere.
- Advisory lock IDs are fixed constants: `commands.expire` = 5274001, `sessions.cleanup` = 5274002.
- Default `client_cert_header` is `X-Forwarded-Client-Cert`. Default `sweep_interval_seconds` is 300, minimum 10.

---

## File Structure

**Created**

| File | Responsibility |
|---|---|
| `internal/server/sweeper/sweeper.go` | `Job`, `Runner`, tick loop, panic recovery |
| `internal/server/sweeper/jobs.go` | The two concrete jobs and their lock IDs |
| `internal/server/sweeper/sweeper_test.go` | Lock contention and job behaviour against Postgres |
| `internal/server/agentapi/clientcert.go` | `CertError`, `TLSClientCert`, `HeaderClientCert` |
| `internal/server/agentapi/clientcert_test.go` | Header parsing, trust, and verification tests |
| `internal/agent/runner/runner.go` | The agent run loop, extracted from `main.go` |
| `internal/agent/agentcfg/agentcfg.go` | `agent.yaml` load/save and token stripping |
| `internal/agent/agentcfg/agentcfg_test.go` | Round-trip and token-stripping tests |
| `internal/agent/logging/logging.go` | Handler assembly (file + stderr) |
| `internal/agent/logging/rotate.go` | Size-based rotating file writer |
| `internal/agent/logging/rotate_test.go` | Rotation and retention tests |
| `internal/agent/logging/eventlog_windows.go` | Event Log handler, `//go:build windows` |
| `internal/agent/logging/eventlog_other.go` | No-op stub |
| `cmd/retune-agent/service_windows.go` | SCM host, `install`, `uninstall`, `configure` |
| `cmd/retune-agent/service_other.go` | Stubs returning a clear error |
| `deploy/docker/Dockerfile` | Three-stage build |
| `deploy/docker/docker-compose.yml` | Server + Postgres |
| `deploy/docker/.env.example` | Documented environment |
| `deploy/msi/Package.wxs` | WiX package |
| `deploy/msi/build.ps1` | Agent + MSI build |
| `.dockerignore` | Build context trimming |

**Modified**

| File | Change |
|---|---|
| `internal/config/file.go` | Five new keys in the struct and the `set()` map |
| `internal/config/server.go` | New fields, `behind-proxy` validation, trusted-proxy parsing |
| `internal/server/agentapi/handler.go` | `ClientCert` field replaces the inline `r.TLS` read |
| `internal/server/app/app.go` | Picks the client-cert source; skips `TLSConfig` behind a proxy |
| `internal/server/store/store.go` | `WithAdvisoryLock` |
| `internal/server/ca/keystore.go` | `EnvKeyStore` |
| `cmd/retune-server/main.go` | Plain listener behind a proxy, starts the sweeper, `ca cert` |
| `cmd/retune-agent/main.go` | Calls `runner.Run`; new subcommands in usage |
| `Makefile` | `docker`, `msi`, `agent` targets |
| `.github/workflows/ci.yml` | Docker build on Linux, MSI build and artifact on Windows |
| `README.md` | Deployment and install documentation |

---

## Task 1: Server configuration for behind-proxy

**Files:**
- Modify: `internal/config/server.go:13-23` (struct), `:38-48` (load), `:70-78` (TLS switch)
- Modify: `internal/config/file.go` (struct and `set()` map)
- Test: `internal/config/server_test.go`

**Interfaces:**
- Produces: `config.Server` gains `ClientCertHeader string`, `TrustedProxies []netip.Prefix`, `CAKeySource string`, `SweepInterval time.Duration`.

- [ ] **Step 1: Write the failing tests**

Add to `internal/config/server_test.go`. The existing table asserting `TLS_MODE: behind-proxy` is an error must be **removed** from the invalid cases first.

```go
func TestLoadServerBehindProxy(t *testing.T) {
	base := map[string]string{
		"DATABASE_URL": "postgres://x/y",
		"PUBLIC_URL":   "https://mdm.example.com",
		"TLS_MODE":     "behind-proxy",
	}
	with := func(extra map[string]string) func(string) string {
		env := map[string]string{}
		for k, v := range base {
			env[k] = v
		}
		for k, v := range extra {
			env[k] = v
		}
		return func(k string) string { return env[k] }
	}

	t.Run("requires a trusted proxy list", func(t *testing.T) {
		_, err := config.LoadServer(with(nil))
		if err == nil || !strings.Contains(err.Error(), "TRUSTED_PROXIES") {
			t.Fatalf("want a TRUSTED_PROXIES error, got %v", err)
		}
	})

	t.Run("rejects an empty header name", func(t *testing.T) {
		_, err := config.LoadServer(with(map[string]string{
			"TRUSTED_PROXIES": "10.0.0.0/8", "CLIENT_CERT_HEADER": " ",
		}))
		if err == nil || !strings.Contains(err.Error(), "CLIENT_CERT_HEADER") {
			t.Fatalf("want a CLIENT_CERT_HEADER error, got %v", err)
		}
	})

	t.Run("accepts CIDRs and bare addresses", func(t *testing.T) {
		c, err := config.LoadServer(with(map[string]string{
			"TRUSTED_PROXIES": "10.0.0.0/8, 192.168.1.7",
		}))
		if err != nil {
			t.Fatal(err)
		}
		if got := len(c.TrustedProxies); got != 2 {
			t.Fatalf("want 2 prefixes, got %d", got)
		}
		if !c.TrustedProxies[1].IsSingleIP() {
			t.Error("a bare address should become a single-IP prefix")
		}
		if c.ClientCertHeader != "X-Forwarded-Client-Cert" {
			t.Errorf("default header = %q", c.ClientCertHeader)
		}
	})

	t.Run("rejects an unparseable entry", func(t *testing.T) {
		_, err := config.LoadServer(with(map[string]string{"TRUSTED_PROXIES": "10.0.0.0/8, nonsense"}))
		if err == nil || !strings.Contains(err.Error(), "nonsense") {
			t.Fatalf("want the bad value named, got %v", err)
		}
	})
}

func TestLoadServerSweepInterval(t *testing.T) {
	env := func(v string) func(string) string {
		return func(k string) string {
			switch k {
			case "DATABASE_URL":
				return "postgres://x/y"
			case "PUBLIC_URL":
				return "https://mdm.example.com"
			case "SWEEP_INTERVAL_SECONDS":
				return v
			}
			return ""
		}
	}
	c, err := config.LoadServer(env(""))
	if err != nil || c.SweepInterval != 5*time.Minute {
		t.Fatalf("default sweep interval = %v, err %v", c.SweepInterval, err)
	}
	if _, err := config.LoadServer(env("5")); err == nil {
		t.Error("want an error below the 10 second minimum")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/config/ -run 'BehindProxy|SweepInterval' -v`
Expected: FAIL — `c.TrustedProxies` undefined.

- [ ] **Step 3: Add the fields and parsing**

In `internal/config/server.go`, extend the struct (note the corrected comment on `TLSMode`):

```go
type Server struct {
	DatabaseURL      string
	PublicURL        string
	AgentListen      string
	TLSMode          string // "self-signed" | "provided" | "behind-proxy"
	TLSCertFile      string
	TLSKeyFile       string
	DataDir          string
	CheckinInterval  time.Duration
	SessionTTL       time.Duration
	ClientCertHeader string
	TrustedProxies   []netip.Prefix
	CAKeySource      string
	SweepInterval    time.Duration
}
```

In `LoadServer`, after the `SESSION_TTL_HOURS` block:

```go
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
```

Replace the TLS switch:

```go
switch c.TLSMode {
case "self-signed":
case "provided":
	if c.TLSCertFile == "" || c.TLSKeyFile == "" {
		return Server{}, errors.New("TLS_MODE=provided requires TLS_CERT_FILE and TLS_KEY_FILE")
	}
case "behind-proxy":
	// The proxy terminates TLS, so the device certificate arrives in a header.
	// Without a header name and a trusted sender the agent API would be
	// unauthenticated, so refuse to start rather than serve it.
	if strings.TrimSpace(c.ClientCertHeader) == "" {
		return Server{}, errors.New("TLS_MODE=behind-proxy requires a non-empty CLIENT_CERT_HEADER")
	}
	if len(c.TrustedProxies) == 0 {
		return Server{}, errors.New("TLS_MODE=behind-proxy requires TRUSTED_PROXIES (comma-separated IPs or CIDRs)")
	}
default:
	return Server{}, fmt.Errorf("unsupported TLS_MODE %q (supported: self-signed, provided, behind-proxy)", c.TLSMode)
}
```

And the helper:

```go
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
```

Add `"net/netip"` and `"strings"` to the imports.

- [ ] **Step 4: Add the keys to the config file loader**

In `internal/config/file.go`, add to `fileConfig`:

```go
ClientCertHeader     string `yaml:"client_cert_header"`
TrustedProxies       string `yaml:"trusted_proxies"`
CAKeySource          string `yaml:"ca_key_source"`
SweepIntervalSeconds int    `yaml:"sweep_interval_seconds"`
```

and to the `set()` map, alongside the existing string entries:

```go
set("CLIENT_CERT_HEADER", f.ClientCertHeader)
set("TRUSTED_PROXIES", f.TrustedProxies)
set("CA_KEY_SOURCE", f.CAKeySource)
if f.SweepIntervalSeconds != 0 {
	values["SWEEP_INTERVAL_SECONDS"] = strconv.Itoa(f.SweepIntervalSeconds)
}
```

Match the surrounding style exactly — read the file first, since the int entries use a different shape from the string ones.

- [ ] **Step 5: Run the config tests**

Run: `go test ./internal/config/ -v`
Expected: PASS, including the existing file tests.

- [ ] **Step 6: Commit**

```bash
git add internal/config
git commit -m "feat(config): accept behind-proxy TLS with a trusted proxy list"
```

---

## Task 2: Client certificate seam

**Files:**
- Create: `internal/server/agentapi/clientcert.go`, `internal/server/agentapi/clientcert_test.go`
- Modify: `internal/server/agentapi/handler.go:22-30` (field), `:75-81` (the read)
- Modify: `internal/server/app/app.go:70-96`

**Interfaces:**
- Consumes: `config.Server.ClientCertHeader`, `.TrustedProxies` from Task 1.
- Produces: `agentapi.CertError`, `agentapi.TLSClientCert`, `agentapi.HeaderClientCert(header string, trusted []netip.Prefix, pool *x509.CertPool) func(*http.Request) (*x509.Certificate, error)`.

- [ ] **Step 1: Write the failing tests**

`internal/server/agentapi/clientcert_test.go`. Use the existing test helpers for issuing certificates if the package has them; otherwise generate a throwaway CA in the test with `crypto/ecdsa` and `x509.CreateCertificate`.

```go
func TestHeaderClientCert(t *testing.T) {
	caCert, caKey := testCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	leaf := testLeaf(t, caCert, caKey, uuid.New().String())
	encoded := url.QueryEscape(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})))

	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	get := agentapi.HeaderClientCert("X-Forwarded-Client-Cert", trusted, pool)

	newReq := func(remote, header string) *http.Request {
		r := httptest.NewRequest("POST", "/api/agent/v1/checkin", nil)
		r.RemoteAddr = remote
		if header != "" {
			r.Header.Set("X-Forwarded-Client-Cert", header)
		}
		return r
	}

	t.Run("trusted peer with a valid certificate", func(t *testing.T) {
		got, err := get(newReq("10.1.2.3:4567", encoded))
		if err != nil {
			t.Fatal(err)
		}
		if got == nil || got.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
			t.Fatal("wrong certificate returned")
		}
	})

	t.Run("accepts unescaped PEM", func(t *testing.T) {
		raw := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))
		if _, err := get(newReq("10.1.2.3:4567", raw)); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("untrusted peer sending the header is rejected", func(t *testing.T) {
		_, err := get(newReq("203.0.113.9:4567", encoded))
		var ce agentapi.CertError
		if !errors.As(err, &ce) || ce.Status != http.StatusForbidden {
			t.Fatalf("want 403 CertError, got %v", err)
		}
	})

	t.Run("untrusted peer without the header presents no certificate", func(t *testing.T) {
		got, err := get(newReq("203.0.113.9:4567", ""))
		if err != nil || got != nil {
			t.Fatalf("want (nil, nil), got (%v, %v)", got, err)
		}
	})

	t.Run("malformed header", func(t *testing.T) {
		_, err := get(newReq("10.1.2.3:4567", "not-a-certificate"))
		var ce agentapi.CertError
		if !errors.As(err, &ce) || ce.Status != http.StatusUnauthorized {
			t.Fatalf("want 401 CertError, got %v", err)
		}
	})

	t.Run("certificate from another CA", func(t *testing.T) {
		otherCA, otherKey := testCA(t)
		foreign := testLeaf(t, otherCA, otherKey, uuid.New().String())
		enc := url.QueryEscape(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: foreign.Raw})))
		_, err := get(newReq("10.1.2.3:4567", enc))
		var ce agentapi.CertError
		if !errors.As(err, &ce) || ce.Status != http.StatusUnauthorized {
			t.Fatalf("want 401 CertError, got %v", err)
		}
	})
}
```

Write `testCA` and `testLeaf` helpers in the same file: `testCA` returns a self-signed CA certificate and its key; `testLeaf` issues a client certificate with `CommonName` set to the given string and `ExtKeyUsageClientAuth`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/server/agentapi/ -run HeaderClientCert -v`
Expected: FAIL — undefined `agentapi.HeaderClientCert`.

- [ ] **Step 3: Implement `clientcert.go`**

```go
package agentapi

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

// CertError is a client-certificate failure carrying the response to send.
type CertError struct {
	Status  int
	Code    string
	Message string
}

func (e CertError) Error() string { return e.Message }

// TLSClientCert reads the certificate from the request's own TLS handshake.
// It returns (nil, nil) when the client presented none, which is how /enroll
// stays reachable.
func TLSClientCert(r *http.Request) (*x509.Certificate, error) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		return nil, nil
	}
	return r.TLS.VerifiedChains[0][0], nil
}

// HeaderClientCert reads the certificate from a header set by a trusted
// reverse proxy. The proxy delivers the bytes; it never supplies a verdict,
// so the certificate is verified against pool here.
func HeaderClientCert(header string, trusted []netip.Prefix, pool *x509.CertPool) func(*http.Request) (*x509.Certificate, error) {
	return func(r *http.Request) (*x509.Certificate, error) {
		raw := r.Header.Get(header)
		if !peerTrusted(r.RemoteAddr, trusted) {
			if raw != "" {
				// Someone reached the server directly and asserted a client
				// certificate. That is an attack, not a missing certificate.
				return nil, CertError{http.StatusForbidden, "untrusted_proxy",
					"client certificate headers are only accepted from a trusted proxy"}
			}
			return nil, nil
		}
		if raw == "" {
			return nil, nil
		}
		cert, err := parseCertHeader(raw)
		if err != nil {
			return nil, CertError{http.StatusUnauthorized, "client_cert_invalid", err.Error()}
		}
		if _, err := cert.Verify(x509.VerifyOptions{
			Roots:     pool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}); err != nil {
			return nil, CertError{http.StatusUnauthorized, "client_cert_invalid",
				"client certificate was not issued by this server"}
		}
		return cert, nil
	}
}

func peerTrusted(remoteAddr string, trusted []netip.Prefix) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// parseCertHeader accepts a PEM certificate, URL-encoded (nginx's
// ssl_client_escaped_cert, and what Caddy is usually configured to send) or
// literal.
func parseCertHeader(raw string) (*x509.Certificate, error) {
	if !strings.Contains(raw, "BEGIN CERTIFICATE") {
		decoded, err := url.QueryUnescape(raw)
		if err != nil {
			return nil, fmt.Errorf("client certificate header is not valid URL encoding")
		}
		raw = decoded
	}
	block, _ := pem.Decode([]byte(raw))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("client certificate header is not a PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("client certificate header is not a valid certificate")
	}
	return cert, nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/server/agentapi/ -run HeaderClientCert -v`
Expected: PASS.

- [ ] **Step 5: Use the seam in the handler**

Add the field to `Handler`:

```go
// ClientCert returns the device certificate for a request, already verified
// against the internal CA, or (nil, nil) if the request presented none.
ClientCert func(*http.Request) (*x509.Certificate, error)
```

Replace `handler.go:77-81` with:

```go
leaf, err := h.ClientCert(r)
if err != nil {
	var ce CertError
	if errors.As(err, &ce) {
		writeError(w, ce.Status, ce.Code, ce.Message)
		return
	}
	h.Log.Error("read client certificate", "error", err)
	writeError(w, http.StatusInternalServerError, "internal", "internal server error")
	return
}
if leaf == nil {
	writeError(w, http.StatusUnauthorized, "client_cert_required", "a device client certificate is required")
	return
}
serial := leaf.SerialNumber.Text(16)
id, err := uuid.Parse(leaf.Subject.CommonName)
```

Note the existing `id, err := uuid.Parse(...)` becomes `=` for `err` if the compiler complains about shadowing — use `id, parseErr := uuid.Parse(...)` and adjust, whichever reads cleaner.

Add `"crypto/x509"` to the handler imports.

- [ ] **Step 6: Wire it in `app.New`**

In `internal/server/app/app.go`, after `authority` is loaded, before building the handler:

```go
clientCert := agentapi.TLSClientCert
if cfg.TLSMode == "behind-proxy" {
	clientCert = agentapi.HeaderClientCert(cfg.ClientCertHeader, cfg.TrustedProxies, authority.Pool())
}
```

Pass `ClientCert: clientCert` in the `agentapi.Handler` literal.

Make the server certificate and TLS config conditional — behind a proxy there is no TLS to configure:

```go
var tlsCfg *tls.Config
if cfg.TLSMode != "behind-proxy" {
	serverCert, err := loadServerCert(cfg, authority)
	if err != nil {
		st.Close()
		return nil, err
	}
	tlsCfg = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    authority.Pool(),
	}
}
```

and set `TLSConfig: tlsCfg` in the returned `App`.

- [ ] **Step 7: Serve plain HTTP behind a proxy**

In `cmd/retune-server/main.go`, replace the `go func() { errc <- srv.ListenAndServeTLS("", "") }()` line with:

```go
go func() {
	if cfg.TLSMode == "behind-proxy" {
		// The proxy terminates TLS; serving it again here would double-wrap.
		errc <- srv.ListenAndServe()
		return
	}
	errc <- srv.ListenAndServeTLS("", "")
}()
```

- [ ] **Step 8: Run the full server suite**

Run: `go test ./internal/server/... ./cmd/...`
Expected: PASS. Existing `agentapi` tests exercise the mTLS path through `TLSClientCert`; if any construct a `Handler` literal directly they need `ClientCert: agentapi.TLSClientCert` added.

- [ ] **Step 9: Commit**

```bash
git add internal/server cmd/retune-server
git commit -m "feat(server): read the device certificate from a trusted proxy header"
```

---

## Task 3: Advisory lock helper and the sweeper package

**Files:**
- Modify: `internal/server/store/store.go` (add `WithAdvisoryLock`)
- Create: `internal/server/sweeper/sweeper.go`, `internal/server/sweeper/jobs.go`, `internal/server/sweeper/sweeper_test.go`
- Modify: `cmd/retune-server/main.go` (start the runner in `serve`)

**Interfaces:**
- Produces: `store.Store.WithAdvisoryLock(ctx, id int64, fn func(*store.Queries) error) (bool, error)`; `sweeper.Job{Name string, LockID int64, Interval time.Duration, Run func(context.Context, *store.Queries, time.Time) (int64, error)}`; `sweeper.Runner{Store, Jobs, Log, Now}` with `Start(ctx)` and `RunOnce(ctx, Job) (int64, bool, error)`; `sweeper.DefaultJobs(interval time.Duration) []Job`.

- [ ] **Step 1: Write the failing test**

`internal/server/sweeper/sweeper_test.go`:

```go
func TestExpireCommandsJob(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	// A device and a command whose TTL has already passed.
	dev := storetest.Device(t, st)
	past := time.Now().Add(-time.Hour)
	cmdID := storetest.QueuedCommand(t, st, dev.ID, past)

	r := &sweeper.Runner{Store: st, Log: slog.New(slog.DiscardHandler), Now: time.Now}
	job := sweeper.DefaultJobs(time.Minute)[0]
	n, ran, err := r.RunOnce(ctx, job)
	if err != nil || !ran {
		t.Fatalf("RunOnce: n=%d ran=%v err=%v", n, ran, err)
	}
	if n != 1 {
		t.Fatalf("expired %d commands, want 1", n)
	}
	got, err := st.Q().GetCommand(ctx, cmdID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "expired" {
		t.Fatalf("status = %q, want expired", got.Status)
	}
}

func TestAdvisoryLockSkipsConcurrentRun(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	const lockID = 5274099

	held := make(chan struct{})
	release := make(chan struct{})
	go func() {
		_, _ = st.WithAdvisoryLock(ctx, lockID, func(*store.Queries) error {
			close(held)
			<-release
			return nil
		})
	}()
	<-held

	ran, err := st.WithAdvisoryLock(ctx, lockID, func(*store.Queries) error {
		t.Error("the second caller should not have run the job")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if ran {
		t.Fatal("want ran=false while the lock is held")
	}
	close(release)
}
```

Check `internal/server/store/storetest/storetest.go` for the helpers it already exposes. If `Device` and `QueuedCommand` do not exist, add them there — a device row and a command row with a chosen `expires_at` — rather than duplicating insert SQL in the sweeper test.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/server/sweeper/ -v`
Expected: FAIL — no such package.

- [ ] **Step 3: Add `WithAdvisoryLock`**

In `internal/server/store/store.go`:

```go
// WithAdvisoryLock runs fn while holding the Postgres advisory lock id, and
// reports whether it ran. It reports false without running fn when another
// session already holds the lock, so a second replica skips the tick instead
// of queueing behind the first and repeating the work.
//
// The lock is session-scoped, so it is taken and released on one dedicated
// connection; releasing from a different pooled connection would do nothing.
func (s *Store) WithAdvisoryLock(ctx context.Context, id int64, fn func(q *Queries) error) (bool, error) {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return false, err
	}
	defer conn.Release()

	var got bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, id).Scan(&got); err != nil {
		return false, err
	}
	if !got {
		return false, nil
	}
	defer func() {
		// Use a fresh context: the caller's may already be cancelled, and the
		// lock must be released on this connection before it goes back.
		unlockCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, _ = conn.Exec(unlockCtx, `SELECT pg_advisory_unlock($1)`, id)
	}()
	return true, fn(&Queries{db: conn})
}
```

`pgxpool.Conn` satisfies `DBTX`. Add `"time"` to the imports if it is not already there.

- [ ] **Step 4: Implement the sweeper**

`internal/server/sweeper/sweeper.go`:

```go
// Package sweeper runs periodic maintenance jobs. Each job is guarded by a
// Postgres advisory lock so that only one server replica runs it per tick.
package sweeper

import (
	"context"
	"log/slog"
	"time"

	"retune/internal/server/store"
)

// Job is one periodic maintenance task.
type Job struct {
	Name     string
	LockID   int64
	Interval time.Duration
	// Run does the work and reports how many rows it affected.
	Run func(ctx context.Context, q *store.Queries, now time.Time) (int64, error)
}

// Runner runs jobs on their own tickers until its context is cancelled.
type Runner struct {
	Store *store.Store
	Jobs  []Job
	Log   *slog.Logger
	Now   func() time.Time
}

// Start launches one goroutine per job and returns immediately.
func (r *Runner) Start(ctx context.Context) {
	for _, job := range r.Jobs {
		go r.loop(ctx, job)
	}
}

func (r *Runner) loop(ctx context.Context, job Job) {
	t := time.NewTicker(job.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n, ran, err := r.runRecovered(ctx, job)
			switch {
			case err != nil:
				// A failing job is retried on the next tick; it never stops
				// the runner.
				r.Log.Warn("sweeper job failed", "job", job.Name, "error", err)
			case ran && n > 0:
				r.Log.Info("sweeper job ran", "job", job.Name, "rows", n)
			}
		}
	}
}

func (r *Runner) runRecovered(ctx context.Context, job Job) (n int64, ran bool, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panic: %v", p)
		}
	}()
	return r.RunOnce(ctx, job)
}

// RunOnce runs one job immediately if the advisory lock is free, and reports
// the rows affected and whether it ran.
func (r *Runner) RunOnce(ctx context.Context, job Job) (int64, bool, error) {
	var n int64
	ran, err := r.Store.WithAdvisoryLock(ctx, job.LockID, func(q *store.Queries) error {
		var err error
		n, err = job.Run(ctx, q, r.Now())
		return err
	})
	return n, ran, err
}
```

Add `"fmt"` to the imports.

`internal/server/sweeper/jobs.go`:

```go
package sweeper

import (
	"context"
	"time"

	"retune/internal/server/store"
)

// Lock IDs are fixed so they stay stable across restarts and replicas.
const (
	lockExpireCommands  = 5274001
	lockCleanupSessions = 5274002
)

// DefaultJobs are the maintenance jobs every server runs.
func DefaultJobs(interval time.Duration) []Job {
	return []Job{
		{
			// Commands were only expired when a device checked in, so a command
			// queued for a machine that never comes back stayed queued forever.
			Name: "commands.expire", LockID: lockExpireCommands, Interval: interval,
			Run: func(ctx context.Context, q *store.Queries, now time.Time) (int64, error) {
				return q.ExpireCommands(ctx, now)
			},
		},
		{
			Name: "sessions.cleanup", LockID: lockCleanupSessions, Interval: interval,
			Run: func(ctx context.Context, q *store.Queries, now time.Time) (int64, error) {
				return q.DeleteExpiredSessions(ctx, now)
			},
		},
	}
}
```

- [ ] **Step 5: Run the sweeper tests**

Run: `go test ./internal/server/sweeper/ -v`
Expected: PASS.

- [ ] **Step 6: Start the runner in `serve`**

In `cmd/retune-server/main.go`, after `defer a.Close()`:

```go
sweep := &sweeper.Runner{
	Store: a.Store,
	Jobs:  sweeper.DefaultJobs(cfg.SweepInterval),
	Log:   log,
	Now:   time.Now,
}
sweep.Start(ctx)
```

The goroutines stop when `ctx` is cancelled, which is the same signal context that triggers shutdown.

- [ ] **Step 7: Verify the build and full suite**

Run: `go build ./... && go test ./internal/server/... ./cmd/...`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/server cmd/retune-server
git commit -m "feat(server): sweep expired commands and sessions on a timer"
```

---

## Task 4: CA key from the environment, and CA certificate export

**Files:**
- Modify: `internal/server/ca/keystore.go`
- Modify: `internal/server/app/app.go:50`, `cmd/retune-server/main.go:162-176`
- Test: `internal/server/ca/keystore_test.go`

**Interfaces:**
- Consumes: `config.Server.CAKeySource` from Task 1.
- Produces: `ca.EnvKeyStore{CertPEM, KeyPEM string}` satisfying `ca.KeyStore`; `ca.KeyStoreFor(cfg config.Server) (ca.KeyStore, error)` is **not** added — the selection is a small switch in `app.New`, since only two call sites need it.

- [ ] **Step 1: Read the existing interface**

Read `internal/server/ca/keystore.go` in full. `EnvKeyStore` must satisfy the same interface as `FileKeyStore`, including whatever the "not yet created" signal is (an error value or a boolean) — match it exactly.

- [ ] **Step 2: Write the failing test**

```go
func TestEnvKeyStoreRoundTrip(t *testing.T) {
	// Create a CA in a temp dir, read the PEMs back out, and load them from
	// an EnvKeyStore: the same CA must come back.
	dir := t.TempDir()
	authority, err := ca.LoadOrCreate(context.Background(), ca.FileKeyStore{Dir: dir}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}

	loaded, err := ca.LoadOrCreate(context.Background(),
		ca.EnvKeyStore{CertPEM: string(certPEM), KeyPEM: string(keyPEM)}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Cert().Equal(authority.Cert()) {
		t.Fatal("EnvKeyStore loaded a different CA")
	}
}

func TestEnvKeyStoreRefusesToCreate(t *testing.T) {
	_, err := ca.LoadOrCreate(context.Background(), ca.EnvKeyStore{}, time.Now())
	if err == nil {
		t.Fatal("want an error when CA_KEY_PEM is not set")
	}
}
```

Adjust the file names (`ca.crt`, `ca.key`) to whatever `FileKeyStore` actually writes — confirm in Step 1.

- [ ] **Step 3: Run the test to verify it fails**

Run: `go test ./internal/server/ca/ -run EnvKeyStore -v`
Expected: FAIL — undefined `ca.EnvKeyStore`.

- [ ] **Step 4: Implement `EnvKeyStore`**

It reads from its two string fields and **refuses to save**, returning an error explaining that a CA key supplied through the environment cannot be created by the server — the operator must generate one and set `CA_KEY_PEM`/`CA_CERT_PEM`. Silently generating a CA that vanishes when the container restarts would orphan every enrolled device.

- [ ] **Step 5: Select the key store in `app.New`**

Replace the hardcoded `ca.FileKeyStore` at `app.go:50`:

```go
var keys ca.KeyStore = ca.FileKeyStore{Dir: filepath.Join(cfg.DataDir, "ca")}
if cfg.CAKeySource == "env" {
	keys = ca.EnvKeyStore{CertPEM: os.Getenv("CA_CERT_PEM"), KeyPEM: os.Getenv("CA_KEY_PEM")}
}
authority, err := ca.LoadOrCreate(ctx, keys, time.Now())
```

`app.New` does not take a `getenv`, so reading `os.Getenv` directly here is consistent with it being process configuration; add `"os"` to the imports.

- [ ] **Step 6: Add `ca cert` and stop `ca fingerprint` creating a CA**

In `cmd/retune-server/main.go`, the `ca` command becomes a two-way switch on `args[1]`: `fingerprint` and `cert`. Both load the CA **without creating one**: check whether the key store already holds a CA and return

```
no certificate authority exists yet; start the server once to create one
```

if it does not. `cert` prints the PEM of `authority.Cert().Raw`; `fingerprint` prints `pki.Fingerprint(authority.Cert().Raw)` as it does today.

Update the usage block to list `ca cert`.

- [ ] **Step 7: Run the tests**

Run: `go test ./internal/server/ca/ ./cmd/retune-server/ -v`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/server/ca internal/server/app cmd/retune-server
git commit -m "feat(server): load the CA key from the environment and export the CA cert"
```

---

## Task 5: Container image and Compose stack

**Files:**
- Create: `deploy/docker/Dockerfile`, `deploy/docker/docker-compose.yml`, `deploy/docker/.env.example`, `.dockerignore`
- Modify: `Makefile`

- [ ] **Step 1: Write `.dockerignore`**

```
.git
bin
data
agent-data
web/node_modules
internal/server/console/dist/assets
internal/server/console/dist/index.html
docs
```

- [ ] **Step 2: Write the Dockerfile**

`deploy/docker/Dockerfile` — note it is built with the **repository root** as context, because it needs both `web/` and the Go module.

```dockerfile
# syntax=docker/dockerfile:1

# The console is built first: the Go binary embeds it with go:embed, and the
# built assets are gitignored, so skipping this stage would produce a server
# whose console is a 503 page rather than a build failure.
FROM node:24-alpine AS console
WORKDIR /src
COPY web/package.json web/package-lock.json ./web/
RUN npm --prefix web ci
COPY web ./web
RUN npm --prefix web run build

FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=console /src/internal/server/console/dist ./internal/server/console/dist
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/retune-server ./cmd/retune-server
# Created here so that a fresh named volume inherits this ownership and the
# non-root process can write the CA key on first start.
RUN mkdir -p /out/data && chown 65532:65532 /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/retune-server /retune-server
COPY --from=build --chown=65532:65532 /out/data /var/lib/retune
USER nonroot
EXPOSE 8443
ENTRYPOINT ["/retune-server"]
CMD ["serve"]
```

- [ ] **Step 3: Write the Compose file**

`deploy/docker/docker-compose.yml`:

```yaml
name: retune

services:
  db:
    image: postgres:17
    environment:
      POSTGRES_USER: retune
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-retune}
      POSTGRES_DB: retune
    volumes:
      - db:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U retune -d retune"]
      interval: 5s
      timeout: 5s
      retries: 10

  server:
    build:
      context: ../..
      dockerfile: deploy/docker/Dockerfile
    environment:
      DATABASE_URL: postgres://retune:${POSTGRES_PASSWORD:-retune}@db:5432/retune?sslmode=disable
      PUBLIC_URL: ${PUBLIC_URL:-https://localhost:8443}
      DATA_DIR: /var/lib/retune
    ports:
      - "8443:8443"
    volumes:
      - ca:/var/lib/retune
    depends_on:
      db:
        condition: service_healthy
    restart: unless-stopped

volumes:
  db:
  ca:
```

No migrate step: `app.New` runs migrations at startup under an advisory lock.

- [ ] **Step 4: Write `.env.example`**

```
# Copy to .env and edit before running docker compose up.
POSTGRES_PASSWORD=change-me
# The address agents will use to reach this server.
PUBLIC_URL=https://mdm.example.com
```

- [ ] **Step 5: Add Makefile targets**

```make
docker:
	docker build -f deploy/docker/Dockerfile -t retune-server:dev .

compose-up:
	docker compose -f deploy/docker/docker-compose.yml up --build -d

compose-down:
	docker compose -f deploy/docker/docker-compose.yml down
```

Add them to `.PHONY`.

- [ ] **Step 6: Build the image**

Run: `docker build -f deploy/docker/Dockerfile -t retune-server:dev .`
Expected: a successful build. Then confirm the console actually made it in:

```bash
docker run --rm --entrypoint /retune-server retune-server:dev --help 2>&1 | head -5
```

- [ ] **Step 7: Bring the stack up and verify**

```bash
docker compose -f deploy/docker/docker-compose.yml up --build -d
docker compose -f deploy/docker/docker-compose.yml logs server
```

Expected: the log line `agent API listening` with a `ca_fingerprint`, and no migration errors. Then `curl -k https://localhost:8443/` returns the console HTML, **not** the "run npm run build" 503. Tear down with `docker compose ... down -v`.

- [ ] **Step 8: Commit**

```bash
git add deploy/docker .dockerignore Makefile
git commit -m "build: distroless server image and compose stack"
```

---

## Task 6: Extract the agent run loop

**Files:**
- Create: `internal/agent/runner/runner.go`
- Modify: `cmd/retune-agent/main.go:69-126`

**Interfaces:**
- Produces: `runner.Options{DataDir string, Once bool, Log *slog.Logger, Out io.Writer}` and `runner.Run(ctx context.Context, opts Options) error`, returning `checkin.ErrUnenrolled` when the server has unenrolled the device.

This task is a pure refactor: no behaviour changes, and the existing agent tests must pass untouched.

- [ ] **Step 1: Create the package**

`internal/agent/runner/runner.go` holds everything currently inside `case "run":` — identity load, `state.Open`, `session.New`, `sess.Start`, and the `once` / forever branches. The differences from today:

- The logger arrives in `Options` instead of being built inline, so the service can pass an Event Log handler.
- `signal.NotifyContext` stays in `main.go`. The runner takes a context and does not install signal handlers, because under the SCM the stop signal is a service control request, not a POSIX signal.
- Human-readable progress lines go to `opts.Out`; when it is nil they are skipped, which is what the service wants.

```go
// Package runner hosts the agent's check-in loop, independent of how the
// process was started: a terminal and the Windows service both call Run.
package runner

type Options struct {
	DataDir string
	Once    bool
	Log     *slog.Logger
	// Out receives human-readable progress. Nil under the service.
	Out io.Writer
}

// Run checks in until ctx is cancelled. It returns checkin.ErrUnenrolled if
// the server has unenrolled this device, after the local identity and state
// have been removed.
func Run(ctx context.Context, opts Options) error
```

`Run` returns `checkin.ErrUnenrolled` rather than swallowing it — `main.go` prints the friendly message, and the service disables itself. That is the one behavioural difference, and it moves the decision to the caller that can act on it.

- [ ] **Step 2: Rewrite the `run` case**

```go
case "run":
	once := fs.Bool("once", false, "check in once and exit")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := runner.Run(ctx, runner.Options{
		DataDir: *dataDir,
		Once:    *once,
		Log:     slog.New(slog.NewTextHandler(os.Stderr, nil)),
		Out:     out,
	})
	if errors.Is(err, checkin.ErrUnenrolled) {
		fmt.Fprintln(out, "This device was unenrolled; local identity and state removed.")
		return nil
	}
	return err
```

Remove the imports `main.go` no longer uses (`filepath`, `time`, `rand/v2`, `session`, `state`, `executor`, `inventory`, `identity`) — `go vet` will flag them.

- [ ] **Step 3: Verify no behaviour changed**

Run: `go build ./... && go test ./internal/agent/... ./cmd/retune-agent/ -v`
Expected: PASS, with no test edits. If a test needed editing, the refactor changed behaviour — find out why before continuing.

- [ ] **Step 4: Verify by hand**

Run: `go run ./cmd/retune-agent run --once --data-dir ./agent-data`
Expected: the same output as before the refactor (an error about not being enrolled if `./agent-data` is empty).

- [ ] **Step 5: Commit**

```bash
git add internal/agent/runner cmd/retune-agent
git commit -m "refactor(agent): extract the run loop so a service can host it"
```

---

## Task 7: Agent logging

**Files:**
- Create: `internal/agent/logging/logging.go`, `rotate.go`, `rotate_test.go`, `eventlog_windows.go`, `eventlog_other.go`

**Interfaces:**
- Produces: `logging.New(opts logging.Options) (*slog.Logger, func() error, error)` where `Options{Dir string, Stderr bool, EventLog bool}`; the returned func closes the file.

- [ ] **Step 1: Write the failing rotation test**

`internal/agent/logging/rotate_test.go`:

```go
func TestRotateKeepsBoundedHistory(t *testing.T) {
	dir := t.TempDir()
	w, err := logging.NewRotatingFile(filepath.Join(dir, "agent.log"), 100, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	line := strings.Repeat("x", 40) + "\n"
	for i := 0; i < 20; i++ {
		if _, err := w.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := filepath.Glob(filepath.Join(dir, "agent.log*"))
	if err != nil {
		t.Fatal(err)
	}
	// The live file plus at most (keep-1) rotated ones.
	if len(entries) > 3 {
		t.Fatalf("kept %d files, want at most 3: %v", len(entries), entries)
	}
	for _, e := range entries {
		st, err := os.Stat(e)
		if err != nil {
			t.Fatal(err)
		}
		if st.Size() > 200 {
			t.Errorf("%s is %d bytes, rotation did not bound it", e, st.Size())
		}
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/agent/logging/ -v`
Expected: FAIL — no such package.

- [ ] **Step 3: Implement the rotating writer**

`NewRotatingFile(path string, maxBytes int64, keep int) (*RotatingFile, error)`. `Write` rotates **before** writing when the current size plus the new record would exceed `maxBytes`: close the file, shift `agent.log.(keep-1)` → dropped, `agent.log.N` → `agent.log.N+1`, `agent.log` → `agent.log.1`, reopen. Guard with a mutex, since slog handlers write from several goroutines. `Close` closes the file.

- [ ] **Step 4: Implement the handler assembly**

`logging.New` composes a `slog.Handler` writing to an `io.MultiWriter` of the rotating file and, when `Stderr` is set, `os.Stderr`. When `EventLog` is set it wraps the handler in the platform handler from `eventlog_windows.go`, which forwards records at `slog.LevelWarn` and above to the Windows Event Log source `Retune` and passes everything through to the wrapped handler. On non-Windows, `eventlog_other.go` returns the handler unchanged.

The Event Log source must already be registered — `retune-agent install` does that in Task 9. If opening it fails, log a warning to the file and carry on rather than failing startup; an agent that will not start because it cannot write to the Event Log is worse than one that logs to a file only.

Default file location: `filepath.Join(opts.Dir, "logs", "agent.log")`, 5 MB, keeping 5.

- [ ] **Step 5: Run the tests**

Run: `go test ./internal/agent/logging/ -v && go vet ./...`
Expected: PASS on both Linux and Windows.

- [ ] **Step 6: Commit**

```bash
git add internal/agent/logging
git commit -m "feat(agent): rotating file and Event Log logging"
```

---

## Task 8: Agent configuration file and first-start enrollment

**Files:**
- Create: `internal/agent/agentcfg/agentcfg.go`, `agentcfg_test.go`
- Modify: `internal/agent/runner/runner.go`

**Interfaces:**
- Produces: `agentcfg.Config{ServerURL, EnrollToken, ServerCertFingerprint string}`; `agentcfg.Load(dir string) (Config, error)` returning `agentcfg.ErrNoConfig` when the file is absent; `agentcfg.Save(dir string, c Config) error`; `agentcfg.ClearToken(dir string) error`.

- [ ] **Step 1: Write the failing test**

```go
func TestSaveLoadAndClearToken(t *testing.T) {
	dir := t.TempDir()
	want := agentcfg.Config{
		ServerURL:             "https://mdm.example.com",
		EnrollToken:           "secret-token",
		ServerCertFingerprint: "sha256:abc",
	}
	if err := agentcfg.Save(dir, want); err != nil {
		t.Fatal(err)
	}
	got, err := agentcfg.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("round trip: got %+v want %+v", got, want)
	}

	if err := agentcfg.ClearToken(dir); err != nil {
		t.Fatal(err)
	}
	got, err = agentcfg.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.EnrollToken != "" {
		t.Error("the spent token should be gone")
	}
	if got.ServerURL != want.ServerURL || got.ServerCertFingerprint != want.ServerCertFingerprint {
		t.Error("clearing the token must not disturb the rest of the file")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "agent.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "secret-token") {
		t.Error("the token is still on disk")
	}
}

func TestLoadMissing(t *testing.T) {
	if _, err := agentcfg.Load(t.TempDir()); !errors.Is(err, agentcfg.ErrNoConfig) {
		t.Fatalf("want ErrNoConfig, got %v", err)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/agent/agentcfg/ -v`
Expected: FAIL — no such package.

- [ ] **Step 3: Implement it**

`agent.yaml` with `yaml:"server_url"`, `yaml:"enroll_token"`, `yaml:"server_cert_fingerprint"`, using `gopkg.in/yaml.v3` (already a dependency). `Save` writes with mode `0o600` and `MkdirAll` at `0o700`. `ClearToken` loads, blanks `EnrollToken`, and saves.

- [ ] **Step 4: Enroll on first start in the runner**

At the top of `runner.Run`, before the existing identity load:

```go
idStore := identity.Store{Dir: opts.DataDir, Keys: identity.DefaultKeys()}
id, err := idStore.Load()
if errors.Is(err, identity.ErrNotEnrolled) {
	id, err = enrollFromConfig(ctx, opts, idStore)
}
if err != nil {
	return err
}
```

`enrollFromConfig` loads `agentcfg`. If there is no config, or it has no `server_url` or `enroll_token`, it returns an error explaining that the agent is not enrolled and not configured — `retune-agent enroll` or an MSI install is needed. Otherwise it calls `enrollment.Enroll` with `Facts: facts.Device()` and the same `identity.Store`, and on success calls `agentcfg.ClearToken`, logging that the spent token was removed. A `ClearToken` failure is logged, not fatal: the device is enrolled, and failing the start over a leftover token would leave a working agent dead.

Retrying is the caller's job — the service loop in Task 9 retries; `retune-agent run` reports the error and exits, which is what a person at a terminal wants.

- [ ] **Step 5: Run the tests**

Run: `go test ./internal/agent/... -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/agent
git commit -m "feat(agent): enroll from agent.yaml on first start and spend the token"
```

---

## Task 9: Windows service host and subcommands

**Files:**
- Create: `cmd/retune-agent/service_windows.go`, `cmd/retune-agent/service_other.go`
- Modify: `cmd/retune-agent/main.go` (dispatch and usage)

**Interfaces:**
- Consumes: `runner.Run`, `agentcfg.Save`, `logging.New`, `checkin.ErrUnenrolled`.
- Produces (Windows): `runService(ctx context.Context, dataDir string) error`, `installService(exePath string) error`, `uninstallService() error`, `isWindowsService() bool`. `service_other.go` provides the same names, with `isWindowsService()` returning false and the rest returning an error.

- [ ] **Step 1: Add the subcommands to `main.go`**

Usage becomes:

```
usage: retune-agent <command>

commands:
  enroll --server URL --token T [--pin sha256:...] [--data-dir D]
  run [--data-dir D] [--once]
  configure --server URL --token T [--pin sha256:...] [--data-dir D]   (Windows)
  install [--data-dir D]                                              (Windows)
  uninstall                                                           (Windows)
```

At the very top of `run(ctx, args, out)`, before the `len(args) == 0` check:

```go
// The service control manager starts us with no arguments.
if len(args) == 0 && isWindowsService() {
	return runService(ctx, defaultDataDir())
}
```

`configure` parses `--server`, `--token`, `--pin`, calls `agentcfg.Save`, then restricts the data directory ACL. `install` and `uninstall` call through to the platform functions.

- [ ] **Step 2: Implement `service_other.go`**

```go
//go:build !windows

package main

import (
	"context"
	"errors"
)

func isWindowsService() bool { return false }

func runService(context.Context, string) error {
	return errors.New("the Retune service is only available on Windows")
}

func installService(string) error {
	return errors.New("service installation is only available on Windows")
}

func uninstallService() error {
	return errors.New("service removal is only available on Windows")
}

func secureDataDir(string) error { return nil }
```

- [ ] **Step 3: Implement `service_windows.go`**

Behind `//go:build windows`. Four pieces:

**`isWindowsService`** wraps `svc.IsWindowsService()`.

**`runService`** calls `svc.Run("Retune", &handler{dataDir: dataDir})`. The handler:

```go
func (h *handler) Execute(args []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}

	log, closeLog, err := logging.New(logging.Options{Dir: h.dataDir, EventLog: true})
	if err != nil {
		return true, 1
	}
	defer closeLog()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- h.serve(ctx, log) }()

	status <- svc.Status{State: svc.Running, Accepts: accepted}
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				<-done
				return false, 0
			}
		case err := <-done:
			if errors.Is(err, checkin.ErrUnenrolled) {
				log.Warn("device was unenrolled; disabling the service")
				if err := disableService(); err != nil {
					log.Error("disable the service", "error", err)
				}
			} else if err != nil {
				log.Error("agent stopped", "error", err)
			}
			status <- svc.Status{State: svc.StopPending}
			return false, 0
		}
	}
}
```

`h.serve` wraps `runner.Run` in a retry loop so that an unconfigured or unreachable server does not make the SCM fight the process with restarts: on any error other than `checkin.ErrUnenrolled` it logs, waits 60 seconds (or until `ctx` is done), and calls `runner.Run` again. `ErrUnenrolled` is returned immediately.

**`installService`** connects with `mgr.Connect`, refuses if the service exists, and creates it:

```go
s, err := m.CreateService("Retune", exePath, mgr.Config{
	DisplayName:  "Retune Agent",
	Description:  "Reports inventory to the Retune server and runs assigned commands.",
	StartType:    mgr.StartAutomatic,
	ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
	ErrorControl: mgr.ErrorNormal,
})
```

LocalSystem is the default when `ServiceStartName` is empty. Then set recovery actions — restart after 60 seconds, three times, resetting the count after a day:

```go
err = s.SetRecoveryActions([]mgr.RecoveryAction{
	{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
}, uint32((24 * time.Hour).Seconds()))
```

and register the Event Log source with `eventlog.InstallAsEventCreate("Retune", eventlog.Error|eventlog.Warning|eventlog.Info)`, tolerating "already exists".

**`uninstallService`** opens the service, sends `svc.Stop` and waits up to 30 seconds for `svc.Stopped`, calls `s.Delete()`, and `eventlog.Remove("Retune")`, tolerating "not found" from each.

**`disableService`** opens the service, reads its `Config`, sets `StartType: mgr.StartDisabled`, and calls `UpdateConfig`.

**`secureDataDir(dir string)`** restricts the ACL to SYSTEM and Administrators by running
`icacls <dir> /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F"`.
Shelling out to `icacls` is deliberate: building the equivalent ACL through `windows.SetNamedSecurityInfo` is a great deal of code for a one-line result, and `icacls` ships with Windows.

All four report a readable error when not run as Administrator rather than surfacing a raw `Access is denied`.

- [ ] **Step 4: Verify it builds on both platforms**

Run: `go build ./... && GOOS=windows go build ./... && go vet ./...`
Expected: success on both. On Windows use `$env:GOOS='linux'; go build ./...` then reset.

- [ ] **Step 5: Install and verify on a real machine**

**Ask the user before this step** — it registers a service on their machine.

```powershell
go build -o bin/retune-agent.exe ./cmd/retune-agent
bin/retune-agent.exe install
bin/retune-agent.exe configure --server https://localhost:18443 --token <token> --pin sha256:<fp>
Start-Service Retune
Get-Service Retune
Get-Content C:\ProgramData\Retune\logs\agent.log -Tail 20
```

Expected: the service reaches `Running`, the log shows an enrollment followed by check-ins, and the device appears in the console. Then `Stop-Service Retune` returns promptly rather than timing out, and `bin/retune-agent.exe uninstall` removes it.

- [ ] **Step 6: Commit**

```bash
git add cmd/retune-agent
git commit -m "feat(agent): run as a Windows service with install and uninstall"
```

---

## Task 10: MSI

**Files:**
- Create: `deploy/msi/Package.wxs`, `deploy/msi/build.ps1`
- Modify: `Makefile`

- [ ] **Step 1: Write `Package.wxs`**

WiX 5 schema. A fixed `UpgradeCode` — generate one **once** with `New-Guid` and paste it in; it must never change again or upgrades break.

Structure:
- `<Package Name="Retune Agent" Manufacturer="Retune" Version="$(Version)" UpgradeCode="<fixed guid>" Scope="perMachine">`
- `<MajorUpgrade DowngradeErrorMessage="A newer version of the Retune Agent is already installed." />`
- `<MediaTemplate EmbedCab="yes" />`
- A `StandardDirectory` of `ProgramFiles64Folder` containing `Retune\retune-agent.exe` as the `KeyPath`.
- `<ServiceInstall Id="RetuneService" Name="Retune" DisplayName="Retune Agent" Type="ownProcess" Start="auto" Account="LocalSystem" ErrorControl="normal" Description="Reports inventory to the Retune server and runs assigned commands." />` plus `<ServiceControl Id="RetuneServiceControl" Name="Retune" Start="install" Stop="both" Remove="uninstall" Wait="yes" />`
- Public properties `SERVER_URL`, `ENROLL_TOKEN`, `SERVER_CERT_FINGERPRINT`, and `<Property Id="MsiHiddenProperties" Value="ENROLL_TOKEN" />` so the token stays out of the installer log.
- A deferred, elevated custom action running `retune-agent.exe configure --server [SERVER_URL] --token [ENROLL_TOKEN] --pin [SERVER_CERT_FINGERPRINT]`, sequenced **after `InstallFiles` and before `StartServices`**, conditioned on `SERVER_URL AND ENROLL_TOKEN` so an install without them still succeeds and simply leaves the agent unconfigured.
- A custom action on uninstall removing `C:\ProgramData\Retune`, conditioned on `REMOVE="ALL"`.

- [ ] **Step 2: Write `build.ps1`**

```powershell
param(
  [string]$Version = "0.1.0",
  [string]$OutDir  = "bin"
)
$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "../..")
$out  = Join-Path $root $OutDir
New-Item -ItemType Directory -Force -Path $out | Out-Null

$env:GOOS = "windows"; $env:GOARCH = "amd64"
& go build -trimpath -o (Join-Path $out "retune-agent.exe") (Join-Path $root "cmd/retune-agent")
if ($LASTEXITCODE -ne 0) { throw "go build failed" }

& wix build -arch x64 `
  -d Version=$Version `
  -d AgentExe=(Join-Path $out "retune-agent.exe") `
  (Join-Path $PSScriptRoot "Package.wxs") `
  -o (Join-Path $out "retune-agent.msi")
if ($LASTEXITCODE -ne 0) { throw "wix build failed" }
Write-Host "Built $(Join-Path $out 'retune-agent.msi')"
```

- [ ] **Step 3: Build the MSI**

Run: `pwsh deploy/msi/build.ps1`
Expected: `bin/retune-agent.msi` exists. WiX 5.0.2 is already installed as a dotnet global tool.

- [ ] **Step 4: Install it and verify**

**Ask the user before this step** — it installs software on their machine.

```powershell
msiexec /i bin\retune-agent.msi SERVER_URL=https://localhost:18443 ENROLL_TOKEN=<token> SERVER_CERT_FINGERPRINT=sha256:<fp> /qn /l*v bin\msi.log
Get-Service Retune
Get-Content C:\ProgramData\Retune\logs\agent.log -Tail 20
Select-String -Path bin\msi.log -Pattern "ENROLL_TOKEN"
```

Expected: the service is `Running`, the device shows up in the console, and the token does **not** appear in the log — that last check is the point of `MsiHiddenProperties`. Then `msiexec /x bin\retune-agent.msi /qn` removes the service and `C:\ProgramData\Retune`.

- [ ] **Step 5: Add the Makefile target and commit**

```make
msi:
	pwsh deploy/msi/build.ps1
```

```bash
git add deploy/msi Makefile
git commit -m "build: WiX MSI installing the agent as a service"
```

---

## Task 11: CI and documentation

**Files:**
- Modify: `.github/workflows/ci.yml`, `README.md`

- [ ] **Step 1: Build the image in CI**

Add to the Linux job, after the Go build:

```yaml
      - name: Build the server image
        run: docker build -f deploy/docker/Dockerfile -t retune-server:ci .
```

- [ ] **Step 2: Build the MSI in CI**

Add to the Windows job:

```yaml
      - name: Install WiX
        run: dotnet tool install --global wix --version 5.0.2

      - name: Build the MSI
        run: pwsh deploy/msi/build.ps1 -Version 0.1.${{ github.run_number }}

      - uses: actions/upload-artifact@v4
        with:
          name: retune-agent-msi
          path: bin/retune-agent.msi
```

`permissions: contents: read` is enough; nothing is published.

- [ ] **Step 3: Document deployment in the README**

Add a **Deploying the server** section covering the Compose quick start (copy `.env.example`, `docker compose up`, `bootstrap-admin` through `docker compose exec`), and a **Behind a reverse proxy** subsection with the required settings and a worked nginx snippet showing `ssl_client_certificate` pointing at the output of `retune-server ca cert` and `proxy_set_header X-Forwarded-Client-Cert $ssl_client_escaped_cert;`.

Replace the placeholder in the "Enroll a machine" section — which currently says the msiexec line will be shown once the MSI is available — with the real command:

```
msiexec /i retune-agent.msi SERVER_URL=https://mdm.example.com ENROLL_TOKEN=xxxx [SERVER_CERT_FINGERPRINT=sha256:...] /qn
```

Document `retune-agent install`, `uninstall` and `configure`, and note that unenrolling a device stops and disables the service, leaving the MSI installed so a new token can re-enroll it.

Add the new configuration keys to the README's settings table.

- [ ] **Step 4: Validate the workflow file**

Run: `python -c "import yaml,sys; d=yaml.safe_load(open('.github/workflows/ci.yml')); print(list(d['jobs']), [len(j['steps']) for j in d['jobs'].values()])"`
Expected: both jobs listed with their new step counts.

- [ ] **Step 5: Commit**

```bash
git add .github README.md
git commit -m "ci: build the server image and the agent MSI"
```

---

## Task 12: Milestone verification

- [ ] **Step 1: Full suite**

Run: `go vet ./... && go test -count=1 ./... && npm --prefix web run test`
Expected: all pass.

- [ ] **Step 2: End-to-end through the container**

Bring up the Compose stack, create an admin and an enrollment token inside it, install the MSI on this machine pointed at it, and confirm: the device enrolls, inventory arrives, a script queued from the console runs and reports its exit code, and the audit log attributes it. This is the same end-to-end check M3 finished with, but through the packaged artifacts rather than `go run`.

- [ ] **Step 3: Sweeper verification**

Queue a command for a device that is not running, with `--ttl 10s`. Within one sweep interval its status becomes `expired` without any agent check-in. This is the bug the sweeper fixes, so it is worth seeing fail-then-pass.

- [ ] **Step 4: Update the roadmap**

Tick M4 in `docs/superpowers/plans/2026-09-12-roadmap.md` the way M1–M3 were marked.

- [ ] **Step 5: Finish the branch**

**REQUIRED SUB-SKILL:** Use superpowers:finishing-a-development-branch.

---

## Self-Review

**Spec coverage.** §3 config → Task 1. §4 device auth and the `ca cert` helper → Tasks 2 and 4. §5 sweepers → Task 3. §6 image and Compose → Task 5. §7 service, refactor, config, logging, unenrollment → Tasks 6–9. §8 MSI → Task 10. §9 build and CI → Tasks 5, 10, 11. §10 testing → covered within each task plus Task 12. §2's `ca_key_source` decision → Task 4.

**Type consistency.** `runner.Options`/`runner.Run` are defined in Task 6 and consumed in Tasks 8 and 9. `agentcfg.Save` is defined in Task 8 and consumed by `configure` in Task 9. `sweeper.Runner.RunOnce` returns `(int64, bool, error)` in both its definition and its test. `store.WithAdvisoryLock` returns `(bool, error)` in its definition, its test, and its caller. `agentapi.CertError` is defined in Task 2 and used in its tests and the handler.

**Known risk.** Task 2 changes an authentication path. The existing `agentapi` tests are the safety net; if any construct a `Handler` literal directly, they will fail to compile until `ClientCert` is set, which is the desired loud failure rather than a silently unauthenticated server.
