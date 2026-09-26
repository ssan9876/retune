package serverupdate

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"retune/internal/release"
)

// Binary updates a server installed as a plain binary and run by systemd.
// The server has already downloaded the new binary into StagedPath; nothing
// about it is believed until its hash matches the verified manifest's.
type Binary struct {
	Run Runner
	// BinaryPath is the installed server, which the unit runs.
	BinaryPath string
	// StagedPath is the downloaded new binary.
	StagedPath string
	// Unit is the systemd unit to restart.
	Unit string
	// ReadyURL is the server's /readyz.
	ReadyURL string
	// DatabaseURL is what pg_dump connects to.
	DatabaseURL string
	BackupDir   string
	Keep        int
	// GOARCH picks the build from the manifest; runtime.GOARCH if empty.
	GOARCH        string
	HealthTimeout time.Duration
	Poll          time.Duration
	HTTP          *http.Client
}

// Current asks the installed binary its version.
func (b *Binary) Current(ctx context.Context) (string, error) {
	out, err := b.Run.Run(ctx, Cmd{Name: b.BinaryPath, Args: []string{"version"}})
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// Backup runs pg_dump. The connection string goes in the environment, not on
// the command line, where anyone on the machine could read its password.
func (b *Binary) Backup(ctx context.Context, name string) (string, error) {
	if err := os.MkdirAll(b.BackupDir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(b.BackupDir, name+".dump")
	env, err := pgEnv(b.DatabaseURL)
	if err != nil {
		return "", err
	}
	if _, err := b.Run.Run(ctx, Cmd{Name: "pg_dump", Args: []string{"-Fc", "-f", path}, Env: env}); err != nil {
		os.Remove(path)
		return "", fmt.Errorf("%w (is the PostgreSQL client installed?)", err)
	}
	prune(b.BackupDir, b.Keep)
	return path, nil
}

// Stage checks the downloaded binary against the manifest's hash for this
// machine's architecture.
func (b *Binary) Stage(_ context.Context, m release.ReleaseManifest) (string, error) {
	arch := b.GOARCH
	if arch == "" {
		arch = runtime.GOARCH
	}
	a, ok := m.Find(release.AssetServer, "linux", arch)
	if !ok {
		return "", fmt.Errorf("release %s publishes no server for linux/%s", m.Version, arch)
	}
	got, err := fileSHA256(b.StagedPath)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(got, a.SHA256) {
		return "", fmt.Errorf("the downloaded server hashes to %s, not the manifest's %s", got, a.SHA256)
	}
	return b.StagedPath, nil
}

// Swap keeps a copy of the running binary, moves the new one into place and
// restarts the unit.
func (b *Binary) Swap(ctx context.Context, staged string) (string, error) {
	previous := b.BinaryPath + ".previous"
	if err := copyFile(b.BinaryPath, previous); err != nil {
		return "", err
	}
	if err := install(staged, b.BinaryPath); err != nil {
		return "", err
	}
	if _, err := b.Run.Run(ctx, Cmd{Name: "systemctl", Args: []string{"restart", b.Unit}}); err != nil {
		return previous, err
	}
	return previous, nil
}

// WaitHealthy polls /readyz until it answers 200.
func (b *Binary) WaitHealthy(ctx context.Context) error {
	timeout, poll := b.HealthTimeout, b.Poll
	if timeout == 0 {
		timeout = 3 * time.Minute
	}
	if poll == 0 {
		poll = 2 * time.Second
	}
	client := b.HTTP
	if client == nil {
		// The probe talks to this machine's own server, whose certificate may
		// well be self-signed; what is being asked is whether it is ready.
		client = &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}}
	}
	deadline := time.Now().Add(timeout)
	last := ""
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.ReadyURL, nil)
		if err != nil {
			return err
		}
		if res, err := client.Do(req); err == nil {
			io.Copy(io.Discard, io.LimitReader(res.Body, 1024))
			res.Body.Close()
			if res.StatusCode == http.StatusOK {
				return nil
			}
			last = res.Status
		} else {
			last = err.Error()
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the new server was not ready after %s (last: %s)", timeout, last)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
}

// Restore puts the previous binary back and restarts the unit.
func (b *Binary) Restore(ctx context.Context, previous string) error {
	if err := install(previous, b.BinaryPath); err != nil {
		return err
	}
	_, err := b.Run.Run(ctx, Cmd{Name: "systemctl", Args: []string{"restart", b.Unit}})
	return err
}

// pgEnv turns a postgres:// URL into the libpq environment variables.
func pgEnv(raw string) ([]string, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		return nil, fmt.Errorf("the database URL is not a postgres:// URL")
	}
	env := []string{"PGHOST=" + u.Hostname(), "PGDATABASE=" + strings.TrimPrefix(u.Path, "/")}
	if p := u.Port(); p != "" {
		env = append(env, "PGPORT="+p)
	}
	if u.User != nil {
		env = append(env, "PGUSER="+u.User.Username())
		if pw, ok := u.User.Password(); ok {
			env = append(env, "PGPASSWORD="+pw)
		}
	}
	if m := u.Query().Get("sslmode"); m != "" {
		env = append(env, "PGSSLMODE="+m)
	}
	return env, nil
}

// install copies src next to dst and renames it over dst, so the unit never
// starts a half-written binary.
func install(src, dst string) error {
	tmp := dst + ".new"
	if err := copyFile(src, tmp); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	mode := os.FileMode(0o755)
	if fi, err := in.Stat(); err == nil {
		mode = fi.Mode().Perm()
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
