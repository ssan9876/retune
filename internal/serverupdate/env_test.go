package serverupdate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"retune/internal/release"
)

// fakeRunner answers commands by prefix and records every one it ran.
type fakeRunner struct {
	answers map[string]string
	errs    map[string]error
	ran     []Cmd
}

func (r *fakeRunner) Run(_ context.Context, c Cmd) ([]byte, error) {
	r.ran = append(r.ran, c)
	line := c.String()
	for prefix, err := range r.errs {
		if strings.HasPrefix(line, prefix) {
			return nil, err
		}
	}
	best := ""
	for prefix := range r.answers {
		if strings.HasPrefix(line, prefix) && len(prefix) > len(best) {
			best = prefix
		}
	}
	out := r.answers[best]
	if c.Stdout != nil {
		_, _ = c.Stdout.Write([]byte(out))
		return nil, nil
	}
	return []byte(out), nil
}

func (r *fakeRunner) ranLine(prefix string) bool {
	for _, c := range r.ran {
		if strings.HasPrefix(c.String(), prefix) {
			return true
		}
	}
	return false
}

func newDocker(t *testing.T, r *fakeRunner) *Docker {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("PUBLIC_URL=https://mdm.example.com\nRETUNE_IMAGE=old\nPOSTGRES_PASSWORD=pw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &Docker{Run: r, ProjectDir: dir, Service: "server", DBService: "db", DBUser: "retune", DBName: "retune",
		BackupDir: filepath.Join(dir, "backups"), Keep: 2, HealthTimeout: time.Second, Poll: time.Millisecond}
}

func TestDockerReadsTheVersionFromTheImageLabel(t *testing.T) {
	r := &fakeRunner{answers: map[string]string{
		"docker compose": "abc123\n", "docker inspect --format {{index .Config.Labels": "1.1.0\n",
	}}
	d := newDocker(t, r)
	if v, err := d.Current(context.Background()); err != nil || v != "1.1.0" {
		t.Fatalf("Current = %q, %v", v, err)
	}
	r.answers["docker inspect --format {{index .Config.Labels"] = "<no value>"
	if v, _ := d.Current(context.Background()); v != "0.0.0-dev" {
		t.Fatalf("an unlabelled image is a development build, got %q", v)
	}
}

func TestDockerPullsByDigestAndSwapsThroughCompose(t *testing.T) {
	r := &fakeRunner{answers: map[string]string{
		"docker compose": "abc123", "docker inspect --format {{.Image}}": "sha256:previd",
		"docker inspect --format {{index .Config.Labels": "1.1.0",
	}}
	d := newDocker(t, r)
	f := newFixture(t)
	raw, _ := f.manifest(t, "1.2.0")
	var m release.ReleaseManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	ref, err := d.Stage(context.Background(), m)
	if err != nil || !r.ranLine("docker pull ghcr.io/example/retune-server@sha256:") {
		t.Fatalf("Stage = %q, %v; ran %v", ref, err, r.ran)
	}
	previous, err := d.Swap(context.Background(), ref)
	if err != nil || previous != "retune-server-rollback:1.1.0" {
		t.Fatalf("Swap = %q, %v", previous, err)
	}
	if !r.ranLine("docker tag sha256:previd retune-server-rollback:1.1.0") {
		t.Fatalf("the running image should be tagged to roll back to: %v", r.ran)
	}
	if !r.ranLine("docker compose --project-directory " + d.ProjectDir + " up -d --no-deps --no-build server") {
		t.Fatalf("only the server should be recreated: %v", r.ran)
	}
	env, _ := os.ReadFile(filepath.Join(d.ProjectDir, ".env"))
	want := "PUBLIC_URL=https://mdm.example.com\nRETUNE_IMAGE=" + ref + "\nPOSTGRES_PASSWORD=pw\n"
	if string(env) != want {
		t.Fatalf(".env = %q, want %q", env, want)
	}
	if err := d.Restore(context.Background(), previous); err != nil {
		t.Fatal(err)
	}
	env, _ = os.ReadFile(filepath.Join(d.ProjectDir, ".env"))
	if !strings.Contains(string(env), "RETUNE_IMAGE=retune-server-rollback:1.1.0\n") {
		t.Fatalf("Restore should pin the previous image: %q", env)
	}
}

// After the first update .env pins a digest. Rolling back goes to that digest
// rather than the local rollback tag, which an image prune would delete.
func TestDockerRollsBackToThePinnedDigest(t *testing.T) {
	r := &fakeRunner{answers: map[string]string{
		"docker compose": "abc123", "docker inspect --format {{.Image}}": "sha256:previd",
		"docker inspect --format {{index .Config.Labels": "1.1.0",
	}}
	d := newDocker(t, r)
	pinned := "ghcr.io/example/retune-server@sha256:1111111111111111111111111111111111111111111111111111111111111111"
	if err := os.WriteFile(filepath.Join(d.ProjectDir, ".env"), []byte("RETUNE_IMAGE="+pinned+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous, err := d.Swap(context.Background(), "ghcr.io/example/retune-server@sha256:2222222222222222222222222222222222222222222222222222222222222222")
	if err != nil || previous != pinned {
		t.Fatalf("Swap = %q, %v; want the pinned digest %q", previous, err, pinned)
	}
	if !r.ranLine("docker tag sha256:previd retune-server-rollback:1.1.0") {
		t.Fatalf("the running image should still be tagged: %v", r.ran)
	}
	if err := d.Restore(context.Background(), previous); err != nil {
		t.Fatal(err)
	}
	env, _ := os.ReadFile(filepath.Join(d.ProjectDir, ".env"))
	if string(env) != "RETUNE_IMAGE="+pinned+"\n" {
		t.Fatalf("Restore should pin the previous digest again: %q", env)
	}
}

func TestDockerBacksUpThroughTheDatabaseContainerAndPrunes(t *testing.T) {
	r := &fakeRunner{answers: map[string]string{"docker compose": "PGDMP dump bytes"}}
	d := newDocker(t, r)
	for i, name := range []string{"one", "two", "three"} {
		path, err := d.Backup(context.Background(), name)
		if err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(path); string(b) != "PGDMP dump bytes" {
			t.Fatalf("dump = %q", b)
		}
		// Make each newer than the last for pruning.
		stamp := time.Now().Add(time.Duration(i) * time.Minute)
		_ = os.Chtimes(path, stamp, stamp)
	}
	if !r.ranLine("docker compose --project-directory " + d.ProjectDir + " exec -T db pg_dump -U retune -Fc retune") {
		t.Fatalf("pg_dump should run in the database container: %v", r.ran)
	}
	entries, _ := os.ReadDir(d.BackupDir)
	if len(entries) != 2 {
		t.Fatalf("keep 2 dumps, have %d", len(entries))
	}
	if _, err := os.Stat(filepath.Join(d.BackupDir, "one.dump")); !os.IsNotExist(err) {
		t.Fatal("the oldest dump should have been pruned")
	}
}

func TestDockerBackupThatWritesNothingFails(t *testing.T) {
	r := &fakeRunner{answers: map[string]string{"docker compose": ""}}
	d := newDocker(t, r)
	if _, err := d.Backup(context.Background(), "empty"); err == nil {
		t.Fatal("an empty dump is not a backup")
	}
	if entries, _ := os.ReadDir(d.BackupDir); len(entries) != 0 {
		t.Fatal("the empty file should be removed")
	}
}

func TestDockerWaitsForTheHealthCheck(t *testing.T) {
	r := &fakeRunner{answers: map[string]string{"docker compose": "abc", "docker inspect --format {{if": "healthy"}}
	if err := newDocker(t, r).WaitHealthy(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.answers["docker inspect --format {{if"] = "unhealthy"
	if err := newDocker(t, r).WaitHealthy(context.Background()); err == nil || !strings.Contains(err.Error(), "unhealthy") {
		t.Fatalf("WaitHealthy = %v", err)
	}
	r.answers["docker inspect --format {{if"] = "starting"
	if err := newDocker(t, r).WaitHealthy(context.Background()); err == nil || !strings.Contains(err.Error(), "not healthy after") {
		t.Fatalf("WaitHealthy = %v, want a timeout", err)
	}
}

func TestBinaryChecksTheStagedHash(t *testing.T) {
	f := newFixture(t)
	raw, _ := f.manifest(t, "1.2.0")
	var m release.ReleaseManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	staged := filepath.Join(dir, "staged")
	b := &Binary{StagedPath: staged, GOARCH: "amd64"}
	if err := os.WriteFile(staged, []byte("something else"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Stage(context.Background(), m); err == nil || !strings.Contains(err.Error(), "not the manifest's") {
		t.Fatalf("Stage = %v, want a hash mismatch", err)
	}
	if err := os.WriteFile(staged, f.server, 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := b.Stage(context.Background(), m); err != nil || got != staged {
		t.Fatalf("Stage = %q, %v", got, err)
	}
	b.GOARCH = "arm64"
	if _, err := b.Stage(context.Background(), m); err == nil {
		t.Fatal("no arm64 server in the release")
	}
}

func TestBinarySwapsKeepsThePreviousAndRestores(t *testing.T) {
	dir := t.TempDir()
	installed := filepath.Join(dir, "retune-server")
	staged := filepath.Join(dir, "staged")
	_ = os.WriteFile(installed, []byte("old"), 0o755)
	_ = os.WriteFile(staged, []byte("new"), 0o644)
	r := &fakeRunner{}
	b := &Binary{Run: r, BinaryPath: installed, Unit: "retune-server"}
	previous, err := b.Swap(context.Background(), staged)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(installed); string(got) != "new" {
		t.Fatalf("installed = %q", got)
	}
	if got, _ := os.ReadFile(previous); string(got) != "old" {
		t.Fatalf("previous = %q", got)
	}
	if !r.ranLine("systemctl restart retune-server") {
		t.Fatalf("the unit should be restarted: %v", r.ran)
	}
	if err := b.Restore(context.Background(), previous); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(installed); string(got) != "old" {
		t.Fatalf("after Restore, installed = %q", got)
	}
}

func TestBinaryWaitsForReadyz(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	b := &Binary{ReadyURL: srv.URL, HealthTimeout: 5 * time.Second, Poll: time.Millisecond, HTTP: srv.Client()}
	if err := b.WaitHealthy(context.Background()); err != nil {
		t.Fatal(err)
	}
	b.HealthTimeout = 10 * time.Millisecond
	b.ReadyURL = srv.URL + "/never"
	calls.Store(-1000)
	if err := b.WaitHealthy(context.Background()); err == nil {
		t.Fatal("a server that never answers 200 is not ready")
	}
}

// The database password reaches pg_dump through its environment, never its
// command line.
func TestBinaryBackupKeepsThePasswordOffTheCommandLine(t *testing.T) {
	r := &fakeRunner{}
	b := &Binary{Run: r, DatabaseURL: "postgres://retune:s3cret@db.example.com:5433/retune?sslmode=require", BackupDir: t.TempDir()}
	if _, err := b.Backup(context.Background(), "x"); err != nil {
		t.Fatal(err)
	}
	c := r.ran[0]
	if strings.Contains(c.String(), "s3cret") {
		t.Fatalf("the password is on the command line: %s", c)
	}
	env := strings.Join(c.Env, " ")
	for _, want := range []string{"PGPASSWORD=s3cret", "PGHOST=db.example.com", "PGPORT=5433", "PGUSER=retune", "PGDATABASE=retune", "PGSSLMODE=require"} {
		if !strings.Contains(env, want) {
			t.Errorf("env %q lacks %s", env, want)
		}
	}
}
