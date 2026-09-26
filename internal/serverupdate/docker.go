package serverupdate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"retune/internal/release"
	"retune/internal/version"
)

// VersionLabel is the image label the server's version is read from.
const VersionLabel = "org.opencontainers.image.version"

// ImageVar is the .env variable the Compose file takes the server image from.
const ImageVar = "RETUNE_IMAGE"

// Docker updates a server run by Docker Compose. It pins the new image by
// digest in the project's .env and has Compose recreate the server container,
// so the project stays the source of truth: `docker compose up -d` afterwards
// keeps the updated server rather than reverting it.
type Docker struct {
	Run Runner
	// ProjectDir holds the Compose file and its .env.
	ProjectDir string
	// Service and DBService are the server's and PostgreSQL's service names.
	Service   string
	DBService string
	// DBUser and DBName are who pg_dump connects as, and to what.
	DBUser string
	DBName string
	// BackupDir receives the database dumps; the newest Keep are kept.
	BackupDir string
	Keep      int
	// HealthTimeout bounds the wait for the new server to report healthy.
	HealthTimeout time.Duration
	Poll          time.Duration
}

func (d *Docker) compose(args ...string) Cmd {
	return Cmd{Name: "docker", Args: append([]string{"compose", "--project-directory", d.ProjectDir}, args...)}
}

func (d *Docker) run(ctx context.Context, c Cmd) (string, error) {
	out, err := d.Run.Run(ctx, c)
	return strings.TrimSpace(string(out)), err
}

// container is the server's running container.
func (d *Docker) container(ctx context.Context) (string, error) {
	id, err := d.run(ctx, d.compose("ps", "-q", d.Service))
	if err != nil {
		return "", err
	}
	if id == "" {
		return "", fmt.Errorf("the %s service has no container", d.Service)
	}
	return strings.Fields(id)[0], nil
}

// Current reads the running server's version from its image label.
func (d *Docker) Current(ctx context.Context) (string, error) {
	id, err := d.container(ctx)
	if err != nil {
		return "", err
	}
	v, err := d.run(ctx, Cmd{Name: "docker", Args: []string{"inspect", "--format",
		`{{index .Config.Labels "` + VersionLabel + `"}}`, id}})
	if err != nil {
		return "", err
	}
	if v == "" || v == "<no value>" {
		return version.DevVersion, nil
	}
	return v, nil
}

// Backup dumps the database from inside its own container, so the updater
// needs no PostgreSQL client of its own, then keeps only the newest dumps.
func (d *Docker) Backup(ctx context.Context, name string) (string, error) {
	if err := os.MkdirAll(d.BackupDir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(d.BackupDir, name+".dump")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	c := d.compose("exec", "-T", d.DBService, "pg_dump", "-U", d.DBUser, "-Fc", d.DBName)
	c.Stdout = f
	_, runErr := d.Run.Run(ctx, c)
	closeErr := f.Close()
	if runErr == nil {
		runErr = closeErr
	}
	if runErr == nil {
		if fi, err := os.Stat(path); err != nil || fi.Size() == 0 {
			runErr = errors.New("pg_dump wrote nothing")
		}
	}
	if runErr != nil {
		os.Remove(path)
		return "", runErr
	}
	prune(d.BackupDir, d.Keep)
	return path, nil
}

// Stage pulls the release's server image by the digest its signed manifest
// names: never by tag, which whoever controls the registry could move.
func (d *Docker) Stage(ctx context.Context, m release.ReleaseManifest) (string, error) {
	img, ok := m.ServerImage()
	if !ok {
		return "", fmt.Errorf("release %s publishes no server image", m.Version)
	}
	ref := img.Image + "@" + img.Digest
	if _, err := d.run(ctx, Cmd{Name: "docker", Args: []string{"pull", ref}}); err != nil {
		return "", err
	}
	return ref, nil
}

// Swap tags the running image so it can be gone back to, pins the new one in
// .env and recreates the server container on it. The database and the
// updater are left alone.
func (d *Docker) Swap(ctx context.Context, ref string) (string, error) {
	id, err := d.container(ctx)
	if err != nil {
		return "", err
	}
	imageID, err := d.run(ctx, Cmd{Name: "docker", Args: []string{"inspect", "--format", "{{.Image}}", id}})
	if err != nil {
		return "", err
	}
	current, _ := d.Current(ctx)
	previous := "retune-server-rollback:" + safe(current)
	if _, err := d.run(ctx, Cmd{Name: "docker", Args: []string{"tag", imageID, previous}}); err != nil {
		return "", err
	}
	if err := setEnv(filepath.Join(d.ProjectDir, ".env"), ImageVar, ref); err != nil {
		return "", err
	}
	if _, err := d.run(ctx, d.compose("up", "-d", "--no-deps", "--no-build", d.Service)); err != nil {
		return previous, err
	}
	return previous, nil
}

// WaitHealthy waits for the server container's health check to pass.
func (d *Docker) WaitHealthy(ctx context.Context) error {
	timeout, poll := d.HealthTimeout, d.Poll
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	if poll == 0 {
		poll = 3 * time.Second
	}
	deadline := time.Now().Add(timeout)
	last := ""
	for {
		if id, err := d.container(ctx); err == nil {
			status, err := d.run(ctx, Cmd{Name: "docker", Args: []string{"inspect", "--format",
				"{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}", id}})
			if err == nil {
				last = status
				switch status {
				case "healthy":
					return nil
				case "unhealthy", "exited", "dead":
					return fmt.Errorf("the new server is %s", status)
				}
			}
		}
		if time.Now().After(deadline) {
			if last == "running" {
				return fmt.Errorf("the %s service has no health check, so the updater cannot tell whether the new server is ready; add the one in deploy/docker/docker-compose.yml", d.Service)
			}
			return fmt.Errorf("the new server was not healthy after %s (last %q)", timeout, last)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
}

// Restore pins the tagged previous image and recreates the server on it.
func (d *Docker) Restore(ctx context.Context, previous string) error {
	if err := setEnv(filepath.Join(d.ProjectDir, ".env"), ImageVar, previous); err != nil {
		return err
	}
	_, err := d.run(ctx, d.compose("up", "-d", "--no-deps", "--no-build", d.Service))
	return err
}

// setEnv sets one variable in a .env file, keeping every other line as it
// was, and the file's permissions.
func setEnv(path, key, value string) error {
	mode := os.FileMode(0o600)
	var lines []string
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if fi, err := os.Stat(path); err == nil {
			mode = fi.Mode().Perm()
		}
		lines = strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
		if n := len(lines); n > 0 && lines[n-1] == "" {
			lines = lines[:n-1]
		}
	case !errors.Is(err, os.ErrNotExist):
		return err
	}
	line := key + "=" + value
	found := false
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), key+"=") {
			lines[i], found = line, true
		}
	}
	if !found {
		lines = append(lines, line)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(lines, "\n")+"\n"), mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// prune keeps the newest keep dumps in dir and deletes the rest.
func prune(dir string, keep int) {
	if keep <= 0 {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type dump struct {
		path string
		mod  time.Time
	}
	var dumps []dump
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".dump") {
			continue
		}
		if fi, err := e.Info(); err == nil {
			dumps = append(dumps, dump{filepath.Join(dir, e.Name()), fi.ModTime()})
		}
	}
	sort.Slice(dumps, func(i, j int) bool { return dumps[i].mod.After(dumps[j].mod) })
	for _, old := range dumps[min(keep, len(dumps)):] {
		os.Remove(old.path)
	}
}
