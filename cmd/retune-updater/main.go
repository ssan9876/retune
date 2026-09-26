// Command retune-updater updates a Retune server run by Docker Compose, when
// an administrator asks for it from the console.
//
// It is the only part of the stack with the Docker socket, and it trusts the
// server with nothing but the choice of version: it fetches that release's
// signed manifest from the release feed itself, verifies it against
// AGENT_RELEASE_KEYS, and installs the server image by the digest the manifest
// names. Before swapping it dumps the database, and if the new server does not
// report healthy it puts the previous image back.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"retune/internal/config"
	"retune/internal/release"
	"retune/internal/server/releasefeed"
	"retune/internal/serverupdate"
	"retune/internal/version"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println(version.Version)
		return
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func run() error {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	token := os.Getenv("UPDATER_TOKEN")
	if len(token) < 16 {
		return errors.New("UPDATER_TOKEN must be set, to at least 16 characters, and match the server's")
	}
	keys, err := release.ParseTrustList(os.Getenv("AGENT_RELEASE_KEYS"))
	if err != nil {
		return fmt.Errorf("AGENT_RELEASE_KEYS: %w", err)
	}
	if len(keys) == 0 {
		return errors.New("AGENT_RELEASE_KEYS must be set: no release can be verified without them")
	}
	keep, err := strconv.Atoi(env("UPDATER_BACKUPS_KEEP", "5"))
	if err != nil || keep < 1 {
		return errors.New("UPDATER_BACKUPS_KEEP must be a positive integer")
	}
	stateDir := env("UPDATER_STATE_DIR", "/var/lib/retune-updater")
	svc := &serverupdate.Service{
		Token:  token,
		States: serverupdate.FileStore{Path: stateDir + "/state.json"},
		Updater: &serverupdate.Updater{
			Env: &serverupdate.Docker{
				Run:        serverupdate.ExecRunner{},
				ProjectDir: env("UPDATER_PROJECT_DIR", "/project"),
				Service:    env("UPDATER_SERVER_SERVICE", "server"),
				DBService:  env("UPDATER_DB_SERVICE", "db"),
				DBUser:     env("POSTGRES_USER", "retune"),
				DBName:     env("POSTGRES_DB", "retune"),
				BackupDir:  env("UPDATER_BACKUP_DIR", "/backups"),
				Keep:       keep,
			},
			Fetch: serverupdate.FeedFetcher{Source: releasefeed.GitHub{URL: env("RELEASE_FEED_URL", config.DefaultReleaseFeedURL)}},
			Keys:  keys,
			Now:   time.Now,
			Log:   log,
		},
	}
	svc.Updater.Save = svc.States.Save
	if err := svc.Recover(); err != nil {
		return err
	}

	socket := env("UPDATER_SOCKET", "/run/retune-updater/updater.sock")
	l, err := serverupdate.ListenUnix(socket)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	srv := &http.Server{Handler: svc.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	log.Info("retune-updater listening", "socket", socket, "version", version.Version, "keys", len(keys))
	if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
