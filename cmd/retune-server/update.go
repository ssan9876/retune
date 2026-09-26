package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"retune/internal/config"
	"retune/internal/serverupdate"
	"retune/internal/version"
)

// updateApplyCmd applies an update the server staged, for a binary install
// run by systemd. The retune-server-update.path unit starts it, as root, when
// the server writes the request file; it verifies the release itself against
// AGENT_RELEASE_KEYS, backs up the database, swaps the binary, restarts the
// server and puts the old binary back if the new one does not become ready.
func updateApplyCmd(ctx context.Context, args []string, getenv func(string) string, out io.Writer) error {
	fs := flag.NewFlagSet("update-apply", flag.ContinueOnError)
	binary := fs.String("binary", "", "the installed server binary (default: this one)")
	unit := fs.String("unit", "retune-server", "the systemd unit that runs the server")
	backups := fs.String("backup-dir", "", "where database dumps go (default: DATA_DIR/backups)")
	keep := fs.Int("keep", 5, "how many dumps to keep")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.LoadServer(getenv)
	if err != nil {
		return err
	}
	if len(cfg.AgentReleaseKeys) == 0 {
		return errors.New("AGENT_RELEASE_KEYS must be set: no release can be verified without them")
	}
	path := *binary
	if path == "" {
		if path, err = os.Executable(); err != nil {
			return err
		}
		if path, err = filepath.EvalSymlinks(path); err != nil {
			return err
		}
	}
	dir := *backups
	if dir == "" {
		dir = filepath.Join(cfg.DataDir, "backups")
	}
	env := &serverupdate.Binary{
		Run: serverupdate.ExecRunner{}, BinaryPath: path, Unit: *unit, ReadyURL: healthcheckURL(cfg),
		DatabaseURL: cfg.DatabaseURL, BackupDir: dir, Keep: *keep,
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	st, ran, err := serverupdate.ApplyStaged(ctx, cfg.ServerUpdate.Dir, env, cfg.AgentReleaseKeys, log)
	if err != nil {
		return err
	}
	if !ran {
		fmt.Fprintln(out, "no update is waiting")
		return nil
	}
	fmt.Fprintf(out, "update to %s: %s %s\n", st.Version, st.Phase, st.Error)
	if st.Phase != serverupdate.PhaseHealthy {
		return fmt.Errorf("the update to %s did not succeed: %s", st.Version, st.Phase)
	}
	return nil
}

// versionCmd prints the version this binary was built as.
func versionCmd(out io.Writer) error {
	fmt.Fprintln(out, version.Version)
	return nil
}
