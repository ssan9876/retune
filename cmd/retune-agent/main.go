// Command retune-agent is the Retune endpoint agent.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"retune/internal/agent/agentcfg"
	"retune/internal/agent/checkin"
	"retune/internal/agent/enrollment"
	"retune/internal/agent/facts"
	"retune/internal/agent/identity"
	"retune/internal/agent/logging"
	"retune/internal/agent/runner"
	"retune/internal/agent/selfupdate"
)

const usage = `usage: retune-agent <command>

commands:
  enroll --server URL --token T [--pin sha256:...] [--data-dir D]
  run [--data-dir D] [--once]
  configure --server URL --token T [--pin sha256:...] [--data-dir D]   (Windows)
  install [--data-dir D]                                              (Windows)
  uninstall                                                           (Windows)
  cleanup [--data-dir D]                                              (Windows)
  supervise-update [--data-dir D]                                     (Windows)`

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out io.Writer) error {
	// The service control manager starts us with the arguments recorded when
	// the service was installed, which is the only way a service learns
	// anything about where its state lives.
	if isWindowsService() {
		return runService(ctx, serviceDataDir(args))
	}
	if len(args) == 0 {
		return errors.New(usage)
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	dataDir := fs.String("data-dir", defaultDataDir(), "agent state directory")
	switch args[0] {
	case "enroll":
		server := fs.String("server", "", "server URL, e.g. https://mdm.example.com")
		token := fs.String("token", "", "enrollment token")
		pin := fs.String("pin", "", "server CA fingerprint (sha256:...) for self-signed servers")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *server == "" || *token == "" {
			return errors.New("--server and --token are required")
		}
		// Before the device key is written, not after: a hand-enrolled machine
		// gets the same locked-down directory the MSI path gets from
		// configure, and for the same reasons.
		if err := secureDataDir(*dataDir); err != nil {
			return err
		}
		id, err := enrollment.Enroll(ctx, enrollment.Options{
			ServerURL: *server, Token: *token, Pin: *pin, Facts: facts.Device(),
			Store: identity.Store{Dir: *dataDir, Keys: identity.DefaultKeys()},
		})
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Enrolled as device %s\n", id.DeviceID)
		return nil

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

	case "configure":
		server := fs.String("server", "", "server URL, e.g. https://mdm.example.com")
		token := fs.String("token", "", "enrollment token")
		pin := fs.String("pin", "", "server CA fingerprint (sha256:...) for self-signed servers")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *server == "" || *token == "" {
			return errors.New("--server and --token are required")
		}
		if err := agentcfg.Save(*dataDir, agentcfg.Config{
			ServerURL: *server, EnrollToken: *token, ServerCertFingerprint: *pin,
		}); err != nil {
			return err
		}
		// The directory holds the enrollment token and, shortly, the device
		// key, so it must not be readable by ordinary users.
		if err := secureDataDir(*dataDir); err != nil {
			return err
		}
		// The MSI installs the service itself, so this is the only place on
		// that path where the Event Log source gets registered.
		if err := registerEventLogSource(); err != nil {
			return err
		}
		fmt.Fprintf(out, "Wrote %s; the service will enroll on its next start.\n",
			filepath.Join(*dataDir, agentcfg.FileName))
		return nil

	case "cleanup":
		// Run by the installer on uninstall, before the executable is removed.
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if err := removeEventLogSource(); err != nil {
			return err
		}
		if err := os.RemoveAll(*dataDir); err != nil {
			return err
		}
		fmt.Fprintf(out, "Removed %s and the Event Log source.\n", *dataDir)
		return nil

	case "install":
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		// The service about to be created runs as LocalSystem out of this
		// directory, so it is locked down before it exists rather than
		// whenever somebody happens to run configure.
		if err := secureDataDir(*dataDir); err != nil {
			return err
		}
		if err := installService(exe, *dataDir); err != nil {
			return err
		}
		fmt.Fprintln(out, "Installed the Retune service.")
		return nil

	case "uninstall":
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if err := uninstallService(); err != nil {
			return err
		}
		fmt.Fprintln(out, "Removed the Retune service.")
		return nil

	case "supervise-update":
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		// Run from a copy of the outgoing build, detached, by the agent that
		// is about to be replaced. It is the known-good binary supervising its
		// own replacement.
		control, err := selfupdate.NewController(selfupdate.ServiceName)
		if err != nil {
			return err
		}
		defer control.Close()
		log, closeLog, err := logging.New(logging.Options{Dir: *dataDir, EventLog: true})
		if err != nil {
			return err
		}
		defer closeLog()
		return (&selfupdate.Supervisor{Dir: *dataDir, Control: control, Log: log}).Supervise(ctx)

	default:
		return fmt.Errorf("unknown command %q\n%s", args[0], usage)
	}
}

// serviceDataDir reads the state directory from the arguments the service
// control manager passes. A service installed by the MSI is created without
// them and uses the default.
func serviceDataDir(args []string) string {
	for i, a := range args {
		if a == "--data-dir" && i+1 < len(args) {
			return args[i+1]
		}
		if dir, found := strings.CutPrefix(a, "--data-dir="); found {
			return dir
		}
	}
	return defaultDataDir()
}

func defaultDataDir() string {
	if runtime.GOOS == "windows" {
		if pd := os.Getenv("ProgramData"); pd != "" {
			return filepath.Join(pd, "Retune")
		}
		return `C:\ProgramData\Retune`
	}
	return "/var/lib/retune"
}
