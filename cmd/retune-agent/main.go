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
	"syscall"

	"retune/internal/agent/agentcfg"
	"retune/internal/agent/checkin"
	"retune/internal/agent/enrollment"
	"retune/internal/agent/facts"
	"retune/internal/agent/identity"
	"retune/internal/agent/runner"
)

const usage = `usage: retune-agent <command>

commands:
  enroll --server URL --token T [--pin sha256:...] [--data-dir D]
  run [--data-dir D] [--once]
  configure --server URL --token T [--pin sha256:...] [--data-dir D]   (Windows)
  install [--data-dir D]                                              (Windows)
  uninstall                                                           (Windows)`

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out io.Writer) error {
	// The service control manager starts us with no arguments.
	if len(args) == 0 && isWindowsService() {
		return runService(ctx, defaultDataDir())
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
		fmt.Fprintf(out, "Wrote %s; the service will enroll on its next start.\n",
			filepath.Join(*dataDir, agentcfg.FileName))
		return nil

	case "install":
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		if err := installService(exe); err != nil {
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

	default:
		return fmt.Errorf("unknown command %q\n%s", args[0], usage)
	}
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
