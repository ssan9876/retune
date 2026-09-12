// Command retune-agent is the Retune endpoint agent.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"retune/internal/agent/checkin"
	"retune/internal/agent/enrollment"
	"retune/internal/agent/executor"
	"retune/internal/agent/facts"
	"retune/internal/agent/identity"
	"retune/internal/agent/inventory"
	"retune/internal/agent/session"
	"retune/internal/agent/state"
)

const usage = `usage: retune-agent <command>

commands:
  enroll --server URL --token T [--pin sha256:...] [--data-dir D]
  run [--data-dir D] [--once]`

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out io.Writer) error {
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
		idStore := identity.Store{Dir: *dataDir, Keys: identity.DefaultKeys()}
		id, err := idStore.Load()
		if err != nil {
			return err
		}
		st, err := state.Open(filepath.Join(*dataDir, "state.db"))
		if err != nil {
			return err
		}
		defer st.Close()

		log := slog.New(slog.NewTextHandler(os.Stderr, nil))
		sess, err := session.New(session.Config{
			Identity:  id,
			IDStore:   idStore,
			State:     st,
			Collector: inventory.NewCollector(),
			Executor: &executor.Executor{
				Runner:    executor.DefaultRunner(filepath.Join(*dataDir, "scripts")),
				Restarter: executor.DefaultRestarter(),
				Now:       time.Now,
			},
			Log: log,
		})
		if err != nil {
			return err
		}

		ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer stop()
		sess.Start(ctx)

		loop := &checkin.Loop{Client: sess, Facts: facts.Checkin, Log: log, Rand: rand.Float64}
		if *once {
			wait, err := loop.RunOnce(ctx)
			switch {
			case errors.Is(err, checkin.ErrUnenrolled):
				fmt.Fprintln(out, "This device was unenrolled; local identity and state removed.")
				return nil
			case err != nil:
				return err
			}
			sess.Wait()
			if err := sess.FlushResults(ctx); err != nil {
				log.Warn("some results are still queued", "error", err)
			}
			fmt.Fprintf(out, "Check-in OK; next in %s\n", wait.Round(time.Second))
			return nil
		}
		if errors.Is(loop.Run(ctx), checkin.ErrUnenrolled) {
			fmt.Fprintln(out, "This device was unenrolled; local identity and state removed.")
		}
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
