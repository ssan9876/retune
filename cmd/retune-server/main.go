// Command retune-server runs the Retune management server.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"retune/internal/config"
	"retune/internal/pki"
	"retune/internal/server/app"
	"retune/internal/server/ca"
	"retune/internal/server/enroll"
	"retune/internal/server/store"
)

const usage = `usage: retune-server <command>

commands:
  serve                  run the server
  migrate                apply database migrations
  token create [flags]   create an enrollment token (--label, --max-uses, --expires-in)
  ca fingerprint         print the internal CA fingerprint for agent pinning
  device list            list enrolled devices
  device show <id>       show one device with its inventory and recent commands
  device retire <id>     stop accepting check-ins from a device
  device unenroll <id>   tell the agent to delete its identity and state
  command queue [flags]  queue a command (--device, --type, --script, --script-file, --timeout, --delay, --message, --ttl)
  command show <id>      show a command and its result`

func main() {
	if err := run(context.Background(), os.Args[1:], os.Getenv, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, getenv func(string) string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	switch args[0] {
	case "serve":
		return serve(ctx, getenv)
	case "migrate":
		url := getenv("DATABASE_URL")
		if url == "" {
			return errors.New("DATABASE_URL is required")
		}
		return store.Migrate(url)
	case "token":
		return tokenCmd(ctx, args[1:], getenv, out)
	case "ca":
		return caCmd(ctx, args[1:], getenv, out)
	case "device":
		return deviceCmd(ctx, args[1:], getenv, out)
	case "command":
		return commandCmd(ctx, args[1:], getenv, out)
	default:
		return fmt.Errorf("unknown command %q\n%s", args[0], usage)
	}
}

// openStore connects to the database named by DATABASE_URL.
func openStore(ctx context.Context, getenv func(string) string) (*store.Store, error) {
	url := getenv("DATABASE_URL")
	if url == "" {
		return nil, errors.New("DATABASE_URL is required")
	}
	return store.Open(ctx, url)
}

func serve(ctx context.Context, getenv func(string) string) error {
	cfg, err := config.LoadServer(getenv)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	a, err := app.New(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer a.Close()

	srv := &http.Server{
		Addr:              cfg.AgentListen,
		Handler:           a.Handler,
		TLSConfig:         a.TLSConfig,
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServeTLS("", "") }()
	log.Info("agent API listening", "addr", cfg.AgentListen, "public_url", cfg.PublicURL,
		"ca_fingerprint", pki.Fingerprint(a.CA.Cert().Raw))

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

func tokenCmd(ctx context.Context, args []string, getenv func(string) string, out io.Writer) error {
	if len(args) == 0 || args[0] != "create" {
		return errors.New("usage: retune-server token create [--label L] [--max-uses N] [--expires-in 168h]")
	}
	fs := flag.NewFlagSet("token create", flag.ContinueOnError)
	label := fs.String("label", "", "label shown in the console")
	maxUses := fs.Int("max-uses", 0, "maximum enrollments (0 = unlimited)")
	expiresIn := fs.Duration("expires-in", 0, "lifetime, e.g. 168h (0 = never)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *maxUses < 0 || *expiresIn < 0 {
		return errors.New("--max-uses and --expires-in must not be negative")
	}
	st, err := openStore(ctx, getenv)
	if err != nil {
		return err
	}
	defer st.Close()

	opts := enroll.TokenOptions{Label: *label, CreatedBy: "cli"}
	if *maxUses > 0 {
		opts.MaxUses = maxUses
	}
	if *expiresIn > 0 {
		exp := time.Now().Add(*expiresIn)
		opts.ExpiresAt = &exp
	}
	svc := &enroll.Service{Store: st, Now: time.Now}
	plain, tok, err := svc.CreateToken(ctx, opts)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Token ID: %s\nToken:    %s\n(The token is shown only once.)\n", tok.ID, plain)
	return nil
}

func caCmd(ctx context.Context, args []string, getenv func(string) string, out io.Writer) error {
	if len(args) != 1 || args[0] != "fingerprint" {
		return errors.New("usage: retune-server ca fingerprint")
	}
	dir := getenv("DATA_DIR")
	if dir == "" {
		dir = "data"
	}
	authority, err := ca.LoadOrCreate(ctx, ca.FileKeyStore{Dir: filepath.Join(dir, "ca")}, time.Now())
	if err != nil {
		return err
	}
	fmt.Fprintln(out, pki.Fingerprint(authority.Cert().Raw))
	return nil
}
