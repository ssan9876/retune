package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"retune/internal/config"
	"retune/internal/server/auth"
	"retune/internal/server/secrets"
	"retune/internal/server/store"
)

const adminUsage = `usage: retune-server admin list | create | password | totp | disable | enable [flags]

flags:
  --email E       the account to act on (required except for list)
  --password P    new password; generated and printed when omitted
  --role R        admin (default) or read_only, for create
  --enable        turn TOTP on, for totp
  --disable       turn TOTP off, for totp`

func authService(st *store.Store) *auth.Service {
	return &auth.Service{Store: st, Now: time.Now, SessionTTL: 12 * time.Hour, Issuer: "Retune"}
}

// cliSecretKey loads the server's secret key the way the server does, but
// never creates one: a key the server doesn't have would seal secrets it
// can't read.
func cliSecretKey(getenv func(string) string) (*secrets.Key, error) {
	source, err := config.Value(getenv, "CA_KEY_SOURCE")
	if err != nil {
		return nil, err
	}
	if source == "env" {
		return secrets.FromHex(getenv("SECRET_KEY"))
	}
	dir, err := config.DataDir(getenv)
	if err != nil {
		return nil, err
	}
	key, err := secrets.LoadFile(dir)
	if errors.Is(err, secrets.ErrNoKey) {
		return nil, fmt.Errorf("%w; run this where the server's DATA_DIR is, or set DATA_DIR", err)
	}
	return key, err
}

// bootstrapAdminCmd creates the first account.
func bootstrapAdminCmd(ctx context.Context, args []string, getenv func(string) string, out io.Writer) error {
	fs := flag.NewFlagSet("bootstrap-admin", flag.ContinueOnError)
	email := fs.String("email", "", "email address to sign in with")
	password := fs.String("password", "", "password; generated when omitted")
	role := fs.String("role", store.RoleAdmin, "admin or read_only")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *email == "" {
		return errors.New("--email is required")
	}
	st, err := openStore(ctx, getenv)
	if err != nil {
		return err
	}
	defer st.Close()

	svc := authService(st)
	has, err := svc.HasAdmins(ctx)
	if err != nil {
		return err
	}
	if has {
		return errors.New("an admin already exists; use `retune-server admin create` instead")
	}
	return createAdmin(ctx, svc, *email, *password, *role, out)
}

func adminCmd(ctx context.Context, args []string, getenv func(string) string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(adminUsage)
	}
	fs := flag.NewFlagSet("admin "+args[0], flag.ContinueOnError)
	email := fs.String("email", "", "the account to act on")
	password := fs.String("password", "", "new password; generated when omitted")
	role := fs.String("role", store.RoleAdmin, "admin or read_only")
	enable := fs.Bool("enable", false, "turn TOTP on")
	disable := fs.Bool("disable", false, "turn TOTP off")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if args[0] != "list" && *email == "" {
		return errors.New("--email is required")
	}

	st, err := openStore(ctx, getenv)
	if err != nil {
		return err
	}
	defer st.Close()
	svc := authService(st)

	switch args[0] {
	case "list":
		admins, err := svc.List(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "EMAIL\tROLE\tTOTP\tSTATUS\tLAST LOGIN")
		for _, a := range admins {
			status := "enabled"
			if a.DisabledAt != nil {
				status = "disabled"
			}
			totp := "off"
			if a.TOTPSecret != "" {
				totp = "on"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", a.Email, a.Role, totp, status, timeOrNever(a.LastLoginAt))
		}
		return tw.Flush()
	case "create":
		return createAdmin(ctx, svc, *email, *password, *role, out)
	}

	admin, err := st.Q().GetAdminByEmail(ctx, store.DefaultTenantID, *email)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("no admin with email %s", *email)
	}
	if err != nil {
		return err
	}

	switch args[0] {
	case "password":
		pw := *password
		if pw == "" {
			if pw, err = auth.GeneratePassword(); err != nil {
				return err
			}
			fmt.Fprintf(out, "Password: %s\n", pw)
		}
		if err := svc.SetPassword(ctx, admin.ID, pw, "cli"); err != nil {
			return err
		}
		fmt.Fprintf(out, "Password changed for %s; existing sessions were signed out.\n", admin.Email)
		return nil
	case "totp":
		switch {
		case *enable == *disable:
			return errors.New("pass exactly one of --enable or --disable")
		case *enable:
			if svc.Key, err = cliSecretKey(getenv); err != nil {
				return err
			}
			secret, url, err := svc.EnableTOTP(ctx, admin.ID, "cli")
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "Secret: %s\nURL:    %s\n", secret, url)
			return nil
		default:
			if err := svc.DisableTOTP(ctx, admin.ID, "cli"); err != nil {
				return err
			}
			fmt.Fprintf(out, "TOTP disabled for %s.\n", admin.Email)
			return nil
		}
	case "disable", "enable":
		off := args[0] == "disable"
		if err := svc.SetDisabled(ctx, admin.ID, off, "cli"); err != nil {
			return err
		}
		fmt.Fprintf(out, "Admin %s %sd.\n", admin.Email, args[0])
		return nil
	default:
		return errors.New(adminUsage)
	}
}

func createAdmin(ctx context.Context, svc *auth.Service, email, password, role string, out io.Writer) error {
	generated := password == ""
	if generated {
		var err error
		if password, err = auth.GeneratePassword(); err != nil {
			return err
		}
	}
	admin, err := svc.CreateAdmin(ctx, auth.CreateAdminOptions{
		Email: email, Password: password, Role: role, Actor: "cli",
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Created %s (%s).\n", admin.Email, admin.Role)
	if generated {
		fmt.Fprintf(out, "Password: %s\n(The password is shown only once.)\n", password)
	}
	return nil
}
