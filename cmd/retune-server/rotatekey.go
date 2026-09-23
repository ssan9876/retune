package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"retune/internal/config"
	"retune/internal/server/rekey"
	"retune/internal/server/secrets"
	"retune/internal/server/store"
)

const rotateKeyUsage = `usage: retune-server rotate-secret-key [--dry-run] [--out FILE]

Re-seals every stored secret - authenticator secrets, BitLocker recovery keys,
local admin passwords, webhook secrets, Wi-Fi and VPN passphrases - under a
new server key, in one transaction. Stop every server first: it refuses to run
while one is connected to the database.

With the key in DATA_DIR (the default), the old secret.key is kept as
secret.key.old-<time> and the new one takes its place. With CA_KEY_SOURCE=env,
the new key is written to --out, for you to put in SECRET_KEY.

  --dry-run   check the current key opens everything, and change nothing
  --out FILE  where to write the new key, with CA_KEY_SOURCE=env`

// rotateKeyCmd retires the server's secret key for a new one.
func rotateKeyCmd(ctx context.Context, args []string, getenv func(string) string, out io.Writer) error {
	flags := flag.NewFlagSet("rotate-secret-key", flag.ContinueOnError)
	dryRun := flags.Bool("dry-run", false, "check, and change nothing")
	outFile := flags.String("out", "", "where to write the new key, with CA_KEY_SOURCE=env")
	flags.Usage = func() { fmt.Fprintln(out, rotateKeyUsage) }
	if err := flags.Parse(args); err != nil {
		return err
	}
	source, err := config.Value(getenv, "CA_KEY_SOURCE")
	if err != nil {
		return err
	}
	current, err := cliSecretKey(getenv)
	if err != nil {
		return err
	}
	next, nextHex, err := secrets.Generate()
	if err != nil {
		return err
	}
	st, err := openStore(ctx, getenv)
	if err != nil {
		return err
	}
	defer st.Close()

	if *dryRun {
		c, err := rekey.Rotate(ctx, st, current, next, true)
		if err != nil {
			return rotateError(err)
		}
		fmt.Fprintf(out, "The current key opens all %d stored secrets. Nothing was changed.\n", c.Total())
		return nil
	}

	// The new key is written before anything is re-sealed with it, so that
	// however this ends there is a key for what the database holds.
	var newPath, keyPath string
	if source == "env" {
		if *outFile == "" {
			return errors.New("with CA_KEY_SOURCE=env, --out names the file to write the new key to")
		}
		newPath = *outFile
	} else {
		dir, err := config.DataDir(getenv)
		if err != nil {
			return err
		}
		keyPath = filepath.Join(dir, secrets.FileName)
		newPath = keyPath + ".new"
	}
	if err := secrets.WriteNew(newPath, nextHex); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%s already exists: a rotation may have been interrupted. If the server can't open its secrets, that file holds the key they were re-sealed under; otherwise remove it and run this again", newPath)
		}
		return err
	}

	c, err := rekey.Rotate(ctx, st, current, next, false)
	if err != nil {
		// Nothing was committed: the old key is still the right one.
		_ = os.Remove(newPath)
		return rotateError(err)
	}
	fmt.Fprintf(out, "Re-sealed %d secrets: %d authenticator secrets, %d BitLocker keys, %d local admin passwords, %d webhook secrets, %d profile versions.\n",
		c.Total(), c.AuthenticatorSecrets, c.BitLockerKeys, c.AdminPasswords, c.ChannelSecrets, c.ProfileVersions)

	if source == "env" {
		fmt.Fprintf(out, "The new key is in %s. Set SECRET_KEY to its contents on every server before starting them, then delete the file.\n", newPath)
		return nil
	}
	oldPath := keyPath + ".old-" + time.Now().UTC().Format("20060102T150405Z")
	if err := os.Rename(keyPath, oldPath); err != nil {
		return fmt.Errorf("the secrets are re-sealed under the key in %s, but moving the old key aside failed: %w. Move %s to %s by hand before starting the server", newPath, err, newPath, keyPath)
	}
	if err := os.Rename(newPath, keyPath); err != nil {
		return fmt.Errorf("the secrets are re-sealed under the key in %s, but putting it in place failed: %w. Move it to %s by hand before starting the server", newPath, err, keyPath)
	}
	fmt.Fprintf(out, "The new key is in %s; the old one is %s. Copy the new key to every server and into your backups, then destroy the old one.\n", keyPath, oldPath)
	return nil
}

func rotateError(err error) error {
	if errors.Is(err, store.ErrServerRunning) {
		return errors.New("a Retune server is running against this database: stop every server, then run this again")
	}
	return fmt.Errorf("%w; nothing was changed", err)
}
