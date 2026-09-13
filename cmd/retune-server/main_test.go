package main

import (
	"bytes"
	"context"
	"encoding/pem"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"retune/internal/pki"
	"retune/internal/server/ca"
	"retune/internal/server/store/storetest"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestRun(t *testing.T) {
	ctx := context.Background()

	t.Run("unknown command", func(t *testing.T) {
		if err := run(ctx, []string{"bogus"}, env(nil), io.Discard); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("ca commands need an existing CA", func(t *testing.T) {
		e := env(map[string]string{"DATA_DIR": t.TempDir()})
		err := run(ctx, []string{"ca", "fingerprint"}, e, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "no certificate authority") {
			t.Fatalf("want a missing-CA error, got %v", err)
		}
	})

	t.Run("ca fingerprint is stable and ca cert matches it", func(t *testing.T) {
		dir := t.TempDir()
		e := env(map[string]string{"DATA_DIR": dir})
		// The server creates the CA; the ca commands only read it.
		if _, err := ca.LoadOrCreate(ctx, ca.FileKeyStore{Dir: filepath.Join(dir, "ca")}, time.Now()); err != nil {
			t.Fatal(err)
		}
		var a, b bytes.Buffer
		if err := run(ctx, []string{"ca", "fingerprint"}, e, &a); err != nil {
			t.Fatal(err)
		}
		if err := run(ctx, []string{"ca", "fingerprint"}, e, &b); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(a.String(), "sha256:") || a.String() != b.String() {
			t.Fatalf("fingerprints %q vs %q", a.String(), b.String())
		}

		var certOut bytes.Buffer
		if err := run(ctx, []string{"ca", "cert"}, e, &certOut); err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(certOut.Bytes())
		if block == nil || block.Type != "CERTIFICATE" {
			t.Fatalf("ca cert did not print a PEM certificate: %q", certOut.String())
		}
		if got := pki.Fingerprint(block.Bytes); got != strings.TrimSpace(a.String()) {
			t.Fatalf("ca cert fingerprint %q != ca fingerprint %q", got, a.String())
		}
	})

	t.Run("migrate then token create", func(t *testing.T) {
		e := env(map[string]string{"DATABASE_URL": storetest.DatabaseURL(t)})
		if err := run(ctx, []string{"migrate"}, e, io.Discard); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := run(ctx, []string{"token", "create", "--label", "lab", "--max-uses", "5", "--expires-in", "24h"}, e, &out); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "Token:    rt_") {
			t.Fatalf("output = %q", out.String())
		}
		if err := run(ctx, []string{"token", "create", "--max-uses", "-1"}, e, io.Discard); err == nil {
			t.Fatal("negative max uses must fail")
		}
	})
}
