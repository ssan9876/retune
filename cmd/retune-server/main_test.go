package main

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

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

	t.Run("ca fingerprint is stable", func(t *testing.T) {
		e := env(map[string]string{"DATA_DIR": t.TempDir()})
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
