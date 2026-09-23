package opsign_test

import (
	"errors"
	"testing"
	"time"

	"retune/internal/opsign"
	"retune/internal/release"
)

func key(t *testing.T) release.PrivateKey {
	t.Helper()
	k, err := release.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestManifestsAreFixedText(t *testing.T) {
	// sha256("Write-Output hi"). Every signature ever made depends on these
	// bytes; changing them is a new manifest version, not an edit.
	if got, want := string(opsign.ScriptManifest("Write-Output hi", "")),
		"retune-script-manifest/v1\nbody=dddc449c81014eb646ce38a66057fbe6b61659fb14cc1e04701447afb6ab06b9\ndetection=\n"; got != want {
		t.Fatalf("script manifest = %q\nwant %q", got, want)
	}
	if string(opsign.ScriptManifest("a\r\nb\r\n", "")) != string(opsign.ScriptManifest("a\nb\n", "")) {
		t.Fatal("CRLF and LF must hash the same")
	}
	if string(opsign.ScriptManifest("a b", "")) == string(opsign.ScriptManifest("ab", "")) {
		t.Fatal("other whitespace must still count")
	}
	exp := time.Date(2026, 9, 23, 12, 0, 0, 0, time.FixedZone("x", 3600))
	want := "retune-command-manifest/v1\ntype=wipe\ndevice=0192aaaa-bbbb\nprotected=true\nexpires=2026-09-23T11:00:00Z\n"
	if got := string(opsign.WipeManifest("0192AAAA-bbbb", true, exp)); got != want {
		t.Fatalf("wipe manifest = %q\nwant %q", got, want)
	}
}

func TestScriptSignatures(t *testing.T) {
	k, other := key(t), key(t)
	trusted := []release.PublicKey{k.Public()}
	sig := opsign.Sign(k, opsign.ScriptManifest("Get-Date", "Test-Path C:\\x"))

	if err := opsign.Verify(trusted, opsign.ScriptManifest("Get-Date", "Test-Path C:\\x"), &sig); err != nil {
		t.Fatalf("valid: %v", err)
	}
	cases := map[string]struct {
		manifest []byte
		sig      *opsign.Signature
		trusted  []release.PublicKey
		want     error
	}{
		"tampered body":      {opsign.ScriptManifest("Get-Date; Remove-Item C:\\", "Test-Path C:\\x"), &sig, trusted, opsign.ErrBadSignature},
		"tampered detection": {opsign.ScriptManifest("Get-Date", ""), &sig, trusted, opsign.ErrBadSignature},
		"unsigned":           {opsign.ScriptManifest("Get-Date", ""), nil, trusted, opsign.ErrUnsigned},
		"untrusted key":      {opsign.ScriptManifest("Get-Date", "Test-Path C:\\x"), &sig, []release.PublicKey{other.Public()}, opsign.ErrUntrustedKey},
		"no keys":            {opsign.ScriptManifest("Get-Date", "Test-Path C:\\x"), &sig, nil, opsign.ErrNoKeys},
		"garbage":            {opsign.ScriptManifest("Get-Date", "Test-Path C:\\x"), &opsign.Signature{KeyID: k.Public().ID(), Signature: "!!"}, trusted, opsign.ErrBadSignature},
	}
	for name, c := range cases {
		if err := opsign.Verify(c.trusted, c.manifest, c.sig); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", name, err, c.want)
		}
	}
}

func TestWipeOrders(t *testing.T) {
	k := key(t)
	trusted := []release.PublicKey{k.Public()}
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	exp := now.Add(time.Hour)
	sig := opsign.Sign(k, opsign.WipeManifest("dev-1", false, exp))

	if err := opsign.VerifyWipe(trusted, "dev-1", false, exp, now, &sig); err != nil {
		t.Fatalf("valid: %v", err)
	}
	for name, c := range map[string]struct {
		device    string
		protected bool
		exp, now  time.Time
		want      error
	}{
		"another device":      {"dev-2", false, exp, now, opsign.ErrBadSignature},
		"protected turned on": {"dev-1", true, exp, now, opsign.ErrBadSignature},
		"expiry moved":        {"dev-1", false, exp.Add(time.Hour), now, opsign.ErrBadSignature},
		"after it lapsed":     {"dev-1", false, exp, exp, opsign.ErrExpired},
		"no expiry at all":    {"dev-1", false, time.Time{}, now, opsign.ErrUnsigned},
	} {
		if err := opsign.VerifyWipe(trusted, c.device, c.protected, c.exp, c.now, &sig); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", name, err, c.want)
		}
	}
}

func TestParsePolicyFailsClosed(t *testing.T) {
	if p := opsign.ParsePolicy(""); p.Enforced {
		t.Fatal("an empty list must not enforce")
	}
	k := key(t)
	if p := opsign.ParsePolicy(k.Public().Encode()); !p.Enforced || len(p.Keys) != 1 {
		t.Fatalf("one key = %+v", p)
	}
	// A malformed list enforces with no keys: everything is refused.
	p := opsign.ParsePolicy("not-a-key")
	if !p.Enforced || len(p.Keys) != 0 {
		t.Fatalf("malformed = %+v", p)
	}
	sig := opsign.Sign(k, opsign.ScriptManifest("x", ""))
	if err := opsign.Verify(p.Keys, opsign.ScriptManifest("x", ""), &sig); !errors.Is(err, opsign.ErrNoKeys) {
		t.Fatalf("verify under a malformed list = %v", err)
	}
}
