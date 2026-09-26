package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"retune/internal/opsign"
	"retune/internal/protocol"
	"retune/internal/release"
)

func signed(t *testing.T, args []string) opsign.Signature {
	t.Helper()
	var out bytes.Buffer
	if err := run(args, os.Getenv, &out); err != nil {
		t.Fatal(err)
	}
	var sig opsign.Signature
	if err := json.Unmarshal(out.Bytes(), &sig); err != nil {
		t.Fatalf("output %q: %v", out.String(), err)
	}
	return sig
}

// The app JSON an administrator signs is the body they send the API, with
// the defaults left out; the signature must verify against the version an
// agent is sent, with the server's defaults filled in.
func TestSignApp(t *testing.T) {
	dir, pub := operationsKey(t)
	key := filepath.Join(dir, "operations.key")

	winget := filepath.Join(dir, "7zip.json")
	if err := os.WriteFile(winget, []byte(`{"name":"7-Zip","package_id":"7zip.7zip","install_args":"--silent"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	sig := signed(t, []string{"sign-app", "--key", key, winget})
	sent := protocol.AppVersionResponse{
		Version: 3, PackageID: "7zip.7zip", Scope: protocol.ScopeMachine, InstallArgs: "--silent",
		Source: protocol.AppSourceWinget,
	}
	if err := opsign.Verify([]release.PublicKey{pub}, sent.Definition().Manifest(), &sig); err != nil {
		t.Fatalf("winget app: %v", err)
	}

	installer := filepath.Join(dir, "setup.msi")
	if err := os.WriteFile(installer, []byte("not really an msi"), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("not really an msi"))
	pkg := filepath.Join(dir, "pkg.json")
	if err := os.WriteFile(pkg, []byte(`{"name":"Contoso","source":"package","installer_type":"msi",
		"detection":{"type":"msi_product_code","product_code":"{12345678-1234-1234-1234-123456789ABC}"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	sig = signed(t, []string{"sign-app", "--key", key, "--file", installer, pkg})
	sent = protocol.AppVersionResponse{
		Version: 1, Scope: protocol.ScopeMachine, Source: protocol.AppSourcePackage, InstallerType: "msi",
		FileName: "setup.msi", FileSHA256: hex.EncodeToString(sum[:]), FileSize: 17,
		SuccessExitCodes: protocol.DefaultSuccessExitCodes(),
		Detection:        &protocol.DetectionRule{Type: protocol.DetectMSIProductCode, ProductCode: "{12345678-1234-1234-1234-123456789ABC}"},
	}
	if err := opsign.Verify([]release.PublicKey{pub}, sent.Definition().Manifest(), &sig); err != nil {
		t.Fatalf("package: %v", err)
	}
	// A different file is a different app.
	sent.FileSHA256 = strings.Repeat("0", 64)
	if err := opsign.Verify([]release.PublicKey{pub}, sent.Definition().Manifest(), &sig); err == nil {
		t.Fatal("the signature should not cover another file")
	}

	// A package's signature is over its file: with neither --file nor a
	// hash, there is nothing to sign.
	if err := run([]string{"sign-app", "--key", key, pkg}, os.Getenv, &bytes.Buffer{}); err == nil {
		t.Error("a package with no hash should not be signed")
	}
	// A hash in the JSON that isn't the file's is a mistake worth stopping.
	wrong := filepath.Join(dir, "wrong.json")
	if err := os.WriteFile(wrong, []byte(`{"source":"package","installer_type":"msi","file_sha256":"`+strings.Repeat("1", 64)+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"sign-app", "--key", key, "--file", installer, wrong}, os.Getenv, &bytes.Buffer{}); err == nil {
		t.Error("a hash that disagrees with the file should fail")
	}
}

func TestSignProfile(t *testing.T) {
	dir, pub := operationsKey(t)
	key := filepath.Join(dir, "operations.key")
	settings := []protocol.Setting{
		{Kind: protocol.KindService, Name: "Spooler", Startup: protocol.StartupDisabled, State: protocol.StateStopped},
		{Kind: protocol.KindWiFi, SSID: "Office", Security: "wpa2_personal", Passphrase: "correct horse battery"},
	}
	body, _ := json.Marshal(map[string]any{"name": "Baseline", "settings": settings})
	file := filepath.Join(dir, "profile.json")
	if err := os.WriteFile(file, body, 0o644); err != nil {
		t.Fatal(err)
	}
	sig := signed(t, []string{"sign-profile", "--key", key, file})
	if err := opsign.Verify([]release.PublicKey{pub}, protocol.ProfileManifest(settings), &sig); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// Just the array works too.
	arr, _ := json.Marshal(settings)
	if err := os.WriteFile(file, arr, 0o644); err != nil {
		t.Fatal(err)
	}
	sig = signed(t, []string{"sign-profile", "--key", key, file})
	if err := opsign.Verify([]release.PublicKey{pub}, protocol.ProfileManifest(settings), &sig); err != nil {
		t.Fatalf("verify array: %v", err)
	}

	// A secret left out can't be signed: devices receive it, so the
	// signature has to cover it.
	settings[1].Passphrase = ""
	arr, _ = json.Marshal(settings)
	if err := os.WriteFile(file, arr, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"sign-profile", "--key", key, file}, os.Getenv, &bytes.Buffer{}); err == nil {
		t.Error("a profile missing its passphrase should not be signed")
	}
}
