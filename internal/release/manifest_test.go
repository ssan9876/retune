package release_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"retune/internal/release"
)

func testManifest(t *testing.T) []byte {
	t.Helper()
	raw, err := json.Marshal(release.ReleaseManifest{
		Schema: release.ManifestSchema, Version: "1.4.0", PublishedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
		Notes: "- a change",
		Assets: []release.Asset{
			{Name: "retune-agent.exe", Kind: release.AssetAgent, OS: "windows", Arch: "amd64", SHA256: digest("exe"), Size: 3},
			{Name: "retune-server", Kind: release.AssetServerImage, Image: "ghcr.io/x/retune-server:1.4.0", Digest: "sha256:" + digest("img")},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestReleaseManifestSignAndVerify(t *testing.T) {
	priv, _ := release.GenerateKey()
	raw := testManifest(t)
	sig, err := release.SignReleaseManifest(priv, raw)
	if err != nil {
		t.Fatal(err)
	}
	m, err := release.VerifyReleaseManifest([]release.PublicKey{priv.Public()}, raw, sig)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if a, ok := m.Find(release.AssetAgent, "windows", "amd64"); !ok || a.SHA256 != digest("exe") {
		t.Fatalf("windows agent not found: %+v", m)
	}
	if img, ok := m.ServerImage(); !ok || img.Digest != "sha256:"+digest("img") {
		t.Fatalf("server image not found: %+v", m)
	}
}

func TestReleaseManifestRefusals(t *testing.T) {
	priv, _ := release.GenerateKey()
	other, _ := release.GenerateKey()
	raw := testManifest(t)
	sig, _ := release.SignReleaseManifest(priv, raw)
	trusted := []release.PublicKey{priv.Public()}

	if _, err := release.VerifyReleaseManifest(nil, raw, sig); !errors.Is(err, release.ErrNoTrustedKeys) {
		t.Errorf("no keys: %v", err)
	}
	if _, err := release.VerifyReleaseManifest([]release.PublicKey{other.Public()}, raw, sig); !errors.Is(err, release.ErrUntrustedKey) {
		t.Errorf("untrusted key: %v", err)
	}
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-2] = ' '
	if _, err := release.VerifyReleaseManifest(trusted, tampered, sig); !errors.Is(err, release.ErrManifestMismatch) {
		t.Errorf("edited manifest: %v", err)
	}
	forged := sig
	forged.Signature = append([]byte(nil), sig.Signature...)
	forged.Signature[0] ^= 1
	if _, err := release.VerifyReleaseManifest(trusted, raw, forged); !errors.Is(err, release.ErrBadSignature) {
		t.Errorf("flipped bit: %v", err)
	}
	// The signature names the version it covers; claiming another fails.
	renamed := sig
	renamed.Version = "9.9.9"
	if _, err := release.VerifyReleaseManifest(trusted, raw, renamed); err == nil {
		t.Error("a signature relabelled with another version must not verify")
	}
}

// A release manifest's signature and an agent build's signature over the
// same hash must not be interchangeable.
func TestReleaseManifestSignatureIsNotAnAgentSignature(t *testing.T) {
	priv, _ := release.GenerateKey()
	raw := testManifest(t)
	sig, _ := release.SignReleaseManifest(priv, raw)
	err := release.Verify([]release.PublicKey{priv.Public()}, release.Manifest{Version: sig.Version, SHA256: sig.SHA256}, sig)
	if !errors.Is(err, release.ErrBadSignature) {
		t.Fatalf("a manifest signature verified as an agent build's: %v", err)
	}
}

func TestClassifyAsset(t *testing.T) {
	for name, want := range map[string][3]string{
		"retune-agent.exe":                {release.AssetAgent, "windows", "amd64"},
		"retune-agent.exe.sig":            {release.AssetSignature, "", ""},
		"retune-agent.msi":                {release.AssetAgentInstaller, "windows", "amd64"},
		"retune-agent.pkg":                {release.AssetAgentInstaller, "darwin", "universal"},
		"retune-agent-darwin-arm64":       {release.AssetAgent, "darwin", "arm64"},
		"retune-agent-darwin-universal":   {release.AssetAgent, "darwin", "universal"},
		"retune-agent-linux-amd64":        {release.AssetAgent, "linux", "amd64"},
		"retune-server-windows-amd64.exe": {release.AssetServer, "windows", "amd64"},
		"retune-sign-darwin-arm64":        {release.AssetTool, "darwin", "arm64"},
		"SHA256SUMS":                      {release.AssetOther, "", ""},
	} {
		k, o, a := release.ClassifyAsset(name)
		if [3]string{k, o, a} != want {
			t.Errorf("%s = %s/%s/%s, want %v", name, k, o, a, want)
		}
	}
}

func TestVersionOrdering(t *testing.T) {
	ordered := []string{"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.2.0", "2.0.0"}
	for i := 0; i+1 < len(ordered); i++ {
		if !release.Newer(ordered[i+1], ordered[i]) || release.Newer(ordered[i], ordered[i+1]) {
			t.Errorf("%s should be newer than %s", ordered[i+1], ordered[i])
		}
	}
	if release.Newer("1.0.0", "1.0.0") {
		t.Error("a version is not newer than itself")
	}
	if release.Newer("garbage", "1.0.0") {
		t.Error("an unparseable version is never newer")
	}
	for _, bad := range []string{"1.0", "1.0.0.0", "01.0.0", "a.b.c", ""} {
		if _, err := release.ParseVersion(bad); err == nil {
			t.Errorf("%q should not parse", bad)
		}
	}
	if v, err := release.ParseVersion("v1.2.3-rc.1"); err != nil || v.Major != 1 || v.Pre != "rc.1" {
		t.Errorf("v-prefixed version: %+v %v", v, err)
	}
}
