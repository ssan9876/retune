package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"retune/internal/release"
)

// releaseManifest writes release.json: every published file with its hash,
// and the server image by digest. Signatures are listed too, so a reader can
// fetch a build's .sig by name, and so is anything unrecognised.
func releaseManifest(version string, prerelease bool, notesFile, image, imageDigest, outFile string, files []string, now time.Time, out io.Writer) error {
	m := release.ReleaseManifest{
		Schema: release.ManifestSchema, Version: version, Prerelease: prerelease,
		PublishedAt: now.UTC().Truncate(time.Second),
	}
	if notesFile != "" {
		b, err := os.ReadFile(notesFile)
		if err != nil {
			return err
		}
		m.Notes = string(b)
	}
	for _, path := range files {
		name := filepath.Base(path)
		// The manifest and its own signature can't list themselves.
		if name == filepath.Base(outFile) || name == filepath.Base(outFile)+".sig" {
			continue
		}
		st, err := os.Stat(path)
		if err != nil {
			return err
		}
		sum, err := hashFile(path)
		if err != nil {
			return err
		}
		kind, goos, goarch := release.ClassifyAsset(name)
		m.Assets = append(m.Assets, release.Asset{
			Name: name, Kind: kind, OS: goos, Arch: goarch, SHA256: sum, Size: st.Size(),
		})
	}
	if image != "" {
		m.Assets = append(m.Assets, release.Asset{
			Name: "retune-server-image", Kind: release.AssetServerImage, OS: "linux", Arch: "multi",
			Image: image, Digest: imageDigest,
		})
	}
	if err := m.Validate(); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(outFile, append(raw, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(out, "wrote %s: %s, %d assets\n", outFile, version, len(m.Assets))
	return nil
}

// signRelease writes MANIFEST.sig beside a release manifest.
func signRelease(priv release.PrivateKey, manifest string, out io.Writer) error {
	raw, err := os.ReadFile(manifest)
	if err != nil {
		return err
	}
	sig, err := release.SignReleaseManifest(priv, raw)
	if err != nil {
		return err
	}
	b, err := json.Marshal(sig)
	if err != nil {
		return err
	}
	if err := os.WriteFile(manifest+".sig", append(b, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(out, "signed %s (%s) with key %s\n", manifest, sig.Version, sig.KeyID)
	return nil
}

// verifyRelease checks a release manifest and its signature the way a server
// does before it believes a word of it.
func verifyRelease(trusted []release.PublicKey, manifest, sigfile string, out io.Writer) error {
	raw, err := os.ReadFile(manifest)
	if err != nil {
		return err
	}
	sigRaw, err := os.ReadFile(sigfile)
	if err != nil {
		return err
	}
	sig, err := release.DecodeSidecar(sigRaw)
	if err != nil {
		return err
	}
	m, err := release.VerifyReleaseManifest(trusted, raw, sig)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "ok: %s is release %s (%d assets) signed by key %s\n", manifest, m.Version, len(m.Assets), sig.KeyID)
	return nil
}
