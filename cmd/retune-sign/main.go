// retune-sign signs agent builds with an offline release key, and scripts,
// apps, profiles and wipe orders with an offline operations key, and verifies
// release signatures. It is what a release or change process runs; the server never
// holds either private key.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"retune/internal/opsign"
	"retune/internal/protocol"
	"retune/internal/release"
)

const usage = `usage:
  retune-sign keygen --out DIR [--name release|operations]
  retune-sign pubkey --key FILE|env:NAME
  retune-sign sign --key FILE|env:NAME --version V BINARY
  retune-sign verify --trust KEY[,KEY...] BINARY SIGFILE
  retune-sign sign-script --key FILE|env:NAME [--detection FILE] SCRIPT
  retune-sign sign-app --key FILE|env:NAME [--file INSTALLER] APP.json
  retune-sign sign-profile --key FILE|env:NAME PROFILE.json
  retune-sign sign-wipe --key FILE|env:NAME --device ID [--protected] [--valid-for 4h]`

func main() {
	if err := run(os.Args[1:], os.Getenv, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string, getenv func(string) string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	switch args[0] {
	case "keygen":
		fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
		outDir := fs.String("out", "", "directory to write NAME.key and NAME.pub into")
		name := fs.String("name", "release", "release, or operations for a key that signs scripts, apps, profiles and wipes")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *outDir == "" {
			return errors.New("--out is required")
		}
		if *name != "release" && *name != "operations" {
			return errors.New("--name must be release or operations")
		}
		return keygen(*outDir, *name, out)
	case "pubkey":
		// Prints the public half of a key, so a build that holds only the
		// private key (a CI secret) can stamp the matching trust list.
		fs := flag.NewFlagSet("pubkey", flag.ContinueOnError)
		key := fs.String("key", "", "path to a .key file, or env:NAME")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *key == "" || fs.NArg() != 0 {
			return errors.New(usage)
		}
		priv, err := loadKey(*key, getenv)
		if err != nil {
			return err
		}
		fmt.Fprintln(out, priv.Public().Encode())
		return nil
	case "sign":
		fs := flag.NewFlagSet("sign", flag.ContinueOnError)
		key := fs.String("key", "", "path to release.key, or env:NAME to read the seed from the environment")
		version := fs.String("version", "", "the version this build is stamped with")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *key == "" || *version == "" || fs.NArg() != 1 {
			return errors.New(usage)
		}
		priv, err := loadKey(*key, getenv)
		if err != nil {
			return err
		}
		return sign(priv, *version, fs.Arg(0), out)
	case "verify":
		fs := flag.NewFlagSet("verify", flag.ContinueOnError)
		trust := fs.String("trust", "", "comma-separated public keys to trust")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 2 {
			return errors.New(usage)
		}
		keys, err := release.ParseTrustList(*trust)
		if err != nil {
			return err
		}
		return verify(keys, fs.Arg(0), fs.Arg(1), out)
	case "sign-script":
		fs := flag.NewFlagSet("sign-script", flag.ContinueOnError)
		key := fs.String("key", "", "path to operations.key, or env:NAME")
		detection := fs.String("detection", "", "the script's detection script, if it has one")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *key == "" || fs.NArg() != 1 {
			return errors.New(usage)
		}
		priv, err := loadKey(*key, getenv)
		if err != nil {
			return err
		}
		return signScript(priv, fs.Arg(0), *detection, out)
	case "sign-app":
		fs := flag.NewFlagSet("sign-app", flag.ContinueOnError)
		key := fs.String("key", "", "path to operations.key, or env:NAME")
		file := fs.String("file", "", "the installer an uploaded package installs, to take its hash from")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *key == "" || fs.NArg() != 1 {
			return errors.New(usage)
		}
		priv, err := loadKey(*key, getenv)
		if err != nil {
			return err
		}
		return signApp(priv, fs.Arg(0), *file, out)
	case "sign-profile":
		fs := flag.NewFlagSet("sign-profile", flag.ContinueOnError)
		key := fs.String("key", "", "path to operations.key, or env:NAME")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *key == "" || fs.NArg() != 1 {
			return errors.New(usage)
		}
		priv, err := loadKey(*key, getenv)
		if err != nil {
			return err
		}
		return signProfile(priv, fs.Arg(0), out)
	case "sign-wipe":
		fs := flag.NewFlagSet("sign-wipe", flag.ContinueOnError)
		key := fs.String("key", "", "path to operations.key, or env:NAME")
		device := fs.String("device", "", "the device ID the order is for")
		protected := fs.Bool("protected", false, "a protected wipe")
		validFor := fs.Duration("valid-for", 4*time.Hour, "how long the order stays valid, at most 24h")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *key == "" || *device == "" || fs.NArg() != 0 {
			return errors.New(usage)
		}
		if *validFor <= 0 || *validFor > opsign.MaxWipeValidity {
			return errors.New("--valid-for must be more than 0 and at most 24h")
		}
		priv, err := loadKey(*key, getenv)
		if err != nil {
			return err
		}
		return signWipe(priv, *device, *protected, time.Now().Add(*validFor), out)
	default:
		return fmt.Errorf("unknown command %q\n%s", args[0], usage)
	}
}

// signScript prints the signature for a script and its detection script, as
// the JSON the console and API take.
func signScript(priv release.PrivateKey, script, detection string, out io.Writer) error {
	body, err := os.ReadFile(script)
	if err != nil {
		return err
	}
	var det []byte
	if detection != "" {
		if det, err = os.ReadFile(detection); err != nil {
			return err
		}
	}
	sig := opsign.Sign(priv, opsign.ScriptManifest(string(body), string(det)))
	return json.NewEncoder(out).Encode(sig)
}

// signApp prints the signature for an app version. APP.json is the body the
// console or API sends to create or edit the app; with --file, the
// installer's hash is taken from the file itself, so what is signed is the
// file in hand rather than a hash copied from somewhere.
func signApp(priv release.PrivateKey, appFile, installer string, out io.Writer) error {
	raw, err := os.ReadFile(appFile)
	if err != nil {
		return err
	}
	var def protocol.AppDefinition
	if err := json.Unmarshal(raw, &def); err != nil {
		return fmt.Errorf("read %s: %w", appFile, err)
	}
	if installer != "" {
		sum, err := hashFile(installer)
		if err != nil {
			return err
		}
		if def.FileSHA256 != "" && !strings.EqualFold(strings.TrimSpace(def.FileSHA256), sum) {
			return fmt.Errorf("%s says file_sha256 %s, but %s hashes to %s", appFile, def.FileSHA256, installer, sum)
		}
		def.FileSHA256 = sum
		if def.FileName == "" {
			def.FileName = filepath.Base(installer)
		}
	}
	if def.Source == protocol.AppSourcePackage && def.FileSHA256 == "" {
		return errors.New("an uploaded package's signature covers its hash: pass --file or set file_sha256")
	}
	sig := opsign.Sign(priv, def.Manifest())
	return json.NewEncoder(out).Encode(sig)
}

// signProfile prints the signature for a profile's settings. PROFILE.json is
// the body the console or API sends — an object with "settings" — or just the
// settings array. A secret, such as a Wi-Fi passphrase, must be in it in the
// clear: the signature covers what devices receive.
func signProfile(priv release.PrivateKey, profileFile string, out io.Writer) error {
	raw, err := os.ReadFile(profileFile)
	if err != nil {
		return err
	}
	var settings []protocol.Setting
	if trimmed := strings.TrimSpace(string(raw)); strings.HasPrefix(trimmed, "[") {
		err = json.Unmarshal(raw, &settings)
	} else {
		var body struct {
			Settings []protocol.Setting `json:"settings"`
		}
		err = json.Unmarshal(raw, &body)
		settings = body.Settings
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", profileFile, err)
	}
	if err := protocol.ValidateSettings(settings); err != nil {
		return err
	}
	for _, s := range settings {
		if s.HasSecret() && s.NeedsSecret() && s.Passphrase == "" {
			return fmt.Errorf("%s has no passphrase in %s: sign the settings with their secrets in the clear", s.Identity(), profileFile)
		}
	}
	sig := opsign.Sign(priv, protocol.ProfileManifest(settings))
	return json.NewEncoder(out).Encode(sig)
}

// signWipe prints a signed wipe order: the expiry it is bound to, with the
// signature.
func signWipe(priv release.PrivateKey, device string, protected bool, expires time.Time, out io.Writer) error {
	expires = expires.UTC().Truncate(time.Second)
	sig := opsign.Sign(priv, opsign.WipeManifest(device, protected, expires))
	return json.NewEncoder(out).Encode(struct {
		Device    string    `json:"device"`
		Protected bool      `json:"protected"`
		Expires   time.Time `json:"expires"`
		opsign.Signature
	}{device, protected, expires, sig})
}

func keygen(dir, name string, out io.Writer) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	priv, err := release.GenerateKey()
	if err != nil {
		return err
	}
	// O_EXCL: a release key silently replaced is a fleet that can no longer
	// be updated, so an existing file is an error, never overwritten.
	if err := writeNew(filepath.Join(dir, name+".key"), []byte(priv.Encode()+"\n"), 0o600); err != nil {
		return err
	}
	if err := writeNew(filepath.Join(dir, name+".pub"), []byte(priv.Public().Encode()+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(out, "key id: %s\npublic key: %s\n", priv.Public().ID(), priv.Public().Encode())
	return nil
}

func writeNew(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func loadKey(spec string, getenv func(string) string) (release.PrivateKey, error) {
	if name, ok := strings.CutPrefix(spec, "env:"); ok {
		v := getenv(name)
		if v == "" {
			return release.PrivateKey{}, fmt.Errorf("environment variable %s is not set", name)
		}
		return release.DecodePrivateKey(v)
	}
	b, err := os.ReadFile(spec)
	if err != nil {
		return release.PrivateKey{}, err
	}
	return release.DecodePrivateKey(string(b))
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func sign(priv release.PrivateKey, version, binary string, out io.Writer) error {
	sum, err := hashFile(binary)
	if err != nil {
		return err
	}
	sig := release.Sign(priv, release.Manifest{Version: version, SHA256: sum})
	b, err := json.Marshal(sig)
	if err != nil {
		return err
	}
	if err := os.WriteFile(binary+".sig", append(b, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(out, "signed %s as %s with key %s\n", binary, version, sig.KeyID)
	return nil
}

func verify(trusted []release.PublicKey, binary, sigfile string, out io.Writer) error {
	sum, err := hashFile(binary)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(sigfile)
	if err != nil {
		return err
	}
	sig, err := release.DecodeSidecar(raw)
	if err != nil {
		return err
	}
	if err := release.Verify(trusted, release.Manifest{Version: sig.Version, SHA256: sum}, sig); err != nil {
		return err
	}
	fmt.Fprintf(out, "ok: %s is %s signed by key %s\n", binary, sig.Version, sig.KeyID)
	return nil
}
