// retune-sign signs agent builds with an offline release key, and scripts
// and wipe orders with an offline operations key, and verifies release
// signatures. It is what a release or change process runs; the server never
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
	"retune/internal/release"
)

const usage = `usage:
  retune-sign keygen --out DIR [--name release|operations]
  retune-sign sign --key FILE|env:NAME --version V BINARY
  retune-sign verify --trust KEY[,KEY...] BINARY SIGFILE
  retune-sign sign-script --key FILE|env:NAME [--detection FILE] SCRIPT
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
		name := fs.String("name", "release", "release, or operations for a key that signs scripts and wipes")
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
