package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// A release is described by release.json, published beside its files and
// signed with the same release key as the agent builds. A server trusts what
// the manifest says only because of that signature: the hashes in it are what
// every downloaded file is then checked against.

// Asset kinds in a release manifest.
const (
	// AssetAgent is a bare agent binary, which self-update installs.
	AssetAgent = "agent"
	// AssetAgentInstaller is an MSI or pkg: what a first install uses.
	AssetAgentInstaller = "agent-installer"
	// AssetServer is a server binary.
	AssetServer = "server"
	// AssetServerImage is the server's container image, by digest.
	AssetServerImage = "server-image"
	// AssetTool is retune-sign.
	AssetTool = "tool"
	// AssetSignature is a build's .sig sidecar.
	AssetSignature = "signature"
	// AssetOther is anything else published with the release.
	AssetOther = "other"
)

// ManifestSchema is the release.json format this code writes and reads.
const ManifestSchema = 1

// ReleaseManifest is release.json.
type ReleaseManifest struct {
	Schema      int       `json:"schema"`
	Version     string    `json:"version"`
	Prerelease  bool      `json:"prerelease"`
	PublishedAt time.Time `json:"published_at"`
	Notes       string    `json:"notes"`
	Assets      []Asset   `json:"assets"`
}

// Asset is one file (or the image) a release publishes.
type Asset struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	OS   string `json:"os,omitempty"`
	Arch string `json:"arch,omitempty"`
	// SHA256 is the file's hash. An image has none; its Digest says the same.
	SHA256 string `json:"sha256,omitempty"`
	Size   int64  `json:"size,omitempty"`
	// Image and Digest name a container image, for AssetServerImage.
	Image  string `json:"image,omitempty"`
	Digest string `json:"digest,omitempty"`
}

// ClassifyAsset says what a published file is from its name, which the
// release workflow keeps stable: retune-agent-darwin-arm64, retune-server-
// linux-amd64, retune-agent.exe and so on.
func ClassifyAsset(name string) (kind, goos, goarch string) {
	if strings.HasSuffix(name, ".sig") {
		return AssetSignature, "", ""
	}
	switch name {
	case "retune-agent.exe":
		return AssetAgent, "windows", "amd64"
	case "retune-agent.msi":
		return AssetAgentInstaller, "windows", "amd64"
	case "retune-agent.pkg":
		return AssetAgentInstaller, "darwin", "universal"
	}
	base := strings.TrimSuffix(name, ".exe")
	for prefix, kind := range map[string]string{
		"retune-agent-":  AssetAgent,
		"retune-server-": AssetServer,
		"retune-sign-":   AssetTool,
	} {
		rest, ok := strings.CutPrefix(base, prefix)
		if !ok {
			continue
		}
		goos, goarch, ok := strings.Cut(rest, "-")
		if !ok || goos == "" || goarch == "" {
			return AssetOther, "", ""
		}
		return kind, goos, goarch
	}
	return AssetOther, "", ""
}

// Find returns the asset of one kind for one platform.
func (m ReleaseManifest) Find(kind, goos, goarch string) (Asset, bool) {
	for _, a := range m.Assets {
		if a.Kind == kind && a.OS == goos && a.Arch == goarch {
			return a, true
		}
	}
	return Asset{}, false
}

// Named returns the asset with this file name.
func (m ReleaseManifest) Named(name string) (Asset, bool) {
	for _, a := range m.Assets {
		if a.Name == name {
			return a, true
		}
	}
	return Asset{}, false
}

// ServerImage is the release's server image, if it published one.
func (m ReleaseManifest) ServerImage() (Asset, bool) {
	for _, a := range m.Assets {
		if a.Kind == AssetServerImage {
			return a, true
		}
	}
	return Asset{}, false
}

// Validate checks what a reader of a manifest relies on: a version, and a
// well-formed hash on every file.
func (m ReleaseManifest) Validate() error {
	if m.Schema != ManifestSchema {
		return fmt.Errorf("release manifest schema %d is not %d", m.Schema, ManifestSchema)
	}
	if _, err := ParseVersion(m.Version); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, a := range m.Assets {
		if a.Name == "" || seen[a.Name] {
			return fmt.Errorf("release manifest has an unnamed or repeated asset %q", a.Name)
		}
		seen[a.Name] = true
		if a.Kind == AssetServerImage {
			if a.Image == "" || !strings.HasPrefix(a.Digest, "sha256:") {
				return fmt.Errorf("release manifest image %q has no image or digest", a.Name)
			}
			continue
		}
		if raw, err := hex.DecodeString(a.SHA256); err != nil || len(raw) != sha256.Size {
			return fmt.Errorf("release manifest asset %q has no valid sha256", a.Name)
		}
	}
	return nil
}

// releaseManifestBytes is what a release manifest's signature covers. It has
// its own first line, so a signature over release.json can never be passed
// off as one over an agent build with the same hash, or the other way round.
func releaseManifestBytes(version, sum string) []byte {
	return []byte("retune-release-manifest/v1\nversion=" + version + "\nsha256=" + strings.ToLower(sum) + "\n")
}

// SignReleaseManifest signs release.json's exact bytes.
func SignReleaseManifest(priv PrivateKey, raw []byte) (Signature, error) {
	var m ReleaseManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return Signature{}, fmt.Errorf("release manifest: %w", err)
	}
	if err := m.Validate(); err != nil {
		return Signature{}, err
	}
	sum := sha256.Sum256(raw)
	hexSum := hex.EncodeToString(sum[:])
	return Signature{
		Version: m.Version, SHA256: hexSum, KeyID: priv.Public().ID(),
		Signature: ed25519.Sign(priv.Raw, releaseManifestBytes(m.Version, hexSum)),
	}, nil
}

// VerifyReleaseManifest checks release.json's bytes against its signature and
// only then parses them. The version the signature names must be the one the
// manifest carries.
func VerifyReleaseManifest(trusted []PublicKey, raw []byte, sig Signature) (ReleaseManifest, error) {
	if len(trusted) == 0 {
		return ReleaseManifest{}, ErrNoTrustedKeys
	}
	sum := sha256.Sum256(raw)
	hexSum := hex.EncodeToString(sum[:])
	if !strings.EqualFold(sig.SHA256, hexSum) {
		return ReleaseManifest{}, ErrManifestMismatch
	}
	verified := false
	for _, k := range trusted {
		if k.ID() != sig.KeyID {
			continue
		}
		if !ed25519.Verify(k.Raw, releaseManifestBytes(sig.Version, hexSum), sig.Signature) {
			return ReleaseManifest{}, ErrBadSignature
		}
		verified = true
		break
	}
	if !verified {
		return ReleaseManifest{}, fmt.Errorf("%w (key %s)", ErrUntrustedKey, sig.KeyID)
	}
	var m ReleaseManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return ReleaseManifest{}, fmt.Errorf("release manifest: %w", err)
	}
	if m.Version != sig.Version {
		return ReleaseManifest{}, ErrManifestMismatch
	}
	if err := m.Validate(); err != nil {
		return ReleaseManifest{}, err
	}
	return m, nil
}

// Version is a MAJOR.MINOR.PATCH[-PRERELEASE] version.
type Version struct {
	Major, Minor, Patch int
	Pre                 string
}

// ErrBadVersion is a version string that is not MAJOR.MINOR.PATCH[-PRE].
var ErrBadVersion = errors.New("not a MAJOR.MINOR.PATCH version")

// ParseVersion reads a version, with or without a leading v.
func ParseVersion(s string) (Version, error) {
	core, pre, _ := strings.Cut(strings.TrimPrefix(strings.TrimSpace(s), "v"), "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return Version{}, fmt.Errorf("%w: %q", ErrBadVersion, s)
	}
	var n [3]int
	for i, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 || p == "" || (len(p) > 1 && p[0] == '0') {
			return Version{}, fmt.Errorf("%w: %q", ErrBadVersion, s)
		}
		n[i] = v
	}
	return Version{Major: n[0], Minor: n[1], Patch: n[2], Pre: pre}, nil
}

// Compare orders versions by semantic-version precedence: -1, 0 or 1.
func (v Version) Compare(o Version) int {
	for _, d := range [][2]int{{v.Major, o.Major}, {v.Minor, o.Minor}, {v.Patch, o.Patch}} {
		if d[0] != d[1] {
			if d[0] < d[1] {
				return -1
			}
			return 1
		}
	}
	switch {
	case v.Pre == o.Pre:
		return 0
	case v.Pre == "":
		// A release outranks its own prereleases.
		return 1
	case o.Pre == "":
		return -1
	}
	a, b := strings.Split(v.Pre, "."), strings.Split(o.Pre, ".")
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] == b[i] {
			continue
		}
		ai, aerr := strconv.Atoi(a[i])
		bi, berr := strconv.Atoi(b[i])
		switch {
		case aerr == nil && berr == nil:
			if ai < bi {
				return -1
			}
			return 1
		case aerr == nil:
			return -1
		case berr == nil:
			return 1
		case a[i] < b[i]:
			return -1
		default:
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	return 0
}

// Newer reports whether version a is newer than b. A string that does not
// parse is never newer.
func Newer(a, b string) bool {
	va, err := ParseVersion(a)
	if err != nil {
		return false
	}
	vb, err := ParseVersion(b)
	if err != nil {
		return true
	}
	return va.Compare(vb) > 0
}
