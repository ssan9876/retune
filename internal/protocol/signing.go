package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// AppDefinition is everything an operations signature over an app version
// covers: what gets installed, and every command line and rule the agent acts
// on. It is the app's content, not its identity on a server: like a signed
// script, an approved installer is approved wherever it is used, and nothing
// that isn't covered here can change what a device runs.
type AppDefinition struct {
	Source            string         `json:"source"`
	PackageID         string         `json:"package_id"`
	PinnedVersion     string         `json:"pinned_version"`
	Scope             string         `json:"scope"`
	InstallArgs       string         `json:"install_args"`
	InstallerType     string         `json:"installer_type"`
	FileName          string         `json:"file_name"`
	FileSHA256        string         `json:"file_sha256"`
	UninstallCommand  string         `json:"uninstall_command"`
	SuccessExitCodes  []int          `json:"success_exit_codes"`
	Detection         *DetectionRule `json:"detection"`
	UninstallPrevious bool           `json:"uninstall_previous"`
}

// normalized fills in what the server fills in when it stores a version, so
// that the definition an administrator signs, the one the server checks and
// the one an agent receives all produce the same manifest.
func (d AppDefinition) normalized() AppDefinition {
	if d.Source == "" {
		d.Source = AppSourceWinget
	}
	if d.Source == AppSourceWinget {
		if d.Scope == "" {
			d.Scope = ScopeMachine
		}
		// Winget versions carry none of the package fields.
		d.InstallerType, d.FileName, d.FileSHA256, d.UninstallCommand = "", "", "", ""
		d.SuccessExitCodes, d.Detection, d.UninstallPrevious = nil, nil, false
		return d
	}
	d.PackageID, d.PinnedVersion = "", ""
	if d.Scope == "" {
		d.Scope = ScopeMachine
	}
	d.FileName = strings.TrimSpace(d.FileName)
	d.FileSHA256 = strings.ToLower(strings.TrimSpace(d.FileSHA256))
	if len(d.SuccessExitCodes) == 0 {
		d.SuccessExitCodes = DefaultSuccessExitCodes()
	}
	return d
}

// Manifest is the exact text signed for an app version.
func (d AppDefinition) Manifest() []byte {
	b, _ := json.Marshal(d.normalized())
	return append([]byte("retune-app-manifest/v1\n"), b...)
}

// Definition is what a signature over this version must cover.
func (v AppVersionResponse) Definition() AppDefinition {
	return AppDefinition{
		Source: v.Source, PackageID: v.PackageID, PinnedVersion: v.PinnedVersion, Scope: v.Scope,
		InstallArgs: v.InstallArgs, InstallerType: v.InstallerType, FileName: v.FileName,
		FileSHA256: v.FileSHA256, UninstallCommand: v.UninstallCommand, SuccessExitCodes: v.SuccessExitCodes,
		Detection: v.Detection, UninstallPrevious: v.UninstallPrevious,
	}
}

// ProfileManifest is the exact text signed for a profile version: the hash of
// its settings as a device receives them, secrets in the clear. The sealed
// form a server stores differs every time it is sealed, and only a server
// can open it, so neither the person signing nor the agent could check it.
func ProfileManifest(settings []Setting) []byte {
	clean := make([]Setting, len(settings))
	for i, s := range settings {
		s.SealedSecret, s.SecretSet = nil, false
		clean[i] = s
	}
	b, _ := json.Marshal(clean)
	sum := sha256.Sum256(b)
	return []byte("retune-profile-manifest/v1\nsettings=" + hex.EncodeToString(sum[:]) + "\n")
}
