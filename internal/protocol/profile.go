package protocol

import (
	"encoding/base64"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"
)

// ItemKindProfile is the assignment kind for configuration profiles.
const ItemKindProfile = "profile"

// Setting kinds shipped in M7.
const (
	KindRegistry = "registry"
	KindService  = "service"
	KindGroup    = "local_group_members"
	KindFile     = "file"
)

// Registry value types.
const (
	RegSZ       = "REG_SZ"
	RegExpandSZ = "REG_EXPAND_SZ"
	RegDWord    = "REG_DWORD"
	RegQWord    = "REG_QWORD"
	RegMultiSZ  = "REG_MULTI_SZ"
)

// Service startup types and desired states.
const (
	StartupAutomatic = "automatic"
	StartupManual    = "manual"
	StartupDisabled  = "disabled"

	StateRunning = "running"
	StateStopped = "stopped"
)

// Group membership modes.
const (
	ModeAdditive = "additive"
	ModeExact    = "exact"
)

// Ensure values.
const (
	EnsurePresent = "present"
	EnsureAbsent  = "absent"
)

// Per-setting statuses an agent reports.
const (
	SettingCompliant  = "compliant"
	SettingRemediated = "remediated"
	SettingError      = "error"
	SettingConflict   = "conflict"
)

// MaxFileBytes caps the contents of a file setting.
const MaxFileBytes = 1 << 20

// ErrBadSetting is returned when a setting does not make sense.
var ErrBadSetting = errors.New("invalid setting")

// Setting is one thing a profile states about a machine. The fields a kind
// does not use are left empty; Validate rejects anything else.
type Setting struct {
	Kind string `json:"kind"`

	// Hive, Key and Type belong to registry settings.
	Hive string `json:"hive,omitempty"`
	Key  string `json:"key,omitempty"`
	Type string `json:"type,omitempty"`
	// Name is the registry value name, or the service name.
	Name string `json:"name,omitempty"`
	// Data is the registry value, as text. REG_MULTI_SZ separates its strings
	// with newlines.
	Data string `json:"data,omitempty"`

	// Startup and State belong to service settings.
	Startup string `json:"startup,omitempty"`
	State   string `json:"state,omitempty"`

	// Group, Members and Mode belong to local group settings.
	Group   string   `json:"group,omitempty"`
	Members []string `json:"members,omitempty"`
	Mode    string   `json:"mode,omitempty"`

	// Path and ContentBase64 belong to file settings.
	Path          string `json:"path,omitempty"`
	ContentBase64 string `json:"content_base64,omitempty"`

	// Ensure says whether the thing should exist, for registry and file.
	Ensure string `json:"ensure,omitempty"`
}

// Identity is the key two profiles must agree on to be setting the same thing.
// Windows treats these names case-insensitively, so two profiles differing only
// in case are the same setting and must be seen as one.
func (s Setting) Identity() string {
	switch s.Kind {
	case KindRegistry:
		return fmt.Sprintf("registry:%s\\%s!%s",
			strings.ToUpper(s.Hive), strings.ToLower(normalizeKey(s.Key)), strings.ToLower(s.Name))
	case KindService:
		return "service:" + strings.ToLower(s.Name)
	case KindGroup:
		return "local_group_members:" + strings.ToLower(s.Group)
	case KindFile:
		return "file:" + strings.ToLower(NormalizePath(s.Path))
	}
	return s.Kind + ":"
}

// NormalizePath puts a Windows path in one form so two spellings of the same
// file are recognised as one setting.
func NormalizePath(p string) string {
	return path.Clean(strings.ReplaceAll(strings.TrimSpace(p), "\\", "/"))
}

func normalizeKey(k string) string {
	return strings.Trim(strings.ReplaceAll(strings.TrimSpace(k), "/", "\\"), "\\")
}

// MultiSZ splits REG_MULTI_SZ data into its strings.
func (s Setting) MultiSZ() []string {
	raw := strings.ReplaceAll(s.Data, "\r\n", "\n")
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// Content decodes a file setting's contents.
func (s Setting) Content() ([]byte, error) {
	return base64.StdEncoding.DecodeString(s.ContentBase64)
}

// Validate reports whether a setting can be applied, so an agent never meets
// one it cannot parse.
func (s Setting) Validate() error {
	switch s.Kind {
	case KindRegistry:
		return s.validateRegistry()
	case KindService:
		return s.validateService()
	case KindGroup:
		return s.validateGroup()
	case KindFile:
		return s.validateFile()
	case "":
		return fmt.Errorf("%w: every setting needs a kind", ErrBadSetting)
	}
	return fmt.Errorf("%w: unsupported kind %q", ErrBadSetting, s.Kind)
}

func (s Setting) validateRegistry() error {
	switch strings.ToUpper(s.Hive) {
	case "HKLM":
	case "HKCU":
		// Writing there needs the signed-in user's loaded hive, which needs
		// the interactive-session support that does not exist yet. Refusing
		// here beats letting someone build a profile that can only error.
		return fmt.Errorf("%w: HKCU settings are not supported yet, because they need the signed-in user's hive", ErrBadSetting)
	default:
		return fmt.Errorf("%w: hive must be HKLM, not %q", ErrBadSetting, s.Hive)
	}
	if normalizeKey(s.Key) == "" {
		return fmt.Errorf("%w: a registry setting needs a key", ErrBadSetting)
	}
	if s.Name == "" {
		return fmt.Errorf("%w: a registry setting needs a value name", ErrBadSetting)
	}
	if s.Ensure == EnsureAbsent {
		return nil
	}
	if s.Ensure != "" && s.Ensure != EnsurePresent {
		return fmt.Errorf("%w: ensure must be %q or %q", ErrBadSetting, EnsurePresent, EnsureAbsent)
	}
	switch s.Type {
	case RegSZ, RegExpandSZ, RegMultiSZ:
	case RegDWord, RegQWord:
		if _, err := strconv.ParseUint(strings.TrimSpace(s.Data), 10, 64); err != nil {
			return fmt.Errorf("%w: %s data must be a whole number, got %q", ErrBadSetting, s.Type, s.Data)
		}
	case "":
		return fmt.Errorf("%w: a registry setting needs a type", ErrBadSetting)
	default:
		return fmt.Errorf("%w: unsupported registry type %q", ErrBadSetting, s.Type)
	}
	return nil
}

func (s Setting) validateService() error {
	if strings.TrimSpace(s.Name) == "" {
		return fmt.Errorf("%w: a service setting needs a name", ErrBadSetting)
	}
	switch s.Startup {
	case StartupAutomatic, StartupManual, StartupDisabled, "":
	default:
		return fmt.Errorf("%w: startup must be automatic, manual or disabled, not %q", ErrBadSetting, s.Startup)
	}
	switch s.State {
	case StateRunning, StateStopped, "":
	default:
		return fmt.Errorf("%w: state must be running or stopped, not %q", ErrBadSetting, s.State)
	}
	if s.Startup == "" && s.State == "" {
		return fmt.Errorf("%w: a service setting needs a startup type, a state, or both", ErrBadSetting)
	}
	if s.Startup == StartupDisabled && s.State == StateRunning {
		return fmt.Errorf("%w: a disabled service cannot also be required to run", ErrBadSetting)
	}
	return nil
}

func (s Setting) validateGroup() error {
	if strings.TrimSpace(s.Group) == "" {
		return fmt.Errorf("%w: a group setting needs a group name", ErrBadSetting)
	}
	switch s.Mode {
	case ModeAdditive, ModeExact:
	case "":
		return fmt.Errorf("%w: a group setting needs a mode of additive or exact", ErrBadSetting)
	default:
		return fmt.Errorf("%w: mode must be additive or exact, not %q", ErrBadSetting, s.Mode)
	}
	if len(s.Members) == 0 && s.Mode == ModeAdditive {
		return fmt.Errorf("%w: an additive group setting with no members does nothing", ErrBadSetting)
	}
	for _, m := range s.Members {
		if strings.TrimSpace(m) == "" {
			return fmt.Errorf("%w: a group member cannot be blank", ErrBadSetting)
		}
	}
	return nil
}

func (s Setting) validateFile() error {
	if NormalizePath(s.Path) == "." || strings.TrimSpace(s.Path) == "" {
		return fmt.Errorf("%w: a file setting needs a path", ErrBadSetting)
	}
	switch s.Ensure {
	case EnsureAbsent:
		if s.ContentBase64 != "" {
			return fmt.Errorf("%w: a file being removed cannot also have contents", ErrBadSetting)
		}
		return nil
	case EnsurePresent, "":
	default:
		return fmt.Errorf("%w: ensure must be %q or %q", ErrBadSetting, EnsurePresent, EnsureAbsent)
	}
	content, err := s.Content()
	if err != nil {
		return fmt.Errorf("%w: file contents must be base64", ErrBadSetting)
	}
	if len(content) > MaxFileBytes {
		return fmt.Errorf("%w: a file may be at most %d bytes", ErrBadSetting, MaxFileBytes)
	}
	return nil
}

// ValidateSettings checks a whole profile, reporting which setting is wrong.
// Two settings claiming the same identity within one profile is an error the
// author can fix now, unlike a conflict between two profiles.
func ValidateSettings(settings []Setting) error {
	if len(settings) == 0 {
		return fmt.Errorf("%w: a profile needs at least one setting", ErrBadSetting)
	}
	seen := map[string]int{}
	for i, s := range settings {
		if err := s.Validate(); err != nil {
			return fmt.Errorf("setting %d: %w", i+1, err)
		}
		id := s.Identity()
		if first, ok := seen[id]; ok {
			return fmt.Errorf("%w: settings %d and %d both configure %s",
				ErrBadSetting, first+1, i+1, id)
		}
		seen[id] = i
	}
	return nil
}

// ProfileVersionResponse is the body of
// GET /api/agent/v1/profiles/{id}/versions/{version}.
type ProfileVersionResponse struct {
	Version  int       `json:"version"`
	Settings []Setting `json:"settings"`
	Hash     string    `json:"hash"`
}

// SettingResult is what the agent found for one setting.
type SettingResult struct {
	Identity string `json:"identity"`
	Status   string `json:"status"`
	Detail   string `json:"detail,omitempty"`
}

// ProfileStatus is POSTed to /api/agent/v1/profiles/{id}/status.
type ProfileStatus struct {
	Version  int             `json:"version"`
	Settings []SettingResult `json:"settings"`
}

// ProfileOptions are the per-assignment settings of a profile.
type ProfileOptions struct {
	// RevertOnRemoval restores what was there before, when the profile stops
	// applying to a device.
	RevertOnRemoval bool `json:"revert_on_removal"`
}
