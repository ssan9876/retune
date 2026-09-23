package protocol

import (
	"encoding/base64"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ItemKindProfile is the assignment kind for configuration profiles.
const ItemKindProfile = "profile"

// Setting kinds shipped in M7.
const (
	KindRegistry = "registry"
	KindService  = "service"
	KindGroup    = "local_group_members"
	KindFile     = "file"

	KindFirewallProfile = "firewall_profile"
	KindFirewallRule    = "firewall_rule"
	KindWindowsUpdate   = "windows_update"
	KindBitLocker       = "bitlocker"

	// KindDefender sets Microsoft Defender Antivirus preferences (M15).
	KindDefender = "defender"
)

// DefenderPreference is one Defender field a setting can name: its JSON name,
// the Set-MpPreference parameter it becomes, and the words it accepts with
// the number Defender stores for each. Validation and the agent's handler
// both read this one table, so the two cannot disagree about what "high"
// means.
type DefenderPreference struct {
	Field     string
	Parameter string
	Values    map[string]int
}

// DefenderPreferences are the fields of a defender setting, in the order the
// agent applies them. realtime_monitoring is a bool and so is not here; it is
// handled beside these.
var DefenderPreferences = []DefenderPreference{
	{"cloud_protection", "MAPSReporting", map[string]int{"off": 0, "basic": 1, "advanced": 2}},
	{"sample_submission", "SubmitSamplesConsent", map[string]int{"prompt": 0, "safe": 1, "never": 2, "all": 3}},
	{"pua_protection", "PUAProtection", map[string]int{"off": 0, "on": 1, "audit": 2}},
	{"cloud_block_level", "CloudBlockLevel", map[string]int{"default": 0, "moderate": 1, "high": 2, "high_plus": 4, "zero_tolerance": 6}},
}

// DefenderValue returns the word a setting gives for one of the preferences
// above, or "" when it does not name it.
func (s Setting) DefenderValue(field string) string {
	switch field {
	case "cloud_protection":
		return s.CloudProtection
	case "sample_submission":
		return s.SampleSubmission
	case "pua_protection":
		return s.PUAProtection
	case "cloud_block_level":
		return s.CloudBlockLevel
	}
	return ""
}

// Firewall profiles, directions and actions.
const (
	FirewallDomain  = "domain"
	FirewallPrivate = "private"
	FirewallPublic  = "public"

	FirewallOn  = "on"
	FirewallOff = "off"

	DirectionInbound  = "inbound"
	DirectionOutbound = "outbound"

	ActionAllow = "allow"
	ActionBlock = "block"

	ProtocolTCP = "tcp"
	ProtocolUDP = "udp"
	ProtocolAny = "any"
)

// FirewallGroup is the group every rule Retune creates belongs to, which is how
// they are recognised later. A rule outside it was made by something else and
// is never removed.
const FirewallGroup = "Retune"

// BitLocker encryption methods.
const (
	XtsAes128 = "XtsAes128"
	XtsAes256 = "XtsAes256"
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

	// Ensure says whether the thing should exist, for registry, file and
	// firewall rules.
	Ensure string `json:"ensure,omitempty"`

	// Profile and State belong to firewall profile settings. State is shared
	// with service settings, which use running/stopped rather than on/off.
	Profile string `json:"profile,omitempty"`

	// Direction, Action, Protocol, LocalPort and Program belong to firewall
	// rules. The rule's display name is Name.
	Direction string `json:"direction,omitempty"`
	Action    string `json:"action,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	LocalPort string `json:"local_port,omitempty"`
	Program   string `json:"program,omitempty"`

	// The Windows Update policy. Pointers so that "not set" is distinct from
	// zero, which is a meaningful deferral and a meaningful hour.
	QualityDeferralDays *int  `json:"quality_deferral_days,omitempty"`
	FeatureDeferralDays *int  `json:"feature_deferral_days,omitempty"`
	ActiveHoursStart    *int  `json:"active_hours_start,omitempty"`
	ActiveHoursEnd      *int  `json:"active_hours_end,omitempty"`
	AutoRestart         *bool `json:"auto_restart,omitempty"`
	// Deadlines force an offered update to install, and restart, this many
	// days after it is offered; the grace period gives a machine that was
	// off that many days more once it comes back.
	QualityDeadlineDays *int `json:"quality_deadline_days,omitempty"`
	FeatureDeadlineDays *int `json:"feature_deadline_days,omitempty"`
	DeadlineGraceDays   *int `json:"deadline_grace_days,omitempty"`
	// PauseQualityFrom and PauseFeatureFrom pause that kind of update from a
	// date, YYYY-MM-DD. Windows ends a pause on its own 35 days later.
	PauseQualityFrom string `json:"pause_quality_from,omitempty"`
	PauseFeatureFrom string `json:"pause_feature_from,omitempty"`
	// TargetProduct and TargetVersion hold a machine on one feature release,
	// such as "Windows 11" and "24H2".
	TargetProduct string `json:"target_product,omitempty"`
	TargetVersion string `json:"target_version,omitempty"`

	// BitLocker.
	RequireEncryption bool   `json:"require_encryption,omitempty"`
	Method            string `json:"method,omitempty"`
	EscrowRecoveryKey bool   `json:"escrow_recovery_key,omitempty"`

	// Defender. Each is optional, and only the ones named are enforced.
	// RealtimeMonitoring is a pointer so that false - turn it off - is
	// distinct from not mentioning it.
	RealtimeMonitoring *bool  `json:"realtime_monitoring,omitempty"`
	CloudProtection    string `json:"cloud_protection,omitempty"`
	SampleSubmission   string `json:"sample_submission,omitempty"`
	PUAProtection      string `json:"pua_protection,omitempty"`
	CloudBlockLevel    string `json:"cloud_block_level,omitempty"`
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
	case KindFirewallProfile:
		return "firewall_profile:" + strings.ToLower(s.Profile)
	case KindFirewallRule:
		return "firewall_rule:" + strings.ToLower(strings.TrimSpace(s.Name))
	case KindWindowsUpdate:
		// One machine has one update policy, so two profiles configuring it
		// differently is exactly the conflict the engine detects.
		return "windows_update:policy"
	case KindBitLocker:
		return "bitlocker:os"
	case KindDefender:
		// One machine has one set of Defender preferences. Two profiles that
		// each name a different field are still a conflict: splitting the
		// identity per field would let two half-policies combine into a
		// configuration nobody wrote.
		return "defender:preferences"
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
	case KindFirewallProfile:
		return s.validateFirewallProfile()
	case KindFirewallRule:
		return s.validateFirewallRule()
	case KindWindowsUpdate:
		return s.validateWindowsUpdate()
	case KindBitLocker:
		return s.validateBitLocker()
	case KindDefender:
		return s.validateDefender()
	case "":
		return fmt.Errorf("%w: every setting needs a kind", ErrBadSetting)
	}
	return fmt.Errorf("%w: unsupported kind %q", ErrBadSetting, s.Kind)
}

func (s Setting) validateRegistry() error {
	switch strings.ToUpper(s.Hive) {
	case "HKLM":
	case "HKCU":
		// Applied to the signed-in user's hive. A machine with nobody signed
		// in reports that plainly rather than silently doing nothing.
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

func (s Setting) validateFirewallProfile() error {
	switch s.Profile {
	case FirewallDomain, FirewallPrivate, FirewallPublic:
	default:
		return fmt.Errorf("%w: profile must be domain, private or public, not %q", ErrBadSetting, s.Profile)
	}
	switch s.State {
	case FirewallOn, FirewallOff:
	default:
		return fmt.Errorf("%w: a firewall profile must be on or off, not %q", ErrBadSetting, s.State)
	}
	return nil
}

func (s Setting) validateFirewallRule() error {
	if strings.TrimSpace(s.Name) == "" {
		return fmt.Errorf("%w: a firewall rule needs a name", ErrBadSetting)
	}
	// The cmdlets read these as wildcards. The agent escapes them anyway, but
	// a rule named * is never what anybody meant.
	if strings.ContainsAny(s.Name, "*?[]`") {
		return fmt.Errorf("%w: a firewall rule's name cannot contain * ? [ ] or `", ErrBadSetting)
	}
	if s.Ensure == EnsureAbsent {
		return nil
	}
	if s.Ensure != "" && s.Ensure != EnsurePresent {
		return fmt.Errorf("%w: ensure must be %q or %q", ErrBadSetting, EnsurePresent, EnsureAbsent)
	}
	switch s.Direction {
	case DirectionInbound, DirectionOutbound:
	default:
		return fmt.Errorf("%w: direction must be inbound or outbound, not %q", ErrBadSetting, s.Direction)
	}
	switch s.Action {
	case ActionAllow, ActionBlock:
	default:
		return fmt.Errorf("%w: action must be allow or block, not %q", ErrBadSetting, s.Action)
	}
	switch s.Protocol {
	case ProtocolTCP, ProtocolUDP, ProtocolAny, "":
	default:
		return fmt.Errorf("%w: protocol must be tcp, udp or any, not %q", ErrBadSetting, s.Protocol)
	}
	if s.LocalPort != "" && s.Protocol == ProtocolAny {
		return fmt.Errorf("%w: a port only means something with tcp or udp", ErrBadSetting)
	}
	if err := validatePort(s.LocalPort); err != nil {
		return err
	}
	return nil
}

// validatePort accepts a port, a range, or nothing.
func validatePort(port string) error {
	if strings.TrimSpace(port) == "" {
		return nil
	}
	for _, part := range strings.Split(port, "-") {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("%w: %q is not a port or port range", ErrBadSetting, port)
		}
	}
	return nil
}

func (s Setting) validateWindowsUpdate() error {
	if err := inRange("quality_deferral_days", s.QualityDeferralDays, 0, 30); err != nil {
		return err
	}
	if err := inRange("feature_deferral_days", s.FeatureDeferralDays, 0, 365); err != nil {
		return err
	}
	if err := inRange("active_hours_start", s.ActiveHoursStart, 0, 23); err != nil {
		return err
	}
	if err := inRange("active_hours_end", s.ActiveHoursEnd, 0, 23); err != nil {
		return err
	}
	if (s.ActiveHoursStart == nil) != (s.ActiveHoursEnd == nil) {
		return fmt.Errorf("%w: active hours need both a start and an end", ErrBadSetting)
	}
	if s.ActiveHoursStart != nil && *s.ActiveHoursStart == *s.ActiveHoursEnd {
		return fmt.Errorf("%w: active hours cannot start and end at the same hour", ErrBadSetting)
	}
	for _, d := range []struct {
		field string
		value *int
		high  int
	}{
		{"quality_deadline_days", s.QualityDeadlineDays, 30},
		{"feature_deadline_days", s.FeatureDeadlineDays, 30},
		{"deadline_grace_days", s.DeadlineGraceDays, 7},
	} {
		if err := inRange(d.field, d.value, 0, d.high); err != nil {
			return err
		}
	}
	if s.DeadlineGraceDays != nil && s.QualityDeadlineDays == nil && s.FeatureDeadlineDays == nil {
		return fmt.Errorf("%w: a deadline grace period needs a deadline", ErrBadSetting)
	}
	for field, value := range map[string]string{"pause_quality_from": s.PauseQualityFrom, "pause_feature_from": s.PauseFeatureFrom} {
		if value == "" {
			continue
		}
		if _, err := time.Parse(time.DateOnly, value); err != nil {
			return fmt.Errorf("%w: %s must be a date, YYYY-MM-DD", ErrBadSetting, field)
		}
	}
	if (s.TargetProduct == "") != (s.TargetVersion == "") {
		return fmt.Errorf("%w: a target release needs both a product and a version", ErrBadSetting)
	}
	if s.TargetProduct != "" {
		if s.TargetProduct != "Windows 10" && s.TargetProduct != "Windows 11" {
			return fmt.Errorf("%w: target_product must be \"Windows 10\" or \"Windows 11\"", ErrBadSetting)
		}
		if !releasePattern.MatchString(s.TargetVersion) {
			return fmt.Errorf("%w: target_version must be a release such as 24H2", ErrBadSetting)
		}
	}
	if s.QualityDeferralDays == nil && s.FeatureDeferralDays == nil &&
		s.ActiveHoursStart == nil && s.AutoRestart == nil &&
		s.QualityDeadlineDays == nil && s.FeatureDeadlineDays == nil &&
		s.PauseQualityFrom == "" && s.PauseFeatureFrom == "" && s.TargetProduct == "" {
		return fmt.Errorf("%w: a windows_update setting with nothing set does nothing", ErrBadSetting)
	}
	return nil
}

// releasePattern is a Windows feature release name, such as 22H2 or 24H2.
var releasePattern = regexp.MustCompile(`^[0-9]{2}H[12]$`)

func inRange(field string, value *int, low, high int) error {
	if value == nil {
		return nil
	}
	if *value < low || *value > high {
		return fmt.Errorf("%w: %s must be between %d and %d", ErrBadSetting, field, low, high)
	}
	return nil
}

func (s Setting) validateBitLocker() error {
	switch s.Method {
	case XtsAes128, XtsAes256, "":
	default:
		return fmt.Errorf("%w: method must be %s or %s, not %q", ErrBadSetting, XtsAes128, XtsAes256, s.Method)
	}
	if !s.RequireEncryption && s.EscrowRecoveryKey {
		return fmt.Errorf("%w: a recovery key can only be escrowed when encryption is required", ErrBadSetting)
	}
	if !s.RequireEncryption && s.Method != "" {
		return fmt.Errorf("%w: an encryption method only means something when encryption is required", ErrBadSetting)
	}
	if !s.RequireEncryption {
		return fmt.Errorf("%w: a bitlocker setting that requires nothing does nothing", ErrBadSetting)
	}
	return nil
}

func (s Setting) validateDefender() error {
	named := s.RealtimeMonitoring != nil
	for _, p := range DefenderPreferences {
		v := s.DefenderValue(p.Field)
		if v == "" {
			continue
		}
		named = true
		if _, ok := p.Values[v]; !ok {
			return fmt.Errorf("%w: %s must be one of %s, not %q", ErrBadSetting, p.Field, strings.Join(sortedWords(p.Values), ", "), v)
		}
	}
	if !named {
		return fmt.Errorf("%w: a defender setting with nothing set does nothing", ErrBadSetting)
	}
	return nil
}

// sortedWords lists a preference's accepted words by the number Defender
// stores, so an error message reads in the order Defender's own docs do.
func sortedWords(values map[string]int) []string {
	words := make([]string, 0, len(values))
	for w := range values {
		words = append(words, w)
	}
	sort.Slice(words, func(i, j int) bool { return values[words[i]] < values[words[j]] })
	return words
}

// BitLockerEscrowRequest is POSTed to /api/agent/v1/bitlocker when a device
// has a recovery password for a volume.
type BitLockerEscrowRequest struct {
	VolumeID         string `json:"volume_id"`
	Method           string `json:"method"`
	RecoveryPassword string `json:"recovery_password"`
}

// BitLockerHasResponse answers whether the server already holds a key.
type BitLockerHasResponse struct {
	Escrowed bool `json:"escrowed"`
}
