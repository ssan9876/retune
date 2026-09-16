// Package compliance is the pure rule engine behind M12 compliance policies:
// parsing a policy's rules JSON and evaluating it against a device's facts.
// Nothing here touches a database or the network, so every rule is
// table-tested without either.
package compliance

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/store"
)

// ErrBadRules is returned for a rules document the caller can fix: an
// unsupported type, an unknown field, a value outside its bound, or the
// wrong number of rules.
var ErrBadRules = errors.New("invalid rules")

// The twelve rule types, exactly as named in the design's rule table.
const (
	RuleOSBuildMin        = "os_build_min"
	RuleAgentVersionMin   = "agent_version_min"
	RuleBitLocker         = "bitlocker"
	RuleTPM               = "tpm"
	RuleCheckedInWithin   = "checked_in_within"
	RuleInventoryWithin   = "inventory_within"
	RuleUpdatesWithin     = "updates_within"
	RuleNoPendingReboot   = "no_pending_reboot"
	RuleMaxLocalAdmins    = "max_local_admins"
	RuleForbiddenSoftware = "forbidden_software"
	RuleRequiredSoftware  = "required_software"
	RuleProfileApplied    = "profile_applied"
)

// bitlocker's volumes parameter.
const (
	VolumesSystem = "system"
	VolumesAll    = "all"
)

// Bounds on the rule parameters that take a number, so a policy cannot ask
// for something nonsensical (a zero-hour grace period, a million rules).
const (
	MinHours = 1
	MaxHours = 8760 // one year

	MinDays = 1
	MaxDays = 365

	MinAdmins = 0
	MaxAdmins = 100

	MinNameLen = 1
	MaxNameLen = 200

	MinRules = 1
	MaxRules = 50
)

// Compliance states. A policy's own state; the overall state across several
// policies (which also has not_evaluated) is derived elsewhere.
const (
	StateCompliant    = "compliant"
	StateNonCompliant = "non_compliant"
	StateUnknown      = "unknown"
)

// Rule is one parsed, validated line of a policy. Only the fields its Type
// uses are populated; the rest are left zero. A flat struct mirrors how
// protocol.Setting represents its own dozen kinds, since here too no two
// types disagree about what a shared field name means.
type Rule struct {
	Type string

	Build      string    // os_build_min
	Version    string    // agent_version_min
	Volumes    string    // bitlocker
	MinVersion string    // tpm, optional
	Hours      int       // checked_in_within, inventory_within
	Days       int       // updates_within
	Count      int       // max_local_admins
	Name       string    // forbidden_software, required_software
	ProfileID  uuid.UUID // profile_applied
}

// ParseRules strictly decodes a policy's rules JSON: 1-50 objects, unknown
// types and unknown fields rejected, every bound checked. It is the single
// place that turns untrusted JSON (a create/update request body, or a row
// read back from compliance_policies.rules) into evaluable Rules.
func ParseRules(raw []byte) ([]Rule, error) {
	var msgs []json.RawMessage
	if err := json.Unmarshal(raw, &msgs); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadRules, err)
	}
	if len(msgs) < MinRules || len(msgs) > MaxRules {
		return nil, fmt.Errorf("%w: a policy needs between %d and %d rules, not %d",
			ErrBadRules, MinRules, MaxRules, len(msgs))
	}
	rules := make([]Rule, 0, len(msgs))
	for i, m := range msgs {
		r, err := parseRule(m)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i+1, err)
		}
		rules = append(rules, r)
	}
	return rules, nil
}

// allowedFields lists the JSON keys (besides "type") that mean something for
// one rule type. A flat Rule struct is fine for evaluation, since "hours"
// means the same thing for both within-rules and "name" for both software
// rules, but parsing must not let a field meant for one type quietly apply to
// another (a "hours" on a no_pending_reboot rule, say) - that is exactly the
// kind of typo strict parsing exists to catch. ok is false for an
// unsupported (or missing) type.
func allowedFields(ruleType string) (fields map[string]bool, ok bool) {
	one := func(name string) map[string]bool { return map[string]bool{name: true} }
	switch ruleType {
	case RuleOSBuildMin:
		return one("build"), true
	case RuleAgentVersionMin:
		return one("version"), true
	case RuleBitLocker:
		return one("volumes"), true
	case RuleTPM:
		return one("min_version"), true
	case RuleCheckedInWithin, RuleInventoryWithin:
		return one("hours"), true
	case RuleUpdatesWithin:
		return one("days"), true
	case RuleNoPendingReboot:
		return map[string]bool{}, true
	case RuleMaxLocalAdmins:
		return one("count"), true
	case RuleForbiddenSoftware, RuleRequiredSoftware:
		return one("name"), true
	case RuleProfileApplied:
		return one("profile_id"), true
	}
	return nil, false
}

func parseRule(raw json.RawMessage) (Rule, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return Rule{}, fmt.Errorf("%w: %v", ErrBadRules, err)
	}

	var ruleType string
	if v, ok := m["type"]; ok {
		if err := json.Unmarshal(v, &ruleType); err != nil {
			return Rule{}, fmt.Errorf("%w: type must be a string: %v", ErrBadRules, err)
		}
		delete(m, "type")
	}

	allowed, known := allowedFields(ruleType)
	if !known {
		if ruleType == "" {
			return Rule{}, fmt.Errorf("%w: every rule needs a type", ErrBadRules)
		}
		return Rule{}, fmt.Errorf("%w: unsupported rule type %q", ErrBadRules, ruleType)
	}
	// A field present but not among this type's own parameters is rejected
	// by name and type, distinct from a field no type recognises at all -
	// both are still "unknown" in the sense DisallowUnknownFields caught
	// before, but naming the type here is what makes a leaked field (e.g.
	// "hours" on a no_pending_reboot rule) as loud as a typo'd key.
	for field := range m {
		if !allowed[field] {
			return Rule{}, fmt.Errorf("%w: field %q does not apply to rule type %q", ErrBadRules, field, ruleType)
		}
	}

	switch ruleType {
	case RuleOSBuildMin:
		build, _, err := stringField(m, "build")
		if err != nil {
			return Rule{}, err
		}
		if !dottedNumeric(build) {
			return Rule{}, fmt.Errorf("%w: build must be digits, optionally dotted, not %q", ErrBadRules, build)
		}
		return Rule{Type: ruleType, Build: build}, nil

	case RuleAgentVersionMin:
		version, _, err := stringField(m, "version")
		if err != nil {
			return Rule{}, err
		}
		if !dottedNumeric(version) {
			return Rule{}, fmt.Errorf("%w: version must be a dotted numeric version, not %q", ErrBadRules, version)
		}
		return Rule{Type: ruleType, Version: version}, nil

	case RuleBitLocker:
		volumes, _, err := stringField(m, "volumes")
		if err != nil {
			return Rule{}, err
		}
		if volumes != VolumesSystem && volumes != VolumesAll {
			return Rule{}, fmt.Errorf("%w: volumes must be %q or %q, not %q", ErrBadRules, VolumesSystem, VolumesAll, volumes)
		}
		return Rule{Type: ruleType, Volumes: volumes}, nil

	case RuleTPM:
		minVersion, present, err := stringField(m, "min_version")
		if err != nil {
			return Rule{}, err
		}
		if present && minVersion != "" && !dottedNumeric(minVersion) {
			return Rule{}, fmt.Errorf("%w: min_version must be a dotted numeric version, not %q", ErrBadRules, minVersion)
		}
		return Rule{Type: ruleType, MinVersion: minVersion}, nil

	case RuleCheckedInWithin, RuleInventoryWithin:
		hours, present, err := intField(m, "hours")
		if err != nil {
			return Rule{}, err
		}
		if !present || hours < MinHours || hours > MaxHours {
			return Rule{}, fmt.Errorf("%w: hours must be between %d and %d, not %d", ErrBadRules, MinHours, MaxHours, hours)
		}
		return Rule{Type: ruleType, Hours: hours}, nil

	case RuleUpdatesWithin:
		days, present, err := intField(m, "days")
		if err != nil {
			return Rule{}, err
		}
		if !present || days < MinDays || days > MaxDays {
			return Rule{}, fmt.Errorf("%w: days must be between %d and %d, not %d", ErrBadRules, MinDays, MaxDays, days)
		}
		return Rule{Type: ruleType, Days: days}, nil

	case RuleNoPendingReboot:
		return Rule{Type: ruleType}, nil

	case RuleMaxLocalAdmins:
		count, present, err := intField(m, "count")
		if err != nil {
			return Rule{}, err
		}
		if !present || count < MinAdmins || count > MaxAdmins {
			return Rule{}, fmt.Errorf("%w: count must be between %d and %d, not %d", ErrBadRules, MinAdmins, MaxAdmins, count)
		}
		return Rule{Type: ruleType, Count: count}, nil

	case RuleForbiddenSoftware, RuleRequiredSoftware:
		name, _, err := stringField(m, "name")
		if err != nil {
			return Rule{}, err
		}
		if len(name) < MinNameLen || len(name) > MaxNameLen {
			return Rule{}, fmt.Errorf("%w: name must be between %d and %d characters, got %d",
				ErrBadRules, MinNameLen, MaxNameLen, len(name))
		}
		return Rule{Type: ruleType, Name: name}, nil

	case RuleProfileApplied:
		profileID, present, err := stringField(m, "profile_id")
		if err != nil {
			return Rule{}, err
		}
		if !present {
			return Rule{}, fmt.Errorf("%w: profile_id is required", ErrBadRules)
		}
		id, err := uuid.Parse(profileID)
		if err != nil {
			return Rule{}, fmt.Errorf("%w: profile_id must be a uuid: %v", ErrBadRules, err)
		}
		return Rule{Type: ruleType, ProfileID: id}, nil
	}
	// allowedFields already rejected any other ruleType.
	panic("unreachable")
}

// stringField reads a string-typed key from a rule's raw fields. present is
// false when the key was absent, distinct from it being set to "": tpm's
// optional min_version is the one caller that needs to tell "not given" from
// "given as empty".
func stringField(m map[string]json.RawMessage, key string) (value string, present bool, err error) {
	raw, ok := m[key]
	if !ok {
		return "", false, nil
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", true, fmt.Errorf("%w: %s must be a string: %v", ErrBadRules, key, err)
	}
	return value, true, nil
}

// intField reads a number-typed key. present is false when the key was
// absent, which is what lets max_local_admins accept an explicit count: 0
// while still rejecting a rule that never mentions count at all.
func intField(m map[string]json.RawMessage, key string) (value int, present bool, err error) {
	raw, ok := m[key]
	if !ok {
		return 0, false, nil
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return 0, true, fmt.Errorf("%w: %s must be a whole number: %v", ErrBadRules, key, err)
	}
	return value, true, nil
}

// MarshalJSON writes only the parameters that matter for this rule's type, so
// a policy's stored rules read as a person wrote them rather than carrying
// every other type's unused zero values.
func (r Rule) MarshalJSON() ([]byte, error) {
	switch r.Type {
	case RuleOSBuildMin:
		return json.Marshal(struct {
			Type  string `json:"type"`
			Build string `json:"build"`
		}{r.Type, r.Build})

	case RuleAgentVersionMin:
		return json.Marshal(struct {
			Type    string `json:"type"`
			Version string `json:"version"`
		}{r.Type, r.Version})

	case RuleBitLocker:
		return json.Marshal(struct {
			Type    string `json:"type"`
			Volumes string `json:"volumes"`
		}{r.Type, r.Volumes})

	case RuleTPM:
		return json.Marshal(struct {
			Type       string `json:"type"`
			MinVersion string `json:"min_version,omitempty"`
		}{r.Type, r.MinVersion})

	case RuleCheckedInWithin, RuleInventoryWithin:
		return json.Marshal(struct {
			Type  string `json:"type"`
			Hours int    `json:"hours"`
		}{r.Type, r.Hours})

	case RuleUpdatesWithin:
		return json.Marshal(struct {
			Type string `json:"type"`
			Days int    `json:"days"`
		}{r.Type, r.Days})

	case RuleNoPendingReboot:
		return json.Marshal(struct {
			Type string `json:"type"`
		}{r.Type})

	case RuleMaxLocalAdmins:
		return json.Marshal(struct {
			Type  string `json:"type"`
			Count int    `json:"count"`
		}{r.Type, r.Count})

	case RuleForbiddenSoftware, RuleRequiredSoftware:
		return json.Marshal(struct {
			Type string `json:"type"`
			Name string `json:"name"`
		}{r.Type, r.Name})

	case RuleProfileApplied:
		return json.Marshal(struct {
			Type      string    `json:"type"`
			ProfileID uuid.UUID `json:"profile_id"`
		}{r.Type, r.ProfileID})
	}
	return nil, fmt.Errorf("%w: unsupported rule type %q", ErrBadRules, r.Type)
}

// MarshalRules is the canonical encoding of a whole policy's rules: what gets
// stored in compliance_policies.rules, so an edit that only reorders JSON
// keys does not look like a change.
func MarshalRules(rules []Rule) ([]byte, error) {
	return json.Marshal(rules)
}

// Failure is one rule that did not come back compliant.
type Failure struct {
	Rule   string `json:"rule"`
	State  string `json:"state"`
	Detail string `json:"detail"`
}

// Result is a whole policy's outcome for one device.
type Result struct {
	State    string    `json:"state"`
	Failures []Failure `json:"failures"`
}

// Facts is everything the evaluator may look at. It carries no methods and no
// database handle, by design: Evaluate is a pure function of Facts and now.
type Facts struct {
	Device    store.Device
	Inventory *protocol.Inventory
	// InventoryReceivedAt is when the inventory currently on file arrived,
	// distinct from anything inside it, so inventory_within does not need
	// Inventory.CollectedAt (which is the agent's clock, not the server's).
	InventoryReceivedAt *time.Time
	// ProfileStatus is the device's item_status for kind "profile", keyed by
	// profile id, as store.ItemSucceeded/ItemFailed/ItemPending/ItemConflict/
	// ItemNotApplicable.
	ProfileStatus map[uuid.UUID]string
}

// Evaluate checks every rule against f and rolls the results up: any
// non-compliant rule makes the policy non_compliant, else any unknown makes
// it unknown, else it is compliant. Failures are returned in rule order, not
// grouped by state, so the same rules and facts always produce the same
// Result byte-for-byte.
func Evaluate(rules []Rule, f Facts, now time.Time) Result {
	var failures []Failure
	for _, r := range rules {
		if failure, ok := evaluateRule(r, f, now); ok {
			failures = append(failures, failure)
		}
	}
	state := StateCompliant
	for _, fl := range failures {
		if fl.State == StateNonCompliant {
			state = StateNonCompliant
			break
		}
	}
	if state == StateCompliant {
		for _, fl := range failures {
			if fl.State == StateUnknown {
				state = StateUnknown
				break
			}
		}
	}
	return Result{State: state, Failures: failures}
}

// evaluateRule reports whether r failed (non-compliant or unknown) against f,
// and if so what to say about it. false means the rule is met.
func evaluateRule(r Rule, f Facts, now time.Time) (Failure, bool) {
	switch r.Type {
	case RuleOSBuildMin:
		return evalOSBuildMin(r, f)
	case RuleAgentVersionMin:
		return evalAgentVersionMin(r, f)
	case RuleBitLocker:
		return evalBitLocker(r, f)
	case RuleTPM:
		return evalTPM(r, f)
	case RuleCheckedInWithin:
		return evalCheckedInWithin(r, f, now)
	case RuleInventoryWithin:
		return evalInventoryWithin(r, f, now)
	case RuleUpdatesWithin:
		return evalUpdatesWithin(r, f, now)
	case RuleNoPendingReboot:
		return evalNoPendingReboot(r, f)
	case RuleMaxLocalAdmins:
		return evalMaxLocalAdmins(r, f)
	case RuleForbiddenSoftware:
		return evalForbiddenSoftware(r, f)
	case RuleRequiredSoftware:
		return evalRequiredSoftware(r, f)
	case RuleProfileApplied:
		return evalProfileApplied(r, f)
	}
	// ParseRules never produces any other Type, so this is unreachable in
	// practice; treat it the same as any other fact the evaluator cannot
	// make sense of.
	return unknownFailure(r.Type, fmt.Sprintf("unsupported rule type %q", r.Type)), true
}

func evalOSBuildMin(r Rule, f Facts) (Failure, bool) {
	build := f.Device.OSBuild
	if build == "" {
		return unknownFailure(r.Type, "the device has not reported an OS build"), true
	}
	cmp, ok := CompareDotted(build, r.Build)
	if !ok {
		return unknownFailure(r.Type, fmt.Sprintf("the OS build %q could not be compared to %q", build, r.Build)), true
	}
	if cmp < 0 {
		return nonCompliant(r.Type, fmt.Sprintf("the OS build is %s, below the required %s", build, r.Build)), true
	}
	return Failure{}, false
}

func evalAgentVersionMin(r Rule, f Facts) (Failure, bool) {
	v := f.Device.AgentVersion
	if !dottedNumeric(v) {
		detail := "the agent version is not reported"
		if v != "" {
			detail = fmt.Sprintf("the agent version %q is not a dotted version number", v)
		}
		return unknownFailure(r.Type, detail), true
	}
	// r.Version was already validated as dotted-numeric at parse time.
	cmp, _ := CompareDotted(v, r.Version)
	if cmp < 0 {
		return nonCompliant(r.Type, fmt.Sprintf("the agent version is %s, below the required %s", v, r.Version)), true
	}
	return Failure{}, false
}

func evalBitLocker(r Rule, f Facts) (Failure, bool) {
	if f.Inventory == nil {
		return unknownFailure(r.Type, "no inventory has been received"), true
	}
	if r.Volumes == VolumesSystem {
		d, found := systemVolume(f.Inventory.Disks)
		if !found {
			return unknownFailure(r.Type, "no system volume was reported"), true
		}
		return bitlockerFailure(r.Type, d)
	}
	// volumes: all. Zero reported fixed volumes is not vacuously compliant -
	// it means inventory did not tell us anything about disks at all, which
	// is the same kind of gap as no inventory being received.
	if len(f.Inventory.Disks) == 0 {
		return unknownFailure(r.Type, "the device reported no fixed volumes"), true
	}
	// A volume reporting unknown outranks one reporting off, since
	// "unknown" means the agent could not tell either way, and an
	// administrator should learn that before being told a specific drive is
	// unencrypted.
	for _, d := range f.Inventory.Disks {
		if d.BitLocker == "unknown" {
			return unknownFailure(r.Type, fmt.Sprintf("BitLocker status is unknown for %s", d.Name)), true
		}
	}
	for _, d := range f.Inventory.Disks {
		if d.BitLocker == "off" {
			return nonCompliant(r.Type, fmt.Sprintf("BitLocker is off on %s", d.Name)), true
		}
	}
	return Failure{}, false
}

func bitlockerFailure(ruleType string, d protocol.Disk) (Failure, bool) {
	switch d.BitLocker {
	case "on":
		return Failure{}, false
	case "off":
		return nonCompliant(ruleType, fmt.Sprintf("BitLocker is off on %s", d.Name)), true
	default:
		return unknownFailure(ruleType, fmt.Sprintf("BitLocker status is unknown for %s", d.Name)), true
	}
}

// systemVolume finds the disk named "C:", tolerating a trailing backslash and
// any case, since that is how Windows reports it and how an administrator
// might type it.
func systemVolume(disks []protocol.Disk) (protocol.Disk, bool) {
	for _, d := range disks {
		name := strings.ToUpper(strings.TrimSuffix(strings.TrimSpace(d.Name), `\`))
		if name == "C:" {
			return d, true
		}
	}
	return protocol.Disk{}, false
}

func evalTPM(r Rule, f Facts) (Failure, bool) {
	if f.Inventory == nil {
		return unknownFailure(r.Type, "no inventory has been received"), true
	}
	hw := f.Inventory.Hardware
	if !hw.TPMPresent {
		return nonCompliant(r.Type, "no TPM is present"), true
	}
	if r.MinVersion == "" {
		return Failure{}, false
	}
	// A TPM that is present but whose version did not come back is a hole in
	// what was collected, not a TPM that fails the floor - the same reading
	// agent_version_min takes of a device that has not reported its version.
	if !dottedNumeric(hw.TPMVersion) {
		return unknownFailure(r.Type, "the TPM version is not reported"), true
	}
	cmp, _ := CompareDotted(hw.TPMVersion, r.MinVersion)
	if cmp < 0 {
		return nonCompliant(r.Type, fmt.Sprintf("the TPM version is %s, below the required %s", hw.TPMVersion, r.MinVersion)), true
	}
	return Failure{}, false
}

func evalCheckedInWithin(r Rule, f Facts, now time.Time) (Failure, bool) {
	if f.Device.LastSeenAt == nil {
		return unknownFailure(r.Type, "the device has never checked in"), true
	}
	elapsed := now.Sub(*f.Device.LastSeenAt)
	if elapsed > time.Duration(r.Hours)*time.Hour {
		return nonCompliant(r.Type, fmt.Sprintf("last check-in was %s ago (limit %s)",
			humanizeSince(elapsed), plural(r.Hours, "hour"))), true
	}
	return Failure{}, false
}

func evalInventoryWithin(r Rule, f Facts, now time.Time) (Failure, bool) {
	if f.InventoryReceivedAt == nil {
		return unknownFailure(r.Type, "inventory has never been received"), true
	}
	elapsed := now.Sub(*f.InventoryReceivedAt)
	if elapsed > time.Duration(r.Hours)*time.Hour {
		return nonCompliant(r.Type, fmt.Sprintf("inventory was last received %s ago (limit %s)",
			humanizeSince(elapsed), plural(r.Hours, "hour"))), true
	}
	return Failure{}, false
}

func evalUpdatesWithin(r Rule, f Facts, now time.Time) (Failure, bool) {
	if f.Inventory == nil || f.Inventory.LastUpdateInstalledAt == nil {
		return unknownFailure(r.Type, "no update installation date has been reported"), true
	}
	elapsed := now.Sub(*f.Inventory.LastUpdateInstalledAt)
	if elapsed > time.Duration(r.Days)*24*time.Hour {
		return nonCompliant(r.Type, fmt.Sprintf("the last update was installed %s ago (limit %s)",
			humanizeSince(elapsed), plural(r.Days, "day"))), true
	}
	return Failure{}, false
}

func evalNoPendingReboot(r Rule, f Facts) (Failure, bool) {
	if f.Inventory == nil {
		return unknownFailure(r.Type, "no inventory has been received"), true
	}
	if f.Inventory.PendingReboot {
		return nonCompliant(r.Type, "a reboot is pending"), true
	}
	return Failure{}, false
}

func evalMaxLocalAdmins(r Rule, f Facts) (Failure, bool) {
	if f.Inventory == nil {
		return unknownFailure(r.Type, "no inventory has been received"), true
	}
	// An empty list is not a device with no administrators - every Windows
	// install has at least one. It means inventory said nothing about them,
	// and a limit checked against nothing must not read as met.
	if len(f.Inventory.LocalAdmins) == 0 {
		return unknownFailure(r.Type, "the device reported no local admins"), true
	}
	n := len(f.Inventory.LocalAdmins)
	if n > r.Count {
		return nonCompliant(r.Type, fmt.Sprintf("there are %d local admins, above the limit of %d", n, r.Count)), true
	}
	return Failure{}, false
}

func evalForbiddenSoftware(r Rule, f Facts) (Failure, bool) {
	if gap, unusable := softwareGap(r.Type, f); unusable {
		return gap, true
	}
	if found := matchSoftware(f.Inventory.Software, r.Name); found != "" {
		return nonCompliant(r.Type, fmt.Sprintf("forbidden software %q is installed", found)), true
	}
	return Failure{}, false
}

func evalRequiredSoftware(r Rule, f Facts) (Failure, bool) {
	if gap, unusable := softwareGap(r.Type, f); unusable {
		return gap, true
	}
	if found := matchSoftware(f.Inventory.Software, r.Name); found == "" {
		return nonCompliant(r.Type, fmt.Sprintf("required software matching %q is not installed", r.Name)), true
	}
	return Failure{}, false
}

// softwareGap reports the fact neither software rule can be evaluated
// against: no inventory at all, or an inventory listing no packages. An empty
// list is not a device with nothing installed; it means the agent told us
// nothing about software, so the absence of a match is not an answer in
// either direction - forbidden software would read as absent and required
// software as missing, and both would be guesses.
func softwareGap(ruleType string, f Facts) (Failure, bool) {
	if f.Inventory == nil {
		return unknownFailure(ruleType, "no inventory has been received"), true
	}
	if len(f.Inventory.Software) == 0 {
		return unknownFailure(ruleType, "the device reported no installed software"), true
	}
	return Failure{}, false
}

// matchSoftware returns the installed package name that contains name
// (case-insensitively), or "" if none does.
func matchSoftware(installed []protocol.Software, name string) string {
	lower := strings.ToLower(name)
	for _, s := range installed {
		if strings.Contains(strings.ToLower(s.Name), lower) {
			return s.Name
		}
	}
	return ""
}

func evalProfileApplied(r Rule, f Facts) (Failure, bool) {
	status, ok := f.ProfileStatus[r.ProfileID]
	if !ok || status == store.ItemPending {
		return unknownFailure(r.Type, "the profile has not finished applying"), true
	}
	if status != store.ItemSucceeded {
		return nonCompliant(r.Type, fmt.Sprintf("the profile's status is %s, not succeeded", status)), true
	}
	return Failure{}, false
}

// humanizeSince says how long ago something happened in the unit a person
// would use for it: hours for anything inside two days, whole days beyond
// that. The within-rules are most often configured in hours - the console
// offers 24 by default - and rounding those down to whole days turned a real
// breach into a sentence claiming the device was fine ("last check-in was 0
// days ago (limit 6 hours)"). Truncating rather than rounding keeps the number
// a lower bound, so the detail never overstates how stale a device is.
func humanizeSince(elapsed time.Duration) string {
	if elapsed < 48*time.Hour {
		return plural(int(elapsed.Hours()), "hour")
	}
	return plural(int(elapsed.Hours()/24), "day")
}

// plural renders a count with its unit, so a detail never reads "1 days".
func plural(n int, unit string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", unit)
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

func unknownFailure(rule, detail string) Failure {
	return Failure{Rule: rule, State: StateUnknown, Detail: detail}
}

func nonCompliant(rule, detail string) Failure {
	return Failure{Rule: rule, State: StateNonCompliant, Detail: detail}
}

// CompareDotted compares two dotted-numeric strings ("26100", "1.2.3")
// segment by segment, as integers, not lexically ("2.0" must sort before
// "10.0"). Missing trailing segments compare as zero, so "26100" equals
// "26100.0". ok is false when either string is empty or contains anything
// but digits and dots.
func CompareDotted(a, b string) (int, bool) {
	as, ok := splitDotted(a)
	if !ok {
		return 0, false
	}
	bs, ok := splitDotted(b)
	if !ok {
		return 0, false
	}
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		var av, bv int
		if i < len(as) {
			av = as[i]
		}
		if i < len(bs) {
			bv = bs[i]
		}
		if av != bv {
			if av < bv {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}

func splitDotted(s string) ([]int, bool) {
	if s == "" {
		return nil, false
	}
	parts := strings.Split(s, ".")
	out := make([]int, len(parts))
	for i, p := range parts {
		if p == "" {
			return nil, false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return nil, false
			}
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, false
		}
		out[i] = n
	}
	return out, true
}

func dottedNumeric(s string) bool {
	_, ok := splitDotted(s)
	return ok
}
