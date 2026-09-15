// Package compliance is the pure rule engine behind M12 compliance policies:
// parsing a policy's rules JSON and evaluating it against a device's facts.
// Nothing here touches a database or the network, so every rule is
// table-tested without either.
package compliance

import (
	"bytes"
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

// wireRule is the strict JSON shape ParseRules decodes each element into.
// DisallowUnknownFields on this rejects any key that is not a parameter of
// some rule type, which is what "unknown field" means here.
type wireRule struct {
	Type       string `json:"type"`
	Build      string `json:"build"`
	Version    string `json:"version"`
	Volumes    string `json:"volumes"`
	MinVersion string `json:"min_version"`
	Hours      int    `json:"hours"`
	Days       int    `json:"days"`
	Count      int    `json:"count"`
	Name       string `json:"name"`
	ProfileID  string `json:"profile_id"`
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

func parseRule(raw json.RawMessage) (Rule, error) {
	var w wireRule
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil {
		return Rule{}, fmt.Errorf("%w: %v", ErrBadRules, err)
	}

	switch w.Type {
	case RuleOSBuildMin:
		if !dottedNumeric(w.Build) {
			return Rule{}, fmt.Errorf("%w: build must be digits, optionally dotted, not %q", ErrBadRules, w.Build)
		}
		return Rule{Type: w.Type, Build: w.Build}, nil

	case RuleAgentVersionMin:
		if !dottedNumeric(w.Version) {
			return Rule{}, fmt.Errorf("%w: version must be a dotted numeric version, not %q", ErrBadRules, w.Version)
		}
		return Rule{Type: w.Type, Version: w.Version}, nil

	case RuleBitLocker:
		if w.Volumes != VolumesSystem && w.Volumes != VolumesAll {
			return Rule{}, fmt.Errorf("%w: volumes must be %q or %q, not %q", ErrBadRules, VolumesSystem, VolumesAll, w.Volumes)
		}
		return Rule{Type: w.Type, Volumes: w.Volumes}, nil

	case RuleTPM:
		if w.MinVersion != "" && !dottedNumeric(w.MinVersion) {
			return Rule{}, fmt.Errorf("%w: min_version must be a dotted numeric version, not %q", ErrBadRules, w.MinVersion)
		}
		return Rule{Type: w.Type, MinVersion: w.MinVersion}, nil

	case RuleCheckedInWithin:
		if w.Hours < MinHours || w.Hours > MaxHours {
			return Rule{}, fmt.Errorf("%w: hours must be between %d and %d, not %d", ErrBadRules, MinHours, MaxHours, w.Hours)
		}
		return Rule{Type: w.Type, Hours: w.Hours}, nil

	case RuleInventoryWithin:
		if w.Hours < MinHours || w.Hours > MaxHours {
			return Rule{}, fmt.Errorf("%w: hours must be between %d and %d, not %d", ErrBadRules, MinHours, MaxHours, w.Hours)
		}
		return Rule{Type: w.Type, Hours: w.Hours}, nil

	case RuleUpdatesWithin:
		if w.Days < MinDays || w.Days > MaxDays {
			return Rule{}, fmt.Errorf("%w: days must be between %d and %d, not %d", ErrBadRules, MinDays, MaxDays, w.Days)
		}
		return Rule{Type: w.Type, Days: w.Days}, nil

	case RuleNoPendingReboot:
		return Rule{Type: w.Type}, nil

	case RuleMaxLocalAdmins:
		if w.Count < MinAdmins || w.Count > MaxAdmins {
			return Rule{}, fmt.Errorf("%w: count must be between %d and %d, not %d", ErrBadRules, MinAdmins, MaxAdmins, w.Count)
		}
		return Rule{Type: w.Type, Count: w.Count}, nil

	case RuleForbiddenSoftware, RuleRequiredSoftware:
		if len(w.Name) < MinNameLen || len(w.Name) > MaxNameLen {
			return Rule{}, fmt.Errorf("%w: name must be between %d and %d characters, got %d",
				ErrBadRules, MinNameLen, MaxNameLen, len(w.Name))
		}
		return Rule{Type: w.Type, Name: w.Name}, nil

	case RuleProfileApplied:
		id, err := uuid.Parse(w.ProfileID)
		if err != nil {
			return Rule{}, fmt.Errorf("%w: profile_id must be a uuid: %v", ErrBadRules, err)
		}
		return Rule{Type: w.Type, ProfileID: id}, nil

	case "":
		return Rule{}, fmt.Errorf("%w: every rule needs a type", ErrBadRules)
	default:
		return Rule{}, fmt.Errorf("%w: unsupported rule type %q", ErrBadRules, w.Type)
	}
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
	// volumes: all. A volume reporting unknown outranks one reporting off,
	// since "unknown" means the agent could not tell either way, and an
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
	if !dottedNumeric(hw.TPMVersion) {
		return nonCompliant(r.Type, "the TPM version is not reported"), true
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
		days := int(elapsed.Hours() / 24)
		return nonCompliant(r.Type, fmt.Sprintf("last check-in was %d days ago (limit %d hours)", days, r.Hours)), true
	}
	return Failure{}, false
}

func evalInventoryWithin(r Rule, f Facts, now time.Time) (Failure, bool) {
	if f.InventoryReceivedAt == nil {
		return unknownFailure(r.Type, "inventory has never been received"), true
	}
	elapsed := now.Sub(*f.InventoryReceivedAt)
	if elapsed > time.Duration(r.Hours)*time.Hour {
		days := int(elapsed.Hours() / 24)
		return nonCompliant(r.Type, fmt.Sprintf("inventory was last received %d days ago (limit %d hours)", days, r.Hours)), true
	}
	return Failure{}, false
}

func evalUpdatesWithin(r Rule, f Facts, now time.Time) (Failure, bool) {
	if f.Inventory == nil || f.Inventory.LastUpdateInstalledAt == nil {
		return unknownFailure(r.Type, "no update installation date has been reported"), true
	}
	elapsed := now.Sub(*f.Inventory.LastUpdateInstalledAt)
	if elapsed > time.Duration(r.Days)*24*time.Hour {
		days := int(elapsed.Hours() / 24)
		return nonCompliant(r.Type, fmt.Sprintf("the last update was installed %d days ago (limit %d days)", days, r.Days)), true
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
	n := len(f.Inventory.LocalAdmins)
	if n > r.Count {
		return nonCompliant(r.Type, fmt.Sprintf("there are %d local admins, above the limit of %d", n, r.Count)), true
	}
	return Failure{}, false
}

func evalForbiddenSoftware(r Rule, f Facts) (Failure, bool) {
	if f.Inventory == nil {
		return unknownFailure(r.Type, "no inventory has been received"), true
	}
	if found := matchSoftware(f.Inventory.Software, r.Name); found != "" {
		return nonCompliant(r.Type, fmt.Sprintf("forbidden software %q is installed", found)), true
	}
	return Failure{}, false
}

func evalRequiredSoftware(r Rule, f Facts) (Failure, bool) {
	if f.Inventory == nil {
		return unknownFailure(r.Type, "no inventory has been received"), true
	}
	if found := matchSoftware(f.Inventory.Software, r.Name); found == "" {
		return nonCompliant(r.Type, fmt.Sprintf("required software matching %q is not installed", r.Name)), true
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
