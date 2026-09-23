package inventory

import (
	"time"

	"retune/internal/protocol"
)

// DefenderRow is what WMI's MSFT_MpComputerStatus gives back, reduced to the
// properties inventory reports. It lives outside the Windows-only file so the
// mapping below is tested on every platform.
type DefenderRow struct {
	AMRunningMode                 string
	AntivirusEnabled              bool
	RealTimeProtectionEnabled     bool
	IsTamperProtected             bool
	AntivirusSignatureVersion     string
	AntivirusSignatureLastUpdated time.Time
	QuickScanEndTime              time.Time
	FullScanEndTime               time.Time
}

// DefenderFromRows maps a Defender status query to inventory. No rows means
// Defender reported nothing - it is not installed, or another antivirus has
// removed it - which is nil, not "off": the server reads nil as unknown
// rather than guessing.
func DefenderFromRows(rows []DefenderRow) *protocol.DefenderStatus {
	if len(rows) == 0 {
		return nil
	}
	r := rows[0]
	return &protocol.DefenderStatus{
		RunningMode:      r.AMRunningMode,
		AntivirusEnabled: r.AntivirusEnabled,
		RealtimeEnabled:  r.RealTimeProtectionEnabled,
		TamperProtected:  r.IsTamperProtected,
		SignatureVersion: r.AntivirusSignatureVersion,
		// Defender reports a scan it has never run as an empty date, which
		// WMI hands back as the zero time.
		SignatureUpdatedAt: timePtr(r.AntivirusSignatureLastUpdated),
		LastQuickScanAt:    timePtr(r.QuickScanEndTime),
		LastFullScanAt:     timePtr(r.FullScanEndTime),
	}
}

// Firewall profile types, as the Windows firewall API numbers them.
const (
	fwProfileDomain  = 1
	fwProfilePrivate = 2
	fwProfilePublic  = 4
)

// firewallProfiles pairs each API profile type with its protocol name, in the
// order they are reported.
var firewallProfiles = []struct {
	Type int
	Name string
}{
	{fwProfileDomain, protocol.FirewallDomain},
	{fwProfilePrivate, protocol.FirewallPrivate},
	{fwProfilePublic, protocol.FirewallPublic},
}

// FirewallFromStates maps the firewall API's answers, keyed by profile type,
// to inventory. A profile the API did not answer for is left out rather than
// reported off; with no answers at all the result is nil.
func FirewallFromStates(enabled map[int]bool) []protocol.FirewallProfileState {
	var out []protocol.FirewallProfileState
	for _, p := range firewallProfiles {
		on, ok := enabled[p.Type]
		if !ok {
			continue
		}
		out = append(out, protocol.FirewallProfileState{Profile: p.Name, Enabled: on})
	}
	return out
}
