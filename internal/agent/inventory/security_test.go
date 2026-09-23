package inventory

import (
	"testing"
	"time"

	"retune/internal/protocol"
)

func TestDefenderFromRows(t *testing.T) {
	if DefenderFromRows(nil) != nil {
		t.Fatal("no rows means Defender reported nothing: nil, not a zero status")
	}
	updated := time.Date(2026, 9, 22, 7, 52, 33, 0, time.FixedZone("PDT", -7*3600))
	got := DefenderFromRows([]DefenderRow{{
		AMRunningMode: "Normal", AntivirusEnabled: true, RealTimeProtectionEnabled: true,
		IsTamperProtected: true, AntivirusSignatureVersion: "1.459.335.0",
		AntivirusSignatureLastUpdated: updated, QuickScanEndTime: updated.Add(-24 * time.Hour),
	}})
	if got.RunningMode != "Normal" || !got.AntivirusEnabled || !got.RealtimeEnabled || !got.TamperProtected ||
		got.SignatureVersion != "1.459.335.0" {
		t.Fatalf("status = %+v", got)
	}
	if got.SignatureUpdatedAt == nil || !got.SignatureUpdatedAt.Equal(updated) || got.SignatureUpdatedAt.Location() != time.UTC {
		t.Errorf("signature time should be kept, in UTC: %v", got.SignatureUpdatedAt)
	}
	if got.LastQuickScanAt == nil {
		t.Error("a quick scan that ran should be reported")
	}
	if got.LastFullScanAt != nil {
		t.Errorf("a full scan that never ran comes back as the zero time and must be omitted, got %v", got.LastFullScanAt)
	}
}

func TestFirewallFromStates(t *testing.T) {
	if FirewallFromStates(nil) != nil {
		t.Fatal("no answers means no firewall block")
	}
	got := FirewallFromStates(map[int]bool{fwProfilePublic: false, fwProfileDomain: true})
	want := []protocol.FirewallProfileState{
		{Profile: protocol.FirewallDomain, Enabled: true},
		{Profile: protocol.FirewallPublic, Enabled: false},
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %+v, want %+v (a profile with no answer is left out, not reported off)", got, want)
	}
}
