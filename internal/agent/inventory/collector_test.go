package inventory

import (
	"testing"
	"time"
)

func TestNormalizeSoftware(t *testing.T) {
	entries := []UninstallEntry{
		{DisplayName: "Git", DisplayVersion: "2.51.0", Publisher: "Git Dev"},
		{DisplayName: "7-Zip", DisplayVersion: "24.08"},
		{DisplayName: "Git", DisplayVersion: "2.51.0", Publisher: "Git Dev"}, // 32- and 64-bit duplicate
		{DisplayName: "  ", DisplayVersion: "1"},                             // no name
		{DisplayName: "Hidden", SystemComponent: 1},                          // system component
		{DisplayName: "KB12345", ParentKeyName: "Office"},                    // update of another product
		{DisplayName: "Go", DisplayVersion: "1.27", InstallDate: "20260901"},
	}
	got := NormalizeSoftware(entries, "machine")
	if len(got) != 3 {
		t.Fatalf("got %d packages: %+v", len(got), got)
	}
	if got[0].Name != "7-Zip" || got[1].Name != "Git" || got[2].Name != "Go" {
		t.Fatalf("unexpected order or filtering: %+v", got)
	}
	if got[1].Publisher != "Git Dev" || got[1].Scope != "machine" || got[2].InstallDate != "20260901" {
		t.Fatalf("fields not carried over: %+v", got)
	}
	if NormalizeSoftware(nil, "user") != nil {
		t.Fatal("no entries must give no packages")
	}
}

func TestCleanSerialAndUUID(t *testing.T) {
	junk := []string{"", "  ", "0", "None", "Default string", "To Be Filled By O.E.M.", "System Serial Number"}
	for _, s := range junk {
		if got := CleanSerial(s); got != "" {
			t.Errorf("CleanSerial(%q) = %q, want empty", s, got)
		}
	}
	if got := CleanSerial("  ABC123 "); got != "ABC123" {
		t.Errorf("CleanSerial = %q", got)
	}

	junkUUIDs := []string{"", "00000000-0000-0000-0000-000000000000", "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF", "03000200-0400-0500-0006-000700080009"}
	for _, s := range junkUUIDs {
		if got := CleanUUID(s); got != "" {
			t.Errorf("CleanUUID(%q) = %q, want empty", s, got)
		}
	}
	if got := CleanUUID(" 4c4c4544-0044-3610 "); got != "4C4C4544-0044-3610" {
		t.Errorf("CleanUUID = %q", got)
	}
}

func TestParseQFEDate(t *testing.T) {
	for _, in := range []string{"9/12/2026", "09/12/2026", "2026-09-12"} {
		got, ok := ParseQFEDate(in)
		if !ok || got.Year() != 2026 || got.Month() != time.September || got.Day() != 12 {
			t.Errorf("ParseQFEDate(%q) = %s, %v", in, got, ok)
		}
	}
	if _, ok := ParseQFEDate("not a date"); ok {
		t.Error("unparseable dates must report false")
	}
}
