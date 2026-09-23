//go:build windows

package inventory

import (
	"context"
	"strings"
	"testing"
)

// TestCollectOnThisMachine checks the real collector against the host it runs
// on. BitLocker, TPM and admin-group data need elevation, so they are not
// asserted here.
func TestCollectOnThisMachine(t *testing.T) {
	inv, err := NewCollector().Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if inv.Hostname == "" || inv.CollectedAt.IsZero() {
		t.Fatalf("inventory = %+v", inv)
	}
	if !strings.Contains(inv.OS.Name, "Windows") || inv.OS.Build == "" || inv.OS.Version == "" {
		t.Fatalf("OS = %+v", inv.OS)
	}
	// Every supported Windows has been patched past its release build.
	if inv.OS.UBR == nil || *inv.OS.UBR <= 0 {
		t.Fatalf("UBR = %v, want the update build revision", inv.OS.UBR)
	}
	if inv.Hardware.RAMBytes == 0 || inv.Hardware.CPU == "" || inv.Hardware.CPULogical == 0 {
		t.Fatalf("hardware = %+v", inv.Hardware)
	}
	if len(inv.Disks) == 0 {
		t.Fatal("expected at least one fixed disk")
	}
	if len(inv.Software) == 0 {
		t.Fatal("expected at least one installed package")
	}
	if len(inv.LocalUsers) == 0 {
		t.Fatal("expected at least one local user")
	}
}

func TestHardwareIdentityOnThisMachine(t *testing.T) {
	serial, smbios := HardwareIdentity()
	t.Logf("serial=%q smbios=%q logged in=%q", serial, smbios, LoggedInUser())
	if strings.TrimSpace(serial) != serial || strings.TrimSpace(smbios) != smbios {
		t.Fatal("identity values must be trimmed")
	}
}

// Reading Defender and the firewall is read-only, so it is checked against
// the real machine. Whether either is on is this machine's business; the test
// only asserts that the answers came back in the shape the server expects.
func TestSecurityStateOnThisMachine(t *testing.T) {
	if d := collectDefender(); d != nil && d.RunningMode == "" {
		t.Errorf("Defender answered without a running mode: %+v", d)
	}
	fw := collectFirewall()
	if len(fw) != 3 {
		t.Fatalf("expected all three firewall profiles, got %+v", fw)
	}
	for _, p := range fw {
		switch p.Profile {
		case "domain", "private", "public":
		default:
			t.Errorf("unexpected profile %q", p.Profile)
		}
	}
}
