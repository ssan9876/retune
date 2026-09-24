//go:build darwin

package inventory

import (
	"context"
	"testing"
)

// TestCollectOnMac collects from the Mac running the test: every tool the
// collector reads must be there and print what the parsers expect.
func TestCollectOnMac(t *testing.T) {
	inv, err := NewCollector().Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("os=%+v hardware=%+v disks=%+v firewall=%+v users=%d admins=%v software=%d adapters=%d",
		inv.OS, inv.Hardware, inv.Disks, inv.Firewall, len(inv.LocalUsers), inv.LocalAdmins, len(inv.Software), len(inv.NetworkAdapters))
	if inv.OS.Name != "macOS" || inv.OS.Version == "" || inv.OS.Build == "" {
		t.Errorf("os = %+v", inv.OS)
	}
	if inv.OS.LastBoot == nil {
		t.Error("no boot time")
	}
	if inv.Hardware.Model == "" || inv.Hardware.SMBIOSUUID == "" || inv.Hardware.RAMBytes == 0 || inv.Hardware.CPULogical == 0 {
		t.Errorf("hardware = %+v", inv.Hardware)
	}
	if len(inv.Disks) != 1 || inv.Disks[0].SizeBytes == 0 || inv.Disks[0].FileSystem == "" {
		t.Errorf("disks = %+v", inv.Disks)
	}
	if len(inv.LocalAdmins) == 0 {
		t.Error("no admin group members")
	}
	if _, uuid := HardwareIdentity(); uuid != inv.Hardware.SMBIOSUUID {
		t.Errorf("HardwareIdentity uuid = %q, inventory %q", uuid, inv.Hardware.SMBIOSUUID)
	}
}
