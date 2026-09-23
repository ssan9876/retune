package protocol

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"
)

func sample() Inventory {
	boot := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	return Inventory{
		CollectedAt: time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC),
		Hostname:    "PC-1",
		OS:          OSInfo{Name: "Microsoft Windows 11 Pro", Version: "10.0.26200", Build: "26200", LastBoot: &boot},
		Hardware:    Hardware{Manufacturer: "Contoso", Model: "Book 9", Serial: "SN1", RAMBytes: 16 << 30},
		Disks:       []Disk{{Name: "C:", SizeBytes: 500 << 30, FreeBytes: 200 << 30}, {Name: "D:", SizeBytes: 100 << 30}},
		NetworkAdapters: []NetworkAdapter{
			{Name: "Wi-Fi", MAC: "00:11:22:33:44:55", IPs: []string{"10.0.0.5", "fe80::1"}},
			{Name: "Ethernet", MAC: "aa:bb:cc:dd:ee:ff", IPs: []string{"10.0.0.6"}},
		},
		Software:    []Software{{Name: "7-Zip", Version: "24.08", Scope: "machine"}, {Name: "Git", Version: "2.51.0", Scope: "machine"}},
		LocalUsers:  []LocalUser{{Name: "admin"}, {Name: "guest", Disabled: true}},
		LocalAdmins: []string{`PC-1\admin`, `PC-1\ops`},
	}
}

func TestInventoryHashIgnoresOrderAndTimes(t *testing.T) {
	a := sample()
	b := sample()
	b.CollectedAt = a.CollectedAt.Add(72 * time.Hour)
	later := a.OS.LastBoot.Add(time.Hour)
	b.OS.LastBoot = &later
	slices.Reverse(b.Disks)
	slices.Reverse(b.Software)
	slices.Reverse(b.NetworkAdapters)
	slices.Reverse(b.LocalUsers)
	slices.Reverse(b.LocalAdmins)
	slices.Reverse(b.NetworkAdapters[0].IPs)
	if InventoryHash(a) != InventoryHash(b) {
		t.Fatal("hash must ignore collection time, boot time and list order")
	}
	if b.Disks[0].Name != "D:" {
		t.Fatal("hashing must not reorder the caller's slices")
	}
}

func TestInventoryHashDetectsChanges(t *testing.T) {
	base := InventoryHash(sample())
	cases := map[string]func(*Inventory){
		"software version": func(i *Inventory) { i.Software[1].Version = "2.52.0" },
		"new package":      func(i *Inventory) { i.Software = append(i.Software, Software{Name: "Go", Version: "1.27"}) },
		"ram":              func(i *Inventory) { i.Hardware.RAMBytes = 32 << 30 },
		"free space":       func(i *Inventory) { i.Disks[0].FreeBytes = 1 << 30 },
		"hostname":         func(i *Inventory) { i.Hostname = "PC-2" },
		"admins":           func(i *Inventory) { i.LocalAdmins = append(i.LocalAdmins, `PC-1\eve`) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			inv := sample()
			mutate(&inv)
			if InventoryHash(inv) == base {
				t.Fatal("hash must change")
			}
		})
	}
}

func TestSoftwareHash(t *testing.T) {
	a := sample().Software
	b := slices.Clone(a)
	slices.Reverse(b)
	if SoftwareHash(a) != SoftwareHash(b) {
		t.Fatal("software hash must ignore order")
	}
	c := slices.Clone(a)
	c[0].Publisher = "Igor Pavlov"
	if SoftwareHash(c) == SoftwareHash(a) {
		t.Fatal("software hash must cover publisher")
	}
}

// An agent or server from before M15 neither sends nor expects the new
// blocks, so an inventory without them must encode exactly as it always did:
// otherwise every stored hash would change on upgrade and every device would
// re-upload at once.
func TestInventoryWithoutSecurityBlocksIsUnchanged(t *testing.T) {
	b, err := json.Marshal(Inventory{Hostname: "PC"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "defender") || strings.Contains(string(b), "firewall") {
		t.Fatalf("absent blocks must be omitted, got %s", b)
	}
	var back Inventory
	if err := json.Unmarshal([]byte(`{"hostname":"PC"}`), &back); err != nil || back.Defender != nil || back.Firewall != nil {
		t.Fatalf("an old document should parse with no security blocks: %+v %v", back, err)
	}
}

func TestInventoryHashIgnoresFirewallOrder(t *testing.T) {
	a := Inventory{Firewall: []FirewallProfileState{{Profile: FirewallDomain, Enabled: true}, {Profile: FirewallPublic}}}
	b := Inventory{Firewall: []FirewallProfileState{{Profile: FirewallPublic}, {Profile: FirewallDomain, Enabled: true}}}
	if InventoryHash(a) != InventoryHash(b) {
		t.Error("profile order must not change the hash")
	}
	b.Firewall[0].Enabled = true
	if InventoryHash(a) == InventoryHash(b) {
		t.Error("a profile turning on must change the hash")
	}
}
