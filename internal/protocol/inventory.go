package protocol

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"
)

// Inventory is the full device inventory document.
type Inventory struct {
	CollectedAt           time.Time        `json:"collected_at"`
	Hostname              string           `json:"hostname"`
	OS                    OSInfo           `json:"os"`
	Hardware              Hardware         `json:"hardware"`
	Disks                 []Disk           `json:"disks"`
	NetworkAdapters       []NetworkAdapter `json:"network_adapters"`
	Software              []Software       `json:"software"`
	LocalUsers            []LocalUser      `json:"local_users"`
	LocalAdmins           []string         `json:"local_admins"`
	PendingReboot         bool             `json:"pending_reboot"`
	LastUpdateInstalledAt *time.Time       `json:"last_update_installed_at,omitempty"`
	// Defender is nil when Microsoft Defender Antivirus reports nothing: not
	// installed, or removed by another antivirus. Nil is "not reported",
	// never "off".
	Defender *DefenderStatus `json:"defender,omitempty"`
	// Firewall is the effective state of each firewall profile, after Group
	// Policy. Nil when it could not be read.
	Firewall []FirewallProfileState `json:"firewall,omitempty"`
}

// DefenderStatus is what Microsoft Defender Antivirus says about itself.
type DefenderStatus struct {
	// RunningMode is Defender's AMRunningMode: "Normal" when it is the
	// machine's antivirus, "Passive Mode" or "EDR Block Mode" when another
	// product is.
	RunningMode        string     `json:"running_mode"`
	AntivirusEnabled   bool       `json:"antivirus_enabled"`
	RealtimeEnabled    bool       `json:"realtime_enabled"`
	TamperProtected    bool       `json:"tamper_protected"`
	SignatureVersion   string     `json:"signature_version"`
	SignatureUpdatedAt *time.Time `json:"signature_updated_at,omitempty"`
	LastQuickScanAt    *time.Time `json:"last_quick_scan_at,omitempty"`
	LastFullScanAt     *time.Time `json:"last_full_scan_at,omitempty"`
}

// DefenderNormalMode is the RunningMode in which Defender is the machine's
// own antivirus, and so the only mode in which its real-time state means
// anything about whether the machine is protected.
const DefenderNormalMode = "Normal"

// FirewallProfileState is one firewall profile's effective state. Profile is
// FirewallDomain, FirewallPrivate or FirewallPublic.
type FirewallProfileState struct {
	Profile string `json:"profile"`
	Enabled bool   `json:"enabled"`
}

// OSInfo describes the operating system.
type OSInfo struct {
	Name        string     `json:"name"`
	Version     string     `json:"version"`
	Build       string     `json:"build"`
	InstallDate *time.Time `json:"install_date,omitempty"`
	LastBoot    *time.Time `json:"last_boot,omitempty"`
}

// Hardware describes the machine.
type Hardware struct {
	Manufacturer string `json:"manufacturer"`
	Model        string `json:"model"`
	Serial       string `json:"serial"`
	SMBIOSUUID   string `json:"smbios_uuid"`
	CPU          string `json:"cpu"`
	CPUCores     int    `json:"cpu_cores"`
	CPULogical   int    `json:"cpu_logical"`
	RAMBytes     uint64 `json:"ram_bytes"`
	TPMPresent   bool   `json:"tpm_present"`
	TPMVersion   string `json:"tpm_version"`
}

// Disk is one fixed volume. BitLocker is "on", "off" or "unknown".
type Disk struct {
	Name       string `json:"name"`
	FileSystem string `json:"file_system"`
	SizeBytes  uint64 `json:"size_bytes"`
	FreeBytes  uint64 `json:"free_bytes"`
	BitLocker  string `json:"bitlocker"`
}

// NetworkAdapter is one IP-enabled adapter.
type NetworkAdapter struct {
	Name string   `json:"name"`
	MAC  string   `json:"mac"`
	IPs  []string `json:"ips"`
}

// Software is one installed package. Scope is "machine" or "user".
type Software struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Publisher   string `json:"publisher"`
	InstallDate string `json:"install_date"`
	Scope       string `json:"scope"`
}

// LocalUser is one local account.
type LocalUser struct {
	Name     string `json:"name"`
	Disabled bool   `json:"disabled"`
}

// InventoryResponse returns the hash the server stored, which the agent
// echoes in later check-ins.
type InventoryResponse struct {
	Hash string `json:"hash"`
}

// InventoryHash identifies inventory content. It ignores the collection
// time, the last boot time and the order of list items.
func InventoryHash(inv Inventory) string {
	c := canonicalInventory(inv)
	c.CollectedAt = time.Time{}
	c.OS.LastBoot = nil
	return hashJSON(c)
}

// SoftwareHash identifies the installed-software list regardless of order.
func SoftwareHash(sw []Software) string { return hashJSON(sortedSoftware(sw)) }

func canonicalInventory(inv Inventory) Inventory {
	c := inv
	c.Software = sortedSoftware(inv.Software)

	c.Disks = slices.Clone(inv.Disks)
	slices.SortFunc(c.Disks, func(a, b Disk) int { return cmp.Compare(a.Name, b.Name) })

	c.NetworkAdapters = slices.Clone(inv.NetworkAdapters)
	for i := range c.NetworkAdapters {
		ips := slices.Clone(c.NetworkAdapters[i].IPs)
		slices.Sort(ips)
		c.NetworkAdapters[i].IPs = ips
	}
	slices.SortFunc(c.NetworkAdapters, func(a, b NetworkAdapter) int {
		return cmp.Or(cmp.Compare(a.MAC, b.MAC), cmp.Compare(a.Name, b.Name))
	})

	c.LocalUsers = slices.Clone(inv.LocalUsers)
	slices.SortFunc(c.LocalUsers, func(a, b LocalUser) int { return cmp.Compare(a.Name, b.Name) })

	c.LocalAdmins = slices.Clone(inv.LocalAdmins)
	slices.Sort(c.LocalAdmins)

	c.Firewall = slices.Clone(inv.Firewall)
	slices.SortFunc(c.Firewall, func(a, b FirewallProfileState) int { return cmp.Compare(a.Profile, b.Profile) })
	return c
}

func sortedSoftware(sw []Software) []Software {
	out := slices.Clone(sw)
	slices.SortFunc(out, func(a, b Software) int {
		return cmp.Or(
			cmp.Compare(a.Name, b.Name),
			cmp.Compare(a.Version, b.Version),
			cmp.Compare(a.Scope, b.Scope),
			cmp.Compare(a.Publisher, b.Publisher),
		)
	})
	return out
}

func hashJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic("protocol: hashing inventory: " + err.Error())
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
