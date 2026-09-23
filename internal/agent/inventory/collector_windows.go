//go:build windows

package inventory

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"github.com/yusufpapurcu/wmi"
	"golang.org/x/sys/windows/registry"

	"retune/internal/protocol"
)

// NewCollector returns the Windows collector.
func NewCollector() Collector { return WindowsCollector{} }

// WindowsCollector reads inventory from WMI and the registry. Sections that
// need elevation (BitLocker, TPM, group membership) are skipped when denied
// rather than failing the whole collection.
type WindowsCollector struct{}

type win32OperatingSystem struct {
	Caption        string
	Version        string
	BuildNumber    string
	InstallDate    time.Time
	LastBootUpTime time.Time
}

type win32ComputerSystem struct {
	Manufacturer        string
	Model               string
	TotalPhysicalMemory uint64
}

type win32Processor struct {
	Name                      string
	NumberOfCores             uint32
	NumberOfLogicalProcessors uint32
}

type win32LogicalDisk struct {
	DeviceID   string
	FileSystem string
	Size       uint64
	FreeSpace  uint64
}

type win32EncryptableVolume struct {
	DriveLetter      string
	ProtectionStatus uint32
}

type win32Tpm struct {
	SpecVersion string
}

type win32NetworkAdapterConfiguration struct {
	Description string
	MACAddress  string
	IPAddress   []string
}

type win32UserAccount struct {
	Name     string
	Disabled bool
}

type win32Account struct {
	Name   string
	Domain string
}

type win32BIOS struct {
	SerialNumber string
}

type win32ComputerSystemProduct struct {
	UUID string
}

type win32UserName struct {
	UserName string
}

type win32QuickFixEngineering struct {
	InstalledOn string
}

// Collect gathers the full inventory document.
func (WindowsCollector) Collect(_ context.Context) (protocol.Inventory, error) {
	inv := protocol.Inventory{CollectedAt: time.Now().UTC()}
	inv.Hostname, _ = os.Hostname()

	var osRows []win32OperatingSystem
	if err := queryOne("SELECT Caption, Version, BuildNumber, InstallDate, LastBootUpTime FROM Win32_OperatingSystem", &osRows); err != nil {
		return inv, err
	}
	o := osRows[0]
	inv.OS = protocol.OSInfo{
		Name: strings.TrimSpace(o.Caption), Version: o.Version, Build: o.BuildNumber,
		InstallDate: timePtr(o.InstallDate), LastBoot: timePtr(o.LastBootUpTime),
	}

	var csRows []win32ComputerSystem
	if err := queryOne("SELECT Manufacturer, Model, TotalPhysicalMemory FROM Win32_ComputerSystem", &csRows); err != nil {
		return inv, err
	}
	serial, smbios := HardwareIdentity()
	inv.Hardware = protocol.Hardware{
		Manufacturer: strings.TrimSpace(csRows[0].Manufacturer),
		Model:        strings.TrimSpace(csRows[0].Model),
		Serial:       serial,
		SMBIOSUUID:   smbios,
		RAMBytes:     csRows[0].TotalPhysicalMemory,
	}

	var cpus []win32Processor
	if wmi.Query("SELECT Name, NumberOfCores, NumberOfLogicalProcessors FROM Win32_Processor", &cpus) == nil && len(cpus) > 0 {
		inv.Hardware.CPU = strings.TrimSpace(cpus[0].Name)
		for _, c := range cpus {
			inv.Hardware.CPUCores += int(c.NumberOfCores)
			inv.Hardware.CPULogical += int(c.NumberOfLogicalProcessors)
		}
	}
	var tpm []win32Tpm
	if wmi.QueryNamespace("SELECT SpecVersion FROM Win32_Tpm", &tpm, `root\CIMV2\Security\MicrosoftTpm`) == nil && len(tpm) > 0 {
		inv.Hardware.TPMPresent = true
		inv.Hardware.TPMVersion = strings.TrimSpace(strings.Split(tpm[0].SpecVersion, ",")[0])
	}

	inv.Disks = collectDisks()
	inv.NetworkAdapters = collectAdapters()
	inv.Software = collectSoftware()
	inv.LocalUsers = collectLocalUsers()
	inv.LocalAdmins = collectLocalAdmins()
	inv.PendingReboot = pendingReboot()
	inv.LastUpdateInstalledAt = lastUpdateInstalled()
	inv.Defender = collectDefender()
	inv.Firewall = collectFirewall()
	return inv, nil
}

// collectDefender reads Microsoft Defender Antivirus's own status. A machine
// without Defender has no such namespace or class; that is nil, not an error.
func collectDefender() *protocol.DefenderStatus {
	var rows []DefenderRow
	if err := wmi.QueryNamespace(`SELECT AMRunningMode, AntivirusEnabled, RealTimeProtectionEnabled,
		IsTamperProtected, AntivirusSignatureVersion, AntivirusSignatureLastUpdated,
		QuickScanEndTime, FullScanEndTime FROM MSFT_MpComputerStatus`,
		&rows, `root\Microsoft\Windows\Defender`); err != nil {
		return nil
	}
	return DefenderFromRows(rows)
}

// collectFirewall asks the firewall API whether each profile is on. The API
// answers with the state in effect, after Group Policy; the WMI class
// MSFT_NetFirewallProfile reads the locally stored settings by default, which
// a policy can override in either direction.
func collectFirewall() []protocol.FirewallProfileState {
	// COM wants the calling thread initialised, and a goroutine can move
	// between threads, so the whole conversation happens on one locked
	// thread of its own.
	result := make(chan map[int]bool, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		result <- firewallStates()
	}()
	return FirewallFromStates(<-result)
}

func firewallStates() map[int]bool {
	if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err != nil {
		// S_FALSE means this thread was already initialised, which is fine
		// but still owes an uninitialise; anything else means no COM.
		var oleErr *ole.OleError
		if !errors.As(err, &oleErr) || oleErr.Code() != sFalse {
			return nil
		}
	}
	defer ole.CoUninitialize()

	unknown, err := oleutil.CreateObject("HNetCfg.FwPolicy2")
	if err != nil {
		return nil
	}
	defer unknown.Release()
	policy, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return nil
	}
	defer policy.Release()

	out := map[int]bool{}
	for _, p := range firewallProfiles {
		v, err := oleutil.GetProperty(policy, "FirewallEnabled", p.Type)
		if err != nil {
			continue
		}
		if on, ok := v.Value().(bool); ok {
			out[p.Type] = on
		}
		_ = v.Clear()
	}
	return out
}

// sFalse is COM's "already done" success code.
const sFalse = 1

// HardwareIdentity returns the firmware serial and SMBIOS UUID, with
// placeholder values dropped.
func HardwareIdentity() (string, string) {
	var serial, smbios string
	var bios []win32BIOS
	if wmi.Query("SELECT SerialNumber FROM Win32_BIOS", &bios) == nil && len(bios) > 0 {
		serial = CleanSerial(bios[0].SerialNumber)
	}
	var product []win32ComputerSystemProduct
	if wmi.Query("SELECT UUID FROM Win32_ComputerSystemProduct", &product) == nil && len(product) > 0 {
		smbios = CleanUUID(product[0].UUID)
	}
	return serial, smbios
}

// LoggedInUser is the interactive user, or "" when nobody is signed in.
func LoggedInUser() string {
	var rows []win32UserName
	if wmi.Query("SELECT UserName FROM Win32_ComputerSystem", &rows) != nil || len(rows) == 0 {
		return ""
	}
	return strings.TrimSpace(rows[0].UserName)
}

func queryOne[T any](query string, dst *[]T) error {
	if err := wmi.Query(query, dst); err != nil {
		return fmt.Errorf("WMI %q: %w", query, err)
	}
	if len(*dst) == 0 {
		return fmt.Errorf("WMI %q returned no rows", query)
	}
	return nil
}

func collectDisks() []protocol.Disk {
	var rows []win32LogicalDisk
	if wmi.Query("SELECT DeviceID, FileSystem, Size, FreeSpace FROM Win32_LogicalDisk WHERE DriveType = 3", &rows) != nil {
		return nil
	}
	encryption := bitLockerStatus()
	out := make([]protocol.Disk, 0, len(rows))
	for _, r := range rows {
		status := "unknown"
		if s, ok := encryption[strings.ToUpper(r.DeviceID)]; ok {
			status = s
		}
		out = append(out, protocol.Disk{
			Name: r.DeviceID, FileSystem: r.FileSystem,
			SizeBytes: r.Size, FreeBytes: r.FreeSpace, BitLocker: status,
		})
	}
	return out
}

// bitLockerStatus needs elevation; without it the map is empty and disks report
// "unknown".
func bitLockerStatus() map[string]string {
	var vols []win32EncryptableVolume
	if wmi.QueryNamespace("SELECT DriveLetter, ProtectionStatus FROM Win32_EncryptableVolume", &vols,
		`root\CIMV2\Security\MicrosoftVolumeEncryption`) != nil {
		return nil
	}
	out := map[string]string{}
	for _, v := range vols {
		letter := strings.ToUpper(strings.TrimSpace(v.DriveLetter))
		if letter == "" {
			continue
		}
		switch v.ProtectionStatus {
		case 1:
			out[letter] = "on"
		case 0:
			out[letter] = "off"
		default:
			out[letter] = "unknown"
		}
	}
	return out
}

func collectAdapters() []protocol.NetworkAdapter {
	var rows []win32NetworkAdapterConfiguration
	if wmi.Query("SELECT Description, MACAddress, IPAddress FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE", &rows) != nil {
		return nil
	}
	out := make([]protocol.NetworkAdapter, 0, len(rows))
	for _, r := range rows {
		out = append(out, protocol.NetworkAdapter{Name: r.Description, MAC: r.MACAddress, IPs: r.IPAddress})
	}
	return out
}

func collectLocalUsers() []protocol.LocalUser {
	var rows []win32UserAccount
	if wmi.Query("SELECT Name, Disabled FROM Win32_UserAccount WHERE LocalAccount = TRUE", &rows) != nil {
		return nil
	}
	out := make([]protocol.LocalUser, 0, len(rows))
	for _, r := range rows {
		out = append(out, protocol.LocalUser{Name: r.Name, Disabled: r.Disabled})
	}
	return out
}

// collectLocalAdmins resolves the Administrators group by SID, so it works on
// localized installs.
func collectLocalAdmins() []string {
	var groups []win32Account
	if wmi.Query("SELECT Name, Domain FROM Win32_Group WHERE LocalAccount = TRUE AND SID = 'S-1-5-32-544'", &groups) != nil || len(groups) == 0 {
		return nil
	}
	g := groups[0]
	query := fmt.Sprintf("ASSOCIATORS OF {Win32_Group.Domain='%s',Name='%s'} WHERE AssocClass = Win32_GroupUser Role = GroupComponent",
		g.Domain, g.Name)
	var members []win32Account
	if wmi.Query(query, &members) != nil {
		return nil
	}
	out := make([]string, 0, len(members))
	for _, m := range members {
		out = append(out, m.Domain+`\`+m.Name)
	}
	return out
}

const uninstallKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`

func collectSoftware() []protocol.Software {
	machine := append(
		readUninstall(registry.LOCAL_MACHINE, uninstallKey),
		readUninstall(registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`)...,
	)
	var user []UninstallEntry
	if sids, err := registry.USERS.ReadSubKeyNames(-1); err == nil {
		for _, sid := range sids {
			if strings.HasPrefix(sid, "S-1-5-21-") && !strings.HasSuffix(sid, "_Classes") {
				user = append(user, readUninstall(registry.USERS, sid+`\`+uninstallKey)...)
			}
		}
	}
	return append(NormalizeSoftware(machine, "machine"), NormalizeSoftware(user, "user")...)
}

func readUninstall(root registry.Key, path string) []UninstallEntry {
	k, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}
	out := make([]UninstallEntry, 0, len(names))
	for _, name := range names {
		sub, err := registry.OpenKey(k, name, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		var e UninstallEntry
		e.DisplayName, _, _ = sub.GetStringValue("DisplayName")
		e.DisplayVersion, _, _ = sub.GetStringValue("DisplayVersion")
		e.Publisher, _, _ = sub.GetStringValue("Publisher")
		e.InstallDate, _, _ = sub.GetStringValue("InstallDate")
		e.ParentKeyName, _, _ = sub.GetStringValue("ParentKeyName")
		e.SystemComponent, _, _ = sub.GetIntegerValue("SystemComponent")
		sub.Close()
		out = append(out, e)
	}
	return out
}

func pendingReboot() bool {
	for _, path := range []string{
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`,
	} {
		if k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE); err == nil {
			k.Close()
			return true
		}
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetStringsValue("PendingFileRenameOperations")
	return err == nil && len(v) > 0
}

func lastUpdateInstalled() *time.Time {
	var rows []win32QuickFixEngineering
	if wmi.Query("SELECT InstalledOn FROM Win32_QuickFixEngineering", &rows) != nil {
		return nil
	}
	var latest time.Time
	for _, r := range rows {
		if t, ok := ParseQFEDate(r.InstalledOn); ok && t.After(latest) {
			latest = t
		}
	}
	return timePtr(latest)
}
