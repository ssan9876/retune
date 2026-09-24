//go:build darwin

package inventory

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"retune/internal/protocol"
)

// NewCollector returns the macOS collector, which reads what the system's own
// command-line tools print. Each tool that fails leaves its part empty rather
// than failing the whole inventory.
func NewCollector() Collector { return macCollector{} }

type macCollector struct{}

// command runs a system tool and returns what it printed, or "" if it failed.
func command(ctx context.Context, name string, args ...string) string {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return ""
	}
	return string(out)
}

func sysctl(ctx context.Context, name string) string {
	return strings.TrimSpace(command(ctx, "/usr/sbin/sysctl", "-n", name))
}

func (macCollector) Collect(ctx context.Context) (protocol.Inventory, error) {
	host, _ := os.Hostname()
	inv := protocol.Inventory{CollectedAt: time.Now().UTC(), Hostname: host}

	inv.OS.Name, inv.OS.Version, inv.OS.Build = parseSwVers(command(ctx, "/usr/bin/sw_vers"))
	inv.OS.LastBoot = parseBootTime(sysctl(ctx, "kern.boottime"))

	serial, uuid := parseIORegPlatform(command(ctx, "/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"))
	inv.Hardware = protocol.Hardware{
		Manufacturer: "Apple",
		Model:        sysctl(ctx, "hw.model"),
		Serial:       CleanSerial(serial),
		SMBIOSUUID:   CleanUUID(uuid),
		CPU:          sysctl(ctx, "machdep.cpu.brand_string"),
	}
	inv.Hardware.CPUCores, _ = strconv.Atoi(sysctl(ctx, "hw.physicalcpu"))
	inv.Hardware.CPULogical, _ = strconv.Atoi(sysctl(ctx, "hw.logicalcpu"))
	inv.Hardware.RAMBytes, _ = strconv.ParseUint(sysctl(ctx, "hw.memsize"), 10, 64)

	inv.Disks = collectDisks(ctx)
	inv.NetworkAdapters = collectAdapters()
	if software, err := parseApplications([]byte(command(ctx, "/usr/sbin/system_profiler", "SPApplicationsDataType", "-json"))); err == nil {
		inv.Software = software
	}
	inv.LocalUsers = parseUsers(command(ctx, "/usr/bin/dscl", ".", "list", "/Users"))
	inv.LocalAdmins = parseGroupMembership(command(ctx, "/usr/bin/dscl", ".", "-read", "/Groups/admin", "GroupMembership"))
	if enabled, known := parseFirewall(command(ctx, "/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate")); known {
		inv.Firewall = macFirewall(enabled)
	}
	return inv, nil
}

// collectDisks reports the startup volume, whose encryption is FileVault's.
func collectDisks(ctx context.Context) []protocol.Disk {
	var st syscall.Statfs_t
	if err := syscall.Statfs("/", &st); err != nil {
		return nil
	}
	return []protocol.Disk{{
		Name:       "/",
		FileSystem: fsType(st.Fstypename[:]),
		SizeBytes:  st.Blocks * uint64(st.Bsize),
		FreeBytes:  st.Bavail * uint64(st.Bsize),
		BitLocker:  parseFileVault(command(ctx, "/usr/bin/fdesetup", "status")),
	}}
}

func fsType(name []int8) string {
	b := make([]byte, 0, len(name))
	for _, c := range name {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

// collectAdapters lists the interfaces that are up and have a hardware
// address, which leaves out loopback and tunnels.
func collectAdapters() []protocol.NetworkAdapter {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := []protocol.NetworkAdapter{}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || len(iface.HardwareAddr) == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		ips := []string{}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				ips = append(ips, n.IP.String())
			}
		}
		if len(ips) == 0 {
			continue
		}
		out = append(out, protocol.NetworkAdapter{Name: iface.Name, MAC: strings.ToUpper(iface.HardwareAddr.String()), IPs: ips})
	}
	return out
}

// HardwareIdentity returns the serial number and hardware UUID.
func HardwareIdentity() (string, string) {
	serial, uuid := parseIORegPlatform(command(context.Background(), "/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"))
	return CleanSerial(serial), CleanUUID(uuid)
}

// LoggedInUser is whoever owns the console, or "" at the login window (where
// root owns it).
func LoggedInUser() string {
	user := strings.TrimSpace(command(context.Background(), "/usr/bin/stat", "-f%Su", "/dev/console"))
	if user == "root" {
		return ""
	}
	return user
}
