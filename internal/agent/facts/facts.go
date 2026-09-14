// Package facts collects the lightweight device facts sent at enrollment
// and check-in. Full inventory arrives in M2.
package facts

import (
	"net"
	"os"

	"retune/internal/agent/inventory"
	"retune/internal/protocol"
)

// PlaceholderVersion is what an unstamped build reports. A build carrying it
// refuses to self-update: it would report the same string after updating, be
// told to update again, and do that on every check-in forever.
const PlaceholderVersion = "0.1.0-dev"

// AgentVersion is reported on every check-in. It is a var, not a const, so a
// release build can stamp it:
//
//	go build -ldflags "-X retune/internal/agent/facts.AgentVersion=1.2.3"
var AgentVersion = PlaceholderVersion

// VersionInjected reports whether this build was stamped with a real version.
func VersionInjected() bool {
	return AgentVersion != "" && AgentVersion != PlaceholderVersion
}

// Device returns the facts sent at enrollment.
func Device() protocol.DeviceFacts {
	host, _ := os.Hostname()
	serial, smbios := inventory.HardwareIdentity()
	return protocol.DeviceFacts{Hostname: host, Serial: serial, SMBIOSUUID: smbios, OSVersion: osVersion()}
}

// Checkin returns the heartbeat payload.
func Checkin() protocol.CheckinRequest {
	return protocol.CheckinRequest{
		AgentVersion:  AgentVersion,
		UptimeSeconds: uptimeSeconds(),
		LoggedInUser:  inventory.LoggedInUser(),
		IPAddresses:   ipAddresses(),
	}
}

func ipAddresses() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() && !ipn.IP.IsLinkLocalUnicast() {
			out = append(out, ipn.IP.String())
		}
	}
	return out
}
