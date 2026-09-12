// Package facts collects the lightweight device facts sent at enrollment
// and check-in. Full inventory arrives in M2.
package facts

import (
	"net"
	"os"

	"retune/internal/agent/inventory"
	"retune/internal/protocol"
)

// AgentVersion is reported on every check-in.
const AgentVersion = "0.1.0-dev"

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
