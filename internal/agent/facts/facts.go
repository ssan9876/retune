// Package facts collects the lightweight device facts sent at enrollment
// and check-in. Full inventory arrives in M2.
package facts

import (
	"net"
	"os"

	"retune/internal/protocol"
)

// AgentVersion is reported on every check-in.
const AgentVersion = "0.1.0-dev"

// Device returns facts for enrollment. Serial and SMBIOS UUID are filled in
// by the M2 inventory collector.
func Device() protocol.DeviceFacts {
	host, _ := os.Hostname()
	return protocol.DeviceFacts{Hostname: host, OSVersion: osVersion()}
}

// Checkin returns the heartbeat payload.
func Checkin() protocol.CheckinRequest {
	return protocol.CheckinRequest{
		AgentVersion:  AgentVersion,
		UptimeSeconds: uptimeSeconds(),
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
