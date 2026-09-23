// Package facts collects the lightweight device facts sent at enrollment
// and check-in. Full inventory arrives in M2.
package facts

import (
	"net"
	"os"

	"retune/internal/agent/inventory"
	"retune/internal/opsign"
	"retune/internal/protocol"
	"retune/internal/release"
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

// TrustedKeysRaw is the comma-separated list of release public keys this
// build trusts, stamped at build time beside the version:
//
//	go build -ldflags "-X retune/internal/agent/facts.TrustedKeysRaw=<base64>,<base64>"
//
// A build with no list cannot self-update. Rotation is a build that trusts
// both keys, then one that trusts only the new one; nothing on a device is
// ever edited to change what it trusts.
var TrustedKeysRaw = ""

// OperationsKeysRaw is the comma-separated list of operations public keys
// this agent was built to require on the scripts it runs and the wipes it
// obeys, stamped at build time:
//
//	go build -ldflags "-X retune/internal/agent/facts.OperationsKeysRaw=<base64>,<base64>"
//
// Empty, the agent requires no signatures. It is a build setting on purpose:
// nothing the server sends can turn it off.
var OperationsKeysRaw = ""

// Operations is what this agent requires. A list that doesn't parse
// enforces with no trusted keys, refusing everything, rather than quietly
// enforcing nothing.
func Operations() opsign.Policy { return opsign.ParsePolicy(OperationsKeysRaw) }

// TrustedKeys parses the stamped list. A list that fails to parse is treated
// as empty rather than partially honoured, since trusting fewer keys than
// intended only ever refuses an update, while trusting a wrong one runs code.
func TrustedKeys() []release.PublicKey {
	keys, err := release.ParseTrustList(TrustedKeysRaw)
	if err != nil {
		return nil
	}
	return keys
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
