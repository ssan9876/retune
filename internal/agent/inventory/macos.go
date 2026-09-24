package inventory

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"

	"retune/internal/protocol"
)

// The macOS collector reads what the system's own tools print. Turning that
// output into inventory is kept here, apart from running the tools, so it is
// tested on every platform against output captured from real Macs.

// parseSwVers reads sw_vers: ProductName, ProductVersion, BuildVersion.
func parseSwVers(out string) (name, version, build string) {
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "ProductName":
			name = value
		case "ProductVersion":
			version = value
		case "BuildVersion":
			build = value
		}
	}
	return name, version, build
}

var ioregValue = regexp.MustCompile(`"(IOPlatformSerialNumber|IOPlatformUUID)" = "([^"]*)"`)

// parseIORegPlatform reads the serial number and hardware UUID from
// `ioreg -rd1 -c IOPlatformExpertDevice`.
func parseIORegPlatform(out string) (serial, uuid string) {
	for _, m := range ioregValue.FindAllStringSubmatch(out, -1) {
		switch m[1] {
		case "IOPlatformSerialNumber":
			serial = m[2]
		case "IOPlatformUUID":
			uuid = m[2]
		}
	}
	return serial, uuid
}

var bootSec = regexp.MustCompile(`sec = (\d+)`)

// parseBootTime reads `sysctl -n kern.boottime`: { sec = 1695456000, usec = 0 } ...
func parseBootTime(out string) *time.Time {
	m := bootSec.FindStringSubmatch(out)
	if m == nil {
		return nil
	}
	sec, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil || sec <= 0 {
		return nil
	}
	t := time.Unix(sec, 0).UTC()
	return &t
}

// parseFileVault reads `fdesetup status` as a disk's encryption state.
func parseFileVault(out string) string {
	switch {
	case strings.Contains(out, "FileVault is On"):
		return "on"
	case strings.Contains(out, "FileVault is Off"):
		return "off"
	}
	return "unknown"
}

// parseFirewall reads `socketfilterfw --getglobalstate`: enabled (State = 1),
// or blocking everything (State = 2), or disabled (State = 0).
func parseFirewall(out string) (enabled, known bool) {
	switch {
	case strings.Contains(out, "State = 1"), strings.Contains(out, "State = 2"), strings.Contains(out, "enabled"):
		return true, true
	case strings.Contains(out, "State = 0"), strings.Contains(out, "disabled"):
		return false, true
	}
	return false, false
}

// systemAccounts are the accounts every Mac has that no person signs in as.
var systemAccounts = map[string]bool{"root": true, "daemon": true, "nobody": true, "Guest": true}

// parseUsers reads `dscl . list /Users`, leaving out the system's own
// accounts (which start with an underscore) and the few that don't.
func parseUsers(out string) []protocol.LocalUser {
	users := []protocol.LocalUser{}
	for _, name := range strings.Fields(out) {
		if strings.HasPrefix(name, "_") || systemAccounts[name] {
			continue
		}
		users = append(users, protocol.LocalUser{Name: name})
	}
	return users
}

// parseGroupMembership reads `dscl . -read /Groups/admin GroupMembership`.
func parseGroupMembership(out string) []string {
	_, members, ok := strings.Cut(out, "GroupMembership:")
	if !ok {
		return []string{}
	}
	return strings.Fields(members)
}

// profilerApps is the part of `system_profiler SPApplicationsDataType -json`
// read here.
type profilerApps struct {
	Apps []struct {
		Name         string `json:"_name"`
		Version      string `json:"version"`
		ObtainedFrom string `json:"obtained_from"`
		Path         string `json:"path"`
		LastModified string `json:"lastModified"`
	} `json:"SPApplicationsDataType"`
}

var sources = map[string]string{
	"apple":                "Apple",
	"mac_app_store":        "Mac App Store",
	"identified_developer": "identified developer",
	"unknown":              "",
}

// parseApplications reads the installed applications. The system's own
// (under /System) are left out: they come and go with macOS itself, which
// the OS version already says.
func parseApplications(out []byte) ([]protocol.Software, error) {
	var p profilerApps
	if err := json.Unmarshal(out, &p); err != nil {
		return nil, err
	}
	software := []protocol.Software{}
	for _, a := range p.Apps {
		if a.Name == "" || strings.HasPrefix(a.Path, "/System/") {
			continue
		}
		scope := "machine"
		if strings.HasPrefix(a.Path, "/Users/") {
			scope = "user"
		}
		publisher, known := sources[a.ObtainedFrom]
		if !known {
			publisher = a.ObtainedFrom
		}
		installed := ""
		if t, err := time.Parse(time.RFC3339, a.LastModified); err == nil {
			installed = t.UTC().Format("2006-01-02")
		}
		software = append(software, protocol.Software{
			Name: a.Name, Version: a.Version, Publisher: publisher, InstallDate: installed, Scope: scope,
		})
	}
	return software, nil
}

// macFirewall reports the Mac's one application firewall as the three
// profiles the firewall_enabled compliance rule checks: it is on for every
// network, or for none.
func macFirewall(enabled bool) []protocol.FirewallProfileState {
	return []protocol.FirewallProfileState{
		{Profile: protocol.FirewallDomain, Enabled: enabled},
		{Profile: protocol.FirewallPrivate, Enabled: enabled},
		{Profile: protocol.FirewallPublic, Enabled: enabled},
	}
}
