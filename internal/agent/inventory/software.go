package inventory

import (
	"cmp"
	"slices"
	"strings"

	"retune/internal/protocol"
)

// UninstallEntry is one subkey of a Windows Uninstall registry key.
type UninstallEntry struct {
	DisplayName     string
	DisplayVersion  string
	Publisher       string
	InstallDate     string
	ParentKeyName   string
	SystemComponent uint64
}

// NormalizeSoftware turns raw registry entries into a sorted, deduplicated
// package list. Entries without a name, hidden system components, and updates
// that belong to another product are dropped.
func NormalizeSoftware(entries []UninstallEntry, scope string) []protocol.Software {
	var out []protocol.Software
	seen := map[string]bool{}
	for _, e := range entries {
		name := strings.TrimSpace(e.DisplayName)
		if name == "" || e.SystemComponent == 1 || strings.TrimSpace(e.ParentKeyName) != "" {
			continue
		}
		version := strings.TrimSpace(e.DisplayVersion)
		key := strings.ToLower(name) + "\x00" + version
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, protocol.Software{
			Name:        name,
			Version:     version,
			Publisher:   strings.TrimSpace(e.Publisher),
			InstallDate: strings.TrimSpace(e.InstallDate),
			Scope:       scope,
		})
	}
	slices.SortFunc(out, func(a, b protocol.Software) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Version, b.Version))
	})
	return out
}
