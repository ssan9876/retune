// Package inventory collects the device inventory the server stores.
package inventory

import (
	"context"
	"strings"
	"time"

	"retune/internal/protocol"
)

// Collector gathers a full inventory document.
type Collector interface {
	Collect(ctx context.Context) (protocol.Inventory, error)
}

// junkSerials are placeholder values some firmware reports. Treating them as
// real would make unrelated machines look like the same reimaged device.
var junkSerials = map[string]bool{
	"":                       true,
	"0":                      true,
	"none":                   true,
	"default string":         true,
	"to be filled by o.e.m.": true,
	"system serial number":   true,
	"chassis serial number":  true,
	"not specified":          true,
	"not applicable":         true,
	"123456789":              true,
	"0123456789":             true,
	"invalid":                true,
}

// junkUUIDs are placeholder SMBIOS UUIDs.
var junkUUIDs = map[string]bool{
	"":                                     true,
	"00000000-0000-0000-0000-000000000000": true,
	"FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF": true,
	"03000200-0400-0500-0006-000700080009": true,
}

// CleanSerial trims a firmware serial and drops known placeholders.
func CleanSerial(s string) string {
	t := strings.TrimSpace(s)
	if junkSerials[strings.ToLower(t)] {
		return ""
	}
	return t
}

// CleanUUID upper-cases an SMBIOS UUID and drops known placeholders.
func CleanUUID(s string) string {
	t := strings.ToUpper(strings.TrimSpace(s))
	if junkUUIDs[t] {
		return ""
	}
	return t
}

// ParseQFEDate reads the InstalledOn value of Win32_QuickFixEngineering, which
// differs by locale.
func ParseQFEDate(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	for _, layout := range []string{"1/2/2006", "01/02/2006", "2006-01-02", "20060102"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}
