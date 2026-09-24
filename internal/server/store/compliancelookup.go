package store

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

// Ways a device can be looked up for its compliance.
const (
	LookupDeviceID = "device_id"
	LookupSerial   = "serial"
	LookupHostname = "hostname"
	LookupMAC      = "mac"
)

var nonHex = regexp.MustCompile(`[^0-9A-F]`)

// NormalizeMAC is a MAC address as its twelve upper-case hex digits,
// whatever separators it was written with, or "" if it isn't one.
func NormalizeMAC(mac string) string {
	hex := nonHex.ReplaceAllString(strings.ToUpper(mac), "")
	if len(hex) != 12 {
		return ""
	}
	return hex
}

// DevicesFor finds the devices matching one identifier, for network access
// control and identity providers asking whether a device is compliant. A
// MAC matches any network adapter the device last reported. At most ten
// are returned: an identifier that matches more isn't identifying anything.
func (q *Queries) DevicesFor(ctx context.Context, by, value string, scope DeviceScope) ([]Device, error) {
	var cond string
	var arg any
	switch by {
	case LookupDeviceID:
		id, err := uuid.Parse(value)
		if err != nil {
			return nil, nil // not a device ID, so no device
		}
		cond, arg = "id = $2", id
	case LookupSerial:
		cond, arg = "upper(serial) = upper($2)", strings.TrimSpace(value)
	case LookupHostname:
		cond, arg = "lower(hostname) = lower($2)", strings.TrimSpace(value)
	case LookupMAC:
		mac := NormalizeMAC(value)
		if mac == "" {
			return nil, nil
		}
		cond = `EXISTS (
			SELECT 1 FROM device_inventory i, jsonb_array_elements(coalesce(i.data->'network_adapters', '[]'::jsonb)) a
			WHERE i.device_id = devices.id
			  AND regexp_replace(upper(coalesce(a->>'mac', '')), '[^0-9A-F]', '', 'g') = $2)`
		arg = mac
	default:
		return nil, fmt.Errorf("unknown lookup %q", by)
	}
	rows, err := q.db.Query(ctx, `
		SELECT `+deviceCols+` FROM devices
		WHERE tenant_id = $1 AND `+cond+` AND `+scopeSQL("id", 3)+`
		ORDER BY status = 'active' DESC, last_seen_at DESC NULLS LAST
		LIMIT 10`, DefaultTenantID, arg, scope.arg())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.Hostname, &d.Serial, &d.SMBIOSUUID, &d.OSVersion, &d.Status, &d.CertSerial,
			&d.CertExpiresAt, &d.LastSeenAt, &d.AgentVersion, &d.EnrolledAt, &d.ReplacedBy,
			&d.PrevCertSerial, &d.OSBuild, &d.Manufacturer, &d.Model); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
