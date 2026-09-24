// Package protocol defines the v1 agent <-> server wire types.
package protocol

import (
	"encoding/json"
	"time"
)

// DeviceFacts identifies a device at enrollment time.
type DeviceFacts struct {
	Hostname   string `json:"hostname"`
	Serial     string `json:"serial"`
	SMBIOSUUID string `json:"smbios_uuid"`
	OSVersion  string `json:"os_version"`
}

// EnrollRequest is POSTed to /api/agent/v1/enroll.
type EnrollRequest struct {
	Token  string      `json:"token"`
	CSRPEM string      `json:"csr_pem"`
	Device DeviceFacts `json:"device"`
}

// ComplianceStatementResponse is a signed statement of the device's
// compliance, from GET /api/agent/v1/compliance-statement.
type ComplianceStatementResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// EnrollResponse returns the device identity.
type EnrollResponse struct {
	DeviceID string `json:"device_id"`
	CertPEM  string `json:"cert_pem"`
	CAPEM    string `json:"ca_pem"`
}

// CheckinRequest is POSTed to /api/agent/v1/checkin over mTLS.
type CheckinRequest struct {
	AgentVersion  string   `json:"agent_version"`
	UptimeSeconds int64    `json:"uptime_seconds"`
	LoggedInUser  string   `json:"logged_in_user"`
	IPAddresses   []string `json:"ip_addresses"`
	InventoryHash string   `json:"inventory_hash"`
}

// Item is one thing assigned to this device through its groups. An agent
// ignores a kind it does not recognise.
type Item struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
	// Version is the item's current version; the agent fetches the contents
	// separately and caches them per version.
	Version int `json:"version,omitempty"`
	// Options configure the deployment. Their shape depends on the kind.
	Options json.RawMessage `json:"options,omitempty"`
}

// CheckinResponse tells the agent when to check in next, whether inventory
// is due, which commands to run, and what is assigned to it.
type CheckinResponse struct {
	IntervalSeconds int       `json:"interval_seconds"`
	InventoryDue    bool      `json:"inventory_due"`
	Commands        []Command `json:"commands"`
	Items           []Item    `json:"items,omitempty"`
}

// Error is the JSON body of every non-2xx response.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
