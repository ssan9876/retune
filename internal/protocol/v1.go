// Package protocol defines the v1 agent <-> server wire types.
package protocol

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

// Item is one thing assigned to this device through its groups. Kinds arrive
// with later milestones, and an agent ignores a kind it does not recognise.
type Item struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
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
