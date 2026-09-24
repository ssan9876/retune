package store

import (
	"time"

	"github.com/google/uuid"
)

// Device statuses.
const (
	DeviceActive     = "active"
	DeviceRetired    = "retired"
	DeviceReplaced   = "replaced"
	DeviceUnenrolled = "unenrolled"
)

// EnrollmentToken authorizes device enrollment. Only the hash is stored.
type EnrollmentToken struct {
	ID        uuid.UUID
	TokenHash []byte
	Label     string
	ExpiresAt *time.Time
	MaxUses   *int
	UseCount  int
	RevokedAt *time.Time
	CreatedBy string
	CreatedAt time.Time
	// RegisteredOnly enrolls only devices registered in advance.
	RegisteredOnly bool
}

// Device is an enrolled endpoint.
type Device struct {
	ID             uuid.UUID
	Hostname       string
	Serial         string
	SMBIOSUUID     string
	OSVersion      string
	Status         string
	CertSerial     string
	CertExpiresAt  time.Time
	LastSeenAt     *time.Time
	AgentVersion   string
	EnrolledAt     time.Time
	ReplacedBy     *uuid.UUID
	PrevCertSerial string
	OSBuild        string
	Manufacturer   string
	Model          string
}

// AuditEntry records an administrative or security-relevant action.
type AuditEntry struct {
	// ID is set on entries read back; InsertAudit makes its own.
	ID         uuid.UUID
	Actor      string
	Action     string
	TargetKind string
	TargetID   string
	Details    map[string]any
	At         time.Time
}
