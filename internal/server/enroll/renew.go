package enroll

import (
	"context"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/store"
)

// Renew issues a fresh client certificate for a device. presentedSerial is the
// serial of the certificate that authenticated the request; it remains
// acceptable until the device uses the new one, so a crash between issuing and
// saving cannot lock the device out.
func (s *Service) Renew(ctx context.Context, deviceID uuid.UUID, presentedSerial string, req protocol.RenewRequest) (protocol.RenewResponse, error) {
	now := s.Now()
	issued, err := s.CA.SignClientCSR([]byte(req.CSRPEM), deviceID.String(), now, s.CertValidity)
	if err != nil {
		return protocol.RenewResponse{}, err
	}
	err = s.Store.InTx(ctx, func(q *store.Queries) error {
		if err := q.UpdateDeviceCert(ctx, store.DefaultTenantID, deviceID, presentedSerial, issued.Serial, issued.NotAfter); err != nil {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: "device:" + deviceID.String(), Action: "device.cert_renewed",
			TargetKind: "device", TargetID: deviceID.String(),
			Details: map[string]any{"serial": issued.Serial, "not_after": issued.NotAfter.Format(time.RFC3339)},
		})
	})
	if err != nil {
		return protocol.RenewResponse{}, err
	}
	return protocol.RenewResponse{CertPEM: string(issued.PEM)}, nil
}
