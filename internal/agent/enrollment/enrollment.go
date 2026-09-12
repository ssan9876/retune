// Package enrollment enrolls the agent and builds its authenticated client.
package enrollment

import (
	"context"
	"errors"
	"fmt"

	"retune/internal/agent/client"
	"retune/internal/agent/identity"
	"retune/internal/protocol"
)

// ErrAlreadyEnrolled is returned when an identity already exists.
var ErrAlreadyEnrolled = errors.New("agent is already enrolled; unenroll first")

// Options configure enrollment.
type Options struct {
	ServerURL string
	Token     string
	Pin       string
	Facts     protocol.DeviceFacts
	Store     identity.Store
}

// Enroll generates a keypair, enrolls with the server, and saves the identity.
func Enroll(ctx context.Context, o Options) (*identity.Identity, error) {
	if _, err := o.Store.Load(); err == nil {
		return nil, ErrAlreadyEnrolled
	} else if !errors.Is(err, identity.ErrNotEnrolled) {
		return nil, err
	}
	key, csrPEM, err := identity.NewKeyAndCSR(o.Facts.Hostname)
	if err != nil {
		return nil, err
	}
	c, err := client.New(o.ServerURL, o.Pin, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Enroll(ctx, protocol.EnrollRequest{Token: o.Token, CSRPEM: csrPEM, Device: o.Facts})
	if err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	id := &identity.Identity{
		DeviceID:  resp.DeviceID,
		ServerURL: o.ServerURL,
		ServerPin: o.Pin,
		CertPEM:   resp.CertPEM,
		CAPEM:     resp.CAPEM,
		Key:       key,
	}
	if err := o.Store.Save(id); err != nil {
		return nil, fmt.Errorf("save identity: %w", err)
	}
	return id, nil
}

// Connect returns an mTLS client for an enrolled identity.
func Connect(id *identity.Identity) (*client.Client, error) {
	cert, err := id.TLSCertificate()
	if err != nil {
		return nil, err
	}
	return client.New(id.ServerURL, id.ServerPin, &cert)
}
