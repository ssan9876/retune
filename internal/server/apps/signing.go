package apps

import (
	"encoding/json"
	"fmt"

	"retune/internal/opsign"
	"retune/internal/protocol"
	"retune/internal/server/store"
)

// Definition is what an operations signature over a stored version covers,
// exactly as an agent will rebuild it from the version it is sent.
func Definition(v store.AppVersion) (protocol.AppDefinition, error) {
	d := protocol.AppDefinition{
		Source: v.Source, PackageID: v.PackageID, PinnedVersion: v.PinnedVersion, Scope: v.Scope,
		InstallArgs: v.InstallArgs, InstallerType: v.InstallerType, FileName: v.FileName,
		FileSHA256: v.FileSHA256, UninstallCommand: v.UninstallCommand, UninstallPrevious: v.UninstallPrevious,
	}
	for _, c := range v.SuccessExitCodes {
		d.SuccessExitCodes = append(d.SuccessExitCodes, int(c))
	}
	if len(v.Detection) > 0 && string(v.Detection) != "null" {
		var rule protocol.DetectionRule
		if err := json.Unmarshal(v.Detection, &rule); err != nil {
			return protocol.AppDefinition{}, fmt.Errorf("decode detection rule: %w", err)
		}
		d.Detection = &rule
	}
	return d, nil
}

// checkSignature refuses a version that isn't signed by a trusted operations
// key, when the server has any: an agent built to require one would refuse
// it anyway, and it is better said now than on every device.
func (s *Service) checkSignature(v store.AppVersion, sig *opsign.Signature) error {
	if len(s.OperationsKeys) == 0 {
		return nil
	}
	d, err := Definition(v)
	if err != nil {
		return err
	}
	if err := opsign.Verify(s.OperationsKeys, d.Manifest(), sig); err != nil {
		return fmt.Errorf("%w: %v; sign it with retune-sign sign-app", ErrBadRequest, err)
	}
	return nil
}

func encodeSignature(sig *opsign.Signature) json.RawMessage {
	if sig == nil {
		return nil
	}
	raw, _ := json.Marshal(sig)
	return raw
}

func decodeSignature(raw json.RawMessage) *opsign.Signature {
	if len(raw) == 0 {
		return nil
	}
	var sig opsign.Signature
	if json.Unmarshal(raw, &sig) != nil {
		return nil
	}
	return &sig
}

// sameSignature compares two stored signatures, which may have come back
// through jsonb with different spacing.
func sameSignature(a, b json.RawMessage) bool {
	sa, sb := decodeSignature(a), decodeSignature(b)
	if sa == nil || sb == nil {
		return sa == nil && sb == nil
	}
	return *sa == *sb
}
