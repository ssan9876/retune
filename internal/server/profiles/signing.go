package profiles

import (
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"retune/internal/opsign"
	"retune/internal/protocol"
)

// checkSignature refuses stored settings that aren't signed by a trusted
// operations key, when the server has any. It checks what a device will be
// sent — secrets opened — since that is what the agent checks too.
func (s *Service) checkSignature(profileID uuid.UUID, stored []byte, sig *opsign.Signature) error {
	if len(s.OperationsKeys) == 0 {
		return nil
	}
	var settings []protocol.Setting
	if err := json.Unmarshal(stored, &settings); err != nil {
		return fmt.Errorf("decode settings: %w", err)
	}
	opened, err := s.ForAgent(profileID, settings)
	if err != nil {
		return err
	}
	if err := opsign.Verify(s.OperationsKeys, protocol.ProfileManifest(opened), sig); err != nil {
		return fmt.Errorf("%w: %v; sign it with retune-sign sign-profile", ErrBadRequest, err)
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

// DecodeSignature reads a stored signature; nil if there is none.
func DecodeSignature(raw json.RawMessage) *opsign.Signature {
	if len(raw) == 0 {
		return nil
	}
	var sig opsign.Signature
	if json.Unmarshal(raw, &sig) != nil {
		return nil
	}
	return &sig
}

func sameSignature(a, b json.RawMessage) bool {
	sa, sb := DecodeSignature(a), DecodeSignature(b)
	if sa == nil || sb == nil {
		return sa == nil && sb == nil
	}
	return *sa == *sb
}
