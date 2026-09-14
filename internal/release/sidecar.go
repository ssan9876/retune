package release

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// sidecar is the on-disk and on-the-wire form of a Signature: the .sig file
// beside a build, and the upload header.
type sidecar struct {
	Version   string `json:"version"`
	SHA256    string `json:"sha256"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

// MarshalJSON writes the sidecar form.
func (s Signature) MarshalJSON() ([]byte, error) {
	return json.Marshal(sidecar{
		Version: s.Version, SHA256: s.SHA256, KeyID: s.KeyID,
		Signature: base64.StdEncoding.EncodeToString(s.Signature),
	})
}

// UnmarshalJSON reads the sidecar form, refusing a signature of the wrong
// length before it can reach a verifier.
func (s *Signature) UnmarshalJSON(b []byte) error {
	var w sidecar
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	raw, err := base64.StdEncoding.DecodeString(w.Signature)
	if err != nil {
		return fmt.Errorf("signature is not base64: %w", err)
	}
	if len(raw) != ed25519.SignatureSize {
		return fmt.Errorf("signature is %d bytes, want %d", len(raw), ed25519.SignatureSize)
	}
	*s = Signature{Version: w.Version, SHA256: w.SHA256, KeyID: w.KeyID, Signature: raw}
	return nil
}

// DecodeSidecar parses a .sig file or an upload header's payload.
func DecodeSidecar(b []byte) (Signature, error) {
	var s Signature
	if err := json.Unmarshal(b, &s); err != nil {
		return Signature{}, err
	}
	return s, nil
}
