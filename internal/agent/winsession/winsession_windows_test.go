//go:build windows

package winsession

import (
	"encoding/base64"
	"strings"
	"testing"
	"unicode/utf16"
)

// The script travels on the command line encoded, because a file under the
// agent's own directory would not be readable by an ordinary user. PowerShell
// expects UTF-16LE, base64.
func TestCommandCarriesTheScriptEncoded(t *testing.T) {
	const script = `Write-Output "hello"`

	line := command(script)
	if !strings.Contains(line, "-NoProfile") || !strings.Contains(line, "-NonInteractive") {
		t.Errorf("the command line should be unattended, got %q", line)
	}

	_, encoded, found := strings.Cut(line, "-EncodedCommand ")
	if !found {
		t.Fatalf("the script should be encoded, got %q", line)
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := decodeUTF16LE(raw); got != script {
		t.Errorf("decoded %q, want %q", got, script)
	}
}

// Text outside the basic plane becomes a surrogate pair, two units, four bytes.
func TestUTF16LEEncodesSurrogatePairs(t *testing.T) {
	const script = "Write-Output '\U0001F600'"

	raw := utf16le(script)
	if len(raw)%2 != 0 {
		t.Fatalf("UTF-16 is two bytes a unit, got %d bytes", len(raw))
	}
	if got := decodeUTF16LE(raw); got != script {
		t.Errorf("decoded %q, want %q", got, script)
	}
}

func decodeUTF16LE(raw []byte) string {
	units := make([]uint16, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		units = append(units, uint16(raw[i])|uint16(raw[i+1])<<8)
	}
	return string(utf16.Decode(units))
}
