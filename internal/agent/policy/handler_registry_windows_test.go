//go:build windows

package policy

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/windows/registry"

	"retune/internal/agent/winsession"
	"retune/internal/protocol"
)

// HKCU is reached through HKEY_USERS, so the path a setting resolves to names
// the signed-in user's SID.
func TestHKCUResolvesUnderTheUsersHive(t *testing.T) {
	previous := userHive
	userHive = func() (string, error) { return "S-1-5-21-1-2-3-1001", nil }
	t.Cleanup(func() { userHive = previous })

	s := setting(`Software\Retune`, "HKCU")
	hive, err := hiveOf(s)
	if err != nil {
		t.Fatal(err)
	}
	if hive != registry.USERS {
		t.Errorf("HKCU should be read through HKEY_USERS, got %v", hive)
	}

	path, err := keyPath(s)
	if err != nil {
		t.Fatal(err)
	}
	if want := `S-1-5-21-1-2-3-1001\Software\Retune`; path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
}

// With nobody signed in there is no hive to write to, and the error says so
// rather than writing somewhere arbitrary.
func TestHKCUWithNobodySignedIn(t *testing.T) {
	previous := userHive
	userHive = func() (string, error) { return "", winsession.ErrNoSession }
	t.Cleanup(func() { userHive = previous })

	_, err := keyPath(setting(`Software\Retune`, "HKCU"))
	if err == nil {
		t.Fatal("it should refuse")
	}
	if !errors.Is(err, winsession.ErrNoSession) {
		t.Errorf("the cause should survive, got %v", err)
	}
	if !strings.Contains(err.Error(), "signed-in user") {
		t.Errorf("the message should explain itself, got %q", err)
	}
}

// HKLM needs no session, so it is unaffected by any of this.
func TestHKLMIsUnchanged(t *testing.T) {
	previous := userHive
	userHive = func() (string, error) { t.Fatal("HKLM must not need a session"); return "", nil }
	t.Cleanup(func() { userHive = previous })

	path, err := keyPath(setting(`SOFTWARE/Retune\`, "HKLM"))
	if err != nil {
		t.Fatal(err)
	}
	if want := `SOFTWARE\Retune`; path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
}

// setting is a registry setting in one hive, which is all these tests need.
func setting(key, hive string) protocol.Setting {
	return protocol.Setting{Kind: protocol.KindRegistry, Hive: hive, Key: key,
		Name: "Managed", Type: protocol.RegSZ, Data: "yes"}
}
