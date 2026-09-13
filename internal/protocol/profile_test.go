package protocol_test

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"retune/internal/protocol"
)

func TestSettingIdentityIgnoresCaseAndSpelling(t *testing.T) {
	cases := []struct {
		name string
		a, b protocol.Setting
		same bool
	}{
		{
			name: "registry key case",
			a:    protocol.Setting{Kind: protocol.KindRegistry, Hive: "HKLM", Key: `SOFTWARE\Retune`, Name: "Managed"},
			b:    protocol.Setting{Kind: protocol.KindRegistry, Hive: "hklm", Key: `software\retune`, Name: "managed"},
			same: true,
		},
		{
			name: "registry trailing slash",
			a:    protocol.Setting{Kind: protocol.KindRegistry, Hive: "HKLM", Key: `SOFTWARE\Retune\`, Name: "X"},
			b:    protocol.Setting{Kind: protocol.KindRegistry, Hive: "HKLM", Key: `SOFTWARE/Retune`, Name: "X"},
			same: true,
		},
		{
			name: "different registry values",
			a:    protocol.Setting{Kind: protocol.KindRegistry, Hive: "HKLM", Key: `SOFTWARE\Retune`, Name: "A"},
			b:    protocol.Setting{Kind: protocol.KindRegistry, Hive: "HKLM", Key: `SOFTWARE\Retune`, Name: "B"},
			same: false,
		},
		{
			name: "service case",
			a:    protocol.Setting{Kind: protocol.KindService, Name: "Spooler"},
			b:    protocol.Setting{Kind: protocol.KindService, Name: "spooler"},
			same: true,
		},
		{
			name: "file separators",
			a:    protocol.Setting{Kind: protocol.KindFile, Path: `C:\ProgramData\Retune\a.txt`},
			b:    protocol.Setting{Kind: protocol.KindFile, Path: "c:/programdata/retune/a.txt"},
			same: true,
		},
		{
			name: "group case",
			a:    protocol.Setting{Kind: protocol.KindGroup, Group: "Administrators"},
			b:    protocol.Setting{Kind: protocol.KindGroup, Group: "administrators"},
			same: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.a.Identity() == tc.b.Identity(); got != tc.same {
				t.Fatalf("%q vs %q: same = %v, want %v", tc.a.Identity(), tc.b.Identity(), got, tc.same)
			}
		})
	}
}

func TestValidateAccepts(t *testing.T) {
	for _, s := range []protocol.Setting{
		{Kind: protocol.KindRegistry, Hive: "HKLM", Key: `SOFTWARE\Retune`, Name: "Managed",
			Type: protocol.RegDWord, Data: "1"},
		{Kind: protocol.KindRegistry, Hive: "HKLM", Key: `SOFTWARE\Retune`, Name: "Gone",
			Ensure: protocol.EnsureAbsent},
		{Kind: protocol.KindRegistry, Hive: "HKLM", Key: `SOFTWARE\Retune`, Name: "List",
			Type: protocol.RegMultiSZ, Data: "one\ntwo"},
		{Kind: protocol.KindService, Name: "Spooler", Startup: protocol.StartupDisabled, State: protocol.StateStopped},
		{Kind: protocol.KindService, Name: "Spooler", State: protocol.StateRunning},
		{Kind: protocol.KindGroup, Group: "Administrators", Mode: protocol.ModeAdditive, Members: []string{"CONTOSO\\Ops"}},
		{Kind: protocol.KindGroup, Group: "Administrators", Mode: protocol.ModeExact},
		{Kind: protocol.KindFile, Path: "C:/temp/a.txt", ContentBase64: base64.StdEncoding.EncodeToString([]byte("hi"))},
		{Kind: protocol.KindFile, Path: "C:/temp/a.txt", Ensure: protocol.EnsureAbsent},
	} {
		if err := s.Validate(); err != nil {
			t.Errorf("Validate(%+v) = %v", s, err)
		}
	}
}

func TestValidateRejects(t *testing.T) {
	big := base64.StdEncoding.EncodeToString(make([]byte, protocol.MaxFileBytes+1))
	cases := map[string]struct {
		setting protocol.Setting
		mention string
	}{
		"no kind":              {protocol.Setting{}, "kind"},
		"unknown kind":         {protocol.Setting{Kind: "sorcery"}, "sorcery"},
		"hkcu":                 {protocol.Setting{Kind: protocol.KindRegistry, Hive: "HKCU", Key: "X", Name: "Y", Type: protocol.RegSZ}, "HKCU"},
		"unknown hive":         {protocol.Setting{Kind: protocol.KindRegistry, Hive: "HKXX", Key: "X", Name: "Y"}, "hive"},
		"no registry key":      {protocol.Setting{Kind: protocol.KindRegistry, Hive: "HKLM", Name: "Y", Type: protocol.RegSZ}, "key"},
		"no value name":        {protocol.Setting{Kind: protocol.KindRegistry, Hive: "HKLM", Key: "X", Type: protocol.RegSZ}, "value name"},
		"no registry type":     {protocol.Setting{Kind: protocol.KindRegistry, Hive: "HKLM", Key: "X", Name: "Y"}, "type"},
		"bad registry type":    {protocol.Setting{Kind: protocol.KindRegistry, Hive: "HKLM", Key: "X", Name: "Y", Type: "REG_WHAT"}, "REG_WHAT"},
		"dword not a number":   {protocol.Setting{Kind: protocol.KindRegistry, Hive: "HKLM", Key: "X", Name: "Y", Type: protocol.RegDWord, Data: "lots"}, "whole number"},
		"no service name":      {protocol.Setting{Kind: protocol.KindService, State: protocol.StateRunning}, "name"},
		"service does nothing": {protocol.Setting{Kind: protocol.KindService, Name: "Spooler"}, "startup type, a state"},
		"bad startup":          {protocol.Setting{Kind: protocol.KindService, Name: "S", Startup: "sometimes"}, "startup"},
		"disabled but running": {protocol.Setting{Kind: protocol.KindService, Name: "S",
			Startup: protocol.StartupDisabled, State: protocol.StateRunning}, "cannot also be required to run"},
		"no group":         {protocol.Setting{Kind: protocol.KindGroup, Mode: protocol.ModeExact}, "group name"},
		"no mode":          {protocol.Setting{Kind: protocol.KindGroup, Group: "Users"}, "mode"},
		"additive nobody":  {protocol.Setting{Kind: protocol.KindGroup, Group: "Users", Mode: protocol.ModeAdditive}, "does nothing"},
		"blank member":     {protocol.Setting{Kind: protocol.KindGroup, Group: "Users", Mode: protocol.ModeAdditive, Members: []string{" "}}, "blank"},
		"no path":          {protocol.Setting{Kind: protocol.KindFile, ContentBase64: "aGk="}, "path"},
		"absent with body": {protocol.Setting{Kind: protocol.KindFile, Path: "C:/a", Ensure: protocol.EnsureAbsent, ContentBase64: "aGk="}, "cannot also have contents"},
		"not base64":       {protocol.Setting{Kind: protocol.KindFile, Path: "C:/a", ContentBase64: "not base64!"}, "base64"},
		"file too big":     {protocol.Setting{Kind: protocol.KindFile, Path: "C:/a", ContentBase64: big}, "at most"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := tc.setting.Validate()
			if err == nil {
				t.Fatalf("Validate(%+v) should have failed", tc.setting)
			}
			if !errors.Is(err, protocol.ErrBadSetting) {
				t.Errorf("error should wrap ErrBadSetting, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.mention) {
				t.Errorf("error %q should mention %q", err, tc.mention)
			}
		})
	}
}

func TestValidateSettings(t *testing.T) {
	ok := []protocol.Setting{
		{Kind: protocol.KindService, Name: "Spooler", State: protocol.StateStopped},
		{Kind: protocol.KindFile, Path: "C:/temp/a.txt", ContentBase64: "aGk="},
	}
	if err := protocol.ValidateSettings(ok); err != nil {
		t.Fatal(err)
	}

	if err := protocol.ValidateSettings(nil); err == nil {
		t.Error("an empty profile should be rejected")
	}

	// The same setting twice inside one profile is a mistake the author can
	// fix now, unlike a conflict between two profiles.
	dup := []protocol.Setting{
		{Kind: protocol.KindService, Name: "Spooler", State: protocol.StateStopped},
		{Kind: protocol.KindService, Name: "spooler", State: protocol.StateRunning},
	}
	err := protocol.ValidateSettings(dup)
	if err == nil || !strings.Contains(err.Error(), "both configure") {
		t.Fatalf("want a duplicate-identity error, got %v", err)
	}

	// The error says which setting is wrong.
	bad := []protocol.Setting{
		{Kind: protocol.KindService, Name: "Spooler", State: protocol.StateStopped},
		{Kind: protocol.KindRegistry, Hive: "HKCU", Key: "X", Name: "Y", Type: protocol.RegSZ},
	}
	if err := protocol.ValidateSettings(bad); err == nil || !strings.Contains(err.Error(), "setting 2") {
		t.Fatalf("the error should point at the setting, got %v", err)
	}
}

func TestMultiSZSplitsLines(t *testing.T) {
	s := protocol.Setting{Kind: protocol.KindRegistry, Data: "one\r\ntwo\n\nthree"}
	got := s.MultiSZ()
	want := []string{"one", "two", "three"}
	if len(got) != len(want) {
		t.Fatalf("MultiSZ() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("MultiSZ() = %v, want %v", got, want)
		}
	}
}

func intp(n int) *int    { return &n }
func boolp(b bool) *bool { return &b }

func TestValidateM8KindsAccepts(t *testing.T) {
	for _, s := range []protocol.Setting{
		{Kind: protocol.KindFirewallProfile, Profile: protocol.FirewallDomain, State: protocol.FirewallOn},
		{Kind: protocol.KindFirewallRule, Name: "Allow app", Direction: protocol.DirectionInbound,
			Action: protocol.ActionAllow, Protocol: protocol.ProtocolTCP, LocalPort: "443"},
		{Kind: protocol.KindFirewallRule, Name: "Allow range", Direction: protocol.DirectionOutbound,
			Action: protocol.ActionBlock, Protocol: protocol.ProtocolUDP, LocalPort: "5000-5010"},
		{Kind: protocol.KindFirewallRule, Name: "Old rule", Ensure: protocol.EnsureAbsent},
		{Kind: protocol.KindWindowsUpdate, QualityDeferralDays: intp(7)},
		{Kind: protocol.KindWindowsUpdate, ActiveHoursStart: intp(8), ActiveHoursEnd: intp(18)},
		{Kind: protocol.KindWindowsUpdate, AutoRestart: boolp(false)},
		{Kind: protocol.KindBitLocker, RequireEncryption: true},
		{Kind: protocol.KindBitLocker, RequireEncryption: true, Method: protocol.XtsAes256, EscrowRecoveryKey: true},
	} {
		if err := s.Validate(); err != nil {
			t.Errorf("Validate(%+v) = %v", s, err)
		}
	}
}

func TestValidateM8KindsRejects(t *testing.T) {
	cases := map[string]struct {
		setting protocol.Setting
		mention string
	}{
		"unknown firewall profile": {
			protocol.Setting{Kind: protocol.KindFirewallProfile, Profile: "guest", State: protocol.FirewallOn},
			"domain, private or public"},
		"firewall neither on nor off": {
			protocol.Setting{Kind: protocol.KindFirewallProfile, Profile: protocol.FirewallDomain, State: "maybe"},
			"on or off"},
		"rule without a name": {
			protocol.Setting{Kind: protocol.KindFirewallRule, Direction: protocol.DirectionInbound, Action: protocol.ActionAllow},
			"name"},
		"rule without a direction": {
			protocol.Setting{Kind: protocol.KindFirewallRule, Name: "X", Action: protocol.ActionAllow},
			"direction"},
		"rule without an action": {
			protocol.Setting{Kind: protocol.KindFirewallRule, Name: "X", Direction: protocol.DirectionInbound},
			"action"},
		"port on protocol any": {
			protocol.Setting{Kind: protocol.KindFirewallRule, Name: "X", Direction: protocol.DirectionInbound,
				Action: protocol.ActionAllow, Protocol: protocol.ProtocolAny, LocalPort: "80"},
			"only means something with tcp or udp"},
		"port out of range": {
			protocol.Setting{Kind: protocol.KindFirewallRule, Name: "X", Direction: protocol.DirectionInbound,
				Action: protocol.ActionAllow, Protocol: protocol.ProtocolTCP, LocalPort: "70000"},
			"not a port"},
		"deferral too long": {
			protocol.Setting{Kind: protocol.KindWindowsUpdate, QualityDeferralDays: intp(45)},
			"between 0 and 30"},
		"hour out of range": {
			protocol.Setting{Kind: protocol.KindWindowsUpdate, ActiveHoursStart: intp(25), ActiveHoursEnd: intp(2)},
			"between 0 and 23"},
		"half of active hours": {
			protocol.Setting{Kind: protocol.KindWindowsUpdate, ActiveHoursStart: intp(8)},
			"both a start and an end"},
		"active hours of no length": {
			protocol.Setting{Kind: protocol.KindWindowsUpdate, ActiveHoursStart: intp(8), ActiveHoursEnd: intp(8)},
			"same hour"},
		"empty update policy": {
			protocol.Setting{Kind: protocol.KindWindowsUpdate},
			"does nothing"},
		"bitlocker requiring nothing": {
			protocol.Setting{Kind: protocol.KindBitLocker},
			"does nothing"},
		"escrow without encryption": {
			protocol.Setting{Kind: protocol.KindBitLocker, EscrowRecoveryKey: true},
			"only be escrowed when encryption is required"},
		"unknown method": {
			protocol.Setting{Kind: protocol.KindBitLocker, RequireEncryption: true, Method: "rot13"},
			"method must be"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := tc.setting.Validate()
			if err == nil {
				t.Fatalf("Validate(%+v) should have failed", tc.setting)
			}
			if !errors.Is(err, protocol.ErrBadSetting) {
				t.Errorf("error should wrap ErrBadSetting, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.mention) {
				t.Errorf("error %q should mention %q", err, tc.mention)
			}
		})
	}
}

// One machine has one update policy, so two profiles configuring it are the
// same setting and the engine will call it a conflict.
func TestWindowsUpdateHasOneIdentity(t *testing.T) {
	a := protocol.Setting{Kind: protocol.KindWindowsUpdate, QualityDeferralDays: intp(7)}
	b := protocol.Setting{Kind: protocol.KindWindowsUpdate, QualityDeferralDays: intp(14)}
	if a.Identity() != b.Identity() {
		t.Fatalf("%q and %q should be the same setting", a.Identity(), b.Identity())
	}
}

func TestFirewallRuleIdentityIgnoresCase(t *testing.T) {
	a := protocol.Setting{Kind: protocol.KindFirewallRule, Name: "Allow App"}
	b := protocol.Setting{Kind: protocol.KindFirewallRule, Name: " allow app "}
	if a.Identity() != b.Identity() {
		t.Fatalf("%q and %q should be the same rule", a.Identity(), b.Identity())
	}
}
