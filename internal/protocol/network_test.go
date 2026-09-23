package protocol

import (
	"errors"
	"strings"
	"testing"
)

func TestWiFiValidation(t *testing.T) {
	good := []Setting{
		{Kind: KindWiFi, SSID: "Contoso", Security: WiFiWPA2Personal, Passphrase: "correct horse"},
		{Kind: KindWiFi, SSID: "Contoso", Security: WiFiWPA3Personal, SealedSecret: &SealedSecret{MAC: "m"}},
		{Kind: KindWiFi, SSID: "Guest", Security: WiFiOpen, Hidden: true},
		{Kind: KindWiFi, SSID: strings.Repeat("x", 32), Security: WiFiOpen},
	}
	for _, s := range good {
		if err := s.Validate(); err != nil {
			t.Errorf("%+v: %v", s, err)
		}
	}
	bad := map[string]Setting{
		"no ssid":            {Kind: KindWiFi, Security: WiFiOpen},
		"33 bytes":           {Kind: KindWiFi, SSID: strings.Repeat("é", 17), Security: WiFiOpen},
		"a quote":            {Kind: KindWiFi, SSID: `a"b`, Security: WiFiOpen},
		"no passphrase":      {Kind: KindWiFi, SSID: "C", Security: WiFiWPA2Personal},
		"short passphrase":   {Kind: KindWiFi, SSID: "C", Security: WiFiWPA2Personal, Passphrase: "1234567"},
		"long passphrase":    {Kind: KindWiFi, SSID: "C", Security: WiFiWPA2Personal, Passphrase: strings.Repeat("a", 64)},
		"non-ASCII":          {Kind: KindWiFi, SSID: "C", Security: WiFiWPA2Personal, Passphrase: "passwörd123"},
		"open with a secret": {Kind: KindWiFi, SSID: "C", Security: WiFiOpen, Passphrase: "correct horse"},
		"enterprise":         {Kind: KindWiFi, SSID: "C", Security: "wpa2_enterprise"},
	}
	for name, s := range bad {
		if err := s.Validate(); !errors.Is(err, ErrBadSetting) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// SSIDs are case-sensitive; VPN names aren't.
	if (Setting{Kind: KindWiFi, SSID: "Lab"}).Identity() == (Setting{Kind: KindWiFi, SSID: "lab"}).Identity() {
		t.Error("two SSIDs differing in case must be two settings")
	}
	if (Setting{Kind: KindVPN, Name: "Corp"}).Identity() != (Setting{Kind: KindVPN, Name: "corp"}).Identity() {
		t.Error("VPN names are case-insensitive on Windows")
	}
}

func TestVPNValidation(t *testing.T) {
	good := []Setting{
		{Kind: KindVPN, Name: "Contoso VPN", Server: "vpn.contoso.com", Tunnel: VPNIKEv2, Authentication: VPNAuthMachineCertificate},
		{Kind: KindVPN, Name: "Lab", Server: "203.0.113.7", Tunnel: VPNSSTP, Authentication: VPNAuthEAP, DNSSuffix: "lab.local"},
		{Kind: KindVPN, Name: "v6", Server: "2001:db8::1", Tunnel: VPNIKEv2, Authentication: VPNAuthMSCHAPv2, SplitTunneling: true},
	}
	for _, s := range good {
		if err := s.Validate(); err != nil {
			t.Errorf("%+v: %v", s, err)
		}
	}
	base := Setting{Kind: KindVPN, Name: "Corp", Server: "vpn.contoso.com", Tunnel: VPNIKEv2, Authentication: VPNAuthEAP}
	bad := map[string]func(*Setting){
		"script in the name":   func(s *Setting) { s.Name = "x'; Remove-Item C:\\ #" },
		"no name":              func(s *Setting) { s.Name = "" },
		"script in the server": func(s *Setting) { s.Server = "vpn.contoso.com'; calc" },
		"no server":            func(s *Setting) { s.Server = "" },
		"l2tp":                 func(s *Setting) { s.Tunnel = "l2tp" },
		"pap":                  func(s *Setting) { s.Authentication = "pap" },
		"sstp with a cert":     func(s *Setting) { s.Tunnel, s.Authentication = VPNSSTP, VPNAuthMachineCertificate },
		"bad dns suffix":       func(s *Setting) { s.DNSSuffix = "corp contoso" },
	}
	for name, mutate := range bad {
		s := base
		mutate(&s)
		if err := s.Validate(); !errors.Is(err, ErrBadSetting) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}
