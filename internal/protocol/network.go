package protocol

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"unicode/utf8"
)

// The network setting kinds.
const (
	// KindWiFi adds a wireless network profile for every user.
	KindWiFi = "wifi"
	// KindVPN adds a VPN connection for every user.
	KindVPN = "vpn"
)

// Wi-Fi security types.
const (
	WiFiOpen          = "open"
	WiFiWPA2Personal  = "wpa2_personal"
	WiFiWPA3Personal  = "wpa3_personal"
	passphraseMinimum = 8
	passphraseMaximum = 63
)

// VPN tunnel and authentication types.
const (
	VPNIKEv2 = "ikev2"
	VPNSSTP  = "sstp"

	VPNAuthEAP                = "eap"
	VPNAuthMachineCertificate = "machine_certificate"
	VPNAuthMSCHAPv2           = "mschapv2"
)

// SealedSecret is a setting's secret as the server stores it: encrypted, with
// a keyed MAC of the plaintext so a profile edit that leaves the secret alone
// isn't a new version. It never leaves the server; agents receive the
// plaintext in the setting's secret field instead, and admins only
// SecretSet.
type SealedSecret struct {
	Ciphertext string `json:"ciphertext"`
	Nonce      string `json:"nonce"`
	MAC        string `json:"mac"`
}

// HasSecret reports whether a setting kind carries a secret.
func (s Setting) HasSecret() bool { return s.Kind == KindWiFi }

// NeedsSecret reports whether this setting must have one.
func (s Setting) NeedsSecret() bool {
	return s.Kind == KindWiFi && (s.Security == WiFiWPA2Personal || s.Security == WiFiWPA3Personal)
}

// validateSSID keeps a network name to what a WLAN profile and netsh can
// carry safely: 1-32 bytes, printable, and no double quote.
func validateSSID(ssid string) error {
	if len(ssid) == 0 || len(ssid) > 32 {
		return fmt.Errorf("%w: ssid must be 1 to 32 bytes", ErrBadSetting)
	}
	if !utf8.ValidString(ssid) || strings.ContainsAny(ssid, "\"\x00\r\n\t") {
		return fmt.Errorf("%w: ssid can't contain quotes or control characters", ErrBadSetting)
	}
	return nil
}

func (s Setting) validateWiFi() error {
	if err := validateSSID(s.SSID); err != nil {
		return err
	}
	switch s.Security {
	case WiFiOpen:
		if s.Passphrase != "" || s.SealedSecret != nil {
			return fmt.Errorf("%w: an open network has no passphrase", ErrBadSetting)
		}
	case WiFiWPA2Personal, WiFiWPA3Personal:
		if s.Passphrase == "" && s.SealedSecret == nil {
			return fmt.Errorf("%w: a %s network needs a passphrase", ErrBadSetting, s.Security)
		}
		if s.Passphrase != "" {
			n := utf8.RuneCountInString(s.Passphrase)
			if n < passphraseMinimum || n > passphraseMaximum || !isPrintableASCII(s.Passphrase) {
				return fmt.Errorf("%w: a passphrase is %d to %d printable ASCII characters", ErrBadSetting,
					passphraseMinimum, passphraseMaximum)
			}
		}
	default:
		return fmt.Errorf("%w: security must be open, wpa2_personal or wpa3_personal", ErrBadSetting)
	}
	return nil
}

func isPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

var (
	vpnNamePattern   = regexp.MustCompile(`^[A-Za-z0-9 ._-]{1,64}$`)
	hostnamePattern  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)
	dnsSuffixPattern = hostnamePattern
)

func (s Setting) validateVPN() error {
	if !vpnNamePattern.MatchString(s.Name) {
		return fmt.Errorf("%w: a VPN's name is 1 to 64 letters, digits, spaces, dots, dashes or underscores", ErrBadSetting)
	}
	if net.ParseIP(s.Server) == nil && (len(s.Server) > 253 || !hostnamePattern.MatchString(s.Server)) {
		return fmt.Errorf("%w: server must be a host name or IP address", ErrBadSetting)
	}
	switch s.Tunnel {
	case VPNIKEv2, VPNSSTP:
	default:
		return fmt.Errorf("%w: tunnel must be ikev2 or sstp", ErrBadSetting)
	}
	switch s.Authentication {
	case VPNAuthEAP, VPNAuthMachineCertificate, VPNAuthMSCHAPv2:
	default:
		return fmt.Errorf("%w: authentication must be eap, machine_certificate or mschapv2", ErrBadSetting)
	}
	if s.Tunnel == VPNSSTP && s.Authentication == VPNAuthMachineCertificate {
		return fmt.Errorf("%w: SSTP can't authenticate with a machine certificate; use IKEv2", ErrBadSetting)
	}
	if s.DNSSuffix != "" && !dnsSuffixPattern.MatchString(s.DNSSuffix) {
		return fmt.Errorf("%w: dns_suffix must be a domain name", ErrBadSetting)
	}
	return nil
}
