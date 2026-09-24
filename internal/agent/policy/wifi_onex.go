package policy

import (
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"slices"
	"strings"

	"retune/internal/protocol"
)

// An 802.1X network adds an OneX element to the WLAN profile, holding an
// EapHostConfig, which holds the method's own settings. Each schema has its
// own namespace, carried in the struct tags below, and Windows checks them.

// EAP method type numbers (IANA).
const (
	eapTypeTLS      = 13
	eapTypePEAP     = 25
	eapTypeMSCHAPv2 = 26
)

type oneX struct {
	XMLName       xml.Name      `xml:"http://www.microsoft.com/networking/OneX/v1 OneX"`
	CacheUserData bool          `xml:"cacheUserData"`
	AuthMode      string        `xml:"authMode"`
	EapHostConfig eapHostConfig `xml:"EAPConfig>EapHostConfig"`
}

type eapHostConfig struct {
	XMLName   xml.Name       `xml:"http://www.microsoft.com/provisioning/EapHostConfig EapHostConfig"`
	EapMethod eapMethod      `xml:"EapMethod"`
	Config    eapHostConfig2 `xml:"Config"`
}

type eapMethod struct {
	Type       eapCommonInt `xml:"http://www.microsoft.com/provisioning/EapCommon Type"`
	VendorID   eapCommonInt `xml:"http://www.microsoft.com/provisioning/EapCommon VendorId"`
	VendorType eapCommonInt `xml:"http://www.microsoft.com/provisioning/EapCommon VendorType"`
	AuthorID   eapCommonInt `xml:"http://www.microsoft.com/provisioning/EapCommon AuthorId"`
}

type eapCommonInt struct {
	Value int `xml:",chardata"`
}

type eapHostConfig2 struct {
	Eap baseEap `xml:"http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1 Eap"`
}

// baseEap is one EAP method's settings: the outer method, or PEAP's inner.
type baseEap struct {
	Type     int       `xml:"Type"`
	PEAP     *peapType `xml:"http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV1 EapType,omitempty"`
	TLS      *tlsType  `xml:"http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1 EapType,omitempty"`
	MSCHAPv2 *mschapv2 `xml:"http://www.microsoft.com/provisioning/MsChapV2ConnectionPropertiesV1 EapType,omitempty"`
}

type serverValidation struct {
	DisableUserPromptForServerValidation bool     `xml:"DisableUserPromptForServerValidation"`
	ServerNames                          string   `xml:"ServerNames"`
	TrustedRootCA                        []string `xml:"TrustedRootCA"`
}

type peapType struct {
	ServerValidation       serverValidation `xml:"ServerValidation"`
	FastReconnect          bool             `xml:"FastReconnect"`
	InnerEapOptional       bool             `xml:"InnerEapOptional"`
	Eap                    baseEap          `xml:"http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1 Eap"`
	EnableQuarantineChecks bool             `xml:"EnableQuarantineChecks"`
	RequireCryptoBinding   bool             `xml:"RequireCryptoBinding"`
	Extensions             peapExtensions   `xml:"PeapExtensions"`
}

type peapExtensions struct {
	PerformServerValidation bool `xml:"http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2 PerformServerValidation"`
	AcceptServerName        bool `xml:"http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2 AcceptServerName"`
}

type mschapv2 struct {
	UseWinLogonCredentials bool `xml:"UseWinLogonCredentials"`
}

type tlsType struct {
	SimpleCertSelection     bool             `xml:"CredentialsSource>CertificateStore>SimpleCertSelection"`
	ServerValidation        serverValidation `xml:"ServerValidation"`
	DifferentUsername       bool             `xml:"DifferentUsername"`
	PerformServerValidation bool             `xml:"http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2 PerformServerValidation"`
	AcceptServerName        bool             `xml:"http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2 AcceptServerName"`
}

// oneXAuthModes are the profile's names for who signs in.
var oneXAuthModes = map[string]string{
	"":                         "machineOrUser",
	protocol.OneXMachineOrUser: "machineOrUser",
	protocol.OneXMachine:       "machine",
	protocol.OneXUser:          "user",
}

// thumbprintBytes writes a thumbprint the way the profile carries it: hex
// bytes separated by spaces.
func thumbprintBytes(t string) (string, error) {
	raw, err := hex.DecodeString(protocol.NormalizeThumbprint(t))
	if err != nil || len(raw) != 20 {
		return "", fmt.Errorf("%q is not a SHA-1 thumbprint", t)
	}
	parts := make([]string, len(raw))
	for i, b := range raw {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(parts, " "), nil
}

// renderOneX builds an 802.1X network's OneX element. The server names and
// trusted roots are always set and the user is never asked to trust a server
// itself: a device only ever talks to the RADIUS servers named.
func renderOneX(s protocol.Setting) (*oneX, error) {
	mode, ok := oneXAuthModes[s.AuthMode]
	if !ok {
		return nil, fmt.Errorf("unknown 802.1X auth mode %q", s.AuthMode)
	}
	sv := serverValidation{DisableUserPromptForServerValidation: true, ServerNames: strings.Join(s.ServerNames, ";")}
	for _, t := range s.TrustedRootThumbprints {
		b, err := thumbprintBytes(t)
		if err != nil {
			return nil, err
		}
		sv.TrustedRootCA = append(sv.TrustedRootCA, b)
	}
	if sv.ServerNames == "" || len(sv.TrustedRootCA) == 0 {
		return nil, fmt.Errorf("an enterprise network needs server names and trusted root thumbprints")
	}
	o := &oneX{CacheUserData: true, AuthMode: mode}
	switch s.EAPMethod {
	case protocol.EAPPEAP:
		o.EapHostConfig.EapMethod.Type.Value = eapTypePEAP
		o.EapHostConfig.Config.Eap = baseEap{Type: eapTypePEAP, PEAP: &peapType{
			ServerValidation: sv, FastReconnect: true,
			Eap:        baseEap{Type: eapTypeMSCHAPv2, MSCHAPv2: &mschapv2{UseWinLogonCredentials: true}},
			Extensions: peapExtensions{PerformServerValidation: true, AcceptServerName: true},
		}}
	case protocol.EAPTLS:
		o.EapHostConfig.EapMethod.Type.Value = eapTypeTLS
		o.EapHostConfig.Config.Eap = baseEap{Type: eapTypeTLS, TLS: &tlsType{
			SimpleCertSelection: true, ServerValidation: sv,
			PerformServerValidation: true, AcceptServerName: true,
		}}
	default:
		return nil, fmt.Errorf("unknown EAP method %q", s.EAPMethod)
	}
	return o, nil
}

// installedOneX is what Test reads back from an exported profile. Its tags
// carry no namespaces, so it reads whatever prefixes Windows chose to write.
type installedOneX struct {
	AuthMode    string   `xml:"MSM>security>OneX>authMode"`
	MethodType  int      `xml:"MSM>security>OneX>EAPConfig>EapHostConfig>EapMethod>Type"`
	ServerNames string   `xml:"MSM>security>OneX>EAPConfig>EapHostConfig>Config>Eap>EapType>ServerValidation>ServerNames"`
	TrustedRoot []string `xml:"MSM>security>OneX>EAPConfig>EapHostConfig>Config>Eap>EapType>ServerValidation>TrustedRootCA"`
}

// oneXMatches reports whether an installed profile's 802.1X settings are the
// ones wanted.
func oneXMatches(raw []byte, want *oneX) bool {
	var have installedOneX
	if err := xml.Unmarshal(raw, &have); err != nil {
		return false
	}
	sv := want.EapHostConfig.Config.Eap.serverValidation()
	norm := func(list []string) []string {
		out := make([]string, 0, len(list))
		for _, t := range list {
			out = append(out, protocol.NormalizeThumbprint(t))
		}
		slices.Sort(out)
		return out
	}
	return strings.EqualFold(have.AuthMode, want.AuthMode) &&
		have.MethodType == want.EapHostConfig.EapMethod.Type.Value &&
		strings.EqualFold(strings.TrimSpace(have.ServerNames), sv.ServerNames) &&
		slices.Equal(norm(have.TrustedRoot), norm(sv.TrustedRootCA))
}

func (b baseEap) serverValidation() serverValidation {
	switch {
	case b.PEAP != nil:
		return b.PEAP.ServerValidation
	case b.TLS != nil:
		return b.TLS.ServerValidation
	}
	return serverValidation{}
}
