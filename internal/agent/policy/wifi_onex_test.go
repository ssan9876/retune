package policy_test

import (
	"context"
	"encoding/xml"
	"strings"
	"testing"

	"retune/internal/agent/policy"
	"retune/internal/protocol"
)

const radiusRoot = "A1B2C3D4E5F60718293A4B5C6D7E8F9001122334"

func enterprise(method string) protocol.Setting {
	return protocol.Setting{Kind: protocol.KindWiFi, SSID: "Contoso Secure", Security: protocol.WiFiWPA2Enterprise,
		EAPMethod: method, ServerNames: []string{"radius1.contoso.com", "radius2.contoso.com"},
		TrustedRootThumbprints: []string{"a1:b2:c3:d4:e5:f6:07:18:29:3a:4b:5c:6d:7e:8f:90:01:12:23:34"}}
}

func TestRenderEnterpriseWLANProfile(t *testing.T) {
	common := []string{
		"<authentication>WPA2</authentication>", "<encryption>AES</encryption>", "<useOneX>true</useOneX>",
		`<OneX xmlns="http://www.microsoft.com/networking/OneX/v1">`,
		"<authMode>machineOrUser</authMode>",
		`<EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">`,
		`xmlns="http://www.microsoft.com/provisioning/EapCommon"`,
		`<Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1">`,
		"<DisableUserPromptForServerValidation>true</DisableUserPromptForServerValidation>",
		"<ServerNames>radius1.contoso.com;radius2.contoso.com</ServerNames>",
		"<TrustedRootCA>a1 b2 c3 d4 e5 f6 07 18 29 3a 4b 5c 6d 7e 8f 90 01 12 23 34</TrustedRootCA>",
	}
	for method, want := range map[string][]string{
		protocol.EAPPEAP: {">25</Type>", "<Type>26</Type>", "<UseWinLogonCredentials>true</UseWinLogonCredentials>",
			`xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV1"`,
			`<PerformServerValidation xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2">true</PerformServerValidation>`},
		protocol.EAPTLS: {">13</Type>", "<SimpleCertSelection>true</SimpleCertSelection>",
			`xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1"`,
			`<PerformServerValidation xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">true</PerformServerValidation>`},
	} {
		out, err := policy.RenderWLANProfile(enterprise(method))
		if err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		text := string(out)
		for _, w := range append(common, want...) {
			if !strings.Contains(text, w) {
				t.Errorf("%s: missing %s in\n%s", method, w, text)
			}
		}
		if strings.Contains(text, "sharedKey") {
			t.Errorf("%s: an enterprise network has no shared key", method)
		}
		// Well-formed XML, whatever the nesting.
		if err := xml.Unmarshal(out, new(struct{})); err != nil {
			t.Errorf("%s: %v", method, err)
		}
	}
	machine := enterprise(protocol.EAPTLS)
	machine.AuthMode = protocol.OneXMachine
	if out, _ := policy.RenderWLANProfile(machine); !strings.Contains(string(out), "<authMode>machine</authMode>") {
		t.Error("auth_mode machine")
	}
	bare := enterprise(protocol.EAPPEAP)
	bare.TrustedRootThumbprints = nil
	if _, err := policy.RenderWLANProfile(bare); err == nil {
		t.Error("an enterprise network with no trusted root must not render")
	}
}

func TestEnterpriseWiFiHandler(t *testing.T) {
	ctx := context.Background()
	netsh := &fakeNetsh{profiles: map[string][]byte{}}
	h := policy.WiFiHandler{Run: netsh.run, TempDir: t.TempDir()}
	s := enterprise(protocol.EAPPEAP)
	if err := h.Set(ctx, s); err != nil {
		t.Fatal(err)
	}
	if ok, err := h.Test(ctx, s); err != nil || !ok {
		t.Fatalf("Test after = %v, %v", ok, err)
	}
	// Thumbprints compare however they were written.
	upper := s
	upper.TrustedRootThumbprints = []string{radiusRoot}
	if ok, _ := h.Test(ctx, upper); !ok {
		t.Error("the same thumbprint in another form must test compliant")
	}
	for name, change := range map[string]func(*protocol.Setting){
		"another root":      func(x *protocol.Setting) { x.TrustedRootThumbprints = []string{strings.Repeat("0", 40)} },
		"another server":    func(x *protocol.Setting) { x.ServerNames = []string{"evil.example.com"} },
		"another method":    func(x *protocol.Setting) { x.EAPMethod = protocol.EAPTLS },
		"another auth mode": func(x *protocol.Setting) { x.AuthMode = protocol.OneXUser },
		"now a personal one": func(x *protocol.Setting) {
			*x = protocol.Setting{Kind: protocol.KindWiFi, SSID: x.SSID, Security: protocol.WiFiWPA2Personal, Passphrase: "correct horse"}
		},
	} {
		changed := s
		change(&changed)
		if ok, _ := h.Test(ctx, changed); ok {
			t.Errorf("%s must be drift", name)
		}
	}
}
