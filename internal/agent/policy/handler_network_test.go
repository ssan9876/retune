package policy_test

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"retune/internal/agent/policy"
	"retune/internal/protocol"
)

func boolPtr(b bool) *bool { return &b }

func TestRenderWLANProfile(t *testing.T) {
	cases := map[string]struct {
		s    protocol.Setting
		want []string
		not  []string
	}{
		"wpa2": {
			protocol.Setting{Kind: protocol.KindWiFi, SSID: "Contoso", Security: protocol.WiFiWPA2Personal, Passphrase: "correct horse"},
			[]string{"<authentication>WPA2PSK</authentication>", "<encryption>AES</encryption>",
				"<keyMaterial>correct horse</keyMaterial>", "<connectionMode>auto</connectionMode>",
				"<nonBroadcast>false</nonBroadcast>", `xmlns="http://www.microsoft.com/networking/WLAN/profile/v1"`},
			nil,
		},
		"wpa3, hidden, manual": {
			protocol.Setting{Kind: protocol.KindWiFi, SSID: "Lab", Security: protocol.WiFiWPA3Personal, Passphrase: "12345678",
				Hidden: true, AutoConnect: boolPtr(false)},
			[]string{"<authentication>WPA3SAE</authentication>", "<nonBroadcast>true</nonBroadcast>", "<connectionMode>manual</connectionMode>"},
			nil,
		},
		"open": {
			protocol.Setting{Kind: protocol.KindWiFi, SSID: "Guest", Security: protocol.WiFiOpen},
			[]string{"<authentication>open</authentication>", "<encryption>none</encryption>"},
			[]string{"sharedKey", "keyMaterial"},
		},
		// Markup in a name or passphrase stays text.
		"escaped": {
			protocol.Setting{Kind: protocol.KindWiFi, SSID: "A&B <Net>", Security: protocol.WiFiWPA2Personal, Passphrase: "</keyMaterial><x>"},
			[]string{"<name>A&amp;B &lt;Net&gt;</name>", "<keyMaterial>&lt;/keyMaterial&gt;&lt;x&gt;</keyMaterial>"},
			nil,
		},
	}
	for name, c := range cases {
		out, err := policy.RenderWLANProfile(c.s)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		text := string(out)
		for _, w := range c.want {
			if !strings.Contains(text, w) {
				t.Errorf("%s: missing %s in\n%s", name, w, text)
			}
		}
		for _, n := range c.not {
			if strings.Contains(text, n) {
				t.Errorf("%s: unexpected %s", name, n)
			}
		}
	}
	if _, err := policy.RenderWLANProfile(protocol.Setting{Kind: protocol.KindWiFi, SSID: "X", Security: protocol.WiFiWPA2Personal}); err == nil {
		t.Error("a personal network with no passphrase must not render")
	}
}

// fakeNetsh keeps WLAN profiles by SSID the way netsh does: export writes a
// file into the folder asked for, add reads one, delete removes by name.
type fakeNetsh struct {
	profiles map[string][]byte
	noWLAN   bool
	calls    []string
}

var (
	netshExport = regexp.MustCompile(`^wlan export profile name="([^"]+)" key=clear folder="([^"]+)"$`)
	netshAdd    = regexp.MustCompile(`^wlan add profile filename="([^"]+)" user=all$`)
	netshDelete = regexp.MustCompile(`^wlan delete profile name="([^"]+)"$`)
)

func (f *fakeNetsh) run(_ context.Context, args string) (string, error) {
	f.calls = append(f.calls, args)
	if f.noWLAN {
		return "The Wireless AutoConfig Service (wlansvc) is not running.", errors.New("exit status 1")
	}
	if m := netshExport.FindStringSubmatch(args); m != nil {
		p, ok := f.profiles[m[1]]
		if !ok {
			return `Profile "` + m[1] + `" is not found on the system.`, errors.New("exit status 1")
		}
		return "", os.WriteFile(filepath.Join(m[2], "Wi-Fi-"+m[1]+".xml"), p, 0o600)
	}
	if m := netshAdd.FindStringSubmatch(args); m != nil {
		raw, err := os.ReadFile(m[1])
		if err != nil {
			return "", err
		}
		var p struct {
			Name string `xml:"name"`
		}
		if err := xml.Unmarshal(raw, &p); err != nil {
			return "", err
		}
		f.profiles[p.Name] = raw
		return "Profile " + p.Name + " is added on interface Wi-Fi.", nil
	}
	if m := netshDelete.FindStringSubmatch(args); m != nil {
		if _, ok := f.profiles[m[1]]; !ok {
			return "", errors.New(`Profile "` + m[1] + `" is not found on any interface.`)
		}
		delete(f.profiles, m[1])
		return "", nil
	}
	return "", errors.New("unexpected netsh " + args)
}

func TestWiFiHandler(t *testing.T) {
	ctx := context.Background()
	netsh := &fakeNetsh{profiles: map[string][]byte{}}
	tmp := t.TempDir()
	h := policy.WiFiHandler{Run: netsh.run, TempDir: tmp}
	s := protocol.Setting{Kind: protocol.KindWiFi, SSID: "Contoso Corp", Security: protocol.WiFiWPA2Personal, Passphrase: "correct horse"}

	prior, err := h.Get(ctx, s)
	if err != nil || prior.Exists {
		t.Fatalf("Get before = %+v, %v", prior, err)
	}
	if ok, err := h.Test(ctx, s); err != nil || ok {
		t.Fatalf("Test before = %v, %v", ok, err)
	}
	if err := h.Set(ctx, s); err != nil {
		t.Fatal(err)
	}
	if ok, err := h.Test(ctx, s); err != nil || !ok {
		t.Fatalf("Test after = %v, %v", ok, err)
	}
	// A changed passphrase is drift.
	changed := s
	changed.Passphrase = "a new passphrase"
	if ok, _ := h.Test(ctx, changed); ok {
		t.Fatal("a different passphrase must not test compliant")
	}
	// No file with the passphrase is left behind.
	if entries, _ := os.ReadDir(tmp); len(entries) != 0 {
		t.Fatalf("left %d files in the temp folder", len(entries))
	}
	if err := h.Revert(ctx, s, prior); err != nil {
		t.Fatal(err)
	}
	if _, ok := netsh.profiles["Contoso Corp"]; ok {
		t.Fatal("revert didn't remove the profile it added")
	}

	// A profile that was there first is put back as it was.
	original, _ := policy.RenderWLANProfile(protocol.Setting{Kind: protocol.KindWiFi, SSID: "Contoso Corp",
		Security: protocol.WiFiWPA2Personal, Passphrase: "the old one"})
	netsh.profiles["Contoso Corp"] = original
	prior, err = h.Get(ctx, s)
	if err != nil || !prior.Exists {
		t.Fatalf("Get existing = %+v, %v", prior, err)
	}
	if err := h.Set(ctx, s); err != nil {
		t.Fatal(err)
	}
	if err := h.Revert(ctx, s, prior); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(netsh.profiles["Contoso Corp"]), "the old one") {
		t.Fatal("revert didn't restore the original profile")
	}
}

func TestWiFiWithoutAnAdapterIsNotApplicable(t *testing.T) {
	h := policy.WiFiHandler{Run: (&fakeNetsh{noWLAN: true}).run, TempDir: t.TempDir()}
	s := protocol.Setting{Kind: protocol.KindWiFi, SSID: "Contoso", Security: protocol.WiFiOpen}
	if _, err := h.Test(context.Background(), s); !errors.Is(err, policy.ErrNotApplicable) {
		t.Fatalf("Test = %v", err)
	}
}

// fakeVPN answers the VpnClient cmdlets from one map.
type fakeVPN struct {
	conns   map[string]map[string]any
	scripts []string
}

var (
	vpnGet    = regexp.MustCompile(`Get-VpnConnection -AllUserConnection -Name '([^']+)'`)
	vpnApply  = regexp.MustCompile(`^(Add|Set)-VpnConnection -AllUserConnection -Name '([^']+)' -ServerAddress '([^']*)' -TunnelType '([^']*)' -AuthenticationMethod '([^']*)' -SplitTunneling \$(True|False|true|false) -DnsSuffix '([^']*)' -Force`)
	vpnRemove = regexp.MustCompile(`^Remove-VpnConnection -AllUserConnection -Name '([^']+)'`)
)

func (f *fakeVPN) run(_ context.Context, script string) (string, error) {
	f.scripts = append(f.scripts, script)
	if m := vpnGet.FindStringSubmatch(script); m != nil {
		c, ok := f.conns[m[1]]
		if !ok {
			return "", nil
		}
		b, err := json.Marshal(c)
		return string(b), err
	}
	if m := vpnApply.FindStringSubmatch(script); m != nil {
		_, exists := f.conns[m[2]]
		if (m[1] == "Add") == exists {
			return "", errors.New(m[1] + " on a connection that does or doesn't exist")
		}
		f.conns[m[2]] = map[string]any{
			"ServerAddress": m[3], "TunnelType": m[4], "AuthenticationMethod": []string{m[5]},
			"SplitTunneling": strings.EqualFold(m[6], "true"), "DnsSuffix": m[7],
		}
		return "", nil
	}
	if m := vpnRemove.FindStringSubmatch(script); m != nil {
		delete(f.conns, m[1])
		return "", nil
	}
	return "", errors.New("unexpected script " + script)
}

func TestVPNHandler(t *testing.T) {
	ctx := context.Background()
	vpn := &fakeVPN{conns: map[string]map[string]any{}}
	h := policy.VPNHandler{Run: vpn.run}
	s := protocol.Setting{
		Kind: protocol.KindVPN, Name: "Contoso VPN", Server: "vpn.contoso.com", Tunnel: protocol.VPNIKEv2,
		Authentication: protocol.VPNAuthMachineCertificate, SplitTunneling: true, DNSSuffix: "corp.contoso.com",
	}
	prior, err := h.Get(ctx, s)
	if err != nil || prior.Exists {
		t.Fatalf("Get before = %+v, %v", prior, err)
	}
	if err := h.Set(ctx, s); err != nil {
		t.Fatal(err)
	}
	if ok, err := h.Test(ctx, s); err != nil || !ok {
		t.Fatalf("Test after = %v, %v", ok, err)
	}
	moved := s
	moved.Server = "vpn2.contoso.com"
	if ok, _ := h.Test(ctx, moved); ok {
		t.Fatal("a different server must not test compliant")
	}
	// Setting again changes the one that is there, rather than adding.
	if err := h.Set(ctx, moved); err != nil {
		t.Fatal(err)
	}
	if err := h.Revert(ctx, s, prior); err != nil {
		t.Fatal(err)
	}
	if len(vpn.conns) != 0 {
		t.Fatalf("revert left %v", vpn.conns)
	}
}

// A setting the machine can't have is reported not_applicable, not error,
// and nothing is set.
func TestNotApplicableIsReported(t *testing.T) {
	netsh := &fakeNetsh{noWLAN: true}
	st, rep := newStore(), newReporter()
	r := &policy.Reconciler{Handlers: []policy.Handler{policy.WiFiHandler{Run: netsh.run, TempDir: t.TempDir()}}, State: st, Client: rep}
	s := protocol.Setting{Kind: protocol.KindWiFi, SSID: "Contoso", Security: protocol.WiFiOpen}
	if err := r.Reconcile(context.Background(), []policy.Assigned{{ProfileID: "p1", Version: 1, Settings: []protocol.Setting{s}}}); err != nil {
		t.Fatal(err)
	}
	if got := statusOf(t, rep.reports["p1"], s.Identity()); got.Status != protocol.SettingNotApplicable {
		t.Fatalf("status = %+v", got)
	}
	for _, call := range netsh.calls {
		if strings.Contains(call, "add profile") {
			t.Fatal("tried to add a profile with no wireless adapter")
		}
	}
}
