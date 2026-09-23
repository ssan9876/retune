package policy

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"retune/internal/protocol"
)

// ErrNotApplicable is returned by a handler for a setting this machine can't
// have and doesn't need, such as Wi-Fi with no wireless adapter.
var ErrNotApplicable = errors.New("not applicable")

// Netsh runs netsh with the rest of a command line after "netsh ", exactly as
// given: netsh parses its own arguments, quotes included.
type Netsh func(ctx context.Context, args string) (string, error)

// WiFiHandler adds a wireless network for every user with netsh, from a WLAN
// profile it renders itself.
type WiFiHandler struct {
	Run Netsh
	// TempDir is where the profile is written for netsh to read, and exported
	// to be compared; empty uses the system's.
	TempDir string
}

func (WiFiHandler) Kind() string { return protocol.KindWiFi }

// wlanProfile is the part of the WLAN profile schema Retune writes and reads.
type wlanProfile struct {
	XMLName        xml.Name `xml:"http://www.microsoft.com/networking/WLAN/profile/v1 WLANProfile"`
	Name           string   `xml:"name"`
	SSID           string   `xml:"SSIDConfig>SSID>name"`
	NonBroadcast   bool     `xml:"SSIDConfig>nonBroadcast"`
	ConnectionType string   `xml:"connectionType"`
	ConnectionMode string   `xml:"connectionMode"`
	Authentication string   `xml:"MSM>security>authEncryption>authentication"`
	Encryption     string   `xml:"MSM>security>authEncryption>encryption"`
	UseOneX        bool     `xml:"MSM>security>authEncryption>useOneX"`
	SharedKey      *wlanKey `xml:"MSM>security>sharedKey,omitempty"`
}

type wlanKey struct {
	KeyType     string `xml:"keyType"`
	Protected   bool   `xml:"protected"`
	KeyMaterial string `xml:"keyMaterial"`
}

// wlanAuth is how each security type is written.
var wlanAuth = map[string][2]string{
	protocol.WiFiOpen:         {"open", "none"},
	protocol.WiFiWPA2Personal: {"WPA2PSK", "AES"},
	protocol.WiFiWPA3Personal: {"WPA3SAE", "AES"},
}

// RenderWLANProfile turns a setting into the profile XML netsh imports. It is
// built with encoding/xml, so nothing in an SSID or passphrase can escape
// its element.
func RenderWLANProfile(s protocol.Setting) ([]byte, error) {
	auth, ok := wlanAuth[s.Security]
	if !ok {
		return nil, fmt.Errorf("unknown Wi-Fi security %q", s.Security)
	}
	mode := "auto"
	if s.AutoConnect != nil && !*s.AutoConnect {
		mode = "manual"
	}
	p := wlanProfile{
		Name: s.SSID, SSID: s.SSID, NonBroadcast: s.Hidden, ConnectionType: "ESS", ConnectionMode: mode,
		Authentication: auth[0], Encryption: auth[1],
	}
	if s.Security != protocol.WiFiOpen {
		if s.Passphrase == "" {
			return nil, errors.New("the definition has no passphrase for this network")
		}
		p.SharedKey = &wlanKey{KeyType: "passPhrase", KeyMaterial: s.Passphrase}
	}
	out, err := xml.MarshalIndent(p, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), out...), nil
}

func (h WiFiHandler) run(ctx context.Context, args string) (string, error) {
	if h.Run == nil {
		return "", fmt.Errorf("%w: Wi-Fi settings are only supported on Windows", ErrNotApplicable)
	}
	out, err := h.Run(ctx, args)
	if err != nil && noWireless(out+err.Error()) {
		return out, fmt.Errorf("%w: this machine has no wireless adapter", ErrNotApplicable)
	}
	return out, err
}

// noWireless recognises netsh saying there is no Wi-Fi to configure.
func noWireless(text string) bool {
	text = strings.ToLower(text)
	return strings.Contains(text, "wlansvc") || strings.Contains(text, "no wireless interface")
}

// export reads the profile named ssid as it is installed now, with its key,
// or nil if there is none.
func (h WiFiHandler) export(ctx context.Context, ssid string) (*wlanProfile, []byte, error) {
	dir, err := os.MkdirTemp(h.TempDir, "retune-wlan-*")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(dir)
	out, err := h.run(ctx, `wlan export profile name="`+ssid+`" key=clear folder="`+dir+`"`)
	if errors.Is(err, ErrNotApplicable) {
		return nil, nil, err
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.xml"))
	if len(files) == 0 {
		if err != nil && !strings.Contains(strings.ToLower(out+err.Error()), "not found") {
			return nil, nil, err
		}
		return nil, nil, nil // no such profile
	}
	raw, err := os.ReadFile(files[0])
	if err != nil {
		return nil, nil, err
	}
	var p wlanProfile
	if err := xml.Unmarshal(raw, &p); err != nil {
		return nil, nil, fmt.Errorf("read the exported Wi-Fi profile: %w", err)
	}
	return &p, raw, nil
}

// wifiState is what was installed before, kept so a revert can put it back.
type wifiState struct {
	Profile []byte `json:"profile"`
}

func (h WiFiHandler) Get(ctx context.Context, s protocol.Setting) (State, error) {
	p, raw, err := h.export(ctx, s.SSID)
	if err != nil || p == nil {
		return State{}, err
	}
	data, err := json.Marshal(wifiState{Profile: raw})
	if err != nil {
		return State{}, err
	}
	return State{Exists: true, Data: data}, nil
}

func (h WiFiHandler) Test(ctx context.Context, s protocol.Setting) (bool, error) {
	have, _, err := h.export(ctx, s.SSID)
	if err != nil || have == nil {
		return false, err
	}
	want, err := RenderWLANProfile(s)
	if err != nil {
		return false, err
	}
	var w wlanProfile
	if err := xml.Unmarshal(want, &w); err != nil {
		return false, err
	}
	key := func(p *wlanProfile) string {
		if p.SharedKey == nil {
			return ""
		}
		return p.SharedKey.KeyMaterial
	}
	return have.SSID == w.SSID && have.NonBroadcast == w.NonBroadcast &&
		strings.EqualFold(have.ConnectionMode, w.ConnectionMode) &&
		strings.EqualFold(have.Authentication, w.Authentication) &&
		strings.EqualFold(have.Encryption, w.Encryption) && key(have) == key(&w), nil
}

// add imports profile XML for every user.
func (h WiFiHandler) add(ctx context.Context, profile []byte) error {
	f, err := os.CreateTemp(h.TempDir, "retune-wlan-*.xml")
	if err != nil {
		return err
	}
	name := f.Name()
	// The file holds the passphrase: it lives only as long as netsh needs it.
	defer os.Remove(name)
	if _, err := f.Write(profile); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	_, err = h.run(ctx, `wlan add profile filename="`+name+`" user=all`)
	return err
}

func (h WiFiHandler) Set(ctx context.Context, s protocol.Setting) error {
	profile, err := RenderWLANProfile(s)
	if err != nil {
		return err
	}
	return h.add(ctx, profile)
}

// Revert puts back the profile that was there before, or removes the one
// this setting added.
func (h WiFiHandler) Revert(ctx context.Context, s protocol.Setting, prior State) error {
	if prior.Exists && len(prior.Data) > 0 {
		var was wifiState
		if err := json.Unmarshal(prior.Data, &was); err != nil {
			return err
		}
		return h.add(ctx, was.Profile)
	}
	_, err := h.run(ctx, `wlan delete profile name="`+s.SSID+`"`)
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "not found") {
		return nil
	}
	return err
}
