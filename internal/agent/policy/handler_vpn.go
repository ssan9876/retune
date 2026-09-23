package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"retune/internal/protocol"
)

// VPNHandler adds a VPN connection for every user with the VpnClient
// cmdlets. Every value that reaches a script has been validated to letters,
// digits and a few separators, and is single-quoted.
type VPNHandler struct {
	Run PowerShell
}

func (VPNHandler) Kind() string { return protocol.KindVPN }

// vpnTunnel and vpnAuth are the cmdlets' names for each choice.
var (
	vpnTunnel = map[string]string{protocol.VPNIKEv2: "Ikev2", protocol.VPNSSTP: "Sstp"}
	vpnAuth   = map[string]string{
		protocol.VPNAuthEAP: "Eap", protocol.VPNAuthMachineCertificate: "MachineCertificate",
		protocol.VPNAuthMSCHAPv2: "MSChapv2",
	}
)

// vpnConnection is a connection as Get-VpnConnection reports it, and what a
// revert puts back.
type vpnConnection struct {
	ServerAddress        string   `json:"ServerAddress"`
	TunnelType           string   `json:"TunnelType"`
	AuthenticationMethod []string `json:"AuthenticationMethod"`
	SplitTunneling       bool     `json:"SplitTunneling"`
	DnsSuffix            string   `json:"DnsSuffix"`
}

func (h VPNHandler) run(ctx context.Context, script string) (string, error) {
	if h.Run == nil {
		return "", fmt.Errorf("%w: VPN settings are only supported on Windows", ErrNotApplicable)
	}
	return h.Run(ctx, script)
}

func (h VPNHandler) read(ctx context.Context, name string) (*vpnConnection, error) {
	out, err := h.run(ctx, "$c = Get-VpnConnection -AllUserConnection -Name "+quote(name)+
		" -ErrorAction SilentlyContinue; if ($c) { $c | Select-Object ServerAddress, "+
		"@{n='TunnelType';e={[string]$_.TunnelType}}, @{n='AuthenticationMethod';e={@($_.AuthenticationMethod | ForEach-Object { [string]$_ })}}, "+
		"SplitTunneling, DnsSuffix | ConvertTo-Json -Compress }")
	if err != nil {
		return nil, err
	}
	out = strings.TrimSpace(out)
	if out == "" {
		return nil, nil
	}
	var c vpnConnection
	if err := json.Unmarshal([]byte(out), &c); err != nil {
		return nil, fmt.Errorf("read the VPN connection: %w", err)
	}
	return &c, nil
}

func (h VPNHandler) Get(ctx context.Context, s protocol.Setting) (State, error) {
	c, err := h.read(ctx, s.Name)
	if err != nil || c == nil {
		return State{}, err
	}
	data, err := json.Marshal(c)
	return State{Exists: true, Data: data}, err
}

func wantedVPN(s protocol.Setting) vpnConnection {
	return vpnConnection{
		ServerAddress: s.Server, TunnelType: vpnTunnel[s.Tunnel],
		AuthenticationMethod: []string{vpnAuth[s.Authentication]},
		SplitTunneling:       s.SplitTunneling, DnsSuffix: s.DNSSuffix,
	}
}

func (h VPNHandler) Test(ctx context.Context, s protocol.Setting) (bool, error) {
	have, err := h.read(ctx, s.Name)
	if err != nil || have == nil {
		return false, err
	}
	want := wantedVPN(s)
	return strings.EqualFold(have.ServerAddress, want.ServerAddress) &&
		strings.EqualFold(have.TunnelType, want.TunnelType) &&
		len(have.AuthenticationMethod) == 1 && strings.EqualFold(have.AuthenticationMethod[0], want.AuthenticationMethod[0]) &&
		have.SplitTunneling == want.SplitTunneling && strings.EqualFold(have.DnsSuffix, want.DnsSuffix), nil
}

// apply adds the connection, or changes the one already there.
func (h VPNHandler) apply(ctx context.Context, name string, c vpnConnection, exists bool) error {
	if len(c.AuthenticationMethod) == 0 {
		return errors.New("a VPN connection needs an authentication method")
	}
	params := " -AllUserConnection -Name " + quote(name) + " -ServerAddress " + quote(c.ServerAddress) +
		" -TunnelType " + quote(c.TunnelType) + " -AuthenticationMethod " + quote(c.AuthenticationMethod[0]) +
		" -SplitTunneling $" + fmt.Sprint(c.SplitTunneling) + " -DnsSuffix " + quote(c.DnsSuffix) + " -Force"
	verb := "Add-VpnConnection"
	if exists {
		verb = "Set-VpnConnection"
	}
	_, err := h.run(ctx, verb+params+" -ErrorAction Stop | Out-Null")
	return err
}

func (h VPNHandler) Set(ctx context.Context, s protocol.Setting) error {
	have, err := h.read(ctx, s.Name)
	if err != nil {
		return err
	}
	return h.apply(ctx, s.Name, wantedVPN(s), have != nil)
}

// Revert puts the connection back as it was, or removes the one this
// setting added.
func (h VPNHandler) Revert(ctx context.Context, s protocol.Setting, prior State) error {
	if prior.Exists && len(prior.Data) > 0 {
		var was vpnConnection
		if err := json.Unmarshal(prior.Data, &was); err != nil {
			return err
		}
		have, err := h.read(ctx, s.Name)
		if err != nil {
			return err
		}
		return h.apply(ctx, s.Name, was, have != nil)
	}
	_, err := h.run(ctx, "Remove-VpnConnection -AllUserConnection -Name "+quote(s.Name)+
		" -Force -ErrorAction SilentlyContinue")
	return err
}
