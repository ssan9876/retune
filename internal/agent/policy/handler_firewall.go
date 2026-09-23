package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"retune/internal/protocol"
)

// PowerShell runs a PowerShell command and returns its standard output. The
// firewall handlers use the NetSecurity cmdlets rather than netsh, because only
// the cmdlets can put a rule in a Group, which is how Retune's own rules are
// recognised later.
type PowerShell func(ctx context.Context, script string) (string, error)

// FirewallProfileHandler turns a firewall profile on or off.
type FirewallProfileHandler struct {
	Run PowerShell
}

func (FirewallProfileHandler) Kind() string { return protocol.KindFirewallProfile }

func (h FirewallProfileHandler) run(ctx context.Context, script string) (string, error) {
	if h.Run == nil {
		return "", errors.New("firewall settings are only supported on Windows")
	}
	return h.Run(ctx, script)
}

// profileName is the cmdlets' spelling of a profile.
func profileName(profile string) string {
	switch strings.ToLower(profile) {
	case protocol.FirewallDomain:
		return "Domain"
	case protocol.FirewallPrivate:
		return "Private"
	case protocol.FirewallPublic:
		return "Public"
	}
	return ""
}

func (h FirewallProfileHandler) enabled(ctx context.Context, s protocol.Setting) (bool, error) {
	name := profileName(s.Profile)
	if name == "" {
		return false, fmt.Errorf("unknown firewall profile %q", s.Profile)
	}
	out, err := h.run(ctx, "(Get-NetFirewallProfile -Name "+name+").Enabled | ConvertTo-Json")
	if err != nil {
		return false, err
	}
	// Enabled comes back as True/False or 1/0 depending on the version.
	text := strings.TrimSpace(strings.Trim(out, "\""))
	return strings.EqualFold(text, "true") || text == "1", nil
}

func (h FirewallProfileHandler) Get(ctx context.Context, s protocol.Setting) (State, error) {
	on, err := h.enabled(ctx, s)
	if err != nil {
		return State{}, err
	}
	state := protocol.FirewallOff
	if on {
		state = protocol.FirewallOn
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return State{}, err
	}
	return State{Exists: true, Data: raw}, nil
}

func (h FirewallProfileHandler) Test(ctx context.Context, s protocol.Setting) (bool, error) {
	on, err := h.enabled(ctx, s)
	if err != nil {
		return false, err
	}
	return on == (s.State == protocol.FirewallOn), nil
}

func (h FirewallProfileHandler) Set(ctx context.Context, s protocol.Setting) error {
	name := profileName(s.Profile)
	if name == "" {
		return fmt.Errorf("unknown firewall profile %q", s.Profile)
	}
	value := "False"
	if s.State == protocol.FirewallOn {
		value = "True"
	}
	_, err := h.run(ctx, "Set-NetFirewallProfile -Name "+name+" -Enabled "+value)
	return err
}

// Revert puts the profile back the way it was found.
func (h FirewallProfileHandler) Revert(ctx context.Context, s protocol.Setting, prior State) error {
	if !prior.Exists || len(prior.Data) == 0 {
		return nil
	}
	var was string
	if err := json.Unmarshal(prior.Data, &was); err != nil {
		return err
	}
	return h.Set(ctx, protocol.Setting{
		Kind: protocol.KindFirewallProfile, Profile: s.Profile, State: was,
	})
}

// FirewallRuleHandler manages one named firewall rule.
type FirewallRuleHandler struct {
	Run PowerShell
}

func (FirewallRuleHandler) Kind() string { return protocol.KindFirewallRule }

func (h FirewallRuleHandler) run(ctx context.Context, script string) (string, error) {
	if h.Run == nil {
		return "", errors.New("firewall settings are only supported on Windows")
	}
	return h.Run(ctx, script)
}

// firewallRule is the part of a rule this handler compares and restores.
type firewallRule struct {
	Name      string `json:"name"`
	Group     string `json:"group"`
	Enabled   string `json:"enabled"`
	Direction string `json:"direction"`
	Action    string `json:"action"`
	Protocol  string `json:"protocol"`
	LocalPort string `json:"local_port"`
	Program   string `json:"program"`
}

// singleQuotes are every character PowerShell accepts as a single quote: the
// ASCII one and four typographic ones. Escaping only the ASCII quote left a
// value containing a curly one able to close the string and run the rest.
var singleQuotes = strings.NewReplacer(
	"'", "''", "\u2018", "\u2018\u2018", "\u2019", "\u2019\u2019", "\u201A", "\u201A\u201A", "\u201B", "\u201B\u201B",
)

// quote makes a value safe to put inside a single-quoted PowerShell string.
func quote(value string) string {
	return "'" + singleQuotes.Replace(value) + "'"
}

// exactName is a -DisplayName argument that matches only that name. The
// parameter takes wildcards, so a rule named * would otherwise have matched
// - and on removal, deleted - every rule on the machine.
func exactName(name string) string {
	return "([WildcardPattern]::Escape(" + quote(name) + "))"
}

// removeOurs deletes rules with this name that Retune created, and no
// others: Windows allows several rules to share a display name, and one made
// by something else on the machine is never Retune's to remove.
func removeOurs(name string) string {
	return "Get-NetFirewallRule -DisplayName " + exactName(name) + " -ErrorAction SilentlyContinue | " +
		"Where-Object { $_.Group -eq " + quote(protocol.FirewallGroup) + " } | Remove-NetFirewallRule"
}

// lookupScript reads one rule with the filters that hold its port and program,
// which live on separate objects in the cmdlets' model.
func lookupScript(name string) string {
	return `$r = Get-NetFirewallRule -DisplayName ` + exactName(name) + ` -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $r) { '' ; exit 0 }
$f = $r | Get-NetFirewallPortFilter
$a = $r | Get-NetFirewallApplicationFilter
[pscustomobject]@{
  name      = [string]$r.DisplayName
  group     = [string]$r.Group
  enabled   = [string]$r.Enabled
  direction = [string]$r.Direction
  action    = [string]$r.Action
  protocol  = [string]$f.Protocol
  local_port = [string]$f.LocalPort
  program   = [string]$a.Program
} | ConvertTo-Json -Compress`
}

func (h FirewallRuleHandler) lookup(ctx context.Context, name string) (firewallRule, bool, error) {
	out, err := h.run(ctx, lookupScript(name))
	if err != nil {
		return firewallRule{}, false, err
	}
	trimmed := strings.TrimSpace(out)
	if trimmed == "" {
		return firewallRule{}, false, nil
	}
	var rule firewallRule
	if err := json.Unmarshal([]byte(trimmed), &rule); err != nil {
		return firewallRule{}, false, fmt.Errorf("read the firewall rule: %w", err)
	}
	return rule, true, nil
}

// matches reports whether an existing rule already says what the setting says.
func matches(got firewallRule, want protocol.Setting) bool {
	sameDirection := strings.EqualFold(got.Direction, cmdletDirection(want.Direction))
	sameAction := strings.EqualFold(got.Action, cmdletAction(want.Action))
	sameProtocol := strings.EqualFold(emptyAsAny(got.Protocol), cmdletProtocol(want.Protocol))
	samePort := strings.EqualFold(emptyAsAny(got.LocalPort), emptyAsAny(want.LocalPort))
	sameProgram := strings.EqualFold(emptyAsAny(got.Program), emptyAsAny(want.Program))
	return sameDirection && sameAction && sameProtocol && samePort && sameProgram
}

func emptyAsAny(value string) string {
	if strings.TrimSpace(value) == "" {
		return "Any"
	}
	return value
}

func cmdletDirection(direction string) string {
	if direction == protocol.DirectionOutbound {
		return "Outbound"
	}
	return "Inbound"
}

func cmdletAction(action string) string {
	if action == protocol.ActionBlock {
		return "Block"
	}
	return "Allow"
}

func cmdletProtocol(p string) string {
	switch p {
	case protocol.ProtocolTCP:
		return "TCP"
	case protocol.ProtocolUDP:
		return "UDP"
	}
	return "Any"
}

func (h FirewallRuleHandler) Get(ctx context.Context, s protocol.Setting) (State, error) {
	rule, found, err := h.lookup(ctx, s.Name)
	if err != nil || !found {
		return State{}, err
	}
	raw, err := json.Marshal(rule)
	if err != nil {
		return State{}, err
	}
	return State{Exists: true, Data: raw}, nil
}

func (h FirewallRuleHandler) Test(ctx context.Context, s protocol.Setting) (bool, error) {
	rule, found, err := h.lookup(ctx, s.Name)
	if err != nil {
		return false, err
	}
	if s.Ensure == protocol.EnsureAbsent {
		// A rule outside Retune's group belongs to something else, so as far as
		// this setting is concerned there is nothing to remove.
		return !found || !strings.EqualFold(rule.Group, protocol.FirewallGroup), nil
	}
	if !found {
		return false, nil
	}
	return matches(rule, s), nil
}

func (h FirewallRuleHandler) Set(ctx context.Context, s protocol.Setting) error {
	rule, found, err := h.lookup(ctx, s.Name)
	if err != nil {
		return err
	}

	if s.Ensure == protocol.EnsureAbsent {
		if !found {
			return nil
		}
		if !strings.EqualFold(rule.Group, protocol.FirewallGroup) {
			// Never delete a rule something else on the machine put there.
			return fmt.Errorf("the rule %q was not created by Retune, so it is left alone", s.Name)
		}
		_, err := h.run(ctx, removeOurs(s.Name))
		return err
	}

	if found {
		if !strings.EqualFold(rule.Group, protocol.FirewallGroup) {
			// Replacing it would mean deleting a rule something else made.
			return fmt.Errorf("a rule named %q already exists and was not created by Retune, so it is left alone", s.Name)
		}
		if _, err := h.run(ctx, removeOurs(s.Name)); err != nil {
			return err
		}
	}
	return h.create(ctx, s)
}

func (h FirewallRuleHandler) create(ctx context.Context, s protocol.Setting) error {
	args := []string{
		"-DisplayName " + quote(s.Name),
		"-Group " + quote(protocol.FirewallGroup),
		"-Direction " + cmdletDirection(s.Direction),
		"-Action " + cmdletAction(s.Action),
		"-Protocol " + cmdletProtocol(s.Protocol),
		"-Enabled True",
	}
	if strings.TrimSpace(s.LocalPort) != "" {
		args = append(args, "-LocalPort "+quote(s.LocalPort))
	}
	if strings.TrimSpace(s.Program) != "" {
		args = append(args, "-Program "+quote(s.Program))
	}
	_, err := h.run(ctx, "New-NetFirewallRule "+strings.Join(args, " ")+" | Out-Null")
	return err
}

// Revert removes a rule Retune created, or puts back the one it replaced.
func (h FirewallRuleHandler) Revert(ctx context.Context, s protocol.Setting, prior State) error {
	if !prior.Exists {
		rule, found, err := h.lookup(ctx, s.Name)
		if err != nil || !found {
			return err
		}
		if !strings.EqualFold(rule.Group, protocol.FirewallGroup) {
			return nil
		}
		_, err = h.run(ctx, removeOurs(s.Name))
		return err
	}

	var was firewallRule
	if err := json.Unmarshal(prior.Data, &was); err != nil {
		return err
	}
	if _, err := h.run(ctx, removeOurs(s.Name)); err != nil {
		return err
	}
	restored := protocol.Setting{
		Kind: protocol.KindFirewallRule, Name: was.Name,
		Direction: strings.ToLower(was.Direction), Action: strings.ToLower(was.Action),
		Protocol: strings.ToLower(was.Protocol), Program: was.Program,
	}
	if !strings.EqualFold(was.LocalPort, "Any") {
		restored.LocalPort = was.LocalPort
	}
	if strings.EqualFold(was.Protocol, "Any") {
		restored.Protocol = protocol.ProtocolAny
	}
	return h.create(ctx, restored)
}
