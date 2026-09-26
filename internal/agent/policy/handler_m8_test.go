package policy_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"retune/internal/agent/policy"
	"retune/internal/protocol"
)

func intp(n int) *int    { return &n }
func boolp(b bool) *bool { return &b }

// --- Windows Update -------------------------------------------------------

func TestUpdatePolicyValues(t *testing.T) {
	s := protocol.Setting{
		Kind:                protocol.KindWindowsUpdate,
		QualityDeferralDays: intp(7),
		ActiveHoursStart:    intp(8),
		ActiveHoursEnd:      intp(18),
		AutoRestart:         boolp(false),
	}
	values := policy.UpdatePolicyValues(s)

	got := map[string]string{}
	for _, v := range values {
		if v.Kind != protocol.KindRegistry || v.Hive != "HKLM" {
			t.Fatalf("every value should be an HKLM registry setting, got %+v", v)
		}
		got[v.Name] = v.Data
	}
	want := map[string]string{
		"DeferQualityUpdates":             "1",
		"DeferQualityUpdatesPeriodInDays": "7",
		"SetActiveHours":                  "1",
		"ActiveHoursStart":                "8",
		"ActiveHoursEnd":                  "18",
		// The policy is phrased the other way round: 1 means do not reboot
		// while someone is signed in.
		"NoAutoRebootWithLoggedOnUsers": "1",
	}
	for name, value := range want {
		if got[name] != value {
			t.Errorf("%s = %q, want %q", name, got[name], value)
		}
	}
	// Feature deferral was not asked for, so it is not touched at all.
	if _, ok := got["DeferFeatureUpdates"]; ok {
		t.Error("a setting that does not mention feature updates must not change them")
	}
}

func TestAutoRestartAllowed(t *testing.T) {
	values := policy.UpdatePolicyValues(protocol.Setting{
		Kind: protocol.KindWindowsUpdate, AutoRestart: boolp(true),
	})
	if len(values) != 1 || values[0].Data != "0" {
		t.Fatalf("allowing restarts should clear the policy, got %+v", values)
	}
}

// recordingRegistry stands in for the registry handler.
type recordingRegistry struct {
	values  map[string]string
	sets    []string
	reverts []string
}

func newRegistry() *recordingRegistry {
	return &recordingRegistry{values: map[string]string{}}
}

func (r *recordingRegistry) Kind() string { return protocol.KindRegistry }

func (r *recordingRegistry) Get(_ context.Context, s protocol.Setting) (policy.State, error) {
	value, ok := r.values[s.Name]
	if !ok {
		return policy.State{}, nil
	}
	raw, _ := json.Marshal(value)
	return policy.State{Exists: true, Data: raw}, nil
}

func (r *recordingRegistry) Test(_ context.Context, s protocol.Setting) (bool, error) {
	got, ok := r.values[s.Name]
	return ok && got == s.Data, nil
}

func (r *recordingRegistry) Set(_ context.Context, s protocol.Setting) error {
	r.sets = append(r.sets, s.Name+"="+s.Data)
	r.values[s.Name] = s.Data
	return nil
}

func (r *recordingRegistry) Revert(_ context.Context, s protocol.Setting, prior policy.State) error {
	r.reverts = append(r.reverts, s.Name)
	if !prior.Exists {
		delete(r.values, s.Name)
		return nil
	}
	var was string
	if err := json.Unmarshal(prior.Data, &was); err != nil {
		return err
	}
	r.values[s.Name] = was
	return nil
}

func TestWindowsUpdateAppliesAndReverts(t *testing.T) {
	ctx := context.Background()
	reg := newRegistry()
	h := policy.WindowsUpdateHandler{Registry: reg}
	s := protocol.Setting{Kind: protocol.KindWindowsUpdate, QualityDeferralDays: intp(7)}

	// A machine with an existing deferral, so a revert has something to put
	// back rather than only removing.
	reg.values["DeferQualityUpdatesPeriodInDays"] = "3"

	if ok, err := h.Test(ctx, s); err != nil || ok {
		t.Fatalf("a different deferral is not compliant: %v %v", ok, err)
	}
	prior, err := h.Get(ctx, s)
	if err != nil || !prior.Exists {
		t.Fatalf("prior = %+v err %v", prior, err)
	}
	if err := h.Set(ctx, s); err != nil {
		t.Fatal(err)
	}
	if ok, err := h.Test(ctx, s); err != nil || !ok {
		t.Fatalf("after Set it should be compliant: %v %v", ok, err)
	}

	if err := h.Revert(ctx, s, prior); err != nil {
		t.Fatal(err)
	}
	if reg.values["DeferQualityUpdatesPeriodInDays"] != "3" {
		t.Fatalf("revert should restore the previous deferral, got %q",
			reg.values["DeferQualityUpdatesPeriodInDays"])
	}
	// The value this agent introduced is gone again.
	if _, ok := reg.values["DeferQualityUpdates"]; ok {
		t.Error("a value that was not there before should be removed on revert")
	}
}

// --- Firewall -------------------------------------------------------------

// fakeShell answers PowerShell scripts from a small model of the firewall.
type fakeShell struct {
	profiles map[string]bool
	rules    map[string]map[string]string
	ran      []string
}

func newShell() *fakeShell {
	return &fakeShell{
		profiles: map[string]bool{"Domain": true, "Private": true, "Public": true},
		rules:    map[string]map[string]string{},
	}
}

func (f *fakeShell) run(_ context.Context, script string) (string, error) {
	f.ran = append(f.ran, script)
	switch {
	case strings.HasPrefix(script, "(Get-NetFirewallProfile"):
		name := between(script, "-Name ", ")")
		if f.profiles[strings.TrimSpace(name)] {
			return "true", nil
		}
		return "false", nil

	case strings.HasPrefix(script, "Set-NetFirewallProfile"):
		name := strings.TrimSpace(between(script, "-Name ", " -Enabled"))
		f.profiles[name] = strings.Contains(script, "-Enabled True")
		return "", nil

	case strings.HasPrefix(script, "$r = Get-NetFirewallRule"):
		name := quotedAfter(script, "::Escape(")
		rule, ok := f.rules[strings.ToLower(name)]
		if !ok {
			return "", nil
		}
		raw, _ := json.Marshal(rule)
		return string(raw), nil

	case strings.HasPrefix(script, "Get-NetFirewallRule") && strings.HasSuffix(script, "Remove-NetFirewallRule"):
		// Like the real pipeline, only rules in Retune's group are removed.
		name := strings.ToLower(quotedAfter(script, "::Escape("))
		if rule, ok := f.rules[name]; ok && strings.EqualFold(rule["group"], protocol.FirewallGroup) {
			delete(f.rules, name)
		}
		return "", nil

	case strings.HasPrefix(script, "New-NetFirewallRule"):
		rule := map[string]string{
			"name":       quotedAfter(script, "-DisplayName "),
			"group":      quotedAfter(script, "-Group "),
			"direction":  strings.TrimSpace(between(script, "-Direction ", " -Action")),
			"action":     strings.TrimSpace(between(script, "-Action ", " -Protocol")),
			"protocol":   strings.TrimSpace(between(script, "-Protocol ", " -Enabled")),
			"enabled":    "True",
			"local_port": quotedAfter(script, "-LocalPort "),
			"program":    quotedAfter(script, "-Program "),
		}
		f.rules[strings.ToLower(rule["name"])] = rule
		return "", nil
	}
	return "", nil
}

// between returns what lies between two markers, or "".
func between(s, start, end string) string {
	i := strings.Index(s, start)
	if i < 0 {
		return ""
	}
	rest := s[i+len(start):]
	j := strings.Index(rest, end)
	if j < 0 {
		return rest
	}
	return rest[:j]
}

// quotedAfter reads the single-quoted argument following a flag, the way
// PowerShell would: a name or a program path may contain spaces, so splitting
// on whitespace is not good enough.
func quotedAfter(script, flag string) string {
	i := strings.Index(script, flag)
	if i < 0 {
		return ""
	}
	rest := script[i+len(flag):]
	if !strings.HasPrefix(rest, "'") {
		return strings.TrimSpace(between(rest, "", " "))
	}
	rest = rest[1:]
	var b strings.Builder
	for j := 0; j < len(rest); j++ {
		if rest[j] != '\'' {
			b.WriteByte(rest[j])
			continue
		}
		if j+1 < len(rest) && rest[j+1] == '\'' {
			b.WriteByte('\'')
			j++
			continue
		}
		break
	}
	return b.String()
}

func TestFirewallProfileTurnsOffAndBack(t *testing.T) {
	ctx := context.Background()
	shell := newShell()
	h := policy.FirewallProfileHandler{Run: shell.run}
	s := protocol.Setting{
		Kind: protocol.KindFirewallProfile, Profile: protocol.FirewallPublic, State: protocol.FirewallOff,
	}

	if ok, err := h.Test(ctx, s); err != nil || ok {
		t.Fatalf("an enabled profile is not compliant with off: %v %v", ok, err)
	}
	prior, err := h.Get(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Set(ctx, s); err != nil {
		t.Fatal(err)
	}
	if shell.profiles["Public"] {
		t.Fatal("the profile should be off")
	}
	if ok, err := h.Test(ctx, s); err != nil || !ok {
		t.Fatalf("it should now be compliant: %v %v", ok, err)
	}

	if err := h.Revert(ctx, s, prior); err != nil {
		t.Fatal(err)
	}
	if !shell.profiles["Public"] {
		t.Fatal("revert should have turned it back on")
	}
}

func TestFirewallRuleIsCreatedInTheRetuneGroup(t *testing.T) {
	ctx := context.Background()
	shell := newShell()
	h := policy.FirewallRuleHandler{Run: shell.run}
	s := protocol.Setting{
		Kind: protocol.KindFirewallRule, Name: "Allow app", Direction: protocol.DirectionInbound,
		Action: protocol.ActionAllow, Protocol: protocol.ProtocolTCP, LocalPort: "8443",
	}

	if ok, err := h.Test(ctx, s); err != nil || ok {
		t.Fatalf("a missing rule is not compliant: %v %v", ok, err)
	}
	if err := h.Set(ctx, s); err != nil {
		t.Fatal(err)
	}
	rule := shell.rules["allow app"]
	if rule["group"] != protocol.FirewallGroup {
		t.Fatalf("the rule should be tagged %q, got %q", protocol.FirewallGroup, rule["group"])
	}
	if rule["local_port"] != "8443" || rule["protocol"] != "TCP" {
		t.Fatalf("rule = %v", rule)
	}
	if ok, err := h.Test(ctx, s); err != nil || !ok {
		t.Fatalf("after Set it should be compliant: %v %v", ok, err)
	}
}

// A profile must not be able to delete a firewall rule something else on the
// machine is relying on.
func TestFirewallRuleWillNotRemoveSomeoneElsesRule(t *testing.T) {
	ctx := context.Background()
	shell := newShell()
	shell.rules["remote desktop"] = map[string]string{
		"name": "Remote Desktop", "group": "Remote Desktop", "direction": "Inbound",
		"action": "Allow", "protocol": "TCP", "local_port": "3389",
	}
	h := policy.FirewallRuleHandler{Run: shell.run}
	s := protocol.Setting{Kind: protocol.KindFirewallRule, Name: "Remote Desktop", Ensure: protocol.EnsureAbsent}

	// It reports compliant, because as far as this setting is concerned there
	// is no Retune rule to remove.
	if ok, err := h.Test(ctx, s); err != nil || !ok {
		t.Fatalf("a rule outside Retune's group is not this setting's business: %v %v", ok, err)
	}
	err := h.Set(ctx, s)
	if err == nil {
		t.Fatal("removing another owner's rule should be refused")
	}
	if !strings.Contains(err.Error(), "not created by Retune") {
		t.Errorf("the error should explain why, got %v", err)
	}
	if _, still := shell.rules["remote desktop"]; !still {
		t.Fatal("the rule must still be there")
	}
}

func TestFirewallRuleRemovesItsOwn(t *testing.T) {
	ctx := context.Background()
	shell := newShell()
	shell.rules["old rule"] = map[string]string{
		"name": "Old rule", "group": protocol.FirewallGroup, "direction": "Inbound",
		"action": "Allow", "protocol": "TCP", "local_port": "9999",
	}
	h := policy.FirewallRuleHandler{Run: shell.run}
	s := protocol.Setting{Kind: protocol.KindFirewallRule, Name: "Old rule", Ensure: protocol.EnsureAbsent}

	if ok, _ := h.Test(ctx, s); ok {
		t.Fatal("a Retune rule that still exists is not compliant with absent")
	}
	if err := h.Set(ctx, s); err != nil {
		t.Fatal(err)
	}
	if _, still := shell.rules["old rule"]; still {
		t.Fatal("its own rule should be removed")
	}
}

func TestFirewallRuleRevertRemovesWhatItCreated(t *testing.T) {
	ctx := context.Background()
	shell := newShell()
	h := policy.FirewallRuleHandler{Run: shell.run}
	s := protocol.Setting{
		Kind: protocol.KindFirewallRule, Name: "Allow app", Direction: protocol.DirectionInbound,
		Action: protocol.ActionAllow, Protocol: protocol.ProtocolTCP, LocalPort: "8443",
	}

	prior, err := h.Get(ctx, s)
	if err != nil || prior.Exists {
		t.Fatalf("there was no rule before: %+v %v", prior, err)
	}
	if err := h.Set(ctx, s); err != nil {
		t.Fatal(err)
	}
	if err := h.Revert(ctx, s, prior); err != nil {
		t.Fatal(err)
	}
	if _, still := shell.rules["allow app"]; still {
		t.Fatal("a rule this agent created should be removed on revert")
	}
}

// --- BitLocker ------------------------------------------------------------

// fakeBitLocker answers the status script and records what was asked of it.
type fakeBitLocker struct {
	status map[string]any
	ran    []string
	// escrowed is what reached the server.
	escrowed map[string]string
	// enableErr, when set, is how Enable-BitLocker fails.
	enableErr error
}

func newBitLocker(protection, method, recovery string, tpm bool) *fakeBitLocker {
	return &fakeBitLocker{
		status: map[string]any{
			"mount_point": "C:", "protection_status": protection, "volume_status": "FullyEncrypted",
			"encryption_method": method, "recovery_password": recovery, "tpm_present": tpm,
		},
		escrowed: map[string]string{},
	}
}

func (f *fakeBitLocker) run(_ context.Context, script string) (string, error) {
	f.ran = append(f.ran, script)
	switch {
	case strings.HasPrefix(script, "$v = Get-BitLockerVolume"):
		raw, _ := json.Marshal(f.status)
		return string(raw), nil
	case strings.HasPrefix(script, "Enable-BitLocker"):
		if f.enableErr != nil {
			return "", f.enableErr
		}
		f.status["protection_status"] = "On"
		return "", nil
	case strings.HasPrefix(script, "Add-BitLockerKeyProtector"):
		f.status["recovery_password"] = "111111-222222-333333"
		return "", nil
	}
	return "", nil
}

func (f *fakeBitLocker) HasRecoveryKey(_ context.Context, volumeID string) (bool, error) {
	_, ok := f.escrowed[volumeID]
	return ok, nil
}

func (f *fakeBitLocker) EscrowRecoveryKey(_ context.Context, volumeID, _, recoveryPassword string) error {
	f.escrowed[volumeID] = recoveryPassword
	return nil
}

func (f *fakeBitLocker) did(prefix string) bool {
	for _, script := range f.ran {
		if strings.HasPrefix(script, prefix) {
			return true
		}
	}
	return false
}

func TestBitLockerEnablesAndEscrows(t *testing.T) {
	ctx := context.Background()
	fake := newBitLocker("Off", "XtsAes256", "", true)
	h := policy.BitLockerHandler{Run: fake.run, Escrow: fake}
	s := protocol.Setting{Kind: protocol.KindBitLocker, RequireEncryption: true, EscrowRecoveryKey: true}

	if ok, err := h.Test(ctx, s); err != nil || ok {
		t.Fatalf("an unencrypted drive is not compliant: %v %v", ok, err)
	}
	if err := h.Set(ctx, s); err != nil {
		t.Fatal(err)
	}
	if !fake.did("Enable-BitLocker") {
		t.Fatal("it should have enabled encryption")
	}
	if fake.escrowed["C:"] != "111111-222222-333333" {
		t.Fatalf("the recovery key should have been escrowed, got %v", fake.escrowed)
	}
	if ok, err := h.Test(ctx, s); err != nil || !ok {
		t.Fatalf("it should now be compliant: %v %v", ok, err)
	}
}

// When encryption does not start, the reason reaches the server and no
// recovery key is escrowed for a drive that is not encrypted.
func TestBitLockerFailureToEnableIsReported(t *testing.T) {
	ctx := context.Background()
	fake := newBitLocker("Off", "", "", true)
	fake.enableErr = errors.New("powershell: exit status 1: BitLocker Drive Encryption detected bootable media")
	h := policy.BitLockerHandler{Run: fake.run, Escrow: fake}
	s := protocol.Setting{Kind: protocol.KindBitLocker, RequireEncryption: true, EscrowRecoveryKey: true}

	err := h.Set(ctx, s)
	if err == nil || !strings.Contains(err.Error(), "bootable media") {
		t.Fatalf("the failure should say why, got %v", err)
	}
	if fake.did("Add-BitLockerKeyProtector") || len(fake.escrowed) != 0 {
		t.Fatalf("nothing should be escrowed for an unencrypted drive, got %v", fake.escrowed)
	}
}

// The script itself decides failure by whether encryption started, since
// Enable-BitLocker's errors do not end the process.
func TestBitLockerEnableChecksThatEncryptionStarted(t *testing.T) {
	ctx := context.Background()
	fake := newBitLocker("Off", "", "", true)
	h := policy.BitLockerHandler{Run: fake.run, Escrow: fake}
	if err := h.Set(ctx, protocol.Setting{Kind: protocol.KindBitLocker, RequireEncryption: true}); err != nil {
		t.Fatal(err)
	}
	for _, script := range fake.ran {
		if strings.HasPrefix(script, "Enable-BitLocker") {
			if !strings.Contains(script, "FullyDecrypted") || !strings.Contains(script, "exit 1") {
				t.Errorf("the enable script should fail when encryption did not start:\n%s", script)
			}
			return
		}
	}
	t.Fatal("Enable-BitLocker never ran")
}

// A key the server already holds for a volume that no longer has a recovery
// password opens nothing, so the volume is not compliant until a new one is
// added and escrowed.
func TestBitLockerWithoutARecoveryPasswordIsNotCompliant(t *testing.T) {
	ctx := context.Background()
	fake := newBitLocker("On", "XtsAes256", "", true)
	fake.escrowed["C:"] = "old-key-for-a-removed-protector"
	h := policy.BitLockerHandler{Run: fake.run, Escrow: fake}
	s := protocol.Setting{Kind: protocol.KindBitLocker, RequireEncryption: true, EscrowRecoveryKey: true}

	if ok, err := h.Test(ctx, s); err != nil || ok {
		t.Fatalf("no local recovery password should not be compliant: %v %v", ok, err)
	}
	if err := h.Set(ctx, s); err != nil {
		t.Fatal(err)
	}
	if fake.escrowed["C:"] != "111111-222222-333333" {
		t.Fatalf("the new recovery password should replace the stale one, got %v", fake.escrowed)
	}
	if ok, err := h.Test(ctx, s); err != nil || !ok {
		t.Fatalf("it should now be compliant: %v %v", ok, err)
	}
}

// Without a TPM, enabling BitLocker would demand a startup key at every boot.
func TestBitLockerWithoutATPMExplainsItself(t *testing.T) {
	ctx := context.Background()
	fake := newBitLocker("Off", "XtsAes256", "", false)
	h := policy.BitLockerHandler{Run: fake.run, Escrow: fake}

	err := h.Set(ctx, protocol.Setting{Kind: protocol.KindBitLocker, RequireEncryption: true})
	if err == nil {
		t.Fatal("it should refuse rather than lock the machine at boot")
	}
	if !strings.Contains(err.Error(), "no TPM") {
		t.Errorf("the error should say why, got %v", err)
	}
	if fake.did("Enable-BitLocker") {
		t.Fatal("nothing should have been encrypted")
	}
}

// A drive already encrypted with another method is left alone: re-encrypting is
// destructive and slow.
func TestBitLockerWillNotReEncrypt(t *testing.T) {
	ctx := context.Background()
	fake := newBitLocker("On", "Aes128", "111111-222222-333333", true)
	h := policy.BitLockerHandler{Run: fake.run, Escrow: fake}
	s := protocol.Setting{Kind: protocol.KindBitLocker, RequireEncryption: true, Method: protocol.XtsAes256}

	_, err := h.Test(ctx, s)
	if err == nil {
		t.Fatal("it should report the mismatch rather than silently re-encrypting")
	}
	if !strings.Contains(err.Error(), "will not re-encrypt") {
		t.Errorf("the error should say what it will not do, got %v", err)
	}
}

// An already-compliant machine does not send its recovery key again.
func TestBitLockerDoesNotReEscrow(t *testing.T) {
	ctx := context.Background()
	fake := newBitLocker("On", "XtsAes256", "111111-222222-333333", true)
	fake.escrowed["C:"] = "111111-222222-333333"
	h := policy.BitLockerHandler{Run: fake.run, Escrow: fake}
	s := protocol.Setting{Kind: protocol.KindBitLocker, RequireEncryption: true, EscrowRecoveryKey: true}

	ok, err := h.Test(ctx, s)
	if err != nil || !ok {
		t.Fatalf("an encrypted, escrowed volume is compliant: %v %v", ok, err)
	}
}

// The recovery password never goes into local state, only to the server.
func TestBitLockerStateHoldsNoRecoveryKey(t *testing.T) {
	ctx := context.Background()
	fake := newBitLocker("On", "XtsAes256", "111111-222222-333333", true)
	h := policy.BitLockerHandler{Run: fake.run, Escrow: fake}

	state, err := h.Get(ctx, protocol.Setting{Kind: protocol.KindBitLocker, RequireEncryption: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(state.Data), "111111") {
		t.Fatalf("the recovery key must not be kept locally, got %s", state.Data)
	}
}

// This kind never decrypts a drive, so it must not implement Revert.
func TestBitLockerCannotBeReverted(t *testing.T) {
	var h any = policy.BitLockerHandler{}
	if _, ok := h.(policy.Reverter); ok {
		t.Fatal("BitLocker must not be revertible: a profile going out of scope must never decrypt a drive")
	}
}

// A name made of wildcards, or holding a typographic quote PowerShell also
// ends strings with, reaches the cmdlets as a literal.
func TestFirewallNamesAreLiteral(t *testing.T) {
	sh := newShell()
	h := policy.FirewallRuleHandler{Run: sh.run}
	for _, name := range []string{"*", "a\u2019; Remove-Item C:\\ -Recurse; \u2019b"} {
		sh.ran = nil
		_, _ = h.Test(context.Background(), protocol.Setting{Kind: protocol.KindFirewallRule, Name: name, Ensure: protocol.EnsureAbsent})
		if len(sh.ran) == 0 || !strings.Contains(sh.ran[0], "[WildcardPattern]::Escape(") {
			t.Fatalf("the lookup should escape wildcards: %v", sh.ran)
		}
	}
	if got := policy.QuoteForTest("it’s"); got != "'it’’s'" {
		t.Errorf("a typographic quote should be doubled, got %q", got)
	}
}

// Replacing a rule of the same name that something else created would mean
// deleting it; the agent refuses instead.
func TestFirewallRuleWillNotReplaceSomeoneElsesRule(t *testing.T) {
	sh := newShell()
	sh.rules["allow app"] = map[string]string{"name": "Allow app", "group": "Contoso", "direction": "Inbound",
		"action": "Allow", "protocol": "TCP", "enabled": "True"}
	h := policy.FirewallRuleHandler{Run: sh.run}
	err := h.Set(context.Background(), protocol.Setting{Kind: protocol.KindFirewallRule, Name: "Allow app",
		Direction: protocol.DirectionInbound, Action: protocol.ActionBlock, Protocol: protocol.ProtocolTCP})
	if err == nil || !strings.Contains(err.Error(), "not created by Retune") {
		t.Fatalf("want a refusal, got %v", err)
	}
	if _, ok := sh.rules["allow app"]; !ok {
		t.Error("the other rule must still be there")
	}
}
