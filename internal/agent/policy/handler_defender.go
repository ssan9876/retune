package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"retune/internal/protocol"
)

// DefenderHandler sets Microsoft Defender Antivirus preferences through the
// Defender cmdlets. Only the fields a setting names are read, written or
// reverted: a profile that only turns on cloud protection must not quietly
// reset whatever else the machine had.
type DefenderHandler struct {
	Run PowerShell
}

func (DefenderHandler) Kind() string { return protocol.KindDefender }

// realtimeParameter is the one preference that is a bool, and phrased the
// other way round: Defender stores whether real-time monitoring is disabled.
const realtimeParameter = "DisableRealtimeMonitoring"

// defenderValues is Defender's preferences as numbers and bools, keyed by
// Set-MpPreference parameter name. It is both what Get-MpPreference is read
// into and what a revert puts back.
type defenderValues map[string]any

// wanted is what the setting asks for, in the same shape.
func wanted(s protocol.Setting) defenderValues {
	out := defenderValues{}
	if s.RealtimeMonitoring != nil {
		out[realtimeParameter] = !*s.RealtimeMonitoring
	}
	for _, p := range protocol.DefenderPreferences {
		if word := s.DefenderValue(p.Field); word != "" {
			out[p.Parameter] = p.Values[word]
		}
	}
	return out
}

func (h DefenderHandler) run(ctx context.Context, script string) (string, error) {
	if h.Run == nil {
		return "", errors.New("defender settings are only supported on Windows")
	}
	return h.Run(ctx, script)
}

// read fetches the current value of every parameter named in want. It always
// asks for all five in one call - Get-MpPreference is slow, and one process
// is cheaper than five - and returns only the named ones.
func (h DefenderHandler) read(ctx context.Context, want defenderValues) (defenderValues, error) {
	params := []string{realtimeParameter}
	for _, p := range protocol.DefenderPreferences {
		params = append(params, p.Parameter)
	}
	out, err := h.run(ctx, "Get-MpPreference | Select-Object "+strings.Join(params, ",")+" | ConvertTo-Json -Compress")
	if err != nil {
		return nil, err
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &all); err != nil {
		return nil, fmt.Errorf("read Defender preferences: %w", err)
	}
	got := defenderValues{}
	for param := range want {
		raw, ok := all[param]
		if !ok {
			return nil, fmt.Errorf("Defender did not report %s", param)
		}
		if param == realtimeParameter {
			var b bool
			if err := json.Unmarshal(raw, &b); err != nil {
				return nil, fmt.Errorf("read %s: %w", param, err)
			}
			got[param] = b
			continue
		}
		var n int
		if err := json.Unmarshal(raw, &n); err != nil {
			return nil, fmt.Errorf("read %s: %w", param, err)
		}
		got[param] = n
	}
	return got, nil
}

// differing lists the parameters whose current value is not the wanted one,
// in a stable order so an error message reads the same every time.
func differing(want, got defenderValues) []string {
	var out []string
	for param, v := range want {
		if got[param] != v {
			out = append(out, param)
		}
	}
	sort.Strings(out)
	return out
}

// write issues one Set-MpPreference naming exactly the given parameters. The
// values come from a fixed table or a bool, never from free text, so nothing
// in the command line needs quoting.
func (h DefenderHandler) write(ctx context.Context, values defenderValues) error {
	params := make([]string, 0, len(values))
	for param := range values {
		params = append(params, param)
	}
	sort.Strings(params)
	var b strings.Builder
	b.WriteString("Set-MpPreference")
	for _, param := range params {
		b.WriteString(" -" + param + " ")
		switch v := values[param].(type) {
		case bool:
			if v {
				b.WriteString("$true")
			} else {
				b.WriteString("$false")
			}
		case int:
			b.WriteString(strconv.Itoa(v))
		default:
			return fmt.Errorf("unexpected value %v for %s", v, param)
		}
	}
	_, err := h.run(ctx, b.String())
	return err
}

func (h DefenderHandler) Get(ctx context.Context, s protocol.Setting) (State, error) {
	got, err := h.read(ctx, wanted(s))
	if err != nil {
		return State{}, err
	}
	raw, err := json.Marshal(got)
	if err != nil {
		return State{}, err
	}
	return State{Exists: true, Data: raw}, nil
}

func (h DefenderHandler) Test(ctx context.Context, s protocol.Setting) (bool, error) {
	want := wanted(s)
	got, err := h.read(ctx, want)
	if err != nil {
		return false, err
	}
	return len(differing(want, got)) == 0, nil
}

// Set writes the named preferences and then reads them back. Tamper
// Protection lets Set-MpPreference succeed while changing nothing, and a
// handler that trusted the exit code would report a change that never
// happened; the engine's own re-test would catch it too, but only with a
// generic message, where this one says what is most likely going on.
func (h DefenderHandler) Set(ctx context.Context, s protocol.Setting) error {
	want := wanted(s)
	if err := h.write(ctx, want); err != nil {
		return err
	}
	got, err := h.read(ctx, want)
	if err != nil {
		return err
	}
	if stuck := differing(want, got); len(stuck) > 0 {
		return fmt.Errorf("Defender did not accept the change to %s; Tamper Protection may be on",
			strings.Join(stuck, ", "))
	}
	return nil
}

// Revert puts back what Get recorded before Retune first changed anything.
func (h DefenderHandler) Revert(ctx context.Context, s protocol.Setting, prior State) error {
	var was map[string]json.RawMessage
	if len(prior.Data) == 0 {
		return nil
	}
	if err := json.Unmarshal(prior.Data, &was); err != nil {
		return err
	}
	values := defenderValues{}
	for param := range wanted(s) {
		raw, ok := was[param]
		if !ok {
			continue
		}
		if param == realtimeParameter {
			var b bool
			if err := json.Unmarshal(raw, &b); err != nil {
				return err
			}
			values[param] = b
			continue
		}
		var n int
		if err := json.Unmarshal(raw, &n); err != nil {
			return err
		}
		values[param] = n
	}
	if len(values) == 0 {
		return nil
	}
	return h.write(ctx, values)
}
