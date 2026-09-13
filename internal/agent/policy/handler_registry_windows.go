//go:build windows

package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/sys/windows/registry"

	"retune/internal/agent/winsession"
	"retune/internal/protocol"
)

// RegistryHandler manages a single registry value.
type RegistryHandler struct{}

func (RegistryHandler) Kind() string { return protocol.KindRegistry }

// registryState is a value as it was found, kept so it can be put back.
type registryState struct {
	Type      string   `json:"type"`
	String    string   `json:"string,omitempty"`
	Number    uint64   `json:"number,omitempty"`
	Strings   []string `json:"strings,omitempty"`
	KeyExists bool     `json:"key_exists"`
}

func hiveOf(s protocol.Setting) (registry.Key, error) {
	switch strings.ToUpper(s.Hive) {
	case "HKLM":
		return registry.LOCAL_MACHINE, nil
	case "HKCU":
		// The signed-in user's hive is reached through HKEY_USERS rather than
		// by impersonating: the hive is loaded while they are signed in, and
		// naming it by SID keeps this free of thread-token juggling.
		return registry.USERS, nil
	}
	return 0, fmt.Errorf("unsupported registry hive %q", s.Hive)
}

// keyPath is the path under the hive. For HKCU it is prefixed with the
// signed-in user's SID, so a machine with nobody signed in says so rather than
// writing somewhere arbitrary.
func keyPath(s protocol.Setting) (string, error) {
	path := strings.Trim(strings.ReplaceAll(strings.TrimSpace(s.Key), "/", `\`), `\`)
	if !strings.EqualFold(s.Hive, "HKCU") {
		return path, nil
	}
	sid, err := userHive()
	if err != nil {
		return "", fmt.Errorf("this setting applies to the signed-in user, but %w", err)
	}
	return sid + `\` + path, nil
}

// userHive is a variable so tests can supply a SID without a real session.
var userHive = winsession.HiveSID

// openKey opens the setting's key for the given access, reporting whether it
// exists at all.
func openKey(s protocol.Setting, access uint32) (registry.Key, bool, error) {
	hive, err := hiveOf(s)
	if err != nil {
		return 0, false, err
	}
	path, err := keyPath(s)
	if err != nil {
		return 0, false, err
	}
	k, err := registry.OpenKey(hive, path, access)
	if errors.Is(err, registry.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return k, true, nil
}

func (RegistryHandler) Get(_ context.Context, s protocol.Setting) (State, error) {
	k, exists, err := openKey(s, registry.QUERY_VALUE)
	if err != nil {
		return State{}, err
	}
	if !exists {
		return State{}, nil
	}
	defer k.Close()

	_, valueType, err := k.GetValue(s.Name, nil)
	if errors.Is(err, registry.ErrNotExist) {
		// The key is there but the value is not, which a revert needs to know:
		// it should remove the value without removing the key.
		raw, mErr := json.Marshal(registryState{KeyExists: true})
		if mErr != nil {
			return State{}, mErr
		}
		return State{Exists: false, Data: raw}, nil
	}
	if err != nil {
		return State{}, err
	}

	was := registryState{KeyExists: true}
	switch valueType {
	case registry.SZ, registry.EXPAND_SZ:
		value, _, err := k.GetStringValue(s.Name)
		if err != nil {
			return State{}, err
		}
		was.Type, was.String = typeName(valueType), value
	case registry.DWORD, registry.QWORD:
		value, _, err := k.GetIntegerValue(s.Name)
		if err != nil {
			return State{}, err
		}
		was.Type, was.Number = typeName(valueType), value
	case registry.MULTI_SZ:
		values, _, err := k.GetStringsValue(s.Name)
		if err != nil {
			return State{}, err
		}
		was.Type, was.Strings = typeName(valueType), values
	default:
		was.Type = typeName(valueType)
	}
	raw, err := json.Marshal(was)
	if err != nil {
		return State{}, err
	}
	return State{Exists: true, Data: raw}, nil
}

func typeName(t uint32) string {
	switch t {
	case registry.SZ:
		return protocol.RegSZ
	case registry.EXPAND_SZ:
		return protocol.RegExpandSZ
	case registry.DWORD:
		return protocol.RegDWord
	case registry.QWORD:
		return protocol.RegQWord
	case registry.MULTI_SZ:
		return protocol.RegMultiSZ
	}
	return ""
}

func (h RegistryHandler) Test(_ context.Context, s protocol.Setting) (bool, error) {
	k, exists, err := openKey(s, registry.QUERY_VALUE)
	if err != nil {
		return false, err
	}
	if !exists {
		// No key means no value, which is exactly what "absent" wants.
		return s.Ensure == protocol.EnsureAbsent, nil
	}
	defer k.Close()

	if s.Ensure == protocol.EnsureAbsent {
		_, _, err := k.GetValue(s.Name, nil)
		if errors.Is(err, registry.ErrNotExist) {
			return true, nil
		}
		return false, nil
	}

	switch s.Type {
	case protocol.RegSZ, protocol.RegExpandSZ:
		got, _, err := k.GetStringValue(s.Name)
		if errors.Is(err, registry.ErrNotExist) {
			return false, nil
		}
		return err == nil && got == s.Data, ignoreMissing(err)
	case protocol.RegDWord, protocol.RegQWord:
		got, _, err := k.GetIntegerValue(s.Name)
		if errors.Is(err, registry.ErrNotExist) {
			return false, nil
		}
		want, convErr := strconv.ParseUint(strings.TrimSpace(s.Data), 10, 64)
		if convErr != nil {
			return false, convErr
		}
		return err == nil && got == want, ignoreMissing(err)
	case protocol.RegMultiSZ:
		got, _, err := k.GetStringsValue(s.Name)
		if errors.Is(err, registry.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return equalStrings(got, s.MultiSZ()), nil
	}
	return false, fmt.Errorf("unsupported registry type %q", s.Type)
}

func (h RegistryHandler) Set(_ context.Context, s protocol.Setting) error {
	hive, err := hiveOf(s)
	if err != nil {
		return err
	}
	if s.Ensure == protocol.EnsureAbsent {
		k, exists, err := openKey(s, registry.SET_VALUE)
		if err != nil || !exists {
			return err
		}
		defer k.Close()
		if err := k.DeleteValue(s.Name); err != nil && !errors.Is(err, registry.ErrNotExist) {
			return err
		}
		return nil
	}

	path, err := keyPath(s)
	if err != nil {
		return err
	}
	k, _, err := registry.CreateKey(hive, path, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return writeValue(k, s.Name, s.Type, s.Data, s.MultiSZ())
}

func writeValue(k registry.Key, name, valueType, data string, multi []string) error {
	switch valueType {
	case protocol.RegSZ:
		return k.SetStringValue(name, data)
	case protocol.RegExpandSZ:
		return k.SetExpandStringValue(name, data)
	case protocol.RegDWord:
		n, err := strconv.ParseUint(strings.TrimSpace(data), 10, 32)
		if err != nil {
			return err
		}
		return k.SetDWordValue(name, uint32(n))
	case protocol.RegQWord:
		n, err := strconv.ParseUint(strings.TrimSpace(data), 10, 64)
		if err != nil {
			return err
		}
		return k.SetQWordValue(name, n)
	case protocol.RegMultiSZ:
		return k.SetStringsValue(name, multi)
	}
	return fmt.Errorf("unsupported registry type %q", valueType)
}

// Revert puts the value back as it was, or removes one this agent created.
func (h RegistryHandler) Revert(_ context.Context, s protocol.Setting, prior State) error {
	hive, err := hiveOf(s)
	if err != nil {
		return err
	}
	var was registryState
	if len(prior.Data) > 0 {
		if err := json.Unmarshal(prior.Data, &was); err != nil {
			return err
		}
	}

	if !prior.Exists {
		// The value was not there before. Remove it, but leave the key: it may
		// hold values this agent knows nothing about.
		k, exists, err := openKey(s, registry.SET_VALUE)
		if err != nil || !exists {
			return err
		}
		defer k.Close()
		if err := k.DeleteValue(s.Name); err != nil && !errors.Is(err, registry.ErrNotExist) {
			return err
		}
		return nil
	}

	path, err := keyPath(s)
	if err != nil {
		return err
	}
	k, _, err := registry.CreateKey(hive, path, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	switch was.Type {
	case protocol.RegSZ, protocol.RegExpandSZ:
		return writeValue(k, s.Name, was.Type, was.String, nil)
	case protocol.RegDWord, protocol.RegQWord:
		return writeValue(k, s.Name, was.Type, strconv.FormatUint(was.Number, 10), nil)
	case protocol.RegMultiSZ:
		return k.SetStringsValue(s.Name, was.Strings)
	}
	return fmt.Errorf("the previous value had an unsupported type %q", was.Type)
}

func ignoreMissing(err error) error {
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	return err
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
