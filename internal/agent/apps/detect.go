package apps

import (
	"fmt"
	"strings"

	"retune/internal/protocol"
)

// Probe reads what a detection rule looks at. The agent uses the real
// registry and file system; tests supply a fake.
type Probe interface {
	// Registry reads value from key under HKEY_LOCAL_MACHINE, looking in the
	// 64-bit view and then the 32-bit one, as a string (numbers in decimal).
	// value "" asks only whether the key exists. found is false, with no
	// error, when the key or value isn't there.
	Registry(key, value string) (data string, found bool, err error)
	// FileVersion reports whether path exists, and its version resource as
	// a dotted string, or "" if it has none.
	FileVersion(path string) (version string, found bool, err error)
	// Expand replaces %VARIABLES% with their values.
	Expand(s string) string
}

// uninstallKey is where Windows Installer lists an installed product.
const uninstallKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\`

// Detect evaluates a rule. An error means the answer is unknown -- the
// registry or disk couldn't be read -- which is not the same as "absent".
func Detect(rule protocol.DetectionRule, p Probe) (installed bool, version string, err error) {
	switch rule.Type {
	case protocol.DetectMSIProductCode:
		key := uninstallKey + rule.ProductCode
		_, found, err := p.Registry(key, "")
		if err != nil || !found {
			return false, "", err
		}
		version, _, err = p.Registry(key, "DisplayVersion")
		if err != nil {
			return false, "", err
		}
		return atLeast(version, rule.VersionAtLeast), version, nil

	case protocol.DetectRegistry:
		data, found, err := p.Registry(strings.Trim(rule.Key, `\`), rule.Value)
		if err != nil || !found {
			return false, "", err
		}
		if rule.Value == "" {
			return true, "", nil
		}
		if rule.Equals != "" && data != rule.Equals {
			return false, data, nil
		}
		return atLeast(data, rule.VersionAtLeast), data, nil

	case protocol.DetectFile:
		version, found, err := p.FileVersion(p.Expand(rule.Path))
		if err != nil || !found {
			return false, "", err
		}
		return atLeast(version, rule.VersionAtLeast), version, nil
	}
	return false, "", fmt.Errorf("unknown detection rule type %q", rule.Type)
}

// atLeast reports whether have meets a minimum version; no minimum is always
// met, and a version that can't be read never meets one.
func atLeast(have, min string) bool {
	if min == "" {
		return true
	}
	want, err := protocol.ParseVersion(min)
	if err != nil {
		return false
	}
	got, err := protocol.ParseVersion(have)
	if err != nil {
		return false
	}
	return got.Compare(want) >= 0
}
