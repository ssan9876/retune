package protocol

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Where an app comes from: a winget package, or a file an administrator
// uploaded.
const (
	AppSourceWinget  = "winget"
	AppSourcePackage = "package"
)

// The kinds of uploaded installer.
const (
	InstallerMSI = "msi"
	InstallerEXE = "exe"
)

// The kinds of detection rule.
const (
	DetectMSIProductCode = "msi_product_code"
	DetectRegistry       = "registry"
	DetectFile           = "file"
)

// MaxPackageBytes is the largest installer that can be uploaded.
const MaxPackageBytes = 2 << 30

// DefaultSuccessExitCodes are the exit codes that mean an installer worked
// when the author doesn't say: 0, and the two Windows Installer codes for
// "worked, but a restart is needed to finish" (3010 and 1641).
func DefaultSuccessExitCodes() []int { return []int{0, 3010, 1641} }

// RebootExitCode reports whether a successful exit code also asks for a
// restart.
func RebootExitCode(code int) bool { return code == 3010 || code == 1641 }

// DetectionRule says how the agent tells whether an uploaded app is
// installed. Only the fields its Type uses are set.
type DetectionRule struct {
	Type string `json:"type"`
	// ProductCode is an MSI product code, braces included, for
	// msi_product_code: installed when Windows lists it as installed.
	ProductCode string `json:"product_code,omitempty"`
	// Key is a registry key under HKEY_LOCAL_MACHINE, for registry; Value is
	// one of its values, empty for "the key exists".
	Key   string `json:"key,omitempty"`
	Value string `json:"value,omitempty"`
	// Equals, for registry, requires the value to be exactly this.
	Equals string `json:"equals,omitempty"`
	// Path is a file, for file; environment variables such as
	// %ProgramFiles% are expanded.
	Path string `json:"path,omitempty"`
	// VersionAtLeast requires a version no older than this: the product's
	// DisplayVersion for msi_product_code, the value for registry, the file's
	// version resource for file.
	VersionAtLeast string `json:"version_at_least,omitempty"`
}

var productCodePattern = regexp.MustCompile(`^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$`)

// ErrBadDetection wraps every detection rule validation failure.
var ErrBadDetection = errors.New("bad detection rule")

// Validate checks that a rule is complete and uses only its own fields.
func (d DetectionRule) Validate() error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrBadDetection, fmt.Sprintf(format, a...))
	}
	if d.VersionAtLeast != "" {
		if _, err := ParseVersion(d.VersionAtLeast); err != nil {
			return bad("version_at_least: %v", err)
		}
	}
	switch d.Type {
	case DetectMSIProductCode:
		if !productCodePattern.MatchString(d.ProductCode) {
			return bad("product_code must look like {12345678-1234-1234-1234-123456789ABC}")
		}
		if d.Key != "" || d.Value != "" || d.Equals != "" || d.Path != "" {
			return bad("an msi_product_code rule takes only product_code and version_at_least")
		}
	case DetectRegistry:
		key := strings.Trim(d.Key, `\`)
		if key == "" || strings.Contains(key, `\\`) {
			return bad(`key must be a path under HKEY_LOCAL_MACHINE, such as SOFTWARE\Contoso\App`)
		}
		if strings.HasPrefix(strings.ToUpper(key), "HKEY_") || strings.HasPrefix(strings.ToUpper(key), "HKLM") {
			return bad("key is already under HKEY_LOCAL_MACHINE; leave the hive off")
		}
		if d.Value == "" && (d.Equals != "" || d.VersionAtLeast != "") {
			return bad("equals and version_at_least need a value to compare")
		}
		if d.Equals != "" && d.VersionAtLeast != "" {
			return bad("use equals or version_at_least, not both")
		}
		if d.ProductCode != "" || d.Path != "" {
			return bad("a registry rule takes only key, value, equals and version_at_least")
		}
	case DetectFile:
		if strings.TrimSpace(d.Path) == "" {
			return bad("path is required")
		}
		if d.ProductCode != "" || d.Key != "" || d.Value != "" || d.Equals != "" {
			return bad("a file rule takes only path and version_at_least")
		}
	default:
		return bad("type must be %s, %s or %s", DetectMSIProductCode, DetectRegistry, DetectFile)
	}
	return nil
}

// Version is a dotted numeric version, such as 10.0.26100.1.
type Version []int

// ParseVersion reads a dotted version of up to four numeric parts.
func ParseVersion(s string) (Version, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty version")
	}
	parts := strings.Split(s, ".")
	if len(parts) > 4 {
		return nil, fmt.Errorf("%q has more than four parts", s)
	}
	v := make(Version, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("%q is not a dotted number version", s)
		}
		v[i] = n
	}
	return v, nil
}

// Compare returns -1, 0 or 1; missing parts count as zero, so 1.2 == 1.2.0.
func (v Version) Compare(o Version) int {
	for i := 0; i < len(v) || i < len(o); i++ {
		a, b := 0, 0
		if i < len(v) {
			a = v[i]
		}
		if i < len(o) {
			b = o[i]
		}
		switch {
		case a < b:
			return -1
		case a > b:
			return 1
		}
	}
	return 0
}
