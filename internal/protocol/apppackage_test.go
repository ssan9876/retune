package protocol

import (
	"errors"
	"testing"
)

func TestDetectionRuleValidate(t *testing.T) {
	good := []DetectionRule{
		{Type: DetectMSIProductCode, ProductCode: "{23170F69-40C1-2702-2600-000001000000}"},
		{Type: DetectMSIProductCode, ProductCode: "{23170F69-40C1-2702-2600-000001000000}", VersionAtLeast: "26.0"},
		{Type: DetectRegistry, Key: `SOFTWARE\Contoso\App`},
		{Type: DetectRegistry, Key: `SOFTWARE\Contoso\App`, Value: "Version", VersionAtLeast: "2.1"},
		{Type: DetectRegistry, Key: `SOFTWARE\Contoso\App`, Value: "Edition", Equals: "Pro"},
		{Type: DetectFile, Path: `%ProgramFiles%\Contoso\app.exe`},
		{Type: DetectFile, Path: `C:\Tools\tool.exe`, VersionAtLeast: "1.2.3.4"},
	}
	for _, d := range good {
		if err := d.Validate(); err != nil {
			t.Errorf("%+v: %v", d, err)
		}
	}
	bad := map[string]DetectionRule{
		"no type":                  {},
		"unknown type":             {Type: "wmi"},
		"product code unbraced":    {Type: DetectMSIProductCode, ProductCode: "23170F69-40C1-2702-2600-000001000000"},
		"product code with a path": {Type: DetectMSIProductCode, ProductCode: "{23170F69-40C1-2702-2600-000001000000}", Path: "x"},
		"registry with no key":     {Type: DetectRegistry},
		"registry with a hive":     {Type: DetectRegistry, Key: `HKLM\SOFTWARE\X`},
		"registry full hive":       {Type: DetectRegistry, Key: `HKEY_LOCAL_MACHINE\SOFTWARE\X`},
		"equals with no value":     {Type: DetectRegistry, Key: `SOFTWARE\X`, Equals: "1"},
		"equals and version":       {Type: DetectRegistry, Key: `SOFTWARE\X`, Value: "V", Equals: "1", VersionAtLeast: "1"},
		"file with no path":        {Type: DetectFile},
		"file with a key":          {Type: DetectFile, Path: "x", Key: "y"},
		"version not numeric":      {Type: DetectFile, Path: "x", VersionAtLeast: "1.2-beta"},
		"version with five parts":  {Type: DetectFile, Path: "x", VersionAtLeast: "1.2.3.4.5"},
	}
	for name, d := range bad {
		if err := d.Validate(); !errors.Is(err, ErrBadDetection) {
			t.Errorf("%s: err = %v, want ErrBadDetection", name, err)
		}
	}
}

func TestVersionCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2", "1.2.0", 0},
		{"1.10", "1.9", 1},
		{"2", "10", -1},
		{"26.00", "26.0", 0},
		{"10.0.26100.1", "10.0.26100.2", -1},
	}
	for _, c := range cases {
		a, err := ParseVersion(c.a)
		if err != nil {
			t.Fatal(err)
		}
		b, err := ParseVersion(c.b)
		if err != nil {
			t.Fatal(err)
		}
		if got := a.Compare(b); got != c.want {
			t.Errorf("%s vs %s = %d, want %d", c.a, c.b, got, c.want)
		}
	}
	for _, s := range []string{"", "a", "1..2", "-1", "1.2.3.4.5"} {
		if _, err := ParseVersion(s); err == nil {
			t.Errorf("ParseVersion(%q) should fail", s)
		}
	}
}
