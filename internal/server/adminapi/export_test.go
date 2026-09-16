package adminapi

import "testing"

// TestCSVSafe covers every prefix character the CSV-injection rule (spec §5)
// names - a cell opening with =, +, -, @, tab or carriage return gets a
// leading apostrophe - plus the cases that must pass through untouched: an
// empty cell and a cell where the character appears anywhere but first.
func TestCSVSafe(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"-1234567890", "'-1234567890"},
		{"=HYPERLINK(\"http://evil\")", "'=HYPERLINK(\"http://evil\")"},
		{"+1234567890", "'+1234567890"},
		{"@SUM(A1)", "'@SUM(A1)"},
		{"\ttabbed", "'\ttabbed"},
		{"\rcarriage", "'\rcarriage"},
		{"normal-hostname", "normal-hostname"},
		{"a=b+c-d@e", "a=b+c-d@e"}, // guarded characters mid-string are fine
	}
	for _, c := range cases {
		if got := csvSafe(c.in); got != c.want {
			t.Errorf("csvSafe(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
