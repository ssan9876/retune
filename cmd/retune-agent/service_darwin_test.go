//go:build darwin

package main

import (
	"encoding/xml"
	"strings"
	"testing"
)

func TestPlist(t *testing.T) {
	p := plist("/usr/local/bin/retune-agent", "/Library/Application Support/Re<tune>")
	if err := xml.Unmarshal(p, new(struct{})); err != nil {
		t.Fatalf("plist is not XML: %v\n%s", err, p)
	}
	for _, want := range []string{
		"<string>com.retune.agent</string>",
		"<string>/usr/local/bin/retune-agent</string>\n\t\t<string>run</string>",
		"<string>/Library/Application Support/Re&lt;tune&gt;</string>",
		"<key>KeepAlive</key>\n\t<true/>",
	} {
		if !strings.Contains(string(p), want) {
			t.Errorf("plist lacks %q:\n%s", want, p)
		}
	}
}
