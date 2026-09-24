package winupdate

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"retune/internal/protocol"
)

// realSearch is what the search script printed on a Windows 11 machine.
const realSearch = `[{"title":"Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.459.366.0) - Current Channel (Broad)","kb":"2267602","severity":"","categories":["Definition Updates","Microsoft Defender Antivirus"],"size":1655356008,"reboot":false}]`

const withSecurity = `[{"title":"2026-09 Cumulative Update for Windows 11 Version 24H2 (KB5065426)","kb":"5065426","severity":"Critical","categories":["Security Updates","Windows 11"],"size":900000000,"reboot":true},
{"title":"A driver","kb":"","severity":"","categories":["Drivers"],"size":1000,"reboot":false}]`

func TestParseScan(t *testing.T) {
	got, err := ParseScan([]byte(realSearch))
	if err != nil || len(got) != 1 {
		t.Fatalf("real output: %+v, %v", got, err)
	}
	if got[0].KB != "KB2267602" || got[0].Security || got[0].SizeBytes != 1655356008 {
		t.Errorf("definition update = %+v", got[0])
	}
	got, err = ParseScan([]byte(withSecurity))
	if err != nil || len(got) != 2 {
		t.Fatalf("with security: %+v, %v", got, err)
	}
	if !got[0].Security || got[0].Severity != "Critical" || !got[0].RebootRequired || got[0].KB != "KB5065426" {
		t.Errorf("cumulative update = %+v", got[0])
	}
	if got[1].Security || got[1].KB != "" {
		t.Errorf("driver = %+v", got[1])
	}
	if got, err := ParseScan([]byte("  ")); err != nil || len(got) != 0 {
		t.Errorf("nothing pending: %+v, %v", got, err)
	}
	if _, err := ParseScan([]byte("not json")); err == nil {
		t.Error("garbage should be an error")
	}
	st := protocol.UpdateStatus{Pending: got}
	if n := len(st.SecurityPending()); n != 1 {
		t.Errorf("security pending = %d, want 1", n)
	}
}

type fakeRunner struct {
	out, errOut string
	code        int
	err         error
	script      string
}

func (f *fakeRunner) RunPowerShell(_ context.Context, script string, stdout, stderr io.Writer) (int, error) {
	f.script = script
	_, _ = io.WriteString(stdout, f.out)
	_, _ = io.WriteString(stderr, f.errOut)
	return f.code, f.err
}

func TestScan(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	st := Scan(context.Background(), &fakeRunner{out: withSecurity}, now)
	if st.Error != "" || len(st.Pending) != 2 || !st.ScannedAt.Equal(now) || len(st.SecurityPending()) != 1 {
		t.Fatalf("status = %+v", st)
	}
	st = Scan(context.Background(), &fakeRunner{code: 1, errOut: "0x8024402C\nmore"}, now)
	if !strings.Contains(st.Error, "0x8024402C") || st.Pending == nil {
		t.Fatalf("a failed search = %+v", st)
	}
	st = Scan(context.Background(), &fakeRunner{err: errors.New("powershell not found")}, now)
	if !strings.Contains(st.Error, "powershell not found") {
		t.Fatalf("a search that didn't run = %+v", st)
	}
}

func TestInstall(t *testing.T) {
	r := &fakeRunner{out: `{"installed":2,"failed":1,"reboot_required":true,"titles":["a","b","c"]}`}
	res, _, err := Install(context.Background(), r, protocol.UpdatesSecurity)
	if err != nil || res.Installed != 2 || res.Failed != 1 || !res.RebootRequired {
		t.Fatalf("result %+v, %v", res, err)
	}
	if !strings.Contains(r.script, "$securityOnly = $true") {
		t.Error("a security install must only choose security updates")
	}
	if _, _, err := Install(context.Background(), r, protocol.UpdatesAll); err != nil || !strings.Contains(r.script, "$securityOnly = $false") {
		t.Errorf("all: %v", err)
	}
	if _, _, err := Install(context.Background(), r, "drivers; Remove-Item"); err == nil {
		t.Error("an unknown scope must be refused before PowerShell runs")
	}
}
