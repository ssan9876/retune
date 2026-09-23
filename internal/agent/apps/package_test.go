package apps_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"retune/internal/agent/apps"
	"retune/internal/protocol"
)

// fakeProbe is a registry and file system in maps. Registry keys are
// "key|value", with "key|" meaning the key itself.
type fakeProbe struct {
	reg   map[string]string
	files map[string]string // path -> version
	err   error
}

func (f fakeProbe) Registry(key, value string) (string, bool, error) {
	if f.err != nil {
		return "", false, f.err
	}
	v, ok := f.reg[key+"|"+value]
	return v, ok, nil
}

func (f fakeProbe) FileVersion(path string) (string, bool, error) {
	if f.err != nil {
		return "", false, f.err
	}
	v, ok := f.files[path]
	return v, ok, nil
}

func (fakeProbe) Expand(s string) string {
	return strings.ReplaceAll(s, "%ProgramFiles%", `C:\Program Files`)
}

const code = "{23170F69-40C1-2702-2600-000001000000}"

func TestDetect(t *testing.T) {
	msiKey := `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\` + code
	probe := fakeProbe{
		reg: map[string]string{
			msiKey + "|": "", msiKey + "|DisplayVersion": "26.00",
			`SOFTWARE\Contoso|`: "", `SOFTWARE\Contoso|Version`: "2.1.0", `SOFTWARE\Contoso|Edition`: "Pro",
		},
		files: map[string]string{`C:\Program Files\Contoso\app.exe`: "3.4.0.1", `C:\bare.txt`: ""},
	}
	cases := []struct {
		name    string
		rule    protocol.DetectionRule
		want    bool
		version string
	}{
		{"msi present", protocol.DetectionRule{Type: protocol.DetectMSIProductCode, ProductCode: code}, true, "26.00"},
		{"msi new enough", protocol.DetectionRule{Type: protocol.DetectMSIProductCode, ProductCode: code, VersionAtLeast: "26"}, true, "26.00"},
		{"msi too old", protocol.DetectionRule{Type: protocol.DetectMSIProductCode, ProductCode: code, VersionAtLeast: "26.1"}, false, "26.00"},
		{"msi absent", protocol.DetectionRule{Type: protocol.DetectMSIProductCode, ProductCode: "{00000000-0000-0000-0000-000000000000}"}, false, ""},
		{"key exists", protocol.DetectionRule{Type: protocol.DetectRegistry, Key: `SOFTWARE\Contoso`}, true, ""},
		{"key missing", protocol.DetectionRule{Type: protocol.DetectRegistry, Key: `SOFTWARE\Fabrikam`}, false, ""},
		{"value missing", protocol.DetectionRule{Type: protocol.DetectRegistry, Key: `SOFTWARE\Contoso`, Value: "Nope"}, false, ""},
		{"value equals", protocol.DetectionRule{Type: protocol.DetectRegistry, Key: `SOFTWARE\Contoso`, Value: "Edition", Equals: "Pro"}, true, "Pro"},
		{"value differs", protocol.DetectionRule{Type: protocol.DetectRegistry, Key: `SOFTWARE\Contoso`, Value: "Edition", Equals: "Home"}, false, "Pro"},
		{"value version", protocol.DetectionRule{Type: protocol.DetectRegistry, Key: `SOFTWARE\Contoso`, Value: "Version", VersionAtLeast: "2.1"}, true, "2.1.0"},
		{"value not a version", protocol.DetectionRule{Type: protocol.DetectRegistry, Key: `SOFTWARE\Contoso`, Value: "Edition", VersionAtLeast: "1"}, false, "Pro"},
		{"file expanded", protocol.DetectionRule{Type: protocol.DetectFile, Path: `%ProgramFiles%\Contoso\app.exe`}, true, "3.4.0.1"},
		{"file too old", protocol.DetectionRule{Type: protocol.DetectFile, Path: `%ProgramFiles%\Contoso\app.exe`, VersionAtLeast: "3.5"}, false, "3.4.0.1"},
		{"file with no version", protocol.DetectionRule{Type: protocol.DetectFile, Path: `C:\bare.txt`, VersionAtLeast: "1"}, false, ""},
		{"file missing", protocol.DetectionRule{Type: protocol.DetectFile, Path: `C:\nope.exe`}, false, ""},
	}
	for _, c := range cases {
		got, version, err := apps.Detect(c.rule, probe)
		if err != nil || got != c.want || version != c.version {
			t.Errorf("%s: = %v, %q, %v; want %v, %q", c.name, got, version, err, c.want, c.version)
		}
	}

	// Unreadable is not absent.
	if _, _, err := apps.Detect(protocol.DetectionRule{Type: protocol.DetectFile, Path: "x"},
		fakeProbe{err: errors.New("access denied")}); err == nil {
		t.Fatal("a probe error must come back as an error")
	}
}

// fakeRunner records command lines and answers with a fixed exit code,
// checking the installer was on disk while it "ran".
type fakeRunner struct {
	mu       sync.Mutex
	commands []apps.Command
	present  []bool
	exit     int
	file     string // checked for existence during Run
}

func (f *fakeRunner) Run(_ context.Context, c apps.Command) apps.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.commands = append(f.commands, c)
	if f.file != "" {
		_, err := os.Stat(f.file)
		f.present = append(f.present, err == nil)
	}
	return apps.Result{ExitCode: f.exit}
}

// fakeDownloader serves one body, checked against the wanted hash the way the
// real client does.
type fakeDownloader struct {
	body  []byte
	calls int
}

func (f *fakeDownloader) DownloadAppPackage(_ context.Context, _ string, _ int, want string, dst io.Writer) error {
	f.calls++
	if _, err := dst.Write(f.body); err != nil {
		return err
	}
	sum := sha256.Sum256(f.body)
	if hex.EncodeToString(sum[:]) != want {
		return errors.New("sha256 mismatch")
	}
	return nil
}

func packageVersion(body []byte, typ, name string) protocol.AppVersionResponse {
	sum := sha256.Sum256(body)
	return protocol.AppVersionResponse{
		Version: 1, Source: protocol.AppSourcePackage, InstallerType: typ, FileName: name,
		FileSHA256: hex.EncodeToString(sum[:]), FileSize: int64(len(body)),
		Detection: &protocol.DetectionRule{Type: protocol.DetectMSIProductCode, ProductCode: code},
	}
}

func TestPackagesInstallMSI(t *testing.T) {
	dir := t.TempDir()
	body := []byte("an msi")
	v := packageVersion(body, protocol.InstallerMSI, "Contoso App.msi")
	v.InstallArgs = `TARGETDIR="C:\Contoso"`
	file := filepath.Join(dir, v.FileSHA256, "Contoso App.msi")
	run := &fakeRunner{file: file}
	p := &apps.Packages{Dir: dir, Download: &fakeDownloader{body: body}, Run: run, Probe: fakeProbe{}}

	r := p.Install(context.Background(), "a1", v)
	if r.Err != nil || r.ExitCode != 0 {
		t.Fatalf("install = %+v", r)
	}
	if len(run.commands) != 1 || !run.present[0] {
		t.Fatalf("commands %+v, file present while running %v", run.commands, run.present)
	}
	c := run.commands[0]
	if !strings.HasSuffix(strings.ToLower(c.Path), `system32\msiexec.exe`) {
		t.Errorf("path = %q", c.Path)
	}
	want := `msiexec.exe /i "` + file + `" /qn /norestart TARGETDIR="C:\Contoso"`
	if c.CmdLine != want {
		t.Errorf("command line = %q\nwant %q", c.CmdLine, want)
	}
	// Nothing is kept once it has run.
	if _, err := os.Stat(filepath.Join(dir, v.FileSHA256)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the download was left behind: %v", err)
	}
}

func TestPackagesInstallEXE(t *testing.T) {
	dir := t.TempDir()
	body := []byte("an exe")
	v := packageVersion(body, protocol.InstallerEXE, "setup.exe")
	v.InstallArgs = "/S /norestart"
	run := &fakeRunner{}
	p := &apps.Packages{Dir: dir, Download: &fakeDownloader{body: body}, Run: run, Probe: fakeProbe{}}
	if r := p.Install(context.Background(), "a1", v); r.Err != nil {
		t.Fatal(r.Err)
	}
	file := filepath.Join(dir, v.FileSHA256, "setup.exe")
	if c := run.commands[0]; c.Path != file || c.CmdLine != `"`+file+`" /S /norestart` {
		t.Errorf("command = %+v", c)
	}
}

func TestPackagesRefuseABadDownload(t *testing.T) {
	dir := t.TempDir()
	v := packageVersion([]byte("the real thing"), protocol.InstallerEXE, "setup.exe")
	run := &fakeRunner{}
	p := &apps.Packages{Dir: dir, Download: &fakeDownloader{body: []byte("tampered")}, Run: run, Probe: fakeProbe{}}
	r := p.Install(context.Background(), "a1", v)
	if r.Err == nil {
		t.Fatal("a hash mismatch must fail the install")
	}
	if len(run.commands) != 0 {
		t.Fatalf("ran %+v from a bad download", run.commands)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("left %d entries behind", len(entries))
	}

	// A file name that isn't one is refused before anything is written.
	v = packageVersion([]byte("x"), protocol.InstallerEXE, `..\evil.exe`)
	if r := p.Install(context.Background(), "a1", v); r.Err == nil {
		t.Fatal("a path in the file name must be refused")
	}
}

func TestPackagesUninstall(t *testing.T) {
	run := &fakeRunner{}
	p := &apps.Packages{Dir: t.TempDir(), Run: run, Probe: fakeProbe{}}

	msi := packageVersion([]byte("x"), protocol.InstallerMSI, "a.msi")
	if r := p.Uninstall(context.Background(), "a1", msi); r.Err != nil {
		t.Fatal(r.Err)
	}
	if got := run.commands[0].CmdLine; got != "msiexec.exe /x "+code+" /qn /norestart" {
		t.Errorf("msi uninstall = %q", got)
	}

	exe := packageVersion([]byte("x"), protocol.InstallerEXE, "setup.exe")
	exe.UninstallCommand = `"%ProgramFiles%\Contoso\uninstall.exe" /S`
	if r := p.Uninstall(context.Background(), "a1", exe); r.Err != nil {
		t.Fatal(r.Err)
	}
	if c := run.commands[1]; c.Path != `C:\Program Files\Contoso\uninstall.exe` ||
		c.CmdLine != `"C:\Program Files\Contoso\uninstall.exe" /S` {
		t.Errorf("exe uninstall = %+v", c)
	}

	exe.UninstallCommand = ""
	if r := p.Uninstall(context.Background(), "a1", exe); r.Err == nil {
		t.Fatal("an exe with no uninstall command can't be removed")
	}
}

func TestPackagesOutcome(t *testing.T) {
	p := &apps.Packages{}
	v := protocol.AppVersionResponse{}
	for code, want := range map[int]apps.Outcome{
		0: apps.OutcomeSucceeded, 3010: apps.OutcomeRebootRequired, 1641: apps.OutcomeRebootRequired,
		1603: apps.OutcomeFailed, -1: apps.OutcomeFailed,
	} {
		if got := p.Outcome(v, code); got != want {
			t.Errorf("default codes, %d = %v, want %v", code, got, want)
		}
	}
	v.SuccessExitCodes = []int{0, 2}
	if p.Outcome(v, 2) != apps.OutcomeSucceeded || p.Outcome(v, 3010) != apps.OutcomeFailed {
		t.Error("a version's own codes replace the defaults")
	}
}
