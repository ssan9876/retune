package apps

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"retune/internal/protocol"
)

// Installer acts on one kind of app: winget packages, or uploaded ones.
type Installer interface {
	// Detect reports whether v is installed; see Winget.Detect for why
	// Result.Err must be checked first.
	Detect(ctx context.Context, id string, v protocol.AppVersionResponse) (installed bool, version string, r Result)
	Install(ctx context.Context, id string, v protocol.AppVersionResponse) Result
	Uninstall(ctx context.Context, id string, v protocol.AppVersionResponse) Result
	// Outcome says what an exit code from Install or Uninstall means.
	Outcome(v protocol.AppVersionResponse, exitCode int) Outcome
}

// wingetInstaller adapts Winget to Installer.
type wingetInstaller struct{ w Winget }

func (w wingetInstaller) Detect(ctx context.Context, _ string, v protocol.AppVersionResponse) (bool, string, Result) {
	return w.w.Detect(ctx, v.PackageID)
}

func (w wingetInstaller) Install(ctx context.Context, _ string, v protocol.AppVersionResponse) Result {
	return w.w.Install(ctx, v)
}

func (w wingetInstaller) Uninstall(ctx context.Context, _ string, v protocol.AppVersionResponse) Result {
	return w.w.Uninstall(ctx, v.PackageID)
}

func (wingetInstaller) Outcome(_ protocol.AppVersionResponse, code int) Outcome {
	return classify(code)
}

// Command is one process to run: the program, and the whole command line as
// Windows passes it (the program included), since installer arguments are
// free-form and quoting them is the author's business.
type Command struct {
	Path    string
	CmdLine string
}

// CommandRunner runs installers. The agent runs them as itself (SYSTEM);
// tests supply a fake that runs nothing.
type CommandRunner interface {
	Run(ctx context.Context, c Command) Result
}

// PackageDownloader fetches an app version's installer, checking its hash.
type PackageDownloader interface {
	DownloadAppPackage(ctx context.Context, id string, version int, wantSHA256 string, dst io.Writer) error
}

// Packages installs uploaded MSI and EXE packages.
type Packages struct {
	// Dir holds installers while they run; each is removed afterwards, so it
	// is only ever as big as the install in progress.
	Dir      string
	Download PackageDownloader
	Run      CommandRunner
	Probe    Probe
}

// Detect implements Installer.
func (p *Packages) Detect(_ context.Context, _ string, v protocol.AppVersionResponse) (bool, string, Result) {
	if v.Detection == nil {
		return false, "", Result{Err: errors.New("this package has no detection rule")}
	}
	installed, version, err := Detect(*v.Detection, p.Probe)
	return installed, version, Result{Err: err}
}

// Install implements Installer: download, verify, run, clean up.
func (p *Packages) Install(ctx context.Context, id string, v protocol.AppVersionResponse) Result {
	file, cleanup, err := p.fetch(ctx, id, v)
	if err != nil {
		return Result{Err: err, ExitCode: -1}
	}
	defer cleanup()
	var c Command
	switch v.InstallerType {
	case protocol.InstallerMSI:
		c = Command{Path: msiexec(), CmdLine: joinArgs(`msiexec.exe /i "`+file+`" /qn /norestart`, v.InstallArgs)}
	case protocol.InstallerEXE:
		c = Command{Path: file, CmdLine: joinArgs(`"`+file+`"`, v.InstallArgs)}
	default:
		return Result{Err: fmt.Errorf("unknown installer type %q", v.InstallerType), ExitCode: -1}
	}
	return p.Run.Run(ctx, c)
}

// Uninstall implements Installer. An MSI detected by its product code needs
// no command: msiexec removes it by that code.
func (p *Packages) Uninstall(ctx context.Context, _ string, v protocol.AppVersionResponse) Result {
	if cmd := strings.TrimSpace(v.UninstallCommand); cmd != "" {
		line := p.Probe.Expand(cmd)
		return p.Run.Run(ctx, Command{Path: program(line), CmdLine: line})
	}
	if v.InstallerType == protocol.InstallerMSI && v.Detection != nil &&
		v.Detection.Type == protocol.DetectMSIProductCode {
		return p.Run.Run(ctx, Command{
			Path: msiexec(), CmdLine: "msiexec.exe /x " + v.Detection.ProductCode + " /qn /norestart",
		})
	}
	return Result{Err: errors.New("this package has no uninstall command"), ExitCode: -1}
}

// Outcome implements Installer: the version's success codes, of which 3010
// and 1641 also mean a restart is needed.
func (p *Packages) Outcome(v protocol.AppVersionResponse, code int) Outcome {
	codes := v.SuccessExitCodes
	if len(codes) == 0 {
		codes = protocol.DefaultSuccessExitCodes()
	}
	for _, c := range codes {
		if c == code {
			if protocol.RebootExitCode(code) {
				return OutcomeRebootRequired
			}
			return OutcomeSucceeded
		}
	}
	return OutcomeFailed
}

var shaHex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// fetch downloads v's installer into its own directory, under the name it was
// uploaded with (some setup programs care what they're called), and returns
// its path and how to remove it.
func (p *Packages) fetch(ctx context.Context, id string, v protocol.AppVersionResponse) (string, func(), error) {
	sha := strings.ToLower(v.FileSHA256)
	name := v.FileName
	if !shaHex.MatchString(sha) {
		return "", nil, fmt.Errorf("the package hash %q is malformed", v.FileSHA256)
	}
	if name == "" || name != filepath.Base(name) || strings.ContainsAny(name, `/\:`) {
		return "", nil, fmt.Errorf("the package file name %q is not a plain file name", name)
	}
	dir := filepath.Join(p.Dir, sha)
	// Anything left from an earlier attempt that died part-way is stale.
	_ = os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	part := filepath.Join(dir, name+".part")
	f, err := os.Create(part)
	if err != nil {
		cleanup()
		return "", nil, err
	}
	err = p.Download.DownloadAppPackage(ctx, id, v.Version, sha, f)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("download the package: %w", err)
	}
	file := filepath.Join(dir, name)
	if err := os.Rename(part, file); err != nil {
		cleanup()
		return "", nil, err
	}
	return file, cleanup, nil
}

func joinArgs(cmd, extra string) string {
	if extra = strings.TrimSpace(extra); extra != "" {
		return cmd + " " + extra
	}
	return cmd
}

// program is the first token of a command line: quoted, or up to a space.
func program(line string) string {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, `"`) {
		if end := strings.Index(line[1:], `"`); end >= 0 {
			return line[1 : end+1]
		}
		return strings.Trim(line, `"`)
	}
	if i := strings.IndexByte(line, ' '); i >= 0 {
		return line[:i]
	}
	return line
}

// msiexec is Windows Installer, from System32 rather than wherever PATH says.
func msiexec() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", "msiexec.exe")
}
