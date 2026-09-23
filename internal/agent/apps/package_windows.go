//go:build windows

package apps

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"retune/internal/agent/executor"
	"retune/internal/protocol"
)

// NewPackages returns the installer for uploaded packages, keeping downloads
// under dir while they run.
func NewPackages(dir string, dl PackageDownloader) (*Packages, error) {
	return &Packages{Dir: dir, Download: dl, Run: windowsRunner{}, Probe: windowsProbe{}}, nil
}

type windowsRunner struct{}

// Run starts c.Path with c.CmdLine as its exact command line: an installer
// parses its own arguments, and Go's quoting of an argument list would get in
// the way of switches like /qn PROPERTY="a b".
func (windowsRunner) Run(ctx context.Context, c Command) Result {
	stdout := executor.NewCapped(protocol.MaxOutputBytes)
	stderr := executor.NewCapped(protocol.MaxOutputBytes)
	cmd := exec.CommandContext(ctx, c.Path)
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: c.CmdLine, HideWindow: true}
	cmd.Stdout, cmd.Stderr = stdout, stderr

	err := cmd.Run()
	res := Result{
		Stdout: stdout.String(), Stderr: stderr.String(),
		OutCut: stdout.Truncated(), ErrCut: stderr.Truncated(),
	}
	var exitErr *exec.ExitError
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		res.TimedOut, res.Err, res.ExitCode = true, ctx.Err(), -1
	case errors.As(err, &exitErr):
		res.ExitCode = int(normalizeExitCode(exitErr.ExitCode()))
	case err != nil:
		res.Err, res.ExitCode = err, -1
	}
	return res
}

type windowsProbe struct{}

func (windowsProbe) Registry(key, value string) (string, bool, error) {
	// A 32-bit installer writes under WOW6432Node; look in both views.
	for _, view := range []uint32{registry.WOW64_64KEY, registry.WOW64_32KEY} {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.QUERY_VALUE|view)
		if errors.Is(err, registry.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", false, err
		}
		data, found, err := readValue(k, value)
		k.Close()
		if err != nil || found {
			return data, found, err
		}
	}
	return "", false, nil
}

func readValue(k registry.Key, name string) (string, bool, error) {
	if name == "" {
		return "", true, nil
	}
	_, typ, err := k.GetValue(name, nil)
	if errors.Is(err, registry.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	switch typ {
	case registry.SZ, registry.EXPAND_SZ:
		s, _, err := k.GetStringValue(name)
		return s, err == nil, err
	case registry.DWORD, registry.QWORD:
		n, _, err := k.GetIntegerValue(name)
		return strconv.FormatUint(n, 10), err == nil, err
	case registry.MULTI_SZ:
		ss, _, err := k.GetStringsValue(name)
		if err != nil || len(ss) == 0 {
			return "", err == nil, err
		}
		return ss[0], true, nil
	}
	// A binary value exists, but has nothing to compare.
	return "", true, nil
}

func (windowsProbe) FileVersion(path string) (string, bool, error) {
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return "", false, nil
	} else if err != nil {
		return "", false, err
	}
	size, err := windows.GetFileVersionInfoSize(path, nil)
	if err != nil || size == 0 {
		return "", true, nil // exists, with no version resource
	}
	buf := make([]byte, size)
	if err := windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&buf[0])); err != nil {
		return "", true, nil
	}
	var info *windows.VS_FIXEDFILEINFO
	var infoLen uint32
	if err := windows.VerQueryValue(unsafe.Pointer(&buf[0]), `\`, unsafe.Pointer(&info), &infoLen); err != nil ||
		info == nil {
		return "", true, nil
	}
	return fmt.Sprintf("%d.%d.%d.%d",
		info.FileVersionMS>>16, info.FileVersionMS&0xffff,
		info.FileVersionLS>>16, info.FileVersionLS&0xffff), true, nil
}

func (windowsProbe) Expand(s string) string {
	out, err := registry.ExpandString(s)
	if err != nil {
		return s
	}
	return out
}
