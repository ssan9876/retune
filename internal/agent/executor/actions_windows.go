//go:build windows

package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"retune/internal/agent/winsession"
)

// SessionLocker locks the console session by running LockWorkStation as the
// signed-in user: a service can't lock someone else's session from its own.
type SessionLocker struct{}

func (SessionLocker) Lock(ctx context.Context) (bool, error) {
	var stderr strings.Builder
	code, err := winsession.RunPowerShell(ctx, "rundll32.exe user32.dll,LockWorkStation", io.Discard, &stderr)
	if errors.Is(err, winsession.ErrNoSession) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if code != 0 {
		return false, fmt.Errorf("LockWorkStation exited %d: %s", code, strings.TrimSpace(stderr.String()))
	}
	return true, nil
}

// Wevtutil exports event logs with wevtutil.exe, which ships with Windows.
type Wevtutil struct{}

func (Wevtutil) Export(ctx context.Context, channel, path string, hours int) error {
	query := fmt.Sprintf("*[System[TimeCreated[timediff(@SystemTime) <= %d]]]", int64(hours)*3600*1000)
	exe := filepath.Join(systemRoot(), "System32", "wevtutil.exe")
	cmd := exec.CommandContext(ctx, exe, "epl", channel, path, "/q:"+query, "/ow:true")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("wevtutil: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// MDMWiper starts a reset through Windows' own MDM remote wipe, the same one
// Intune uses: MDM_RemoteWipe in root\cimv2\mdm\dmmap, which only SYSTEM can
// call. The method returns once the reset is scheduled.
type MDMWiper struct {
	Runner Runner
}

func (w MDMWiper) Wipe(ctx context.Context, protected bool) error {
	method := "doWipeMethod"
	if protected {
		method = "doWipeProtectedMethod"
	}
	script := `$ErrorActionPreference = 'Stop'
$ns = 'root\cimv2\mdm\dmmap'
$class = 'MDM_RemoteWipe'
$session = New-CimSession
$params = New-Object Microsoft.Management.Infrastructure.CimMethodParametersCollection
$params.Add([Microsoft.Management.Infrastructure.CimMethodParameter]::Create('param', '', 'String', 'In'))
$instance = Get-CimInstance -Namespace $ns -ClassName $class -Filter "ParentID='./Vendor/MSFT' and InstanceID='RemoteWipe'"
$session.InvokeMethod($ns, $instance, ` + strconv.Quote(method) + `, $params) | Out-Null
'wipe requested'
`
	var stderr strings.Builder
	code, err := w.Runner.RunPowerShell(ctx, script, io.Discard, &stderr)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("the MDM wipe call failed (exit %d): %s", code, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func systemRoot() string {
	if root := os.Getenv("SystemRoot"); root != "" {
		return root
	}
	return `C:\Windows`
}

// DefaultLocker, DefaultWiper and DefaultEventExporter are the real ones.
func DefaultLocker() Locker               { return SessionLocker{} }
func DefaultWiper(r Runner) Wiper         { return MDMWiper{Runner: r} }
func DefaultEventExporter() EventExporter { return Wevtutil{} }
