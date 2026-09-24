// Package winupdate asks Windows Update, through its own agent's COM API,
// which updates a device is missing, and installs them on request.
package winupdate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"retune/internal/protocol"
)

// Runner runs a PowerShell script: the agent's own.
type Runner interface {
	RunPowerShell(ctx context.Context, script string, stdout, stderr io.Writer) (exitCode int, err error)
}

// ScanTimeout bounds a search; one can take minutes on a slow link.
const ScanTimeout = 15 * time.Minute

// InstallTimeout bounds downloading and installing.
const InstallTimeout = 2 * time.Hour

// securityCategories are the Windows Update categories compliance counts.
var securityCategories = []string{"Security Updates", "Critical Updates"}

// searchScript lists the software updates not installed, as JSON. Hidden
// updates are ones an administrator declined, so they are left out.
const searchScript = `$ErrorActionPreference = 'Stop'
$session = New-Object -ComObject Microsoft.Update.Session
$result = $session.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
$out = foreach ($u in $result.Updates) {
  [pscustomobject]@{
    title = $u.Title
    kb = (@($u.KBArticleIDs) -join ',')
    severity = [string]$u.MsrcSeverity
    categories = @($u.Categories | ForEach-Object { $_.Name })
    size = [int64]$u.MaxDownloadSize
    reboot = ($u.InstallationBehavior.RebootBehavior -ne 0)
  }
}
ConvertTo-Json -InputObject @($out) -Depth 4 -Compress`

// installScript downloads and installs the updates in scope. %s is
// replaced with a PowerShell boolean: whether only security updates count.
const installScript = `$ErrorActionPreference = 'Stop'
$securityOnly = %s
$session = New-Object -ComObject Microsoft.Update.Session
$result = $session.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
$chosen = New-Object -ComObject Microsoft.Update.UpdateColl
$titles = @()
foreach ($u in $result.Updates) {
  $names = @($u.Categories | ForEach-Object { $_.Name })
  if ($securityOnly -and -not ($names -contains 'Security Updates' -or $names -contains 'Critical Updates')) { continue }
  if (-not $u.EulaAccepted) { $u.AcceptEula() }
  [void]$chosen.Add($u)
  $titles += $u.Title
}
if ($chosen.Count -eq 0) {
  ConvertTo-Json -InputObject ([pscustomobject]@{ installed = 0; failed = 0; reboot_required = $false; titles = @() }) -Compress
  exit 0
}
$downloader = $session.CreateUpdateDownloader()
$downloader.Updates = $chosen
[void]$downloader.Download()
$installer = $session.CreateUpdateInstaller()
$installer.Updates = $chosen
$res = $installer.Install()
$ok = 0; $bad = 0
for ($i = 0; $i -lt $chosen.Count; $i++) {
  $code = $res.GetUpdateResult($i).ResultCode
  if ($code -eq 2 -or $code -eq 3) { $ok++ } else { $bad++ }
}
ConvertTo-Json -InputObject ([pscustomobject]@{ installed = $ok; failed = $bad; reboot_required = [bool]$res.RebootRequired; titles = $titles }) -Compress`

// found is one update as the search script writes it.
type found struct {
	Title      string   `json:"title"`
	KB         string   `json:"kb"`
	Severity   string   `json:"severity"`
	Categories []string `json:"categories"`
	Size       int64    `json:"size"`
	Reboot     bool     `json:"reboot"`
}

// ParseScan turns the search script's output into pending updates.
func ParseScan(out []byte) ([]protocol.PendingUpdate, error) {
	out = bytes.TrimSpace(out)
	if len(out) == 0 {
		return []protocol.PendingUpdate{}, nil
	}
	var list []found
	if err := json.Unmarshal(out, &list); err != nil {
		return nil, fmt.Errorf("read the Windows Update search: %w", err)
	}
	pending := make([]protocol.PendingUpdate, 0, len(list))
	for _, f := range list {
		u := protocol.PendingUpdate{
			Title: f.Title, Severity: f.Severity, Categories: f.Categories,
			SizeBytes: f.Size, RebootRequired: f.Reboot,
		}
		if f.KB != "" {
			u.KB = "KB" + strings.TrimPrefix(strings.Split(f.KB, ",")[0], "KB")
		}
		for _, c := range f.Categories {
			if slices.Contains(securityCategories, c) {
				u.Security = true
			}
		}
		pending = append(pending, u)
	}
	return pending, nil
}

// Scan searches Windows Update now.
func Scan(ctx context.Context, r Runner, now time.Time) protocol.UpdateStatus {
	ctx, cancel := context.WithTimeout(ctx, ScanTimeout)
	defer cancel()
	var stdout, stderr bytes.Buffer
	st := protocol.UpdateStatus{ScannedAt: now, Pending: []protocol.PendingUpdate{}}
	code, err := r.RunPowerShell(ctx, searchScript, &stdout, &stderr)
	switch {
	case err != nil:
		st.Error = "searching Windows Update: " + err.Error()
	case code != 0:
		st.Error = "searching Windows Update failed: " + firstLine(stderr.String())
	default:
		pending, err := ParseScan(stdout.Bytes())
		if err != nil {
			st.Error = err.Error()
		} else {
			st.Pending = pending
		}
	}
	return st
}

// Install installs what is in scope, and reports what happened.
func Install(ctx context.Context, r Runner, scope string) (protocol.InstallUpdatesResult, string, error) {
	securityOnly := "$false"
	switch scope {
	case protocol.UpdatesSecurity:
		securityOnly = "$true"
	case protocol.UpdatesAll:
	default:
		return protocol.InstallUpdatesResult{}, "", fmt.Errorf("scope must be security or all, not %q", scope)
	}
	ctx, cancel := context.WithTimeout(ctx, InstallTimeout)
	defer cancel()
	var stdout, stderr bytes.Buffer
	code, err := r.RunPowerShell(ctx, fmt.Sprintf(installScript, securityOnly), &stdout, &stderr)
	if err != nil {
		return protocol.InstallUpdatesResult{}, stderr.String(), err
	}
	if code != 0 {
		return protocol.InstallUpdatesResult{}, stderr.String(), fmt.Errorf("installing updates failed: %s", firstLine(stderr.String()))
	}
	var res protocol.InstallUpdatesResult
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &res); err != nil {
		return protocol.InstallUpdatesResult{}, stdout.String(), fmt.Errorf("read the install result: %w", err)
	}
	return res, "", nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return "no reason given"
	}
	return s
}
