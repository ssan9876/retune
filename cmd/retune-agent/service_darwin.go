//go:build darwin

package main

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
)

// On macOS the agent is a launchd daemon: launchd starts it as root at boot
// with `retune-agent run`, and restarts it if it exits.

const (
	launchdLabel = "com.retune.agent"
	launchdPlist = "/Library/LaunchDaemons/" + launchdLabel + ".plist"
)

// launchd starts daemons with ordinary arguments, so the agent never runs
// "as a service" the way the Windows service control manager starts it.
func isWindowsService() bool { return false }

func runService(context.Context, string) error {
	return errors.New("on macOS the agent runs under launchd; use retune-agent run")
}

// plist renders the daemon's property list. Values are XML-escaped: the data
// directory is the operator's to choose.
func plist(exePath, dataDir string) []byte {
	var b bytes.Buffer
	esc := func(s string) string {
		var e bytes.Buffer
		_ = xml.EscapeText(&e, []byte(s))
		return e.String()
	}
	fmt.Fprintf(&b, `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>run</string>
		<string>--data-dir</string>
		<string>%s</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ThrottleInterval</key>
	<integer>30</integer>
	<key>StandardErrorPath</key>
	<string>/var/log/retune-agent.log</string>
</dict>
</plist>
`, launchdLabel, esc(exePath), esc(dataDir))
	return b.Bytes()
}

func installService(exePath, dataDir string) error {
	if os.Geteuid() != 0 {
		return errors.New("installing the agent needs root; run it with sudo")
	}
	if _, err := os.Stat(launchdPlist); err == nil {
		return fmt.Errorf("the %s daemon is already installed", launchdLabel)
	}
	if err := os.WriteFile(launchdPlist, plist(exePath, dataDir), 0o644); err != nil {
		return err
	}
	if out, err := exec.Command("/bin/launchctl", "bootstrap", "system", launchdPlist).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl bootstrap: %w: %s", err, out)
	}
	return nil
}

func uninstallService() error {
	if os.Geteuid() != 0 {
		return errors.New("removing the agent needs root; run it with sudo")
	}
	if _, err := os.Stat(launchdPlist); err != nil {
		return fmt.Errorf("the %s daemon is not installed", launchdLabel)
	}
	// Already stopped is fine: removing it is what was asked for.
	_ = exec.Command("/bin/launchctl", "bootout", "system/"+launchdLabel).Run()
	return os.Remove(launchdPlist)
}

// secureDataDir makes the data directory root's alone: it holds the device
// key, and the daemon runs as root out of it.
func secureDataDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(dir, 0, 0); err != nil {
			return err
		}
	}
	return os.Chmod(dir, 0o700)
}

// There is no Event Log on macOS; launchd captures the agent's own log.
func registerEventLogSource() error { return nil }
func removeEventLogSource() error   { return nil }
