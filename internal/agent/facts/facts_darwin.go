//go:build darwin

package facts

import (
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func osVersion() string {
	name, _ := exec.Command("/usr/bin/sw_vers", "-productName").Output()
	version, _ := exec.Command("/usr/bin/sw_vers", "-productVersion").Output()
	build, _ := exec.Command("/usr/bin/sw_vers", "-buildVersion").Output()
	if len(version) == 0 {
		return "macOS"
	}
	return strings.TrimSpace(string(name)) + " " + strings.TrimSpace(string(version)) + " (build " + strings.TrimSpace(string(build)) + ")"
}

var bootSec = regexp.MustCompile(`sec = (\d+)`)

func uptimeSeconds() int64 {
	out, err := exec.Command("/usr/sbin/sysctl", "-n", "kern.boottime").Output()
	if err != nil {
		return 0
	}
	m := bootSec.FindSubmatch(out)
	if m == nil {
		return 0
	}
	sec, err := strconv.ParseInt(string(m[1]), 10, 64)
	if err != nil {
		return 0
	}
	return int64(time.Since(time.Unix(sec, 0)).Seconds())
}
