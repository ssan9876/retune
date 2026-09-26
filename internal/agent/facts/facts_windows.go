//go:build windows

package facts

import (
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func osVersion() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return "Windows"
	}
	defer k.Close()
	name, _, _ := k.GetStringValue("ProductName")
	build, _, _ := k.GetStringValue("CurrentBuild")
	return WindowsName(name, build)
}

// x/sys/windows does not wrap GetTickCount64, so call it from kernel32.
var procGetTickCount64 = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetTickCount64")

func uptimeSeconds() int64 {
	ms, _, _ := procGetTickCount64.Call()
	return int64(ms / 1000)
}
