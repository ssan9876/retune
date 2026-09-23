//go:build windows

package executor

import (
	"context"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// LocalAccounts changes local account passwords through the Windows network
// management API, in process: the password never appears on a command line
// or in a script a log could capture.
type LocalAccounts struct{}

var procNetUserSetInfo = windows.NewLazySystemDLL("netapi32.dll").NewProc("NetUserSetInfo")

// BuiltinAdmin finds the account whose SID is the machine's plus RID 500.
func (LocalAccounts) BuiltinAdmin(context.Context) (string, error) {
	computer, err := windows.ComputerName()
	if err != nil {
		return "", err
	}
	machine, _, _, err := windows.LookupSID("", computer)
	if err != nil {
		return "", fmt.Errorf("look up the machine SID: %w", err)
	}
	sid, err := windows.StringToSid(machine.String() + "-500")
	if err != nil {
		return "", err
	}
	name, _, _, err := sid.LookupAccount("")
	if err != nil {
		return "", fmt.Errorf("look up RID 500: %w", err)
	}
	return name, nil
}

// userInfo1003 is USER_INFO_1003: just a password.
type userInfo1003 struct {
	password *uint16
}

func (LocalAccounts) SetPassword(_ context.Context, account, password string) error {
	name, err := windows.UTF16PtrFromString(account)
	if err != nil {
		return err
	}
	pw, err := windows.UTF16FromString(password)
	if err != nil {
		return err
	}
	defer clear(pw)
	info := userInfo1003{password: &pw[0]}
	var parmErr uint32
	r, _, _ := procNetUserSetInfo.Call(0, uintptr(unsafe.Pointer(name)), 1003,
		uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parmErr)))
	if r != 0 {
		return fmt.Errorf("NetUserSetInfo: %w", syscall.Errno(r))
	}
	return nil
}

// DefaultPasswords is the real password setter.
func DefaultPasswords() PasswordSetter { return LocalAccounts{} }
