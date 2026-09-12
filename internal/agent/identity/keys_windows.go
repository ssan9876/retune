//go:build windows

package identity

import (
	"bytes"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// DPAPIKeys seals data with DPAPI in machine scope, so only processes on
// this machine can unseal it; file ACLs restrict it further to SYSTEM.
type DPAPIKeys struct{}

// DefaultKeys returns the platform key provider.
func DefaultKeys() KeyProvider { return DPAPIKeys{} }

func (DPAPIKeys) Protect(plain []byte) ([]byte, error) {
	var out windows.DataBlob
	flags := uint32(windows.CRYPTPROTECT_LOCAL_MACHINE | windows.CRYPTPROTECT_UI_FORBIDDEN)
	if err := windows.CryptProtectData(blob(plain), nil, nil, 0, nil, flags, &out); err != nil {
		return nil, fmt.Errorf("CryptProtectData: %w", err)
	}
	return takeBlob(&out), nil
}

func (DPAPIKeys) Unprotect(sealed []byte) ([]byte, error) {
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(blob(sealed), nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, fmt.Errorf("CryptUnprotectData: %w", err)
	}
	return takeBlob(&out), nil
}

func blob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

// takeBlob copies a DPAPI-allocated buffer into Go memory and frees it.
func takeBlob(b *windows.DataBlob) []byte {
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(b.Data)))
	return bytes.Clone(unsafe.Slice(b.Data, b.Size))
}
