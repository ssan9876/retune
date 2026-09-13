//go:build !windows

// Package winsession runs work in the signed-in user's session. Away from
// Windows there is no such thing, and these stubs say so rather than pretending.
package winsession

import (
	"context"
	"errors"
	"io"
)

// ErrNoSession is returned when nobody is signed in.
var ErrNoSession = errors.New("nobody is signed in")

var errWindowsOnly = errors.New("running in a user session is only supported on Windows")

// MaxScriptBytes caps a script run in a user's session.
const MaxScriptBytes = 8 << 10

// User describes who is signed in.
type User struct {
	SessionID uint32
	Name      string
	SID       string
}

func Active() (User, error) { return User{}, errWindowsOnly }

func HiveSID() (string, error) { return "", errWindowsOnly }

func RunPowerShell(context.Context, string, io.Writer, io.Writer) (int, error) {
	return -1, errWindowsOnly
}

// Available reports whether this process can act in a user's session.
func Available() (bool, string) { return false, errWindowsOnly.Error() }
