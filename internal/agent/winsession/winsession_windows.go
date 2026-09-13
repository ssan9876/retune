//go:build windows

// Package winsession runs work in the signed-in user's session, and finds that
// user's registry hive.
//
// Everything here needs the process to be LocalSystem: taking a user's token is
// a privileged act, and a service is the only thing that can do it. From an
// ordinary administrator prompt these calls fail with access denied, which is
// the correct answer rather than a bug.
package winsession

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ErrNoSession is returned when nobody is signed in at the console.
var ErrNoSession = errors.New("nobody is signed in")

// MaxScriptBytes caps a script run in a user's session. The script travels on
// the command line as an encoded command, because a file under the agent's own
// directory would not be readable by an ordinary user, and Windows caps a
// command line at about 32,000 characters.
const MaxScriptBytes = 8 << 10

// noSession is what WTSGetActiveConsoleSessionId returns when there is no
// console session at all.
const noSession = 0xFFFFFFFF

// User describes who is signed in.
type User struct {
	SessionID uint32
	// Name is DOMAIN\user, for logs and diagnostics.
	Name string
	// SID identifies the account, and names its registry hive.
	SID string
}

// Active returns the user signed in at the console, if there is one.
func Active() (User, error) {
	id := windows.WTSGetActiveConsoleSessionId()
	if id == noSession {
		return User{}, ErrNoSession
	}
	token, err := userToken(id)
	if err != nil {
		return User{}, err
	}
	defer token.Close()

	name, sid, err := identify(token)
	if err != nil {
		return User{}, err
	}
	return User{SessionID: id, Name: name, SID: sid}, nil
}

// userToken opens the token of whoever is signed in to a session. A session
// with no user reports that plainly rather than as an unexplained failure.
func userToken(sessionID uint32) (windows.Token, error) {
	var token windows.Token
	if err := windows.WTSQueryUserToken(sessionID, &token); err != nil {
		if errors.Is(err, windows.ERROR_NO_TOKEN) {
			return 0, ErrNoSession
		}
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return 0, fmt.Errorf("%w (this needs to run as the system account)", err)
		}
		return 0, err
	}
	return token, nil
}

func identify(token windows.Token) (name, sid string, err error) {
	user, err := token.GetTokenUser()
	if err != nil {
		return "", "", err
	}
	sid = user.User.Sid.String()
	account, domain, _, err := user.User.Sid.LookupAccount("")
	if err != nil {
		// The SID is enough to find the hive; the name is only for reading.
		return sid, sid, nil
	}
	if domain != "" {
		return domain + `\` + account, sid, nil
	}
	return account, sid, nil
}

// HiveSID returns the registry hive name of the signed-in user, which is their
// SID under HKEY_USERS.
func HiveSID() (string, error) {
	user, err := Active()
	if err != nil {
		return "", err
	}
	return user.SID, nil
}

// RunPowerShell runs a script as the signed-in user and captures its output.
func RunPowerShell(ctx context.Context, script string, stdout, stderr io.Writer) (int, error) {
	if len(script) > MaxScriptBytes {
		return -1, fmt.Errorf("a script run as the signed-in user may be at most %d bytes", MaxScriptBytes)
	}
	id := windows.WTSGetActiveConsoleSessionId()
	if id == noSession {
		return -1, ErrNoSession
	}
	token, err := userToken(id)
	if err != nil {
		return -1, err
	}
	defer token.Close()

	// A primary token is what CreateProcessAsUser needs; the one WTS hands back
	// is already primary, but duplicating it gives a handle this process owns
	// outright and can safely close.
	var primary windows.Token
	err = windows.DuplicateTokenEx(token, windows.MAXIMUM_ALLOWED, nil,
		windows.SecurityImpersonation, windows.TokenPrimary, &primary)
	if err != nil {
		return -1, fmt.Errorf("duplicate the user token: %w", err)
	}
	defer primary.Close()

	return run(ctx, primary, command(script), stdout, stderr)
}

// command builds the PowerShell command line. The script is passed encoded
// rather than as a file, because a file under the agent's directory is not
// readable by an ordinary user.
func command(script string) string {
	encoded := base64.StdEncoding.EncodeToString(utf16le(script))
	return `powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ` + encoded
}

// utf16le encodes text the way -EncodedCommand expects.
func utf16le(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(units)*2)
	for _, u := range units {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

func run(ctx context.Context, token windows.Token, commandLine string, stdout, stderr io.Writer) (int, error) {
	outRead, outWrite, err := inheritablePipe()
	if err != nil {
		return -1, err
	}
	defer windows.CloseHandle(outRead)
	errRead, errWrite, err := inheritablePipe()
	if err != nil {
		windows.CloseHandle(outWrite)
		return -1, err
	}
	defer windows.CloseHandle(errRead)

	var env *uint16
	if err := windows.CreateEnvironmentBlock(&env, token, false); err != nil {
		windows.CloseHandle(outWrite)
		windows.CloseHandle(errWrite)
		return -1, fmt.Errorf("build the user environment: %w", err)
	}
	defer windows.DestroyEnvironmentBlock(env)

	si := windows.StartupInfo{
		Cb: uint32(unsafe.Sizeof(windows.StartupInfo{})),
		// The interactive desktop, so anything the script shows can appear.
		Desktop:    windows.StringToUTF16Ptr(`winsta0\default`),
		Flags:      windows.STARTF_USESTDHANDLES | windows.STARTF_USESHOWWINDOW,
		ShowWindow: windows.SW_HIDE,
		StdOutput:  outWrite,
		StdErr:     errWrite,
	}
	var pi windows.ProcessInformation

	cmd, err := windows.UTF16PtrFromString(commandLine)
	if err != nil {
		return -1, err
	}
	err = windows.CreateProcessAsUser(token, nil, cmd, nil, nil, true,
		windows.CREATE_UNICODE_ENVIRONMENT|windows.CREATE_NO_WINDOW,
		env, nil, &si, &pi)

	// The child owns its ends now; this process must let go or the reads below
	// never see end-of-file.
	windows.CloseHandle(outWrite)
	windows.CloseHandle(errWrite)
	if err != nil {
		return -1, fmt.Errorf("start the process as the signed-in user: %w", err)
	}
	defer windows.CloseHandle(pi.Thread)
	defer windows.CloseHandle(pi.Process)

	done := make(chan struct{})
	go func() {
		defer close(done)
		copyAll(stdout, outRead)
	}()
	copyAll(stderr, errRead)
	<-done

	return wait(ctx, pi.Process)
}

func copyAll(dst io.Writer, handle windows.Handle) {
	file := newFile(handle)
	defer file.Close()
	_, _ = io.Copy(dst, file)
}

// wait blocks until the process exits, or the context is done, in which case it
// is killed rather than left running in someone's session.
func wait(ctx context.Context, process windows.Handle) (int, error) {
	for {
		event, err := windows.WaitForSingleObject(process, 200)
		if err != nil {
			return -1, err
		}
		if event == uint32(windows.WAIT_OBJECT_0) {
			var code uint32
			if err := windows.GetExitCodeProcess(process, &code); err != nil {
				return -1, err
			}
			return int(code), nil
		}
		select {
		case <-ctx.Done():
			_ = windows.TerminateProcess(process, 1)
			return -1, ctx.Err()
		default:
		}
	}
}

// inheritablePipe returns a pipe whose write end the child inherits and whose
// read end it does not.
func inheritablePipe() (read, write windows.Handle, err error) {
	sa := windows.SecurityAttributes{InheritHandle: 1}
	sa.Length = uint32(unsafe.Sizeof(sa))
	if err := windows.CreatePipe(&read, &write, &sa, 0); err != nil {
		return 0, 0, err
	}
	if err := windows.SetHandleInformation(read, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		windows.CloseHandle(read)
		windows.CloseHandle(write)
		return 0, 0, err
	}
	return read, write, nil
}

// Available reports whether this process can act in a user's session, and says
// why not when it cannot.
func Available() (bool, string) {
	user, err := Active()
	switch {
	case errors.Is(err, ErrNoSession):
		return false, "nobody is signed in"
	case err != nil:
		return false, strings.TrimSpace(err.Error())
	}
	_ = user
	return true, ""
}

// newFile wraps a handle so it can be read with the standard library.
func newFile(handle windows.Handle) *osFile {
	return &osFile{handle: handle}
}

// osFile is the minimum needed to read a pipe to end-of-file.
type osFile struct {
	handle windows.Handle
	closed bool
}

func (f *osFile) Read(p []byte) (int, error) {
	if f.closed {
		return 0, io.EOF
	}
	var read uint32
	err := windows.ReadFile(f.handle, p, &read, nil)
	switch {
	case errors.Is(err, windows.ERROR_BROKEN_PIPE):
		return 0, io.EOF
	case err != nil:
		return 0, err
	case read == 0:
		return 0, io.EOF
	}
	return int(read), nil
}

func (f *osFile) Close() error {
	f.closed = true
	return nil
}
