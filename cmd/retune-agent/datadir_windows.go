//go:build windows

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
)

// secureDataDir makes the agent's data directory belong to SYSTEM and
// Administrators and nobody else, because it holds the enrollment token, the
// device key and the builds the service runs as LocalSystem.
//
// Granting those two full control is not enough on its own. A standard user
// may create folders under C:\ProgramData, so one who gets there first owns
// the directory - and an owner can always rewrite its permissions, keeps any
// entries they added directly, and can have left files, links or junctions
// inside it. So:
//
//   - a directory already there whose owner is not trusted is moved aside
//     (kept, for whoever investigates) and a fresh one made in its place;
//   - the directory's owner becomes Administrators, and its access list is
//     replaced outright and protected from inheritance: SYSTEM and
//     Administrators, full control, and nothing else;
//   - everything inside is reset to inherit that list alone, and anything
//     that is a link or junction is deleted rather than followed, so a
//     planted junction cannot turn the reset onto files elsewhere.
//
// It creates the directory if needed and is safe to repeat: every path that
// writes something sensitive there calls it, usually on a directory an
// earlier run already secured.
func secureDataDir(dir string) error {
	switch info, err := os.Lstat(dir); {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return err
	case !info.IsDir() || isLink(info):
		if err := quarantine(dir); err != nil {
			return err
		}
	default:
		trusted, err := trustedOwner(dir)
		if err != nil {
			return err
		}
		if !trusted {
			if err := quarantine(dir); err != nil {
				return err
			}
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}

	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	full := func(sid *windows.SID) windows.EXPLICIT_ACCESS {
		return windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{
				TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		}
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{full(system), full(admins)}, nil)
	if err != nil {
		return err
	}
	// Administrators rather than SYSTEM as the owner: both an elevated admin
	// running enroll and the LocalSystem service carry that group with the
	// right to own objects, whereas making SYSTEM the owner from an admin's
	// prompt needs a privilege that is not enabled by default.
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		admins, nil, acl, nil); err != nil {
		return fmt.Errorf("restrict permissions on %s: %w", dir, err)
	}

	// Each entry inside gets SYSTEM and Administrators explicitly, and
	// inherits the directory's list besides. Replacing its list outright is
	// what removes anything somebody granted on it directly. (An empty list
	// would say the same with less, but ACLFromEntries cannot build one.)
	own := func(sid *windows.SID) windows.EXPLICIT_ACCESS {
		e := full(sid)
		e.Inheritance = windows.NO_INHERITANCE
		return e
	}
	childACL, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{own(system), own(admins)}, nil)
	if err != nil {
		return err
	}
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == dir {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if isLink(info) {
			// Removing a link or junction removes the link, never what it
			// points at.
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("remove the link %s: %w", path, err)
			}
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		// Replaced, and unprotected so the directory's list is inherited too:
		// whatever was set on this entry directly is gone.
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION,
			admins, nil, childACL, nil); err != nil {
			return fmt.Errorf("reset permissions on %s: %w", path, err)
		}
		return nil
	})
}

// isLink reports a symbolic link, or a junction or other reparse point, which
// Go reports as irregular.
func isLink(info fs.FileInfo) bool {
	return info.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0
}

// trustedOwner reports whether dir is owned by SYSTEM, Administrators, or the
// elevated account running this - which is to say, not by somebody who could
// have prepared it for us.
func trustedOwner(dir string) (bool, error) {
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false, fmt.Errorf("read the owner of %s: %w", dir, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return false, err
	}
	for _, known := range []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid} {
		if owner.IsWellKnown(known) {
			return true, nil
		}
	}
	token := windows.GetCurrentProcessToken()
	if !token.IsElevated() {
		return false, nil
	}
	user, err := token.GetTokenUser()
	if err != nil {
		return false, err
	}
	return owner.Equals(user.User.Sid), nil
}

// quarantine moves a data directory that cannot be trusted out of the way,
// rather than deleting it: whoever investigates will want to see what was in
// it.
func quarantine(dir string) error {
	aside := fmt.Sprintf("%s.untrusted-%s", dir, time.Now().UTC().Format("20060102T150405Z"))
	if err := os.Rename(dir, aside); err != nil {
		return fmt.Errorf("%s is not owned by SYSTEM or Administrators and could not be moved aside: %w", dir, err)
	}
	fmt.Fprintf(os.Stderr, "retune-agent: %s was not owned by SYSTEM or Administrators; moved it to %s and started afresh\n", dir, aside)
	return nil
}
