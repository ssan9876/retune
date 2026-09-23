package policy

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ErrLinkInPath is returned when a file setting's path runs through a link.
var ErrLinkInPath = errors.New("the path goes through a link")

// checkNoLinks refuses a path any existing part of which is a symbolic link,
// a junction or another reparse point. The agent reads, writes and deletes
// these paths as SYSTEM; a link planted by someone who can write to one of
// the folders on the way would otherwise turn a profile's harmless path into
// a write anywhere on the machine.
//
// Go reports symbolic links as ModeSymlink and, from Go 1.23, junctions and
// other reparse points as ModeIrregular, so both are checked. A part that
// doesn't exist ends the walk: nothing below it can be a link yet.
func checkNoLinks(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	vol := filepath.VolumeName(abs)
	rest := strings.TrimPrefix(abs[len(vol):], string(filepath.Separator))
	current := vol + string(filepath.Separator)
	if rest == "" {
		return nil
	}
	for _, part := range strings.Split(rest, string(filepath.Separator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
			return fmt.Errorf("%w: %s is a link (a junction or symbolic link), so Retune won't write through it", ErrLinkInPath, current)
		}
	}
	return nil
}
