//go:build !windows

package apps

import "errors"

// ErrNoPackageSupport is why uploaded packages can't be installed off
// Windows: they are MSI and EXE installers.
var ErrNoPackageSupport = errors.New("uploaded MSI and EXE packages install only on Windows")

// NewPackages returns ErrNoPackageSupport off Windows.
func NewPackages(string, PackageDownloader) (*Packages, error) { return nil, ErrNoPackageSupport }
