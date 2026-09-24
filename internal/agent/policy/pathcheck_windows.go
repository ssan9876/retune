package policy

import "io/fs"

// trustedSystemLink trusts no link on Windows, where the system has none on
// the paths profiles write to.
func trustedSystemLink(string, fs.FileInfo) bool { return false }
