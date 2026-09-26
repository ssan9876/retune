//go:build !windows

package selfupdate

// BinName is the executable staged under each version's directory. It is
// what the supervisor repoints the daemon at, and what a restored daemon
// runs again after a rollback.
const BinName = "retune-agent"

// supervisorName is the copy of the running agent that carries out the
// update. A copy, as on Windows: the daemon's own binary may be replaced by
// a package upgrade while the supervisor is still running out of it.
const supervisorName = "supervisor"
