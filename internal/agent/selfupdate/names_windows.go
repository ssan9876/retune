//go:build windows

package selfupdate

// BinName is the executable staged under each version's directory. It is
// what the supervisor repoints the service at, and what a restored service
// runs again after a rollback.
const BinName = "retune-agent.exe"

// supervisorName is the copy of the running agent that carries out the
// update. It has to be a copy: the service's own image is locked and is
// about to be stopped, so nothing can run straight out of it.
const supervisorName = "supervisor.exe"
