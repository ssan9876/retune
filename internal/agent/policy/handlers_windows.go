//go:build windows

package policy

// DefaultHandlers are the setting kinds this agent can apply.
func DefaultHandlers(escrow Escrower) []Handler {
	return Handlers(Options{PowerShell: RunPowerShell, Escrow: escrow})
}
