package policy

// Options configure the handler set an agent uses.
type Options struct {
	// PowerShell runs scripts for the handlers that need it. Nil away from
	// Windows, where those handlers report that plainly.
	PowerShell PowerShell
	// Escrow sends BitLocker recovery keys to the server.
	Escrow Escrower
}

// Handlers builds the full set of setting handlers.
func Handlers(opts Options) []Handler {
	return []Handler{
		RegistryHandler{},
		ServiceHandler{},
		GroupHandler{},
		FileHandler{},
		WindowsUpdateHandler{},
		FirewallProfileHandler{Run: opts.PowerShell},
		FirewallRuleHandler{Run: opts.PowerShell},
		BitLockerHandler{Run: opts.PowerShell, Escrow: opts.Escrow},
	}
}
