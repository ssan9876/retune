package policy

// Options configure the handler set an agent uses.
type Options struct {
	// PowerShell runs scripts for the handlers that need it. Nil away from
	// Windows, where those handlers report that plainly.
	PowerShell PowerShell
	// Escrow sends BitLocker recovery keys to the server.
	Escrow Escrower
	// Netsh runs netsh, for Wi-Fi. Nil away from Windows.
	Netsh Netsh
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
		DefenderHandler{Run: opts.PowerShell},
		CertificateHandler{Run: opts.PowerShell},
		WiFiHandler{Run: opts.Netsh},
		VPNHandler{Run: opts.PowerShell},
	}
}
