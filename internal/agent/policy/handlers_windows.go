//go:build windows

package policy

// DefaultHandlers are the setting kinds this agent can apply.
func DefaultHandlers() []Handler {
	return []Handler{RegistryHandler{}, ServiceHandler{}, GroupHandler{}, FileHandler{}}
}
