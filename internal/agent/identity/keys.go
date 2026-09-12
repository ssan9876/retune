package identity

// KeyProvider seals the agent's private key at rest.
type KeyProvider interface {
	Protect(plain []byte) ([]byte, error)
	Unprotect(sealed []byte) ([]byte, error)
}

// PlainKeys stores keys unsealed. Use only in tests and non-Windows dev builds.
type PlainKeys struct{}

func (PlainKeys) Protect(b []byte) ([]byte, error)   { return b, nil }
func (PlainKeys) Unprotect(b []byte) ([]byte, error) { return b, nil }
