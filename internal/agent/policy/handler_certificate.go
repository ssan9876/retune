package policy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"retune/internal/protocol"
)

// CertificateHandler puts a certificate into a LocalMachine store through
// PowerShell's certificate provider. It only ever adds or removes the one
// certificate a setting names, by thumbprint.
type CertificateHandler struct {
	Run PowerShell
	// TempDir is where the certificate is written for Import-Certificate;
	// empty uses the system's.
	TempDir string
}

func (CertificateHandler) Kind() string { return protocol.KindCertificate }

func (h CertificateHandler) run(ctx context.Context, script string) (string, error) {
	if h.Run == nil {
		return "", errors.New("certificate settings are only supported on Windows")
	}
	return h.Run(ctx, script)
}

// target is the store path and thumbprint of a setting's certificate, both
// safe to put in a script: the store comes from a fixed table and the
// thumbprint is hex.
func target(s protocol.Setting) (path, thumbprint string, der []byte, err error) {
	store, ok := protocol.CertificateStores[s.Store]
	if !ok {
		return "", "", nil, fmt.Errorf("unknown certificate store %q", s.Store)
	}
	_, der, err = protocol.ParseCertificatePEM(s.CertificatePEM)
	if err != nil {
		return "", "", nil, err
	}
	return `Cert:\LocalMachine\` + store, protocol.Thumbprint(der), der, nil
}

func (h CertificateHandler) present(ctx context.Context, s protocol.Setting) (bool, error) {
	path, thumb, _, err := target(s)
	if err != nil {
		return false, err
	}
	out, err := h.run(ctx, "Test-Path -LiteralPath '"+path+`\`+thumb+"'")
	if err != nil {
		return false, err
	}
	return strings.EqualFold(strings.TrimSpace(out), "True"), nil
}

// Get records whether the certificate was already there, which is what
// decides whether a revert removes it.
func (h CertificateHandler) Get(ctx context.Context, s protocol.Setting) (State, error) {
	ok, err := h.present(ctx, s)
	return State{Exists: ok}, err
}

func (h CertificateHandler) Test(ctx context.Context, s protocol.Setting) (bool, error) {
	return h.present(ctx, s)
}

func (h CertificateHandler) Set(ctx context.Context, s protocol.Setting) error {
	path, _, der, err := target(s)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(h.TempDir, "retune-cert-*.cer")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err := f.Write(der); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	_, err = h.run(ctx, "Import-Certificate -FilePath '"+strings.ReplaceAll(name, "'", "''")+
		"' -CertStoreLocation '"+path+"' | Out-Null")
	return err
}

// Revert removes the certificate, unless it was there before the setting
// first applied: then it was never Retune's to take away.
func (h CertificateHandler) Revert(ctx context.Context, s protocol.Setting, prior State) error {
	if prior.Exists {
		return nil
	}
	path, thumb, _, err := target(s)
	if err != nil {
		return err
	}
	_, err = h.run(ctx, "Remove-Item -LiteralPath '"+path+`\`+thumb+"' -ErrorAction SilentlyContinue")
	return err
}
