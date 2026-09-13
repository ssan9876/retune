package ca

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// ErrNotExist is returned by KeyStore.Load when no CA has been saved yet.
var ErrNotExist = errors.New("CA material does not exist")

// KeyStore persists the CA certificate and private key. Cloud deployments
// will add secret-manager/KMS implementations.
type KeyStore interface {
	Load(ctx context.Context) (certPEM, keyPEM []byte, err error)
	Save(ctx context.Context, certPEM, keyPEM []byte) error
}

// FileKeyStore stores ca.crt and ca.key in Dir.
type FileKeyStore struct {
	Dir string
}

func (f FileKeyStore) Load(ctx context.Context) ([]byte, []byte, error) {
	certPEM, err := os.ReadFile(filepath.Join(f.Dir, "ca.crt"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, ErrNotExist
	}
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(f.Dir, "ca.key"))
	if err != nil {
		return nil, nil, err
	}
	return certPEM, keyPEM, nil
}

// Save writes the key first and refuses to overwrite an existing key.
func (f FileKeyStore) Save(ctx context.Context, certPEM, keyPEM []byte) error {
	if err := os.MkdirAll(f.Dir, 0o700); err != nil {
		return err
	}
	if err := writeNew(filepath.Join(f.Dir, "ca.key"), keyPEM, 0o600); err != nil {
		return err
	}
	return writeNew(filepath.Join(f.Dir, "ca.crt"), certPEM, 0o644)
}

// EnvKeyStore reads the CA from configuration supplied by the environment,
// for deployments with no persistent disk. It cannot create a CA: one that is
// generated on boot and lost on the next restart would orphan every enrolled
// device, so an operator must generate the material and supply it.
type EnvKeyStore struct {
	CertPEM string
	KeyPEM  string
}

func (e EnvKeyStore) Load(ctx context.Context) ([]byte, []byte, error) {
	if e.CertPEM == "" || e.KeyPEM == "" {
		return nil, nil, errors.New(
			"CA_KEY_SOURCE=env requires both CA_CERT_PEM and CA_KEY_PEM; " +
				"generate them once with a file-backed server and copy them in")
	}
	return []byte(e.CertPEM), []byte(e.KeyPEM), nil
}

func (e EnvKeyStore) Save(ctx context.Context, certPEM, keyPEM []byte) error {
	return errors.New("CA_KEY_SOURCE=env cannot create a certificate authority; " +
		"set CA_CERT_PEM and CA_KEY_PEM to material you already have")
}

func writeNew(path string, data []byte, perm os.FileMode) error {
	fh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := fh.Write(data); err != nil {
		fh.Close()
		return err
	}
	return fh.Close()
}
