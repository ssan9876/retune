// Package secrets holds the server key that protects data at rest, such as
// escrowed BitLocker recovery keys.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// FileName is the key file inside the data directory. It sits beside the CA
// key, which deployments are already told to back up.
const FileName = "secret.key"

// KeySize is the AES-256 key length.
const KeySize = 32

// ErrNoKey is returned when a key was expected to be supplied and was not.
var ErrNoKey = errors.New("no server secret key")

// Key is the symmetric key protecting data at rest.
type Key struct {
	aead cipher.AEAD
	// mac is a separate key derived from the same secret, for MACs.
	mac []byte
}

// LoadOrCreateFile reads the key from dir, creating one on first use.
//
// Losing this file makes every escrowed recovery key unreadable, which is why
// it lives in the same directory as the certificate authority.
func LoadOrCreateFile(dir string) (*Key, error) {
	path := filepath.Join(dir, FileName)
	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		fresh := make([]byte, KeySize)
		if _, err := rand.Read(fresh); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		// O_EXCL so two servers starting at once cannot each write a key and
		// leave one of them unable to read what the other encrypted.
		fh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			if errors.Is(err, fs.ErrExist) {
				return LoadOrCreateFile(dir)
			}
			return nil, err
		}
		if _, err := fh.WriteString(hex.EncodeToString(fresh)); err != nil {
			fh.Close()
			return nil, err
		}
		if err := fh.Close(); err != nil {
			return nil, err
		}
		return newKey(fresh)
	case err != nil:
		return nil, err
	}
	return parse(strings.TrimSpace(string(raw)))
}

// LoadFile reads the key from dir, failing if there is none. Commands run
// beside the server use it, so that one pointed at the wrong directory
// reports that rather than making a key the server doesn't have.
func LoadFile(dir string) (*Key, error) {
	raw, err := os.ReadFile(filepath.Join(dir, FileName))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: no %s in %s", ErrNoKey, FileName, dir)
	}
	if err != nil {
		return nil, err
	}
	return parse(strings.TrimSpace(string(raw)))
}

// Generate makes a new random key, returning it and its hex form, which is
// what a key file or SECRET_KEY holds.
func Generate() (*Key, string, error) {
	raw := make([]byte, KeySize)
	if _, err := rand.Read(raw); err != nil {
		return nil, "", err
	}
	k, err := newKey(raw)
	return k, hex.EncodeToString(raw), err
}

// WriteNew writes a key's hex form to a file that must not already exist,
// readable by its owner only.
func WriteNew(path, hexKey string) error {
	fh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := fh.WriteString(hexKey); err != nil {
		fh.Close()
		return err
	}
	return fh.Close()
}

// FromHex builds a key from a hex string, for deployments that supply it
// through the environment rather than a file.
func FromHex(value string) (*Key, error) {
	if strings.TrimSpace(value) == "" {
		return nil, ErrNoKey
	}
	return parse(strings.TrimSpace(value))
}

func parse(value string) (*Key, error) {
	raw, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("the server secret key is not valid hex: %w", err)
	}
	return newKey(raw)
}

func newKey(raw []byte) (*Key, error) {
	if len(raw) != KeySize {
		return nil, fmt.Errorf("the server secret key must be %d bytes, got %d", KeySize, len(raw))
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	mac := sha256.Sum256(append([]byte("retune-mac-v1\x00"), raw...))
	return &Key{aead: aead, mac: mac[:]}, nil
}

// Seal encrypts plaintext, returning the ciphertext and the nonce it used.
// context is authenticated but not stored, so a ciphertext moved to a different
// device or volume will not decrypt.
func (k *Key) Seal(plaintext, context []byte) (ciphertext, nonce []byte, err error) {
	nonce = make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return k.aead.Seal(nil, nonce, plaintext, context), nonce, nil
}

// Open decrypts what Seal produced.
func (k *Key) Open(ciphertext, nonce, context []byte) ([]byte, error) {
	// GCM panics on a nonce of the wrong size; a stored value can be
	// damaged or missing, and that is an error, not a crash.
	if len(nonce) != k.aead.NonceSize() {
		return nil, errors.New("the stored value is damaged: its nonce is the wrong size")
	}
	plaintext, err := k.aead.Open(nil, nonce, ciphertext, context)
	if err != nil {
		return nil, errors.New("the stored value could not be decrypted with this server's key")
	}
	return plaintext, nil
}

// MAC is a keyed hash of data in context: equal for equal inputs, and
// useless to anyone without the key - so it can say whether a secret changed
// without letting a stolen database be used to guess it.
func (k *Key) MAC(data, context []byte) []byte {
	h := hmac.New(sha256.New, k.mac)
	h.Write(context)
	h.Write([]byte{0})
	h.Write(data)
	return h.Sum(nil)
}
