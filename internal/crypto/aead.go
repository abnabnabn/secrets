// Package crypto provides a simplified interface for XChaCha20-Poly1305 encryption.
// XChaCha20-Poly1305 is used for its large 192-bit nonce, making it safe for
// random nonce generation without risk of collisions.
package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

// Box handles authenticated encryption and decryption of payloads.
type Box struct {
	aead cipher.AEAD
}

// NewBox creates a new encryption box from a base64 encoded 32-byte key.
func NewBox(b64Key string) (*Box, error) {
	key, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil || len(key) != 32 {
		return nil, errors.New("key must be exactly 32 bytes in base64")
	}
	return NewBoxFromBytes(key)
}

// NewBoxFromBytes creates a new encryption box from a raw 32-byte key.
func NewBoxFromBytes(key []byte) (*Box, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be exactly 32 bytes")
	}
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return &Box{aead: a}, nil
}

// Encrypt generates a random nonce and encrypts the plaintext with optional
// Authenticated Additional Data (AAD). It returns the nonce and ciphertext.
func (b *Box) Encrypt(plaintext, AAD []byte) (nonce []byte, ciphertext []byte, err error) {
	nonce = make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = b.aead.Seal(nil, nonce, plaintext, AAD)
	return nonce, ciphertext, nil
}

// Decrypt verifies the authenticity of the ciphertext using the nonce and AAD,
// then returns the original plaintext.
func (b *Box) Decrypt(nonce, ciphertext, AAD []byte) ([]byte, error) {
	return b.aead.Open(nil, nonce, ciphertext, AAD)
}
