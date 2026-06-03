package crypto

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBox(t *testing.T) {
	// Valid 32-byte key
	validKey := make([]byte, 32)
	for i := range validKey {
		validKey[i] = byte(i)
	}
	b64Key := base64.StdEncoding.EncodeToString(validKey)

	box, err := NewBox(b64Key)
	require.NoError(t, err)
	assert.NotNil(t, box)

	// Invalid length key
	shortKey := make([]byte, 31)
	b64ShortKey := base64.StdEncoding.EncodeToString(shortKey)
	_, err = NewBox(b64ShortKey)
	assert.Error(t, err)

	// Invalid base64
	_, err = NewBox("this is not valid base64")
	assert.Error(t, err)
}

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	box, err := NewBoxFromBytes(key)
	require.NoError(t, err)

	plaintext := []byte("secret message")
	aad := []byte("context")

	// 1. Successful encryption and decryption
	nonce, ciphertext, err := box.Encrypt(plaintext, aad)
	require.NoError(t, err)
	assert.NotNil(t, nonce)
	assert.NotNil(t, ciphertext)

	decrypted, err := box.Decrypt(nonce, ciphertext, aad)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	// 2. Encryption generates unique nonces and ciphertexts
	nonce2, ciphertext2, err := box.Encrypt(plaintext, aad)
	require.NoError(t, err)
	assert.False(t, bytes.Equal(nonce, nonce2), "Nonces should be random and unique")
	assert.False(t, bytes.Equal(ciphertext, ciphertext2), "Ciphertexts should be different for different nonces")

	// 3. Decryption fails with wrong AAD
	_, err = box.Decrypt(nonce, ciphertext, []byte("wrong context"))
	assert.Error(t, err, "Decryption should fail with wrong AAD")

	// 4. Decryption fails with wrong nonce
	wrongNonce := make([]byte, len(nonce))
	copy(wrongNonce, nonce)
	wrongNonce[0] ^= 0xFF
	_, err = box.Decrypt(wrongNonce, ciphertext, aad)
	assert.Error(t, err, "Decryption should fail with wrong nonce")

	// 5. Decryption fails with corrupted ciphertext
	wrongCiphertext := make([]byte, len(ciphertext))
	copy(wrongCiphertext, ciphertext)
	wrongCiphertext[0] ^= 0xFF
	_, err = box.Decrypt(nonce, wrongCiphertext, aad)
	assert.Error(t, err, "Decryption should fail with corrupted ciphertext")

	// 6. Decryption fails with wrong key
	wrongKey := make([]byte, 32)
	wrongKey[0] = 1
	wrongBox, err := NewBoxFromBytes(wrongKey)
	require.NoError(t, err)
	_, err = wrongBox.Decrypt(nonce, ciphertext, aad)
	assert.Error(t, err, "Decryption should fail with wrong key")
}
