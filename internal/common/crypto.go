package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
)

// CryptoContext provides AES-256-GCM encryption/decryption for tunnel data.
// The encryption key is derived from the shared auth key using SHA-256.
type CryptoContext struct {
	gcm cipher.AEAD
}

// NewCryptoContext derives an AES-256-GCM key from the shared auth key using SHA-256.
// Returns nil if sharedKey is empty (encryption disabled).
func NewCryptoContext(sharedKey string) (*CryptoContext, error) {
	if sharedKey == "" {
		return nil, fmt.Errorf("shared key is empty, cannot initialize encryption")
	}

	hash := sha256.Sum256([]byte(sharedKey + "goremote-tunnel-v1"))
	key := hash[:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher init failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm init failed: %w", err)
	}

	return &CryptoContext{gcm: gcm}, nil
}

// Encrypt encrypts plaintext with AES-256-GCM and returns a base64-encoded string.
// The encoded format is: base64(nonce || ciphertext || tag)
func (cc *CryptoContext) Encrypt(plaintext []byte) (string, error) {
	if cc == nil {
		return "", fmt.Errorf("crypto context is nil")
	}

	nonce := make([]byte, cc.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := cc.gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a base64-encoded string produced by Encrypt.
func (cc *CryptoContext) Decrypt(encoded string) ([]byte, error) {
	if cc == nil {
		return nil, fmt.Errorf("crypto context is nil")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	nonceSize := cc.gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short: %d bytes (min %d)", len(ciphertext), nonceSize)
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := cc.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}
