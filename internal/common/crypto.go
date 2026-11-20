package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"sync"
)

const (
	// TunnelEncryptionOverhead is the number of extra bytes added to a
	// plaintext chunk by tunnel encryption: the AES-GCM nonce plus tag.
	TunnelEncryptionOverhead = 12 + 16
)

type CryptoContext struct {
	gcm cipher.AEAD
}

func NewCryptoContextFromKey(key []byte) (*CryptoContext, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}

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

// EncryptTo seals plaintext into dst's spare capacity and returns the
// nonce-prefixed ciphertext. Reusing the destination buffer avoids one full
// copy of every tunnel chunk.
func (cc *CryptoContext) EncryptTo(dst, plaintext []byte) ([]byte, error) {
	if cc == nil {
		return nil, fmt.Errorf("crypto context is nil")
	}

	nonceSize := cc.gcm.NonceSize()
	need := nonceSize + len(plaintext) + cc.gcm.Overhead()
	if cap(dst) < need {
		dst = make([]byte, nonceSize, need)
	} else {
		dst = dst[:nonceSize]
	}

	if _, err := io.ReadFull(rand.Reader, dst); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	return cc.gcm.Seal(dst, dst, plaintext, nil), nil
}

func (cc *CryptoContext) DecryptBytes(ciphertext []byte) ([]byte, error) {
	return cc.DecryptTo(nil, ciphertext)
}

// DecryptTo opens ciphertext into dst's spare capacity.
func (cc *CryptoContext) DecryptTo(dst, ciphertext []byte) ([]byte, error) {
	if cc == nil {
		return nil, fmt.Errorf("crypto context is nil")
	}

	nonceSize := cc.gcm.NonceSize()
	if len(ciphertext) < nonceSize+cc.gcm.Overhead() {
		return nil, fmt.Errorf("ciphertext too short: %d bytes", len(ciphertext))
	}

	plaintextLen := len(ciphertext) - nonceSize - cc.gcm.Overhead()
	if cap(dst) < plaintextLen {
		dst = make([]byte, 0, plaintextLen)
	} else {
		dst = dst[:0]
	}

	nonce, encrypted := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := cc.gcm.Open(dst, nonce, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}

type CryptoManager struct {
	mu   sync.RWMutex
	keys map[string]*CryptoContext
}

func NewCryptoManager() *CryptoManager {
	return &CryptoManager{
		keys: make(map[string]*CryptoContext),
	}
}

func (cm *CryptoManager) SetKey(clientID string, key []byte) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	ctx, err := NewCryptoContextFromKey(key)
	if err != nil {
		return err
	}
	cm.keys[clientID] = ctx
	return nil
}

func (cm *CryptoManager) RemoveKey(clientID string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	delete(cm.keys, clientID)
}

// EncryptTo encrypts plaintext into dst's spare capacity.
func (cm *CryptoManager) EncryptTo(clientID string, dst, plaintext []byte) ([]byte, error) {
	ctx, err := cm.context(clientID)
	if err != nil {
		return nil, err
	}
	return ctx.EncryptTo(dst, plaintext)
}

func (cm *CryptoManager) DecryptBytes(clientID string, ciphertext []byte) ([]byte, error) {
	ctx, err := cm.context(clientID)
	if err != nil {
		return nil, err
	}
	return ctx.DecryptBytes(ciphertext)
}

func (cm *CryptoManager) context(clientID string) (*CryptoContext, error) {
	cm.mu.RLock()
	ctx, ok := cm.keys[clientID]
	cm.mu.RUnlock()

	if !ok || ctx == nil {
		return nil, fmt.Errorf("encryption key not found for client: %s", clientID)
	}
	return ctx, nil
}

func (cm *CryptoManager) HasKey(clientID string) bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	_, ok := cm.keys[clientID]
	return ok
}
