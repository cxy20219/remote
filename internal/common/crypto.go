package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"sync"
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

func NewCryptoContext(sharedKey string) (*CryptoContext, error) {
	if sharedKey == "" {
		return nil, fmt.Errorf("shared key is empty, cannot initialize encryption")
	}

	hash := sha256.Sum256([]byte(sharedKey + "goremote-tunnel-v1"))
	key := hash[:]

	return NewCryptoContextFromKey(key)
}

func (cc *CryptoContext) Encrypt(plaintext []byte) (string, error) {
	ciphertext, err := cc.EncryptBytes(plaintext)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (cc *CryptoContext) EncryptBytes(plaintext []byte) ([]byte, error) {
	if cc == nil {
		return nil, fmt.Errorf("crypto context is nil")
	}

	nonceSize := cc.gcm.NonceSize()
	out := make([]byte, nonceSize, nonceSize+len(plaintext)+cc.gcm.Overhead())
	nonce := out[:nonceSize]
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	return cc.gcm.Seal(out, nonce, plaintext, nil), nil
}

func (cc *CryptoContext) Decrypt(encoded string) ([]byte, error) {
	if cc == nil {
		return nil, fmt.Errorf("crypto context is nil")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	return cc.DecryptBytes(ciphertext)
}

func (cc *CryptoContext) DecryptBytes(ciphertext []byte) ([]byte, error) {
	if cc == nil {
		return nil, fmt.Errorf("crypto context is nil")
	}

	nonceSize := cc.gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short: %d bytes (min %d)", len(ciphertext), nonceSize)
	}

	nonce, encrypted := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := cc.gcm.Open(nil, nonce, encrypted, nil)
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

func (cm *CryptoManager) Encrypt(clientID string, plaintext []byte) (string, error) {
	cm.mu.RLock()
	ctx, ok := cm.keys[clientID]
	cm.mu.RUnlock()

	if !ok || ctx == nil {
		return "", fmt.Errorf("encryption key not found for client: %s", clientID)
	}

	return ctx.Encrypt(plaintext)
}

func (cm *CryptoManager) EncryptBytes(clientID string, plaintext []byte) ([]byte, error) {
	cm.mu.RLock()
	ctx, ok := cm.keys[clientID]
	cm.mu.RUnlock()

	if !ok || ctx == nil {
		return nil, fmt.Errorf("encryption key not found for client: %s", clientID)
	}

	return ctx.EncryptBytes(plaintext)
}

func (cm *CryptoManager) Decrypt(clientID string, encoded string) ([]byte, error) {
	cm.mu.RLock()
	ctx, ok := cm.keys[clientID]
	cm.mu.RUnlock()

	if !ok || ctx == nil {
		return nil, fmt.Errorf("encryption key not found for client: %s", clientID)
	}

	return ctx.Decrypt(encoded)
}

func (cm *CryptoManager) DecryptBytes(clientID string, ciphertext []byte) ([]byte, error) {
	cm.mu.RLock()
	ctx, ok := cm.keys[clientID]
	cm.mu.RUnlock()

	if !ok || ctx == nil {
		return nil, fmt.Errorf("encryption key not found for client: %s", clientID)
	}

	return ctx.DecryptBytes(ciphertext)
}

func (cm *CryptoManager) HasKey(clientID string) bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	_, ok := cm.keys[clientID]
	return ok
}
