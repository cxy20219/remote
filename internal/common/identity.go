package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func GenerateSignKeypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(nil)
}

func GenerateDHKeypair() (*[32]byte, *[32]byte, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return nil, nil, fmt.Errorf("generate DH private key: %w", err)
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("compute DH public key: %w", err)
	}
	var pubArr [32]byte
	copy(pubArr[:], pub)
	return &priv, &pubArr, nil
}

func DHSharedSecret(privateKey *[32]byte, publicKey *[32]byte) ([]byte, error) {
	shared, err := curve25519.X25519(privateKey[:], publicKey[:])
	if err != nil {
		return nil, fmt.Errorf("X25519 DH: %w", err)
	}
	return shared, nil
}

func EncryptKeyWithSharedSecret(plainKey []byte, sharedSecret []byte) (string, error) {
	h := hkdf.New(sha256.New, sharedSecret, []byte("goremote-enc-key-exchange-v1"), nil)
	encKey := make([]byte, 32)
	if _, err := h.Read(encKey); err != nil {
		return "", fmt.Errorf("hkdf derive: %w", err)
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return "", fmt.Errorf("aes cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gcm: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}

	ciphertext := aead.Seal(nonce, nonce, plainKey, nil)
	return hex.EncodeToString(ciphertext), nil
}

func DecryptKeyWithSharedSecret(encHex string, sharedSecret []byte) ([]byte, error) {
	ciphertext, err := hex.DecodeString(encHex)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}

	h := hkdf.New(sha256.New, sharedSecret, []byte("goremote-enc-key-exchange-v1"), nil)
	encKey := make([]byte, 32)
	if _, err := h.Read(encKey); err != nil {
		return nil, fmt.Errorf("hkdf derive: %w", err)
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	nonceSize := aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plainKey, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plainKey, nil
}

func GenerateEncKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

func SignTimestamp(privKey ed25519.PrivateKey, clientID string, timestamp int64) ([]byte, error) {
	msg := fmt.Sprintf("%s:%d", clientID, timestamp)
	return ed25519.Sign(privKey, []byte(msg)), nil
}

func VerifyTimestamp(pubKey ed25519.PublicKey, clientID string, timestamp int64, signature []byte) bool {
	msg := fmt.Sprintf("%s:%d", clientID, timestamp)
	return ed25519.Verify(pubKey, []byte(msg), signature)
}

func IsTimestampValid(timestamp int64, maxDrift time.Duration) bool {
	now := time.Now().Unix()
	diff := now - timestamp
	if diff < 0 {
		diff = -diff
	}
	return diff <= int64(maxDrift.Seconds())
}

func EncodePrivateKey(key ed25519.PrivateKey) string {
	return hex.EncodeToString(key)
}

func DecodePrivateKey(hexStr string) (ed25519.PrivateKey, error) {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}
	return ed25519.PrivateKey(b), nil
}

func EncodePublicKey(key ed25519.PublicKey) string {
	return hex.EncodeToString(key)
}

func DecodePublicKey(hexStr string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size: %d", len(b))
	}
	return ed25519.PublicKey(b), nil
}

func EncodeBytes(b []byte) string {
	return hex.EncodeToString(b)
}

func DecodeBytes(hexStr string) ([]byte, error) {
	return hex.DecodeString(hexStr)
}