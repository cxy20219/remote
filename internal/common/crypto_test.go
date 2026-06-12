package common

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func TestNewCryptoContext_ValidKey(t *testing.T) {
	cc, err := NewCryptoContext("test-secret-key")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if cc == nil {
		t.Fatal("expected non-nil CryptoContext")
	}
	if cc.gcm == nil {
		t.Fatal("expected non-nil gcm cipher")
	}
}

func TestNewCryptoContext_EmptyKey(t *testing.T) {
	cc, err := NewCryptoContext("")
	if err == nil {
		t.Fatal("expected error for empty key")
	}
	if cc != nil {
		t.Fatal("expected nil CryptoContext for empty key")
	}
}

func TestNewCryptoContext_DifferentKeys(t *testing.T) {
	cc1, _ := NewCryptoContext("key-A")
	cc2, _ := NewCryptoContext("key-B")

	if cc1 == nil || cc2 == nil {
		t.Fatal("expected non-nil contexts")
	}

	plaintext := []byte("test data")

	encoded, err := cc1.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	_, err = cc2.Decrypt(encoded)
	if err == nil {
		t.Fatal("expected decryption to fail with wrong key")
	}
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	cc, err := NewCryptoContext("my-secret-key")
	if err != nil {
		t.Fatalf("NewCryptoContext failed: %v", err)
	}

	plaintext := []byte("Hello, this is tunnel data flowing through the encrypted channel")

	encoded, err := cc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	if encoded == "" {
		t.Fatal("expected non-empty encoded string")
	}

	decoded, err := cc.Decrypt(encoded)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	if !bytes.Equal(decoded, plaintext) {
		t.Fatalf("round-trip mismatch: got %q, want %q", decoded, plaintext)
	}
}

func TestEncryptDecryptBytes_RoundTrip(t *testing.T) {
	cc, err := NewCryptoContext("my-secret-key")
	if err != nil {
		t.Fatalf("NewCryptoContext failed: %v", err)
	}

	plaintext := []byte("binary tunnel payload")
	ciphertext, err := cc.EncryptBytes(plaintext)
	if err != nil {
		t.Fatalf("EncryptBytes failed: %v", err)
	}
	if len(ciphertext) == 0 {
		t.Fatal("expected non-empty ciphertext")
	}

	decoded, err := cc.DecryptBytes(ciphertext)
	if err != nil {
		t.Fatalf("DecryptBytes failed: %v", err)
	}
	if !bytes.Equal(decoded, plaintext) {
		t.Fatalf("round-trip mismatch: got %q, want %q", decoded, plaintext)
	}
}

func TestBinaryTunnelDataFrame_RoundTrip(t *testing.T) {
	data := []byte("encrypted bytes")
	frame, err := EncodeBinaryTunnelDataFrame("tun-1", "conn-2", data, true)
	if err != nil {
		t.Fatalf("EncodeBinaryTunnelDataFrame failed: %v", err)
	}

	decoded, err := DecodeBinaryTunnelDataFrame(frame)
	if err != nil {
		t.Fatalf("DecodeBinaryTunnelDataFrame failed: %v", err)
	}
	if decoded.TunnelID != "tun-1" {
		t.Fatalf("unexpected tunnel id: %q", decoded.TunnelID)
	}
	if decoded.ConnID != "conn-2" {
		t.Fatalf("unexpected conn id: %q", decoded.ConnID)
	}
	if !decoded.IsEOF {
		t.Fatal("expected EOF flag")
	}
	if !bytes.Equal(decoded.Data, data) {
		t.Fatalf("unexpected data: %q", decoded.Data)
	}
}

func TestBinaryTunnelDataFrameRejectsUnknownFlags(t *testing.T) {
	frame, err := EncodeBinaryTunnelDataFrame("tun-1", "conn-2", []byte("data"), false)
	if err != nil {
		t.Fatalf("EncodeBinaryTunnelDataFrame failed: %v", err)
	}

	frame[1] = 0b10
	if _, err := DecodeBinaryTunnelDataFrame(frame); err == nil {
		t.Fatal("expected unknown flags to be rejected")
	}
}

func TestBinaryTunnelDataFrameRejectsInvalidLengths(t *testing.T) {
	frame := []byte{1, 0, 0, 8, 0, 0, 0, 0, 0, 0}
	if _, err := DecodeBinaryTunnelDataFrame(frame); err == nil {
		t.Fatal("expected invalid tunnel_id length to be rejected")
	}

	frame, err := EncodeBinaryTunnelDataFrame("tun-1", "conn-2", []byte("data"), false)
	if err != nil {
		t.Fatalf("EncodeBinaryTunnelDataFrame failed: %v", err)
	}
	binary.BigEndian.PutUint32(frame[6:10], 999)
	if _, err := DecodeBinaryTunnelDataFrame(frame); err == nil {
		t.Fatal("expected invalid data length to be rejected")
	}
}

func TestDecodeStrictJSONRejectsUnknownFieldsAndTrailingValues(t *testing.T) {
	type payload struct {
		Name string `json:"name"`
	}

	var p payload
	if err := DecodeStrictJSON([]byte(`{"name":"agent"}`), &p); err != nil {
		t.Fatalf("DecodeStrictJSON valid payload failed: %v", err)
	}

	if err := DecodeStrictJSON([]byte(`{"name":"agent","extra":true}`), &p); err == nil {
		t.Fatal("expected unknown field to be rejected")
	}

	if err := DecodeStrictJSON([]byte(`{"name":"agent"}{"name":"again"}`), &p); err == nil {
		t.Fatal("expected trailing JSON value to be rejected")
	}
}

func TestDecodePrivateKeyRejectsInvalidSize(t *testing.T) {
	if _, err := DecodePrivateKey("abcd"); err == nil {
		t.Fatal("expected invalid private key size to be rejected")
	}
}

func TestIsTimestampValidAcceptsUnixNano(t *testing.T) {
	if !IsTimestampValid(time.Now().UnixNano(), 5*time.Minute) {
		t.Fatal("expected current UnixNano timestamp to be valid")
	}
}

func TestEncryptDecrypt_EmptyData(t *testing.T) {
	cc, _ := NewCryptoContext("key")
	encoded, err := cc.Encrypt([]byte{})
	if err != nil {
		t.Fatalf("encrypt empty failed: %v", err)
	}

	decoded, err := cc.Decrypt(encoded)
	if err != nil {
		t.Fatalf("decrypt empty failed: %v", err)
	}

	if len(decoded) != 0 {
		t.Fatalf("expected empty result, got %d bytes", len(decoded))
	}
}

func TestEncryptDecrypt_LargeData(t *testing.T) {
	cc, _ := NewCryptoContext("key")
	plaintext := bytes.Repeat([]byte("A"), 64*1024)

	encoded, err := cc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt large failed: %v", err)
	}

	decoded, err := cc.Decrypt(encoded)
	if err != nil {
		t.Fatalf("decrypt large failed: %v", err)
	}

	if !bytes.Equal(decoded, plaintext) {
		t.Fatal("large data round-trip mismatch")
	}
}

func TestDecrypt_CorruptedData(t *testing.T) {
	cc, _ := NewCryptoContext("key")

	_, err := cc.Decrypt("!!!not-valid-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}

	_, err = cc.Decrypt("")
	if err == nil {
		t.Fatal("expected error for empty input")
	}

	encoded, _ := cc.Encrypt([]byte("data"))
	corrupted := encoded[:len(encoded)-4] + "AAAA"
	_, err = cc.Decrypt(corrupted)
	if err == nil {
		t.Fatal("expected error for corrupted ciphertext")
	}
}

func TestEncrypt_DifferentNonces(t *testing.T) {
	cc, _ := NewCryptoContext("key")
	plaintext := []byte("same plaintext")

	encoded1, _ := cc.Encrypt(plaintext)
	encoded2, _ := cc.Encrypt(plaintext)

	if encoded1 == encoded2 {
		t.Fatal("expected different ciphertexts due to random nonces")
	}

	decoded1, _ := cc.Decrypt(encoded1)
	decoded2, _ := cc.Decrypt(encoded2)

	if !bytes.Equal(decoded1, plaintext) || !bytes.Equal(decoded2, plaintext) {
		t.Fatal("decrypt produced wrong result")
	}
}

func TestNilCryptoContext(t *testing.T) {
	var cc *CryptoContext

	_, err := cc.Encrypt([]byte("test"))
	if err == nil {
		t.Fatal("expected error for nil context encrypt")
	}

	_, err = cc.Decrypt("dGVzdA==")
	if err == nil {
		t.Fatal("expected error for nil context decrypt")
	}
}
