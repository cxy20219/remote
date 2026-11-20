package common

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func testKey(fill byte) []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = fill
	}
	return key
}

func TestNewCryptoContextFromKeyRejectsInvalidSize(t *testing.T) {
	if _, err := NewCryptoContextFromKey([]byte("short")); err == nil {
		t.Fatal("expected invalid key size to be rejected")
	}
}

func TestCryptoContextWrongKeyCannotDecrypt(t *testing.T) {
	cc1, err := NewCryptoContextFromKey(testKey(1))
	if err != nil {
		t.Fatalf("NewCryptoContextFromKey: %v", err)
	}
	cc2, err := NewCryptoContextFromKey(testKey(2))
	if err != nil {
		t.Fatalf("NewCryptoContextFromKey: %v", err)
	}

	ciphertext, err := cc1.EncryptTo(nil, []byte("test data"))
	if err != nil {
		t.Fatalf("EncryptBytes: %v", err)
	}
	if _, err := cc2.DecryptBytes(ciphertext); err == nil {
		t.Fatal("expected decryption to fail with wrong key")
	}
}

func TestEncryptDecryptBytesRoundTrip(t *testing.T) {
	cc, err := NewCryptoContextFromKey(testKey(3))
	if err != nil {
		t.Fatalf("NewCryptoContextFromKey: %v", err)
	}

	plaintext := []byte("binary tunnel payload")
	ciphertext, err := cc.EncryptTo(nil, plaintext)
	if err != nil {
		t.Fatalf("EncryptBytes failed: %v", err)
	}
	if len(ciphertext) != len(plaintext)+TunnelEncryptionOverhead {
		t.Fatalf("ciphertext length = %d, want %d", len(ciphertext), len(plaintext)+TunnelEncryptionOverhead)
	}

	decoded, err := cc.DecryptBytes(ciphertext)
	if err != nil {
		t.Fatalf("DecryptBytes failed: %v", err)
	}
	if !bytes.Equal(decoded, plaintext) {
		t.Fatalf("round-trip mismatch: got %q, want %q", decoded, plaintext)
	}
}

func TestTunnelEncryptionOverheadMatchesGCM(t *testing.T) {
	cc, err := NewCryptoContextFromKey(testKey(9))
	if err != nil {
		t.Fatalf("NewCryptoContextFromKey: %v", err)
	}
	for _, size := range []int{0, 1, 1024, TunnelChunkSize} {
		plaintext := make([]byte, size)
		ciphertext, err := cc.EncryptTo(nil, plaintext)
		if err != nil {
			t.Fatalf("EncryptTo(%d): %v", size, err)
		}
		if len(ciphertext) != size+TunnelEncryptionOverhead {
			t.Fatalf("size %d: ciphertext length %d, want %d", size, len(ciphertext), size+TunnelEncryptionOverhead)
		}
	}
}

func TestEncryptToUsesProvidedBuffer(t *testing.T) {
	cc, err := NewCryptoContextFromKey(testKey(4))
	if err != nil {
		t.Fatalf("NewCryptoContextFromKey: %v", err)
	}

	plaintext := bytes.Repeat([]byte("chunk"), 1024)
	dst := make([]byte, 0, len(plaintext)+TunnelEncryptionOverhead)
	ciphertext, err := cc.EncryptTo(dst, plaintext)
	if err != nil {
		t.Fatalf("EncryptTo: %v", err)
	}
	if &ciphertext[0] != &dst[:1][0] {
		t.Fatal("EncryptTo should reuse the provided buffer")
	}

	decoded, err := cc.DecryptBytes(ciphertext)
	if err != nil {
		t.Fatalf("DecryptBytes: %v", err)
	}
	if !bytes.Equal(decoded, plaintext) {
		t.Fatal("round-trip mismatch")
	}
}

func TestNewBinaryTunnelDataFrameWritesIntoPayloadArea(t *testing.T) {
	frame, payload, err := NewBinaryTunnelDataFrame("tun-1", "conn-2", 4, false)
	if err != nil {
		t.Fatalf("NewBinaryTunnelDataFrame: %v", err)
	}
	copy(payload[:4], "data")
	frame = frame[:len(frame)+4]

	decoded, err := DecodeBinaryTunnelDataFrame(frame)
	if err != nil {
		t.Fatalf("DecodeBinaryTunnelDataFrame: %v", err)
	}
	if decoded.TunnelID != "tun-1" || decoded.ConnID != "conn-2" || string(decoded.Data) != "data" {
		t.Fatalf("unexpected decoded frame: %+v", decoded)
	}
}

func TestBinaryTunnelDataFrameRoundTrip(t *testing.T) {
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

func TestEncryptDecryptEmptyData(t *testing.T) {
	cc, _ := NewCryptoContextFromKey(testKey(5))
	encoded, err := cc.EncryptTo(nil, []byte{})
	if err != nil {
		t.Fatalf("encrypt empty failed: %v", err)
	}

	decoded, err := cc.DecryptBytes(encoded)
	if err != nil {
		t.Fatalf("decrypt empty failed: %v", err)
	}
	if len(decoded) != 0 {
		t.Fatalf("expected empty result, got %d bytes", len(decoded))
	}
}

func TestDecryptCorruptedData(t *testing.T) {
	cc, _ := NewCryptoContextFromKey(testKey(6))

	if _, err := cc.DecryptBytes([]byte("short")); err == nil {
		t.Fatal("expected error for short ciphertext")
	}

	ciphertext, _ := cc.EncryptTo(nil, []byte("data"))
	corrupted := append([]byte(nil), ciphertext...)
	corrupted[len(corrupted)-1] ^= 0xff
	if _, err := cc.DecryptBytes(corrupted); err == nil {
		t.Fatal("expected error for corrupted ciphertext")
	}
}

func TestEncryptUsesDifferentNonces(t *testing.T) {
	cc, _ := NewCryptoContextFromKey(testKey(7))
	plaintext := []byte("same plaintext")

	ciphertext1, _ := cc.EncryptTo(nil, plaintext)
	ciphertext2, _ := cc.EncryptTo(nil, plaintext)
	if bytes.Equal(ciphertext1, ciphertext2) {
		t.Fatal("expected different ciphertexts due to random nonces")
	}

	decoded1, _ := cc.DecryptBytes(ciphertext1)
	decoded2, _ := cc.DecryptBytes(ciphertext2)
	if !bytes.Equal(decoded1, plaintext) || !bytes.Equal(decoded2, plaintext) {
		t.Fatal("decrypt produced wrong result")
	}
}

func TestNilCryptoContext(t *testing.T) {
	var cc *CryptoContext

	if _, err := cc.EncryptTo(nil, []byte("test")); err == nil {
		t.Fatal("expected error for nil context encrypt")
	}
	if _, err := cc.DecryptBytes([]byte("test")); err == nil {
		t.Fatal("expected error for nil context decrypt")
	}
}

func TestCryptoManagerHasKey(t *testing.T) {
	manager := NewCryptoManager()
	if manager.HasKey("client-1") {
		t.Fatal("expected no key initially")
	}
	if err := manager.SetKey("client-1", testKey(8)); err != nil {
		t.Fatalf("SetKey: %v", err)
	}
	if !manager.HasKey("client-1") {
		t.Fatal("expected key after SetKey")
	}
	manager.RemoveKey("client-1")
	if manager.HasKey("client-1") {
		t.Fatal("expected key to be removed")
	}
}
