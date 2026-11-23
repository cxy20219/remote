package common

import (
	"bytes"
	"testing"
)

func newAADTestContext(t *testing.T) *CryptoContext {
	t.Helper()
	ctx, err := NewCryptoContextFromKey(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatalf("NewCryptoContextFromKey: %v", err)
	}
	return ctx
}

// buildTunnelFrame 按版本加密一帧并拼成完整线格式。
func buildTunnelFrame(t *testing.T, ctx *CryptoContext, version byte, tunnelID, connID string, data []byte, isEOF bool) ([]byte, *BinaryTunnelData) {
	t.Helper()
	frame, _, err := NewBinaryTunnelDataFrameVersion(tunnelID, connID, len(data)+TunnelEncryptionOverhead, isEOF, version)
	if err != nil {
		t.Fatalf("NewBinaryTunnelDataFrameVersion: %v", err)
	}
	var encrypted []byte
	if version == TunnelFrameVersionAAD {
		encrypted, err = ctx.EncryptToAAD(nil, data, frame)
	} else {
		encrypted, err = ctx.EncryptTo(nil, data)
	}
	if err != nil {
		t.Fatalf("encrypt v%d: %v", version, err)
	}
	full := append(frame, encrypted...)
	decoded, err := DecodeBinaryTunnelDataFrame(full)
	if err != nil {
		t.Fatalf("DecodeBinaryTunnelDataFrame: %v", err)
	}
	return full, decoded
}

// ① v1/v2 各自 round-trip，明文、ID、EOF 标志一致。
func TestTunnelFrameVersionsRoundTrip(t *testing.T) {
	ctx := newAADTestContext(t)

	for _, version := range []byte{TunnelFrameVersionLegacy, TunnelFrameVersionAAD} {
		for _, isEOF := range []bool{false, true} {
			data := []byte("tunnel payload")
			_, decoded := buildTunnelFrame(t, ctx, version, "tunnel-1", "conn-1", data, isEOF)

			if decoded.Version != int(version) {
				t.Fatalf("version = %d, want %d", decoded.Version, version)
			}
			if decoded.TunnelID != "tunnel-1" || decoded.ConnID != "conn-1" {
				t.Fatalf("ids = %q/%q", decoded.TunnelID, decoded.ConnID)
			}
			if decoded.IsEOF != isEOF {
				t.Fatalf("isEOF = %v, want %v", decoded.IsEOF, isEOF)
			}
			plain, err := ctx.DecryptToAAD(nil, decoded.Data, decoded.AAD())
			if err != nil {
				t.Fatalf("decrypt v%d: %v", version, err)
			}
			if !bytes.Equal(plain, data) {
				t.Fatalf("v%d plaintext = %q, want %q", version, plain, data)
			}
		}
	}
}

// ② v2：改任一帧头字节 → 解密失败。
func TestTunnelFrameV2RejectsHeaderTamper(t *testing.T) {
	ctx := newAADTestContext(t)

	full, decoded := buildTunnelFrame(t, ctx, TunnelFrameVersionAAD, "tunnel-aaaa", "conn-1", []byte("hello"), false)
	if _, err := ctx.DecryptToAAD(nil, decoded.Data, decoded.AAD()); err != nil {
		t.Fatalf("baseline decrypt: %v", err)
	}

	for _, offset := range []int{0, 1, 6, 10, len(full) - len(decoded.Data) - 1} {
		tampered := append([]byte(nil), full...)
		tampered[offset] ^= 0x01
		changed, err := DecodeBinaryTunnelDataFrame(tampered)
		if err != nil {
			// 改长度/版本字节可能直接解析失败，也算被拒绝。
			continue
		}
		if _, err := ctx.DecryptToAAD(nil, changed.Data, changed.AAD()); err == nil {
			t.Fatalf("v2 frame with header byte %d tampered still decrypted", offset)
		}
	}
}

// ② 反面：v1 帧头不在 AAD 里，改 ID 后仍能解密——把现状钉成已知缺口。
func TestTunnelFrameV1HeaderTamperStillDecrypts(t *testing.T) {
	ctx := newAADTestContext(t)

	full, _ := buildTunnelFrame(t, ctx, TunnelFrameVersionLegacy, "tunnel-aaaa", "conn-1", []byte("hello"), false)
	tampered := append([]byte(nil), full...)
	tampered[10] ^= 0x01 // tunnel_id 首字节
	decoded, err := DecodeBinaryTunnelDataFrame(tampered)
	if err != nil {
		t.Fatalf("v1 tampered frame should still decode: %v", err)
	}
	if decoded.Version != TunnelFrameVersionLegacy || decoded.AAD() != nil {
		t.Fatalf("v1 frame must not carry AAD: version=%d aad=%v", decoded.Version, decoded.AAD())
	}
	plain, err := ctx.DecryptToAAD(nil, decoded.Data, nil)
	if err != nil {
		t.Fatalf("v1 has no header binding; tampering a header byte must not break decryption: %v", err)
	}
	if !bytes.Equal(plain, []byte("hello")) {
		t.Fatalf("plaintext = %q", plain)
	}
}

// ⑥ AAD 字节范围钉死：Header 恰好是帧头（version 到负载之前），不含负载。
func TestTunnelFrameHeaderIsExactAADRange(t *testing.T) {
	ctx := newAADTestContext(t)
	data := []byte("hello")
	frame, payload, err := NewBinaryTunnelDataFrameVersion("tunnel-aaaa", "conn-1", len(data)+TunnelEncryptionOverhead, false, TunnelFrameVersionAAD)
	if err != nil {
		t.Fatalf("NewBinaryTunnelDataFrameVersion: %v", err)
	}
	headerEnd := binaryTunnelFrameHeaderSize + len("tunnel-aaaa") + len("conn-1")
	if len(frame) != headerEnd {
		t.Fatalf("header length = %d, want %d", len(frame), headerEnd)
	}
	headerBefore := append([]byte(nil), frame...)

	encrypted, err := ctx.EncryptToAAD(payload, data, frame)
	if err != nil {
		t.Fatalf("EncryptToAAD: %v", err)
	}
	if !bytes.Equal(frame, headerBefore) {
		t.Fatal("encryption must not modify the header bytes used as AAD")
	}
	full := frame[:len(frame)+len(encrypted)]
	decoded, err := DecodeBinaryTunnelDataFrame(full)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(decoded.Header) != headerEnd || !bytes.Equal(decoded.Header, headerBefore) {
		t.Fatalf("decoded header = %x, want %x", decoded.Header, headerBefore)
	}

	// 改负载字节不改变 Header（AAD 范围不含负载），但会破坏 GCM tag。
	decoded.Data[0] ^= 0x01
	if !bytes.Equal(decoded.Header, headerBefore) {
		t.Fatal("payload bytes must not be part of the AAD range")
	}
	if _, err := ctx.DecryptToAAD(nil, decoded.Data, decoded.AAD()); err == nil {
		t.Fatal("a modified payload must fail GCM authentication")
	}
}

func TestDecodeTunnelFrameRejectsUnknownVersion(t *testing.T) {
	frame, _, err := NewBinaryTunnelDataFrameVersion("t", "c", 0, false, TunnelFrameVersionAAD)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	frame[0] = 3
	if _, err := DecodeBinaryTunnelDataFrame(frame); err == nil {
		t.Fatal("unknown frame version must be rejected")
	}
}
