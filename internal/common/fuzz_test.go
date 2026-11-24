package common

import (
	"bytes"
	"encoding/json"
	"testing"
)

// encodeFrameVersion 是测试侧的最小编码器：NewBinaryTunnelDataFrameVersion 已经
// 返回完整帧头和可写负载区，这里只把负载拷进去。生产代码没有版本化的
// Encode 入口（agent/server 都直接写进 payload 区省一次拷贝），所以编码器不复刻，
// 直接用这个函数做「编码→解码」可逆性检查。
//
// 注意 payload 是长度 0、容量 payloadLen 的切片：必须先 payload[:len(data)]
// 扩到目标长度再 copy，否则 copy 只会写 0 字节（EncodeBinaryTunnelDataFrame 里
// 也是这么写的）。
func encodeFrameVersion(tunnelID, connID string, data []byte, isEOF bool, version byte) ([]byte, error) {
	frame, payload, err := NewBinaryTunnelDataFrameVersion(tunnelID, connID, len(data), isEOF, version)
	if err != nil {
		return nil, err
	}
	n := copy(payload[:len(data)], data)
	return frame[:len(frame)+n], nil
}

// FuzzDecodeBinaryTunnelDataFrame 覆盖数据面最外层的帧解码：帧头长度、版本、
// flags、两个 ID 长度与负载长度都是攻击者可控的。除「不 panic」外，这里钉住
// 两条更强的性质：
//
//  1. 解出来的 Header/Data 必须与原始字节严格对应（Header 恰为帧头、Data 恰为负载）；
//  2. 成功解码的帧重新编码后必须逐字节还原——编码与解码互为逆运算。长度算术
//     一旦写错，这里会在几秒内炸掉。
func FuzzDecodeBinaryTunnelDataFrame(f *testing.F) {
	seeds := [][]byte{
		nil,
		{},
		{TunnelFrameVersionLegacy},
		make([]byte, binaryTunnelFrameHeaderSize),
		{0x03, 0x00, 0x00, 0x00},
		{TunnelFrameVersionAAD, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	}
	for _, isEOF := range []bool{false, true} {
		for _, version := range []byte{TunnelFrameVersionLegacy, TunnelFrameVersionAAD} {
			if frame, err := encodeFrameVersion("t-1", "c-1", []byte("hello"), isEOF, version); err == nil {
				seeds = append(seeds, frame)
			}
		}
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		decoded, err := DecodeBinaryTunnelDataFrame(raw)
		if err != nil {
			return
		}

		if decoded.Version != TunnelFrameVersionLegacy && decoded.Version != TunnelFrameVersionAAD {
			t.Fatalf("decoded unsupported version %d", decoded.Version)
		}
		headerEnd := binaryTunnelFrameHeaderSize + len(decoded.TunnelID) + len(decoded.ConnID)
		if headerEnd > len(raw) {
			t.Fatalf("header end %d exceeds frame length %d", headerEnd, len(raw))
		}
		if len(decoded.Header) != headerEnd {
			t.Fatalf("header length = %d, want %d", len(decoded.Header), headerEnd)
		}
		if !bytes.Equal(decoded.Header, raw[:headerEnd]) {
			t.Fatalf("header is not the frame prefix")
		}
		if !bytes.Equal(decoded.Data, raw[headerEnd:]) {
			t.Fatalf("payload does not match the remaining frame bytes")
		}

		rebuilt, err := encodeFrameVersion(decoded.TunnelID, decoded.ConnID, decoded.Data, decoded.IsEOF, byte(decoded.Version))
		if err != nil {
			t.Fatalf("re-encoding a decoded frame failed: %v", err)
		}
		if !bytes.Equal(rebuilt, raw) {
			t.Fatalf("encode(decode(frame)) != frame\n got %x\nwant %x", rebuilt, raw)
		}
	})
}

// FuzzDecodeStrictJSON 覆盖 22 处控制面消息共用的严格解码。除「不 panic」外
// 钉住两件事：
//
//  1. 成功解码的输入必须是**恰好一个** JSON 值——再接一个值必须被拒（这就是
//     DecodeStrictJSON 里那段 trailing 检查的全部意义）；
//  2. 成功解码的消息重新编码后必须还能解出来（编码/解码不产生互相不认识的值）。
func FuzzDecodeStrictJSON(f *testing.F) {
	seeds := []string{
		`{"type":"ping"}`,
		`{"type":"register","payload":{"client_id":"c-1"}}`,
		`{}`,
		`{"type":"ping"} `,
		`{"type":"ping"}{}`,
		``,
		`null`,
		`{"type":"ping","unknown":1}`,
	}
	for _, seed := range seeds {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var msg Message
		if err := DecodeStrictJSON(data, &msg); err != nil {
			return
		}

		doubled := append(append([]byte{}, data...), []byte(`{}`)...)
		var extra Message
		if err := DecodeStrictJSON(doubled, &extra); err == nil {
			t.Fatalf("strict decode accepted two JSON values: %q", doubled)
		}

		encoded, err := json.Marshal(msg)
		if err != nil {
			// 解码成功却无法重新编码，说明解码器接受了非法的 Payload。
			t.Fatalf("re-marshalling a decoded message failed: %v", err)
		}
		var roundTrip Message
		if err := DecodeStrictJSON(encoded, &roundTrip); err != nil {
			t.Fatalf("strict decode rejected its own output %q: %v", encoded, err)
		}
	})
}
