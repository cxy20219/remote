package common

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
)

const (
	TunnelChunkSize         = 256 * 1024
	WebSocketBufferSize     = 128 * 1024
	MaxWebSocketMessageSize = 2 * 1024 * 1024

	binaryTunnelFrameHeaderSize = 10

	// TunnelFrameVersionLegacy 是不带 AAD 的原始帧格式：帧头可被篡改，
	// 密文可以在同设备的连接之间搬运（v1 的已知缺口）。
	TunnelFrameVersionLegacy = 1
	// TunnelFrameVersionAAD 的帧头布局与 v1 完全相同，但 GCM 的 AAD 是
	// 帧头整段（version/flags/长度/tunnel_id/conn_id）。改任何头字节都会
	// 认证失败；密文负载本身由 GCM tag 保护，不在 AAD 里。
	TunnelFrameVersionAAD = 2
)

var (
	// ErrTunnelAADRequired：已协商 v2 的加密连接收到了 v1 数据帧——可能是
	// 降级攻击，也可能是对端状态错乱。两个方向都直接断开重连。
	ErrTunnelAADRequired = errors.New("tunnel data frame without AAD on an AAD-negotiated connection")
	// ErrTunnelAADUnexpected：未协商 v2 的连接收到了 v2 帧。
	ErrTunnelAADUnexpected = errors.New("tunnel data frame with AAD but AAD was not negotiated")
)

type Message struct {
	Type       string            `json:"type"`
	Payload    json.RawMessage   `json:"payload,omitempty"`
	BinaryData *BinaryTunnelData `json:"-"`
}

func DecodeStrictJSON(data []byte, dst interface{}) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		return err
	}

	var extra struct{}
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("invalid JSON: multiple values")
		}
		return err
	}

	return nil
}

type BinaryTunnelData struct {
	TunnelID string
	ConnID   string
	Data     []byte
	IsEOF    bool

	// Version 是帧头版本（1/v1 或 2/v2）；Header 是帧头原始字节（version
	// 之后到负载之前的整段）。v2 解密时必须把 Header 原样作为 AAD。
	// Header 别名底层 WS 缓冲区，不能跨消息留存。
	Version int
	Header  []byte
}

// AAD 返回解密该帧时应绑定的附加认证数据：v1 为 nil，v2 是帧头整段。
func (d *BinaryTunnelData) AAD() []byte {
	if d == nil || d.Version != TunnelFrameVersionAAD {
		return nil
	}
	return d.Header
}

type RegisterPayload struct {
	ReAuth         bool   `json:"reauth"`
	ClientID       string `json:"client_id,omitempty"`
	DevicePubkey   string `json:"device_pubkey"`
	DeviceDHPubkey string `json:"device_dh_pubkey,omitempty"`
	Hostname       string `json:"hostname"`
	OS             string `json:"os"`
	Timestamp      int64  `json:"timestamp,omitempty"`
	Signature      string `json:"signature,omitempty"`
}

type RegisterPendingPayload struct {
	ClientID string `json:"client_id"`
	Message  string `json:"message"`
}

type RegisterOKPayload struct {
	ClientID         string `json:"client_id"`
	EncKeyEncrypted  string `json:"enc_key_encrypted,omitempty"`
	ServerDHPubkey   string `json:"server_dh_pubkey,omitempty"`
	EncEnabled       bool   `json:"enc_enabled"`
	ServerSignPubkey string `json:"server_sign_pubkey,omitempty"`
	ServerSignature  string `json:"server_signature,omitempty"`
}

type RegisterFailPayload struct {
	Reason string `json:"reason"`
}

// ClockSkewReasonPrefix 是 register_fail 里「设备时钟超出允许窗口」的固定
// 前缀，后面紧跟带符号的秒数（如 clock_skew:+312s）。agent 据此区分「校时
// 就能重试」和「身份不可用」：前者必须保留本地身份，后者才清 ClientID。
const ClockSkewReasonPrefix = "clock_skew:"

type RegisterUpdatePayload struct {
	Type             string `json:"update_type"`
	ClientID         string `json:"client_id,omitempty"`
	EncKeyEncrypted  string `json:"enc_key_encrypted,omitempty"`
	ServerDHPubkey   string `json:"server_dh_pubkey,omitempty"`
	EncEnabled       bool   `json:"enc_enabled"`
	ServerSignPubkey string `json:"server_sign_pubkey,omitempty"`
	ServerSignature  string `json:"server_signature,omitempty"`
}

type TunnelOpenPayload struct {
	TunnelID  string `json:"tunnel_id"`
	LocalAddr string `json:"local_addr"`
	LocalPort int    `json:"local_port"`
	Protocol  string `json:"protocol"`
}

type TunnelClosePayload struct {
	TunnelID string `json:"tunnel_id"`
}

type TunnelErrorPayload struct {
	TunnelID string `json:"tunnel_id"`
	ConnID   string `json:"conn_id,omitempty"`
	Error    string `json:"error"`
}

type DeviceDeletedPayload struct {
	Reason string `json:"reason"`
}

// NewBinaryTunnelDataFrame allocates a frame with room for payloadLen bytes
// and returns the frame header as well as an empty slice backed by the frame's
// payload area. Callers can encrypt directly into the payload slice, avoiding
// one copy of every tunnel chunk.
func NewBinaryTunnelDataFrame(tunnelID, connID string, payloadLen int, isEOF bool) ([]byte, []byte, error) {
	return NewBinaryTunnelDataFrameVersion(tunnelID, connID, payloadLen, isEOF, TunnelFrameVersionLegacy)
}

// NewBinaryTunnelDataFrameVersion 与 NewBinaryTunnelDataFrame 相同，但显式
// 指定帧头版本。返回的 frame 就是完整帧头（随后是空的可写负载区）：v2
// 加密时直接把它原样作为 AAD 传给 EncryptToAAD。
func NewBinaryTunnelDataFrameVersion(tunnelID, connID string, payloadLen int, isEOF bool, version byte) ([]byte, []byte, error) {
	if version != TunnelFrameVersionLegacy && version != TunnelFrameVersionAAD {
		return nil, nil, fmt.Errorf("unsupported binary tunnel frame version: %d", version)
	}
	if len(tunnelID) > math.MaxUint16 {
		return nil, nil, fmt.Errorf("tunnel_id too long: %d", len(tunnelID))
	}
	if len(connID) > math.MaxUint16 {
		return nil, nil, fmt.Errorf("conn_id too long: %d", len(connID))
	}
	if payloadLen < 0 || uint64(payloadLen) > math.MaxUint32 {
		return nil, nil, fmt.Errorf("tunnel payload too large: %d", payloadLen)
	}

	headerEnd := binaryTunnelFrameHeaderSize + len(tunnelID) + len(connID)
	frame := make([]byte, headerEnd, headerEnd+payloadLen)
	frame[0] = version
	if isEOF {
		frame[1] = 1
	}
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(tunnelID)))
	binary.BigEndian.PutUint16(frame[4:6], uint16(len(connID)))
	binary.BigEndian.PutUint32(frame[6:10], uint32(payloadLen))
	copy(frame[binaryTunnelFrameHeaderSize:], tunnelID)
	copy(frame[binaryTunnelFrameHeaderSize+len(tunnelID):], connID)

	return frame, frame[headerEnd:headerEnd], nil
}

func EncodeBinaryTunnelDataFrame(tunnelID, connID string, data []byte, isEOF bool) ([]byte, error) {
	frame, payload, err := NewBinaryTunnelDataFrame(tunnelID, connID, len(data), isEOF)
	if err != nil {
		return nil, err
	}
	return frame[:len(frame)+copy(payload[:len(data)], data)], nil
}

func DecodeBinaryTunnelDataFrame(frame []byte) (*BinaryTunnelData, error) {
	if len(frame) < binaryTunnelFrameHeaderSize {
		return nil, fmt.Errorf("binary tunnel frame too short: %d", len(frame))
	}
	if frame[0] != TunnelFrameVersionLegacy && frame[0] != TunnelFrameVersionAAD {
		return nil, fmt.Errorf("unsupported binary tunnel frame version: %d", frame[0])
	}
	if frame[1]&^byte(1) != 0 {
		return nil, fmt.Errorf("unsupported binary tunnel frame flags: %d", frame[1])
	}

	tunnelIDLen := int(binary.BigEndian.Uint16(frame[2:4]))
	connIDLen := int(binary.BigEndian.Uint16(frame[4:6]))
	dataLen := binary.BigEndian.Uint32(frame[6:10])

	remaining := len(frame) - binaryTunnelFrameHeaderSize
	if tunnelIDLen > remaining {
		return nil, fmt.Errorf("invalid binary tunnel frame tunnel_id length: %d", tunnelIDLen)
	}
	remaining -= tunnelIDLen
	if connIDLen > remaining {
		return nil, fmt.Errorf("invalid binary tunnel frame conn_id length: %d", connIDLen)
	}
	remaining -= connIDLen
	if uint64(dataLen) != uint64(remaining) {
		return nil, fmt.Errorf("invalid binary tunnel frame data length: got %d, expected %d", dataLen, remaining)
	}

	offset := binaryTunnelFrameHeaderSize
	tunnelID := string(frame[offset : offset+tunnelIDLen])
	offset += tunnelIDLen
	connID := string(frame[offset : offset+connIDLen])
	offset += connIDLen
	headerEnd := offset
	data := frame[offset:]

	return &BinaryTunnelData{
		TunnelID: tunnelID,
		ConnID:   connID,
		Data:     data,
		IsEOF:    frame[1]&1 == 1,
		Version:  int(frame[0]),
		Header:   frame[:headerEnd],
	}, nil
}
