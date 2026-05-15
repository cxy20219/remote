package common

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
)

const (
	TunnelChunkSize         = 256 * 1024
	WebSocketBufferSize     = 128 * 1024
	MaxWebSocketMessageSize = 2 * 1024 * 1024
)

type Message struct {
	Type       string            `json:"type"`
	Payload    json.RawMessage   `json:"payload,omitempty"`
	BinaryData *BinaryTunnelData `json:"-"`
}

type BinaryTunnelData struct {
	TunnelID string
	ConnID   string
	Data     []byte
	IsEOF    bool
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
	ClientID        string `json:"client_id"`
	EncKeyEncrypted string `json:"enc_key_encrypted,omitempty"`
	ServerDHPubkey  string `json:"server_dh_pubkey,omitempty"`
	EncEnabled      bool   `json:"enc_enabled"`
}

type RegisterFailPayload struct {
	Reason string `json:"reason"`
}

type RegisterUpdatePayload struct {
	Type            string `json:"update_type"`
	EncKeyEncrypted string `json:"enc_key_encrypted,omitempty"`
	ServerDHPubkey  string `json:"server_dh_pubkey,omitempty"`
	EncEnabled      bool   `json:"enc_enabled"`
}

type TunnelOpenPayload struct {
	TunnelID  string `json:"tunnel_id"`
	LocalAddr string `json:"local_addr"`
	LocalPort int    `json:"local_port"`
	Protocol  string `json:"protocol"`
}

type TunnelOpenAckPayload struct {
	TunnelID   string `json:"tunnel_id"`
	PublicPort int    `json:"public_port"`
	Success    bool   `json:"success"`
	Error      string `json:"error,omitempty"`
}

type TunnelClosePayload struct {
	TunnelID string `json:"tunnel_id"`
	ConnID   string `json:"conn_id,omitempty"`
}

func EncodeBinaryTunnelDataFrame(tunnelID, connID string, data []byte, isEOF bool) ([]byte, error) {
	if len(tunnelID) > 0xffff {
		return nil, fmt.Errorf("tunnel_id too long: %d", len(tunnelID))
	}
	if len(connID) > 0xffff {
		return nil, fmt.Errorf("conn_id too long: %d", len(connID))
	}

	size := 10 + len(tunnelID) + len(connID) + len(data)
	frame := make([]byte, size)
	frame[0] = 1
	if isEOF {
		frame[1] = 1
	}
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(tunnelID)))
	binary.BigEndian.PutUint16(frame[4:6], uint16(len(connID)))
	binary.BigEndian.PutUint32(frame[6:10], uint32(len(data)))

	offset := 10
	copy(frame[offset:], tunnelID)
	offset += len(tunnelID)
	copy(frame[offset:], connID)
	offset += len(connID)
	copy(frame[offset:], data)
	return frame, nil
}

func DecodeBinaryTunnelDataFrame(frame []byte) (*BinaryTunnelData, error) {
	if len(frame) < 10 {
		return nil, fmt.Errorf("binary tunnel frame too short: %d", len(frame))
	}
	if frame[0] != 1 {
		return nil, fmt.Errorf("unsupported binary tunnel frame version: %d", frame[0])
	}
	if frame[1]&^byte(1) != 0 {
		return nil, fmt.Errorf("unsupported binary tunnel frame flags: %d", frame[1])
	}

	tunnelIDLen := int(binary.BigEndian.Uint16(frame[2:4]))
	connIDLen := int(binary.BigEndian.Uint16(frame[4:6]))
	dataLen := int(binary.BigEndian.Uint32(frame[6:10]))
	expected := 10 + tunnelIDLen + connIDLen + dataLen
	if expected != len(frame) {
		return nil, fmt.Errorf("invalid binary tunnel frame length: got %d, expected %d", len(frame), expected)
	}

	offset := 10
	tunnelID := string(frame[offset : offset+tunnelIDLen])
	offset += tunnelIDLen
	connID := string(frame[offset : offset+connIDLen])
	offset += connIDLen
	data := frame[offset : offset+dataLen]

	return &BinaryTunnelData{
		TunnelID: tunnelID,
		ConnID:   connID,
		Data:     data,
		IsEOF:    frame[1]&1 == 1,
	}, nil
}

type TunnelErrorPayload struct {
	TunnelID string `json:"tunnel_id"`
	ConnID   string `json:"conn_id,omitempty"`
	Error    string `json:"error"`
}

type TunnelUpdatePayload struct {
	TunnelID  string `json:"tunnel_id"`
	LocalAddr string `json:"local_addr,omitempty"`
	LocalPort int    `json:"local_port,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
}

type TunnelUpdateAckPayload struct {
	TunnelID string `json:"tunnel_id"`
	Success  bool   `json:"success"`
	Error    string `json:"error,omitempty"`
}

type DeviceDeletedPayload struct {
	Reason string `json:"reason"`
}
