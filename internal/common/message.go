package common

import "encoding/json"

type Message struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type RegisterPayload struct {
	ReAuth        bool   `json:"reauth"`
	ClientID      string `json:"client_id,omitempty"`
	DevicePubkey  string `json:"device_pubkey"`
	DeviceDHPubkey string `json:"device_dh_pubkey,omitempty"`
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	Timestamp     int64  `json:"timestamp,omitempty"`
	Signature     string `json:"signature,omitempty"`
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

type TunnelDataPayload struct {
	TunnelID string `json:"tunnel_id"`
	ConnID   string `json:"conn_id"`
	Data     string `json:"data"`
	IsEOF    bool   `json:"is_eof"`
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