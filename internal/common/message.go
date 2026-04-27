package common

import "encoding/json"

type Message struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type RegisterPayload struct {
	Key      string `json:"key"`
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
}

type RegisterOKPayload struct {
	ClientID string `json:"client_id"`
}

type RegisterFailPayload struct {
	Reason string `json:"reason"`
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
