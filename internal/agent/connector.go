package agent

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"goremote/internal/buildinfo"
	"goremote/internal/common"
)

const (
	writeWait = 30 * time.Second
	pongWait  = 90 * time.Second
)

type Connector struct {
	serverAddr         string
	tlsEnabled         bool
	tlsCA              string
	insecureSkipVerify bool
	identity           *AgentIdentity

	conn   *websocket.Conn
	mu     sync.Mutex
	closed bool
	// proto 是本次连接协商到的服务端协议版本：1 = 老服务端（101 没回
	// X-Goremote-Proto），2 = 新服务端。
	proto int
	// aad 表示本次连接协商了 v2 帧 AAD（101 回了 X-Goremote-AAD: 1）。
	aad bool
	// serverCaps 是服务端在 101 里声明的能力位（X-Goremote-Caps）。
	serverCaps []string
	// legacyHandshake 让本连接不带任何握手参数，用来复现「老 agent × 新服务端」。
	// 只有测试会设置它：生产路径永远带 proto/ver/commit。
	legacyHandshake bool
}

// agentCaps 是本 agent 支持的细粒度能力位。
//
// 本阶段为空：还没有任何「按 cap 门控的可选字段」。留着这个变量是为了让发送
// 路径是真的（FormatCaps 会走到），将来加第一个可选字段时只需往这里加一项，
// 不用再改握手代码。
var agentCaps = []string{}

func NewConnector(serverAddr string, tlsEnabled bool, tlsCA string, insecureSkipVerify bool, identity *AgentIdentity) *Connector {
	return &Connector{
		serverAddr:         serverAddr,
		tlsEnabled:         tlsEnabled,
		tlsCA:              tlsCA,
		insecureSkipVerify: insecureSkipVerify,
		identity:           identity,
	}
}

func (c *Connector) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	scheme := "ws"
	if c.tlsEnabled {
		scheme = "wss"
	}
	// 握手参数：proto 是行为位，ver/commit 是元数据，caps 是可选特性。
	// 老服务端忽略整个 query（也不回头），新服务端全部可读——这是唯一一条
	// 「老端天然忽略、新端可用、且在第一条 JSON 之前就拿到」的通道，因此
	// 不需要给任何 JSON 消息加字段。
	query := url.Values{}
	query.Set("proto", "2")
	if version := buildinfo.String(); version != buildinfo.Unknown && version != "dev" {
		query.Set("ver", version)
	}
	if commit := buildinfo.Commit(); commit != "dev" {
		query.Set("commit", commit)
	}
	if caps := common.FormatCaps(agentCaps); caps != "" {
		query.Set("caps", caps)
	}
	if c.legacyHandshake {
		// 复现老 agent：什么参数都不带。用于兼容矩阵里「老 agent × 新服务端」。
		query = url.Values{}
	}
	u := url.URL{Scheme: scheme, Host: c.serverAddr, Path: "/ws", RawQuery: query.Encode()}

	slog.Info("connecting to server", "addr", c.serverAddr)

	dialer := websocket.Dialer{
		ReadBufferSize:   common.WebSocketBufferSize,
		WriteBufferSize:  common.WebSocketBufferSize,
		HandshakeTimeout: 10 * time.Second,
	}

	if c.tlsEnabled {
		tlsConfig, err := c.buildTLSConfig()
		if err != nil {
			return err
		}
		dialer.TLSClientConfig = tlsConfig
	}

	conn, resp, err := dialer.Dial(u.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to dial: %w", err)
	}
	conn.SetReadLimit(common.MaxWebSocketMessageSize)

	c.proto = 1
	c.aad = false
	c.serverCaps = nil
	if resp != nil {
		c.proto = parseServerProto(resp.Header.Get("X-Goremote-Proto"))
		c.aad = resp.Header.Get("X-Goremote-AAD") == "1"
		c.serverCaps = common.ParseCaps(resp.Header.Get("X-Goremote-Caps"))
	}

	c.conn = conn
	c.closed = false

	slog.Info("connected to server", "addr", c.serverAddr)
	return nil
}

// ServerProto 返回本次连接协商到的服务端协议版本（1 = 未协商）。
func (c *Connector) ServerProto() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.proto < 1 {
		return 1
	}
	return c.proto
}

// AADEnabled 返回本次连接是否协商了 v2 帧 AAD。
func (c *Connector) AADEnabled() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.aad
}

// ServerCaps 返回服务端声明的能力位（老服务端不声明，返回空）。
func (c *Connector) ServerCaps() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.serverCaps...)
}

// parseServerProto 解析 101 响应里的 X-Goremote-Proto；缺省或非法按 1 处理。
func parseServerProto(raw string) int {
	version, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || version < 2 {
		return 1
	}
	return 2
}

func (c *Connector) buildTLSConfig() (*tls.Config, error) {
	cfg := common.SecureTLSConfig()
	if c.insecureSkipVerify {
		slog.Warn("TLS certificate verification is disabled; the connection is vulnerable to man-in-the-middle attacks")
		cfg.InsecureSkipVerify = true
		return cfg, nil
	}
	if c.tlsCA == "" {
		return cfg, nil
	}

	caCertPEM, err := os.ReadFile(c.tlsCA)
	if err != nil {
		return nil, fmt.Errorf("failed to read TLS CA certificate %q: %w", c.tlsCA, err)
	}

	rootCAs, err := x509.SystemCertPool()
	if err != nil || rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	if ok := rootCAs.AppendCertsFromPEM(caCertPEM); !ok {
		return nil, fmt.Errorf("failed to parse TLS CA certificate %q", c.tlsCA)
	}

	cfg.RootCAs = rootCAs
	return cfg, nil
}

func (c *Connector) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		return err
	}
	return nil
}

func (c *Connector) Send(msg *common.Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return fmt.Errorf("not connected")
	}

	c.conn.SetWriteDeadline(time.Now().Add(writeWait))
	defer c.conn.SetWriteDeadline(time.Time{})
	return c.conn.WriteJSON(msg)
}

func (c *Connector) SendBinary(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return fmt.Errorf("not connected")
	}

	c.conn.SetWriteDeadline(time.Now().Add(writeWait))
	defer c.conn.SetWriteDeadline(time.Time{})
	return c.conn.WriteMessage(websocket.BinaryMessage, data)
}

func (c *Connector) Receive() (*common.Message, error) {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()

	if conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	conn.SetReadDeadline(time.Now().Add(pongWait))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	messageType, data, err := conn.ReadMessage()
	if err != nil {
		return nil, err
	}

	switch messageType {
	case websocket.TextMessage:
		msg := &common.Message{}
		if err := common.DecodeStrictJSON(data, msg); err != nil {
			return nil, err
		}
		return msg, nil
	case websocket.BinaryMessage:
		payload, err := common.DecodeBinaryTunnelDataFrame(data)
		if err != nil {
			return nil, err
		}
		return &common.Message{Type: "tunnel_data_bin", BinaryData: payload}, nil
	default:
		return nil, fmt.Errorf("unsupported websocket message type: %d", messageType)
	}
}

func (c *Connector) RegisterNew(hostname, osName string) error {
	if c.identity == nil {
		return fmt.Errorf("agent identity is not initialized")
	}
	payload := common.RegisterPayload{
		DevicePubkey:   c.identity.DeviceSignPubkey,
		DeviceDHPubkey: c.identity.DeviceDHPubkey,
		Hostname:       hostname,
		OS:             osName,
	}
	payloadJSON, _ := json.Marshal(payload)

	return c.Send(&common.Message{
		Type:    "register",
		Payload: payloadJSON,
	})
}

func (c *Connector) RegisterReauth(clientID string, timestamp int64, hostname, osName string) error {
	payload, err := c.buildRegisterReauthPayload(clientID, timestamp, hostname, osName)
	if err != nil {
		return err
	}
	payloadJSON, _ := json.Marshal(payload)

	return c.Send(&common.Message{
		Type:    "register",
		Payload: payloadJSON,
	})
}

func (c *Connector) buildRegisterReauthPayload(clientID string, timestamp int64, hostname, osName string) (common.RegisterPayload, error) {
	if c.identity == nil {
		return common.RegisterPayload{}, fmt.Errorf("agent identity is not initialized")
	}
	privKey, err := c.identity.GetSignPrivKey()
	if err != nil {
		return common.RegisterPayload{}, fmt.Errorf("get sign privkey: %w", err)
	}

	signature, err := common.SignTimestamp(privKey, clientID, timestamp)
	if err != nil {
		return common.RegisterPayload{}, fmt.Errorf("sign timestamp: %w", err)
	}

	return common.RegisterPayload{
		ReAuth:         true,
		ClientID:       clientID,
		DevicePubkey:   c.identity.DeviceSignPubkey,
		DeviceDHPubkey: c.identity.DeviceDHPubkey,
		Timestamp:      timestamp,
		Signature:      common.EncodeBytes(signature),
		Hostname:       hostname,
		OS:             osName,
	}, nil
}

func (c *Connector) SendPing() error {
	return c.Send(&common.Message{Type: "ping"})
}
