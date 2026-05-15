package agent

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"

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
	done   chan struct{}
	closed bool
}

func NewConnector(serverAddr string, tlsEnabled bool, tlsCA string, insecureSkipVerify bool, identity *AgentIdentity) *Connector {
	return &Connector{
		serverAddr:         serverAddr,
		tlsEnabled:         tlsEnabled,
		tlsCA:              tlsCA,
		insecureSkipVerify: insecureSkipVerify,
		identity:           identity,
		done:               make(chan struct{}),
	}
}

func (c *Connector) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	scheme := "ws"
	if c.tlsEnabled {
		scheme = "wss"
	}
	u := url.URL{Scheme: scheme, Host: c.serverAddr, Path: "/ws"}

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

	conn, _, err := dialer.Dial(u.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to dial: %w", err)
	}

	c.resetConnectionState(conn)

	slog.Info("connected to server", "addr", c.serverAddr)
	return nil
}

func (c *Connector) resetConnectionState(conn *websocket.Conn) {
	if conn != nil {
		conn.SetReadLimit(common.MaxWebSocketMessageSize)
	}
	c.conn = conn
	c.done = make(chan struct{})
	c.closed = false
}

func (c *Connector) buildTLSConfig() (*tls.Config, error) {
	if c.tlsCA == "" && c.insecureSkipVerify {
		return &tls.Config{InsecureSkipVerify: true}, nil
	}
	if c.tlsCA == "" {
		return &tls.Config{}, nil
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

	return &tls.Config{
		RootCAs: rootCAs,
	}, nil
}

func (c *Connector) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}

	c.closed = true
	close(c.done)

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
		if err := json.Unmarshal(data, msg); err != nil {
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

func (c *Connector) Done() <-chan struct{} {
	return c.done
}

func (c *Connector) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn != nil && !c.closed
}

func (c *Connector) RegisterNew(hostname, osName string) error {
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
