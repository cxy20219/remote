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
	writeWait     = 10 * time.Second
	pongWait      = 60 * time.Second
	pingPeriod    = (pongWait * 9) / 10
	maxMessageSize = 512 * 1024
)

type Connector struct {
	serverAddr         string
	tlsEnabled         bool
	tlsCA              string
	insecureSkipVerify bool
	identity          *AgentIdentity

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
		identity:          identity,
		done:              make(chan struct{}),
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
		ReadBufferSize:   1024,
		WriteBufferSize:  1024,
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
	return c.conn.WriteJSON(msg)
}

func (c *Connector) Receive() (*common.Message, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	msg := &common.Message{}
	err := c.conn.ReadJSON(msg)
	if err != nil {
		return nil, err
	}
	return msg, nil
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

func (c *Connector) RegisterReauth(clientID string, timestamp int64) error {
	privKey, err := c.identity.GetSignPrivKey()
	if err != nil {
		return fmt.Errorf("get sign privkey: %w", err)
	}

	signature, err := common.SignTimestamp(privKey, clientID, timestamp)
	if err != nil {
		return fmt.Errorf("sign timestamp: %w", err)
	}

	payload := common.RegisterPayload{
		ReAuth:        true,
		ClientID:      clientID,
		DevicePubkey:  c.identity.DeviceSignPubkey,
		Timestamp:     timestamp,
		Signature:     common.EncodeBytes(signature),
		Hostname:      "",
		OS:            "",
	}
	payloadJSON, _ := json.Marshal(payload)

	return c.Send(&common.Message{
		Type:    "register",
		Payload: payloadJSON,
	})
}

func (c *Connector) SendPing() error {
	return c.Send(&common.Message{Type: "ping"})
}