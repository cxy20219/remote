package server

import (
	"testing"
	"time"
)

func TestClientWriteJSONWithNilConn(t *testing.T) {
	client := &Client{}

	if err := client.WriteJSON(map[string]string{"hello": "world"}); err == nil {
		t.Fatal("expected error when websocket connection is nil")
	}
}

func TestClientWriteMessageWithNilConn(t *testing.T) {
	client := &Client{}

	if err := client.WriteMessage(1, []byte("hello")); err == nil {
		t.Fatal("expected error when websocket connection is nil")
	}
}

func TestClientManagerStaleConnectionCannotRemoveReplacement(t *testing.T) {
	m := NewClientManager()
	oldClient := &Client{ClientID: "client-test"}
	newClient := &Client{ClientID: "client-test"}

	m.Add(oldClient)
	m.Add(newClient)

	if m.IsCurrent("client-test", oldClient) {
		t.Fatal("old client should not be current after replacement")
	}
	if !m.IsCurrent("client-test", newClient) {
		t.Fatal("new client should be current after replacement")
	}
	if m.RemoveIfMatch("client-test", oldClient) {
		t.Fatal("stale client should not remove replacement")
	}
	if _, ok := m.Get("client-test"); !ok {
		t.Fatal("replacement client should remain registered")
	}
	if !m.RemoveIfMatch("client-test", newClient) {
		t.Fatal("current client should be removable")
	}
}

func TestClientManagerStalePingCannotRefreshReplacement(t *testing.T) {
	m := NewClientManager()
	oldClient := &Client{ClientID: "client-test"}
	newClient := &Client{ClientID: "client-test"}

	m.Add(oldClient)
	oldPing := oldClient.LastPing
	m.Add(newClient)
	newClient.LastPing = time.Unix(1, 0)
	newPing := newClient.LastPing

	if m.UpdatePingIfMatch("client-test", oldClient) {
		t.Fatal("stale client should not update replacement heartbeat")
	}
	if !newClient.LastPing.Equal(newPing) {
		t.Fatal("replacement heartbeat should not change from stale ping")
	}
	if oldClient.LastPing != oldPing {
		t.Fatal("old client heartbeat should not change after replacement")
	}
	if !m.UpdatePingIfMatch("client-test", newClient) {
		t.Fatal("current client should update heartbeat")
	}
	if newClient.LastPing.Equal(newPing) {
		t.Fatal("expected current client heartbeat to change")
	}
}

func TestClientManagerActivityRefreshesCurrentClientOnly(t *testing.T) {
	m := NewClientManager()
	oldClient := &Client{ClientID: "client-test"}
	newClient := &Client{ClientID: "client-test"}

	m.Add(oldClient)
	oldPing := oldClient.LastPing
	m.Add(newClient)
	newClient.LastPing = time.Unix(1, 0)
	newPing := newClient.LastPing

	if m.UpdateActivityIfMatch("client-test", oldClient) {
		t.Fatal("stale client should not update replacement activity")
	}
	if !newClient.LastPing.Equal(newPing) {
		t.Fatal("replacement activity should not change from stale client")
	}
	if oldClient.LastPing != oldPing {
		t.Fatal("old client activity should not change after replacement")
	}
	if !m.UpdateActivityIfMatch("client-test", newClient) {
		t.Fatal("current client should update activity")
	}
	if newClient.LastPing.Equal(newPing) {
		t.Fatal("expected current client activity to change")
	}
}
