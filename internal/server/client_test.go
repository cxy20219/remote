package server

import "testing"

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
