package agent

import "testing"

func TestConnectorCloseReconnectCycleRecreatesDoneChannel(t *testing.T) {
	c := NewConnector("localhost:8080", false, "", "secret", false)

	firstDone := c.Done()
	if err := c.Close(); err != nil {
		t.Fatalf("first Close returned error: %v", err)
	}

	select {
	case <-firstDone:
	default:
		t.Fatal("expected first done channel to be closed after Close")
	}

	c.resetConnectionState(nil)

	secondDone := c.Done()
	if secondDone == firstDone {
		t.Fatal("expected a fresh done channel after reconnect")
	}

	select {
	case <-secondDone:
		t.Fatal("expected new done channel to remain open")
	default:
	}

	if err := c.Close(); err != nil {
		t.Fatalf("second Close returned error: %v", err)
	}

	select {
	case <-secondDone:
	default:
		t.Fatal("expected second done channel to be closed after Close")
	}
}
