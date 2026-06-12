package agent

import (
	"encoding/json"
	"testing"

	"goremote/internal/common"
)

func signedRegisterOK(t *testing.T, clientID string, encEnabled bool, serverDHPubkey, encKeyEncrypted string) common.RegisterOKPayload {
	t.Helper()

	pub, priv, err := common.GenerateSignKeypair()
	if err != nil {
		t.Fatalf("GenerateSignKeypair: %v", err)
	}
	sig, err := common.SignServerKeyPayload(priv, clientID, encEnabled, serverDHPubkey, encKeyEncrypted)
	if err != nil {
		t.Fatalf("SignServerKeyPayload: %v", err)
	}

	return common.RegisterOKPayload{
		ClientID:         clientID,
		EncKeyEncrypted:  encKeyEncrypted,
		ServerDHPubkey:   serverDHPubkey,
		EncEnabled:       encEnabled,
		ServerSignPubkey: common.EncodePublicKey(pub),
		ServerSignature:  common.EncodeBytes(sig),
	}
}

func TestProcessRegisterOKPinsServerSignKey(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.IdentityDir = dir
	identity, err := CreateIdentity(dir, "example:8080")
	if err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}

	ag := NewAgent(cfg, identity)
	payload := signedRegisterOK(t, "client-auth", false, "", "")
	if err := ag.processRegisterOK(&payload); err != nil {
		t.Fatalf("processRegisterOK: %v", err)
	}

	if identity.ServerSignPubkey != payload.ServerSignPubkey {
		t.Fatalf("expected server sign pubkey to be pinned, got %q", identity.ServerSignPubkey)
	}
}

func TestProcessRegisterOKRejectsTamperedServerSignature(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.IdentityDir = dir
	identity, err := CreateIdentity(dir, "example:8080")
	if err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}

	ag := NewAgent(cfg, identity)
	payload := signedRegisterOK(t, "client-auth", false, "", "")
	payload.EncEnabled = true
	if err := ag.processRegisterOK(&payload); err == nil {
		t.Fatal("expected tampered payload to be rejected")
	}
}

func TestRegisterUpdateRequiresSignatureAfterPin(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.IdentityDir = dir
	identity, err := CreateIdentity(dir, "example:8080")
	if err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}

	ag := NewAgent(cfg, identity)
	payload := signedRegisterOK(t, "client-auth", false, "", "")
	if err := ag.processRegisterOK(&payload); err != nil {
		t.Fatalf("processRegisterOK: %v", err)
	}

	update := common.RegisterUpdatePayload{ClientID: "client-auth", EncEnabled: false}
	data, _ := json.Marshal(update)
	if err := ag.handler.handleRegisterUpdate(&common.Message{Type: "register_update", Payload: data}); err == nil {
		t.Fatal("expected unsigned register_update to be rejected after pinning server key")
	}
}
