package agent

import (
	"testing"

	"goremote/internal/common"
)

func TestProcessRegisterOKSavesConfiguredIdentityDir(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.IdentityDir = dir
	cfg.Server.Address = "example:8080"

	identity, err := CreateIdentity(dir, cfg.Server.Address)
	if err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}

	ag := NewAgent(cfg, identity)
	if err := ag.processRegisterOK(&common.RegisterOKPayload{
		ClientID:   "client-test",
		EncEnabled: false,
	}); err != nil {
		t.Fatalf("processRegisterOK: %v", err)
	}

	reloaded, err := LoadIdentity(dir)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	if reloaded == nil {
		t.Fatal("expected identity to be saved")
	}
	if reloaded.ClientID != "client-test" {
		t.Fatalf("expected client ID to be saved in configured identity dir, got %q", reloaded.ClientID)
	}
}
