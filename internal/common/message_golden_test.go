package common

import (
	"encoding/json"
	"testing"
)

// TestRegisterPayloadSchemaIsFrozen 是阶段四的硬门之一：注册报文的 JSON 字段集
// 必须与改动前逐字节相同。
//
// 为什么这条测试比它看起来重要：全仓 28 处 DecodeStrictJSON 一律拒绝未知字段，
// 所以给注册/注册应答加任何一个字段，都会让「新 agent × 老服务端」或
// 「老 agent × 新服务端」在第一条消息就被判非法并断开。版本与能力位因此全部
// 走 WS 握手，这里就是那条约束的看门人——字段一改，期望串必须显式改动，
// 改动的人会被迫想清楚兼容性。
func TestRegisterPayloadSchemaIsFrozen(t *testing.T) {
	register := RegisterPayload{
		ReAuth:         true,
		ClientID:       "client-1",
		DevicePubkey:   "pub",
		DeviceDHPubkey: "dh",
		Hostname:       "host",
		OS:             "linux",
		Timestamp:      1700000000,
		Signature:      "sig",
	}
	encoded, err := json.Marshal(register)
	if err != nil {
		t.Fatalf("marshal register: %v", err)
	}
	const wantRegister = `{"reauth":true,"client_id":"client-1","device_pubkey":"pub","device_dh_pubkey":"dh","hostname":"host","os":"linux","timestamp":1700000000,"signature":"sig"}`
	if string(encoded) != wantRegister {
		t.Fatalf("register payload schema changed\n got: %s\nwant: %s", encoded, wantRegister)
	}

	// 新注册不带 client_id/timestamp/signature：omitempty 决定它们不出现，
	// 这正是老服务端能读懂的最小字段集。
	minimal := RegisterPayload{
		DevicePubkey: "pub",
		Hostname:     "host",
		OS:           "linux",
	}
	encoded, err = json.Marshal(minimal)
	if err != nil {
		t.Fatalf("marshal minimal register: %v", err)
	}
	const wantMinimal = `{"reauth":false,"device_pubkey":"pub","hostname":"host","os":"linux"}`
	if string(encoded) != wantMinimal {
		t.Fatalf("minimal register payload changed\n got: %s\nwant: %s", encoded, wantMinimal)
	}

	ok := RegisterOKPayload{
		ClientID:         "client-1",
		EncKeyEncrypted:  "enc",
		ServerDHPubkey:   "sdh",
		EncEnabled:       true,
		ServerSignPubkey: "spub",
		ServerSignature:  "sig",
	}
	encoded, err = json.Marshal(ok)
	if err != nil {
		t.Fatalf("marshal register_ok: %v", err)
	}
	const wantOK = `{"client_id":"client-1","enc_key_encrypted":"enc","server_dh_pubkey":"sdh","enc_enabled":true,"server_sign_pubkey":"spub","server_signature":"sig"}`
	if string(encoded) != wantOK {
		t.Fatalf("register_ok payload schema changed\n got: %s\nwant: %s", encoded, wantOK)
	}

	// 反向：老服务端下发的 register_ok 没有新字段时，新 agent 必须能严格解码。
	const legacyOK = `{"client_id":"client-1","enc_enabled":false}`
	var decoded RegisterOKPayload
	if err := DecodeStrictJSON([]byte(legacyOK), &decoded); err != nil {
		t.Fatalf("a legacy register_ok must still decode: %v", err)
	}
	if decoded.ClientID != "client-1" || decoded.EncEnabled {
		t.Fatalf("decoded legacy register_ok = %+v", decoded)
	}

	// 反向：新 agent 发出的最小注册报文，老服务端（严格解码）也必须接受。
	var legacyDecoded RegisterPayload
	if err := DecodeStrictJSON([]byte(wantMinimal), &legacyDecoded); err != nil {
		t.Fatalf("the minimal register payload must decode strictly: %v", err)
	}
	if legacyDecoded.DevicePubkey != "pub" {
		t.Fatalf("decoded register = %+v", legacyDecoded)
	}
}
