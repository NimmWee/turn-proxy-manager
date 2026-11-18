package main

import (
	"encoding/json"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/windows/conf"
)

func TestManagedBootstrapBindsOriginAndLocalKeyWithoutNetwork(t *testing.T) {
	f := fixture()
	f["peer"] = "8.8.8.8:5000"
	wg, e := conf.FromWgQuick(f["wg"].(string), "FTM")
	if e != nil {
		t.Fatal("synthetic WG")
	}
	b := map[string]any{"version": 1, "format": "ftm-bootstrap", "device_id": "11111111-2222-3333-4444-555555555555", "public_key": wg.Interface.PrivateKey.Public().String(), "origin": "https://8.8.8.8", "internal_api_ip": "10.77.43.1", "claim_nonce": "ftmb1_" + strings.Repeat("A", 43), "expires_at": "2020-01-01T00:00:00Z", "share": share(f)}
	raw, _ := json.Marshal(b)
	if e := checkManagedBootstrap(raw); e != nil {
		t.Fatal("valid expired bootstrap refused before ordinary offline import")
	}
	otherPrivate := conf.Key{1}
	for field, value := range map[string]any{"origin": "https://1.1.1.1", "public_key": otherPrivate.Public().String(), "internal_api_ip": "169.254.169.254", "device_id": "../../secret", "claim_nonce": "ftmb1_secret\r\nHeader: evil", "unknown": true} {
		candidate := map[string]any{}
		for k, v := range b {
			candidate[k] = v
		}
		candidate[field] = value
		raw, _ = json.Marshal(candidate)
		if e := checkManagedBootstrap(raw); e == nil || e.Error() != "MANAGED_BOOTSTRAP_INVALID" {
			t.Fatal("key/origin/bounds substitution accepted or secret error exposed")
		}
	}
	raw, _ = json.Marshal(b)
	raw = append([]byte(`{"version":1,`), raw[1:]...)
	if checkManagedBootstrap(raw) == nil {
		t.Fatal("duplicate envelope field accepted")
	}
}
