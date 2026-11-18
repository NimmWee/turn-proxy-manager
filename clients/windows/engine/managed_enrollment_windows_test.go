package main

import (
	"encoding/json"
	"testing"

	"golang.zx2c4.com/wireguard/windows/conf"
)

func TestManagedEnrollmentKeysAndFirstManifest(t *testing.T) {
	pair, e := newEnrollmentKey("https://8.8.8.8")
	if e != nil {
		t.Fatal("key generation failed")
	}
	other, e := newEnrollmentKey("https://8.8.8.8")
	if e != nil || other.PrivateKey == pair.PrivateKey || !validEnrollmentKey(pair.PrivateKey, pair.PublicKey, "https://8.8.8.8") {
		t.Fatal("new enrollment identity reused or invalid")
	}
	if validEnrollmentKey(pair.PrivateKey, other.PublicKey, "https://8.8.8.8") || validEnrollmentKey(pair.PrivateKey, pair.PublicKey, "https://169.254.169.254") {
		t.Fatal("unbound key/origin accepted")
	}
	m, local := managedManifestFixture()
	raw := managedRequestFixture(t, m, local)
	var original map[string]json.RawMessage
	json.Unmarshal(raw, &original)
	old, _ := parseProfile(local)
	wg, _ := conf.FromWgQuick(old.WG, "FTM")
	request := map[string]any{"manifest": original["manifest"], "private_key": wg.Interface.PrivateKey.String(), "public_key": wg.Interface.PrivateKey.Public().String(), "origin": "https://8.8.8.8", "device_id": m["device_id"], "client_id": m["freeturn"].(map[string]any)["cid"], "etag": json.RawMessage(original["etag"]), "min_revision": int64(1)}
	raw, _ = json.Marshal(request)
	result, e := buildInitialManaged(raw)
	if e != nil || result.Share == "" {
		t.Fatal("first manifest without fake profile refused")
	}
	request["client_id"] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	raw, _ = json.Marshal(request)
	if _, e := buildInitialManaged(raw); e == nil {
		t.Fatal("first manifest replaced locally registered ClientID")
	}
	request["client_id"] = m["freeturn"].(map[string]any)["cid"]
	request["private_key"] = other.PrivateKey
	raw, _ = json.Marshal(request)
	if _, e := buildInitialManaged(raw); e == nil {
		t.Fatal("first manifest replaced pending private key")
	}
}
