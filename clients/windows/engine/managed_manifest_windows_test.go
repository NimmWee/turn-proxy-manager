package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"golang.zx2c4.com/wireguard/windows/conf"
)

func managedManifestFixture() (map[string]any, string) {
	f := fixture()
	f["peer"] = "8.8.8.8:5000"
	local := share(f)
	ft := map[string]any{}
	for _, k := range []string{"v", "provider", "peer", "transport", "mode", "obf", "key", "n", "spc", "cid", "vk"} {
		ft[k] = f[k]
	}
	ft["dns"] = "auto"
	ft["mcap"] = false
	c, _ := conf.FromWgQuick(f["wg"].(string), "FTM")
	key := c.Peers[0].PublicKey.String()
	return map[string]any{"schema_version": 1, "format": "ftm-managed", "device_id": "11111111-2222-3333-4444-555555555555", "revision": int64(2), "name": "Обновление <>& 😀\u2028\\u2028", "platform": "windows", "wireguard": map[string]any{"client_public_key": c.Interface.PrivateKey.Public().String(), "addresses": []string{"10.77.43.9/32"}, "server_public_key": key, "preshared_key": key, "allowed_ips": []string{"0.0.0.0/0", "::/0"}, "dns": []string{"1.1.1.1", "8.8.8.8"}, "mtu": 1280, "local_endpoint": "127.0.0.1:9000", "persistent_keepalive": 25, "ipv6_policy": "block"}, "freeturn": ft, "management": map[string]any{"origin": "https://8.8.8.8", "api_path": "/api/client/v1/", "internal_api_ip": "10.77.43.1", "tls_server_name": "8.8.8.8", "refresh_seconds": 1800}}, local
}
func managedRequestFixture(t *testing.T, m map[string]any, local string) []byte {
	t.Helper()
	raw, _ := json.Marshal(m)
	canonical, e := canonicalManagedJSON(raw)
	if e != nil {
		t.Fatal(e)
	}
	hash := sha256.Sum256(canonical)
	result, _ := json.Marshal(map[string]any{"manifest": json.RawMessage(raw), "current_share": local, "device_id": "11111111-2222-3333-4444-555555555555", "public_key": "m0rVC68DRvql2CjJskgoBO6cCjUnQpp6kqHVqk2ztiY=", "origin": "https://8.8.8.8", "etag": "\"" + hex.EncodeToString(hash[:]) + "\"", "min_revision": int64(2)})
	return result
}
func TestManagedUpdateKeepsPrivateKeyAndRejectsSubstitution(t *testing.T) {
	m, local := managedManifestFixture()
	result, e := buildManagedUpdate(managedRequestFixture(t, m, local))
	if e != nil {
		t.Fatal("valid managed update refused")
	}
	p, _ := parseProfile(result.Share)
	next, _ := conf.FromWgQuick(p.WG, "FTM")
	old, _ := parseProfile(local)
	previous, _ := conf.FromWgQuick(old.WG, "FTM")
	if next.Interface.PrivateKey != previous.Interface.PrivateKey || result.Revision != 2 {
		t.Fatal("managed update replaced local private key")
	}
	for _, mutate := range []func(map[string]any){
		func(v map[string]any) { v["device_id"] = "22222222-2222-3333-4444-555555555555" },
		func(v map[string]any) { v["revision"] = int64(1) },
		func(v map[string]any) {
			v["wireguard"].(map[string]any)["client_public_key"] = previous.Peers[0].PublicKey.String()
		},
		func(v map[string]any) { v["management"].(map[string]any)["origin"] = "https://1.1.1.1" },
		func(v map[string]any) { v["management"].(map[string]any)["internal_api_ip"] = "169.254.169.254" },
		func(v map[string]any) { v["wireguard"].(map[string]any)["addresses"] = []string{"10.99.1.5/32"} },
		func(v map[string]any) { v["freeturn"].(map[string]any)["private_key"] = "SYNTHETIC_SECRET" },
	} {
		bad, local := managedManifestFixture()
		mutate(bad)
		if _, e := buildManagedUpdate(managedRequestFixture(t, bad, local)); e == nil || e.Error() != "MANAGED_CONFIG_INVALID" {
			t.Fatal("managed substitution accepted or private error leaked")
		}
	}
	raw := managedRequestFixture(t, m, local)
	raw = bytes.Replace(raw, []byte(`"etag":"\"`), []byte(`"etag":"\"0`), 1)
	if _, e := buildManagedUpdate(raw); e == nil {
		t.Fatal("invalid ETag accepted")
	}
}
func TestManagedCanonicalJSONMatchesPythonEscaping(t *testing.T) {
	raw := []byte("{\"z\":\"\\u2028\\\\u2028 <>&😀\",\"a\":1}")
	got, e := canonicalManagedJSON(raw)
	expected := []byte("{\"a\":1,\"z\":\" \\\\u2028 <>&😀\"}")
	if e != nil || !bytes.Equal(got, expected) {
		t.Fatal("canonical JSON differs from Python ensure_ascii=False sort_keys encoding")
	}
}
