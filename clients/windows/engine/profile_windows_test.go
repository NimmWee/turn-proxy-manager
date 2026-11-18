package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func fixture() map[string]any {
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
	return map[string]any{"v": 1, "provider": "vk", "peer": "203.0.113.1:5000", "mode": "udp", "transport": "tcp", "obf": "rtpopus3", "key": strings.Repeat("a", 64), "cid": strings.Repeat("b", 32), "n": 6, "spc": 3, "vk": "https://vk.com/call/join/SYNTHETIC", "wg": "[Interface]\nPrivateKey = " + key + "\nAddress = 10.77.43.9/32\nDNS = 1.1.1.1\nMTU = 1280\n[Peer]\nPublicKey = " + key + "\nPresharedKey = " + key + "\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 127.0.0.1:9000\nPersistentKeepalive = 25\n"}
}

func share(v map[string]any) string {
	b, _ := json.Marshal(v)
	return "freeturn://" + base64.RawURLEncoding.EncodeToString(b)
}

func TestImportPreservesSecretsWithoutNetwork(t *testing.T) {
	p, err := parseProfile(share(fixture()))
	if err != nil {
		t.Fatal(err)
	}
	if p.WG != fixture()["wg"] {
		t.Fatal("WG config changed")
	}
	var config map[string]any
	json.Unmarshal([]byte(p.Core), &config)
	if config["routes"] != false || config["subUrl"] != "" {
		t.Fatal("unexpected routing or subscription")
	}
	if config["proxy"].(map[string]any)["listen"] != "127.0.0.1:9000" {
		t.Fatal("non-local listener")
	}
}

func TestDirectAndRelayTransportsPreserveKeysAndRoutes(t *testing.T) {
	for _, provider := range []string{"vk", "direct"} {
		for _, transport := range []string{"tcp", "udp"} {
			for _, obf := range []string{"none", "rtpopus", "rtpopus2", "rtpopus3"} {
				v := fixture()
				v["provider"], v["transport"], v["obf"] = provider, transport, obf
				if provider == "direct" {
					v["vk"] = ""
				}
				if obf == "none" {
					v["key"] = ""
				}
				p, err := parseProfile(share(v))
				if err != nil {
					t.Fatalf("supported %s/%s/%s rejected", provider, transport, obf)
				}
				var core map[string]any
				json.Unmarshal([]byte(p.Core), &core)
				if p.WG != v["wg"] || core["clientId"] != v["cid"] || core["routes"] != false || core["provider"] != provider || core["turn"].(map[string]any)["transport"] != transport {
					t.Fatal("profile altered secrets, routing or transport")
				}
			}
		}
	}
}

func TestStandaloneForwarderCannotBecomeVPNOrPublicListener(t *testing.T) {
	v := fixture()
	v["wg"], v["mode"], v["listen"] = "", "tcp", "127.0.0.1:19000"
	v["bond"] = true
	v["kcp"] = map[string]any{"nodelay": 1, "interval": 20, "resend": 2, "nc": 1, "sndwnd": 512, "rcvwnd": 512, "mtu": 1200, "acknodelay": true}
	p, err := parseProfile(share(v))
	if err != nil {
		t.Fatal("TCP forwarder rejected")
	}
	var core map[string]any
	json.Unmarshal([]byte(p.Core), &core)
	if p.WG != "" || core["routes"] != false || core["proxy"].(map[string]any)["mode"] != "tcp" || core["tunnel"].(map[string]any)["mode"] != "none" {
		t.Fatal("standalone forwarder changed network ownership")
	}
	v["listen"] = "0.0.0.0:19000"
	if _, err = parseProfile(share(v)); err == nil {
		t.Fatal("public forwarder accepted")
	}
	v["listen"] = "127.0.0.1:22"
	if _, err = parseProfile(share(v)); err == nil {
		t.Fatal("privileged forwarder accepted")
	}
}

func TestRejectUnsafeProfilesWithoutEchoingSecrets(t *testing.T) {
	for _, mutation := range []func(map[string]any){
		func(v map[string]any) {
			v["wg"] = strings.ReplaceAll(v["wg"].(string), "[Peer]", "PostUp = SECRET_COMMAND\n[Peer]")
		},
		func(v map[string]any) {
			v["wg"] = strings.ReplaceAll(v["wg"].(string), "127.0.0.1:9000", "8.8.8.8:9000")
		},
		func(v map[string]any) { v["listen"] = "0.0.0.0:9000" },
		func(v map[string]any) { v["vk"] = "https://evil.invalid/SECRET_LINK" },
		func(v map[string]any) { v["mode"] = "tcp" },
		func(v map[string]any) { v["kcp"] = map[string]any{"mtu": 1} },
	} {
		v := fixture()
		mutation(v)
		if _, err := parseProfile(share(v)); err == nil {
			t.Fatal("unsafe profile accepted")
		} else if strings.Contains(err.Error(), "SECRET") {
			t.Fatal("secret exposed")
		}
	}
	duplicate := `{"v":1,"v":1,"provider":"vk","peer":"SECRET"}`
	if _, err := parseProfile("freeturn://" + base64.RawURLEncoding.EncodeToString([]byte(duplicate))); err == nil {
		t.Fatal("duplicate key accepted")
	}
	if _, err := parseProfile(strings.Repeat("x", maxMessage+1)); err == nil {
		t.Fatal("oversized profile accepted")
	}
}
