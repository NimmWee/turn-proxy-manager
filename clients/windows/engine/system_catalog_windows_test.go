package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"testing"
)

func TestSystemCatalogUsesPinnedGeoIPInsteadOfAllocation(t *testing.T) {
	var data struct {
		GeoIP struct {
			Provider     string `json:"provider"`
			Country      string `json:"country"`
			SourceSHA256 string `json:"sourceSHA256"`
		} `json:"geoIP"`
		Sources map[string]string `json:"sources"`
	}
	if json.Unmarshal(systemCatalogJSON, &data) != nil || data.GeoIP.Provider != "DB-IP Lite" || data.GeoIP.Country != "RU" || data.GeoIP.SourceSHA256 == "" || data.GeoIP.SourceSHA256 != data.Sources["dbipCountry"] {
		t.Fatal("RU IP routing still lacks pinned geolocation provenance")
	}
}

func TestSystemCatalogGeoIPRefusesTamperAndUnsafeFutureData(t *testing.T) {
	if _, e := decodeSystemCatalog(append(append([]byte{}, systemCatalogJSON...), byte(' ')), systemCatalogSHA256); e == nil {
		t.Fatal("changed catalog accepted")
	}
	for _, change := range []func(map[string]any){
		func(v map[string]any) { delete(v, "geoIP") },
		func(v map[string]any) { v["geoIP"].(map[string]any)["release"] = "not-a-month" },
		func(v map[string]any) { v["geoIP"].(map[string]any)["sourceSHA256"] = "bad" },
		func(v map[string]any) { v["geoIP"].(map[string]any)["country"] = "US" },
		func(v map[string]any) { v["geoIP"].(map[string]any)["ipv4Prefixes"] = 1 },
		func(v map[string]any) { p := v["ruPrefixes"].([]any); p[0] = "0.0.0.0/0" },
		func(v map[string]any) { p := v["ruPrefixes"].([]any); p[1] = p[0] },
	} {
		var value map[string]any
		if json.Unmarshal(systemCatalogJSON, &value) != nil {
			t.Fatal("fixture")
		}
		change(value)
		raw, _ := json.Marshal(value)
		sum := sha256.Sum256(raw)
		if _, e := decodeSystemCatalog(raw, hex.EncodeToString(sum[:])); e == nil {
			t.Fatal("unsafe catalog metadata/ranges accepted")
		}
	}
}

func TestSystemCatalogGeoIPKeepsProtectedAndExplicitPriorities(t *testing.T) {
	c, e := loadSystemCatalog()
	if e != nil {
		t.Fatal(e)
	}
	p, e := compileSystemPolicy(&systemPolicy{V: 1, Enabled: true, Presets: systemPresets{RussianDirect: true, YouTubeVPN: true, PushVPN: true}, Rules: []domainRule{{Domain: "blocked.example.com", Action: "block", Subdomains: true}, {Domain: "private.example.com", Action: "direct", Subdomains: true}}}, c)
	if e != nil {
		t.Fatal(e)
	}
	for _, test := range []struct{ host, ip, want string }{
		{"unlisted.example.com", "77.88.55.55", "direct"}, {"unlisted.example.com", "8.8.8.8", "vpn"},
		{"googlevideo.com", "77.88.55.55", "vpn"}, {"courier.push.apple.com", "77.88.55.55", "vpn"},
		{"blocked.example.com", "77.88.55.55", "block"}, {"private.example.com", "169.254.169.254", "block"},
		{"private.example.com", "10.77.43.1", "vpn"}, {"private.example.com", "168.63.129.16", "block"},
	} {
		if got := p.DecideFlow(test.host, netip.MustParseAddr(test.ip), 443, "tcp"); got.Action != test.want {
			t.Fatalf("GeoIP priority: %s/%s: %s", test.host, test.ip, got.Action)
		}
	}
}

func TestSystemCatalogPinnedDataAndSnapshot(t *testing.T) {
	c, e := loadSystemCatalog()
	if e != nil {
		t.Fatal(e)
	}
	if len(c.RU.Suffix) < 1900 || len(c.RUPrefixes) < 8000 {
		t.Fatal("incomplete country snapshot")
	}
	p, e := compileSystemPolicy(&systemPolicy{V: 1, Enabled: true, Presets: systemPresets{RussianDirect: true, YouTubeVPN: true, PushVPN: true, ConnectivityDirect: true}}, c)
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct{ host, want string }{{"ya.ru", "direct"}, {"googlevideo.com", "vpn"}, {"mtalk.google.com", "vpn"}, {"courier.push.apple.com", "vpn"}, {"connectivitycheck.gstatic.com", "direct"}, {"unlisted.example.com", "vpn"}} {
		if got := p.DecideFlow(tc.host, netip.MustParseAddr("1.1.1.1"), 443, "tcp"); got.Action != tc.want {
			t.Fatalf("%s = %s", tc.host, got.Action)
		}
	}
	// The caller cannot mutate compiled decisions or IP routes after validation.
	c.RU.Suffix[0] = "unlisted.example.com"
	c.RUPrefixes[0] = netip.MustParsePrefix("1.1.1.0/24")
	if p.DecideFlow("unlisted.example.com", netip.MustParseAddr("1.1.1.1"), 443, "tcp").Action != "vpn" {
		t.Fatal("catalog mutated after compilation")
	}
}
