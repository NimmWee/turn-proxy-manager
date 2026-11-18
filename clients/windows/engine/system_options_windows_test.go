package main

import (
	"encoding/json"
	"strings"
	"testing"

	tun "github.com/sagernet/sing-tun"
)

func TestSystemOptionsStrictAndLegacyDefault(t *testing.T) {
	legacy, e := decodeConnectionOptions([]byte(`{"advancedCaptcha":true,"attemptId":42}`))
	if e != nil || systemRoutingEnabled(legacy.SystemRouting) || !legacy.AdvancedCaptcha {
		t.Fatal("legacy mode changed")
	}
	for _, bad := range []string{
		`{"systemRouting":{"v":1,"enabled":true,"shell":"x"}}`,
		`{"systemRouting":{"v":1,"enabled":true,"Enabled":false}}`,
		`{"systemRouting":{"v":1,"directDNS":["169.254.169.254"]}}`,
		`{"systemRouting":{"v":1,"directDNS":["1.1.1.1","1.1.1.1"]}}`,
	} {
		if _, e := decodeConnectionOptions([]byte(bad)); e == nil {
			t.Fatal("invalid SYSTEM options accepted")
		}
	}
	policy := &systemPolicy{V: 1, Enabled: true, DirectDNS: []string{"77.88.8.8"}}
	compiled, e := prepareSystemRouting(policy, fixture()["wg"].(string))
	if !tun.WithGVisor {
		if e == nil || e.Error() != "SYSTEM_ROUTING_BUILD_REQUIRED" {
			t.Fatal("missing backend accepted")
		}
		return
	}
	if e != nil {
		t.Fatal(e)
	}
	policy.DirectDNS[0] = "1.1.1.1"
	if compiled.DirectDNS[0] != "77.88.8.8" {
		t.Fatal("options mutated after validation")
	}
	encoded, _ := json.Marshal(connectionOptions{AttemptID: 42, SystemRouting: compiled.systemPolicy, FakeDNSRequired: true})
	loaded, e := decodeConnectionOptions(encoded)
	if e != nil || !loaded.FakeDNSRequired || !systemRoutingEnabled(loaded.SystemRouting) || loaded.SystemRouting.DirectDNS[0] != "77.88.8.8" {
		t.Fatal("routing options roundtrip failed")
	}
	for _, badWG := range []string{"", strings.Replace(fixture()["wg"].(string), "10.77.43.9", "10.10.10.9", 1), strings.Replace(fixture()["wg"].(string), "DNS = 1.1.1.1", "DNS = 10.77.43.1", 1)} {
		if _, e := prepareSystemRouting(compiled.systemPolicy, badWG); e == nil {
			t.Fatal("unsupported profile accepted before SCM")
		}
	}
}

func TestSystemIPCRejectsPolicyOnReadOperations(t *testing.T) {
	b := &broker{}
	for _, op := range []string{"status", "disconnect", "socks-stop", "import"} {
		r := b.dispatch(request{V: 1, Op: op, SystemRouting: &systemPolicy{V: 1, Enabled: true}})
		if r.OK || r.Error != "INVALID_REQUEST" {
			t.Fatal("policy accepted outside explicit connect")
		}
	}
}
