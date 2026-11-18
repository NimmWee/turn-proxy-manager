package main

import "testing"

func TestSystemRoutingPreviewStrictAndInactive(t *testing.T) {
	for _, bad := range []string{
		`{"policy":{"v":1,"enabled":true,"shell":"x"}}`,
		`{"policy":{"v":1,"enabled":true,"enabled":false}}`,
		`{"policy":{"v":1,"presets":{"russianDirect":true,"unknown":true}}}`,
		`{"policy":{"v":1},"host":"https://example.com"}`,
		`{"policy":{"v":1},"ip":"wrong"}`,
	} {
		if _, e := checkSystemRouting([]byte(bad)); e == nil {
			t.Fatal("invalid preview accepted")
		}
	}
	result, e := checkSystemRouting([]byte(`{"policy":{"v":1,"enabled":true,"presets":{"russianDirect":true,"youtubeVPN":true}},"host":"youtube.com","ip":"77.88.55.55"}`))
	if e != nil {
		t.Fatal(e)
	}
	if result["active"] != false || result["networkChanged"] != false || result["runtimeIntegrated"] != result["gvisorCompiled"] || result["decision"].(routingDecision).Action != "vpn" {
		t.Fatal("preview claimed active or lost policy precedence")
	}
}
