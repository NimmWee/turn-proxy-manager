package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEffectiveSettingsAndManualPreference(t *testing.T) {
	raw := share(fixture())
	p, err := parseProfile(raw)
	if err != nil {
		t.Fatal(err)
	}
	core, err := configureCaptcha(p.Core, true, true)
	if err != nil {
		t.Fatal(err)
	}
	report, err := describeEffective(raw, core)
	if err != nil {
		t.Fatal(err)
	}
	if !report.ManualCaptcha || report.AdvancedCaptcha {
		t.Fatal("manual preference did not reach core")
	}
	encoded, _ := json.Marshal(report)
	for _, secret := range []string{"privateKey", "preshared", "clientId", "links", "obf"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("unsafe effective settings field")
		}
	}
	direct, err := coreForPath(raw, "direct", true, true)
	if err != nil {
		t.Fatal(err)
	}
	report, err = describeEffective(raw, direct)
	if err != nil || report.StreamLimit != 1 || report.ManualCaptcha || report.Transport != "dtls" {
		t.Fatal("direct effective settings incorrect")
	}
	relay, err := coreForPath(raw, "relay", true, true)
	if err != nil {
		t.Fatal(err)
	}
	report, err = describeEffective(raw, relay)
	if err != nil || !report.ManualCaptcha || report.StreamLimit != report.RequestedStreams {
		t.Fatal("relay lost profile limits/manual preference")
	}
}
