package main

import (
	"encoding/json"
	"testing"
)

func TestAdvancedCaptchaDoesNotChangeKeysOrOverrideManual(t *testing.T) {
	p, e := parseProfile(share(fixture()))
	if e != nil {
		t.Fatal(e)
	}
	original := p.Core
	configured, e := configureCaptcha(original, true)
	if e != nil {
		t.Fatal(e)
	}
	var before, after map[string]any
	json.Unmarshal([]byte(original), &before)
	json.Unmarshal([]byte(configured), &after)
	b := before["vk"].(map[string]any)
	a := after["vk"].(map[string]any)
	if a["advancedCaptcha"] != true || a["autoCaptcha"] != true {
		t.Fatal("experimental automatic mode not configured")
	}
	a["advancedCaptcha"] = b["advancedCaptcha"]
	expected, _ := json.Marshal(before)
	actual, _ := json.Marshal(after)
	if string(actual) != string(expected) {
		t.Fatal("unrelated configuration or credentials changed")
	}
	b["manualCaptcha"] = true
	manual, _ := json.Marshal(before)
	configured, e = configureCaptcha(string(manual), true)
	if e != nil {
		t.Fatal(e)
	}
	json.Unmarshal([]byte(configured), &after)
	if after["vk"].(map[string]any)["advancedCaptcha"] != false {
		t.Fatal("manual mode overridden")
	}
}

func TestCaptchaOptionRejectedOnUnrelatedIPC(t *testing.T) {
	enabled := true
	b := &broker{}
	r := b.dispatch(request{V: 1, Op: "status", AdvancedCaptcha: &enabled})
	if r.OK || r.Error != "INVALID_REQUEST" {
		t.Fatal("connect-only option accepted elsewhere")
	}
}

func TestSocksOptionsRejectedOnUnrelatedIPC(t *testing.T) {
	b := &broker{}
	for _, op := range []string{"status", "connect", "disconnect", "import"} {
		r := b.dispatch(request{V: 1, Op: op, Socks: &socksOptions{Port: 1080, User: "SYNTHETIC_USER", Password: "SYNTHETIC_PASSWORD"}})
		if r.OK || r.Error != "INVALID_REQUEST" {
			t.Fatal("SOCKS options accepted on unrelated operation")
		}
	}
}

func TestCaptchaChallengeIdentityIsNotStatusPolling(t *testing.T) {
	sink := &events{}
	sink.OnCaptcha("http://localhost:8765/synthetic", false)
	first := sink.state.CaptchaID
	sink.OnState("captcha", 0, 1, "")
	if first == 0 || sink.state.CaptchaID != first {
		t.Fatal("status polling changed challenge identity")
	}
	sink.OnCaptcha("", false)
	sink.OnCaptcha("http://localhost:8765/synthetic", false)
	if sink.state.CaptchaID <= first {
		t.Fatal("same URL for a new challenge reused browser state")
	}
	previous := sink.state.CaptchaID
	sink.OnCaptcha("https://invalid.example/", true)
	if sink.state.CaptchaID != previous || sink.state.Manual {
		t.Fatal("external challenge accepted")
	}
}
