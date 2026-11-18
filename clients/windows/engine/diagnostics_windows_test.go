package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDiagnosticEventsContainOnlySafeCodes(t *testing.T) {
	sink := &events{state: runtimeState{State: "connecting"}}
	sink.OnLog("info", "[STREAM 0] [Captcha] Solving captcha (platform=SYNTHETIC_SECRET)...", 0)
	sink.OnLog("warn", "dial TURN (tcp): context deadline exceeded https://vk.com/call/join/SYNTHETIC_SECRET PrivateKey=SYNTHETIC_SECRET", 0)
	sink.OnState("error", 0, 6, "all VK credentials failed: SYNTHETIC_SECRET")
	data, _ := json.Marshal(sink.state)
	if strings.Contains(string(data), "SYNTHETIC_SECRET") || sink.state.ErrorCode == "" || sink.state.Stage != "error" {
		t.Fatal("diagnostic leaked raw data or lost failure")
	}
	if stage, _ := coreLogDiagnostic("info", "unrelated SYNTHETIC_SECRET"); stage != "" {
		t.Fatal("invented progress from unrelated log")
	}
	if safeRuntimeError("unrecognized SYNTHETIC_SECRET") != "TUNNEL_START_FAILED" {
		t.Fatal("raw runtime failure escaped allowlist")
	}
}
