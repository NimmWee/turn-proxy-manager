package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestStructuredJournalPrivacyAndBound(t *testing.T) {
	s := &events{state: runtimeState{State: "connecting"}}
	for i := 0; i < 180; i++ {
		s.OnLog("info", fmt.Sprintf("[STREAM %d] TURN allocation up: https://vk.com/call/join/SYNTHETIC_PRIVATE cid=SYNTHETIC_PRIVATE", i%32), 0)
	}
	s.OnState("connected", 6, 6, "")
	b, _ := json.Marshal(s.state)
	if len(s.state.Events) == 0 || len(s.state.Events) > 128 || strings.Contains(string(b), "SYNTHETIC_PRIVATE") {
		t.Fatal("journal missing, unbounded or leaked secret")
	}
	for _, e := range s.state.Events {
		if !validEventCode(e.Code) {
			t.Fatal("unknown raw event crossed boundary")
		}
	}
	if len(b) > 48*1024 {
		t.Fatal("journal exceeds bounded IPC budget")
	}
}
