package main

import (
	"strings"
	"testing"
	"time"
)

func TestProfileIdentityAndRuntimeGuard(t *testing.T) {
	id := profileIdentity(" freeturn://SYNTHETIC \r\n")
	if id != "67ba0bd705841a5fb85085e6e8d9837a17aebcc300a6c86d6986743bf68bb1a9" || !validProfileIdentity(id) {
		t.Fatal("identity contract mismatch")
	}
	now := time.Unix(1700000000, 0)
	state := runtimeState{PID: 42, Updated: now.Unix(), EventSession: 123, ProfileIdentity: id}
	options := connectionOptions{AttemptID: 123, ProfileIdentity: id}
	if got, attempt := runtimeIdentity(state, options, 42, now); got != id || attempt != 123 {
		t.Fatal("valid runtime rejected")
	}
	bad := []runtimeState{state, state, state, state, state, state}
	bad[0].PID++
	bad[1].Updated -= 7
	bad[2].Updated++
	bad[3].EventSession++
	bad[4].ProfileIdentity = strings.Repeat("b", 64)
	bad[5].ProfileIdentity = ""
	for _, s := range bad {
		if got, attempt := runtimeIdentity(s, options, 42, now); got != "" || attempt != 0 {
			t.Fatal("stale or different runtime accepted")
		}
	}
	if got, _ := runtimeIdentity(state, connectionOptions{}, 42, now); got != "" {
		t.Fatal("legacy options identified as current runtime")
	}
	r := response{OK: true, TunnelActive: true, RuntimeProfileIdentity: id, ConnectionID: 123}
	if !matchesRuntime(r, id, 123) || matchesRuntime(r, id, 124) || matchesRuntime(r, strings.Repeat("b", 64), 123) || matchesRuntime(r, id, 0) {
		t.Fatal("conditional stop could target another attempt/profile")
	}
	r.TunnelActive = false
	if matchesRuntime(r, id, 123) {
		t.Fatal("stopped runtime accepted")
	}
}

func TestRuntimeRequestFieldsFailBeforeSCM(t *testing.T) {
	b := &broker{dir: t.TempDir()}
	// Empty private state cannot establish a runtime identity. This exercises only
	// SCM queries (if installed); the conditional stop must refuse before mutation.
	if r := b.dispatch(request{V: 1, Op: "disconnect-if-current", ExpectedProfile: strings.Repeat("a", 64), ExpectedAttempt: 1}); r.OK || r.Error != "CONNECTION_CHANGED" {
		t.Fatal("unidentified runtime reached stop")
	}
	for _, q := range []request{
		{V: 1, Op: "disconnect-if-current"},
		{V: 1, Op: "disconnect-if-current", ExpectedProfile: strings.Repeat("a", 64)},
		{V: 1, Op: "disconnect-if-current", ExpectedProfile: "bad", ExpectedAttempt: 1},
		{V: 1, Op: "disconnect", ExpectedProfile: strings.Repeat("a", 64), ExpectedAttempt: 1},
		{V: 1, Op: "status", ExpectedAttempt: 1},
	} {
		if r := b.dispatch(q); r.OK || r.Error != "INVALID_REQUEST" {
			t.Fatal("guard fields reached service operations")
		}
	}
	if _, err := decodeConnectionOptions([]byte(`{"advancedCaptcha":false,"profileIdentity":"bad"}`)); err == nil {
		t.Fatal("malformed protected options accepted")
	}
}
