package main

import (
	"strings"
	"testing"
)

func TestRecoveryAttemptGuard(t *testing.T) {
	id := profileIdentity("freeturn://SYNTHETIC")
	r := response{OK: true, State: "error", HasProfile: true, ConfiguredProfileIdentity: id, LastAttemptID: 123}
	if !canRecover(r, id, 123) {
		t.Fatal("stopped failed attempt rejected")
	}
	for _, bad := range []response{
		{OK: true, State: "stopped", ConfiguredProfileIdentity: id, LastAttemptID: 124},
		{OK: true, State: "error", ConfiguredProfileIdentity: strings.Repeat("b", 64), LastAttemptID: 123},
		{OK: false, State: "error", ConfiguredProfileIdentity: id, LastAttemptID: 123},
	} {
		if canRecover(bad, id, 123) {
			t.Fatal("different/untrusted attempt accepted")
		}
	}
	r.TunnelActive = true
	r.RuntimeProfileIdentity = id
	r.ConnectionID = 123
	if !canRecover(r, id, 123) {
		t.Fatal("identified failed runtime rejected")
	}
	for _, state := range []string{"connected", "captcha", "stopping"} {
		r.State = state
		if canRecover(r, id, 123) {
			t.Fatal("healthy/captcha/stopping session accepted")
		}
	}
	r.State = "starting"
	r.Captcha = "http://127.0.0.1:1234/"
	if canRecover(r, id, 123) {
		t.Fatal("captcha accepted")
	}
	r.Captcha = ""
	r.ConnectionID++
	if canRecover(r, id, 123) {
		t.Fatal("runtime receipt mismatch accepted")
	}
}

func TestRecoveryCannotReplaceClientKey(t *testing.T) {
	p, err := parseProfile(share(fixture()))
	if err != nil {
		t.Fatal(err)
	}
	if !sameRecoveryKey(p, p) {
		t.Fatal("unchanged client key rejected")
	}
	other := *p
	other.WG = strings.Replace(p.WG, "PrivateKey = ", "PrivateKey = INVALID", 1)
	if sameRecoveryKey(p, &other) || sameRecoveryKey(p, &profile{}) {
		t.Fatal("invalid/missing client key accepted")
	}
	key := strings.Fields(strings.SplitN(p.WG, "PrivateKey", 2)[1])[1]
	other.WG = strings.Replace(p.WG, key, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=", 1)
	if !safeWG(other.WG) || sameRecoveryKey(p, &other) {
		t.Fatal("different valid private key accepted")
	}
}

func TestRecoveryIPCRefusesUnidentifiedState(t *testing.T) {
	b := &broker{dir: t.TempDir()}
	r := b.dispatch(request{V: 1, Op: "recover-if-current", ExpectedProfile: strings.Repeat("a", 64), ExpectedAttempt: 1, Profile: share(fixture())})
	if r.OK || r.Error != "CONNECTION_CHANGED" {
		t.Fatal("unidentified service reached recovery writes")
	}
	for _, q := range []request{{V: 1, Op: "recover-if-current", Profile: share(fixture())}, {V: 1, Op: "recover-if-current", ExpectedProfile: strings.Repeat("a", 64), ExpectedAttempt: 1, SystemRouting: &systemPolicy{V: 1, Enabled: true}}} {
		if r := b.dispatch(q); r.OK || r.Error != "INVALID_REQUEST" {
			t.Fatal("invalid recovery options reached SCM")
		}
	}
	opts, err := decodeConnectionOptions([]byte(`{"advancedCaptcha":false,"attemptId":123,"cancelled":true}`))
	if err != nil || !opts.Cancelled || opts.AttemptID != 123 {
		t.Fatal("manual cancellation marker lost")
	}
	b.cancelRecovery()
	if !b.recoveryCancelled {
		t.Fatal("missing state blocked manual cancellation gate")
	}
}
