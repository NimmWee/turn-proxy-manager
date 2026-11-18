package main

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func TestPathRendererPreservesIdentity(t *testing.T) {
	raw := share(fixture())
	p, err := parseProfile(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"direct", "relay"} {
		core, err := coreForPath(raw, path, false)
		if err != nil {
			t.Fatal(err)
		}
		var original, changed map[string]any
		json.Unmarshal([]byte(p.Core), &original)
		json.Unmarshal([]byte(core), &changed)
		for _, key := range []string{"peer", "clientId", "obf", "proxy", "dns", "tunnel"} {
			a, _ := json.Marshal(original[key])
			b, _ := json.Marshal(changed[key])
			if string(a) != string(b) {
				t.Fatal("path switch changed identity/config", key)
			}
		}
		provider := "vk"
		if path == "direct" {
			provider = "direct"
		}
		if changed["provider"] != provider {
			t.Fatal("wrong provider")
		}
	}
	if _, err := coreForPath(raw, "invalid", false); err == nil {
		t.Fatal("unknown path accepted")
	}
}

func TestPathWorkerJournalAndNoNetworkRestart(t *testing.T) {
	dir := t.TempDir()
	raw := share(fixture())
	identity := profileIdentity(raw)
	opts := connectionOptions{AttemptID: 123, ProfileIdentity: identity, AutoPaths: true, InitialPath: "direct"}
	data, _ := json.Marshal(opts)
	if err := writeSecret(filepath.Join(dir, "options.dpapi"), "FreeTurn connection options v1", data); err != nil {
		t.Fatal(err)
	}
	journal := pathJournal{1, 123, identity, 1, "relay"}
	data, _ = json.Marshal(journal)
	if err := writeSecret(filepath.Join(dir, "transport-path.dpapi"), "FreeTurn transport path v1", data); err != nil {
		t.Fatal(err)
	}
	sink := &events{state: runtimeState{ProfileIdentity: identity, EventSession: 123, PathMode: "direct"}}
	called := make(chan string, 1)
	stop := startPathWorker(dir, raw, opts, sink, func(core string) error { called <- core; return nil })
	select {
	case <-called:
	case <-time.After(4 * time.Second):
		stop()
		t.Fatal("synthetic restart not called")
	}
	stop()
	sink.mu.Lock()
	epoch, path := sink.state.PathEpoch, sink.state.PathMode
	sink.mu.Unlock()
	if epoch != 1 || path != "relay" {
		t.Fatal("restart acknowledgement missing")
	}
	if _, path, epoch, err := effectivePathCore(dir, raw, opts); err != nil || path != "relay" || epoch != 1 {
		t.Fatal("restart reset durable budget/path")
	}
	b := &broker{dir: dir}
	r := response{OK: true, State: "connected"}
	state := runtimeState{PathMode: "direct"}
	if !b.pathStatus(&r, state, opts) || !r.PathPending || r.State == "connected" {
		t.Fatal("pending journal exposed old proof")
	}
	b.probeConfirmed = time.Now()
	state.PathMode = "relay"
	state.PathEpoch = 1
	r = response{OK: true, State: "connected"}
	if b.pathStatus(&r, state, opts) || !b.probeConfirmed.IsZero() {
		t.Fatal("old egress proof survived epoch change")
	}
	opts.Cancelled = true
	data, _ = json.Marshal(opts)
	if writeSecret(filepath.Join(dir, "options.dpapi"), "FreeTurn connection options v1", data) != nil {
		t.Fatal("cancel save failed")
	}
	journal.Epoch = 2
	journal.Target = "direct"
	data, _ = json.Marshal(journal)
	if writeSecret(filepath.Join(dir, "transport-path.dpapi"), "FreeTurn transport path v1", data) != nil {
		t.Fatal("journal save failed")
	}
	stop = startPathWorker(dir, raw, opts, sink, func(string) error { called <- "unexpected"; return nil })
	time.Sleep(1100 * time.Millisecond)
	stop()
	select {
	case <-called:
		t.Fatal("cancelled attempt restarted transport")
	default:
	}
	for _, bad := range []string{`{}`, `{"version":1,"attempt":123,"identity":"` + identity + `","epoch":3,"target":"direct"}`, `{"version":1,"version":1}`} {
		if _, err := decodePathJournal([]byte(bad)); err == nil {
			t.Fatal("invalid journal accepted")
		}
	}
}

func TestPathSwitchGuard(t *testing.T) {
	id := profileIdentity("freeturn://SYNTHETIC")
	r := response{OK: true, State: "handshake", TunnelActive: true, RuntimeProfileIdentity: id, ConfiguredProfileIdentity: id, ConnectionID: 123, LastAttemptID: 123, AutoPaths: true, RuntimePath: "direct"}
	if !canSwitchPath(r, id, 123, 0, "relay") {
		t.Fatal("eligible attempt rejected")
	}
	bad := r
	bad.State = "connected"
	if canSwitchPath(bad, id, 123, 0, "relay") {
		t.Fatal("healthy path switched")
	}
	bad = r
	bad.PathPending = true
	if canSwitchPath(bad, id, 123, 0, "relay") {
		t.Fatal("pending request repeated")
	}
	bad = r
	bad.PathEpoch = 2
	if canSwitchPath(bad, id, 123, 2, "relay") {
		t.Fatal("budget exceeded")
	}
	if canSwitchPath(r, id, 124, 0, "relay") || canSwitchPath(r, id, 123, 1, "relay") || canSwitchPath(r, id, 123, 0, "direct") {
		t.Fatal("wrong attempt/epoch/target accepted")
	}
	bad = r
	bad.Captcha = "http://127.0.0.1:8765/"
	if canSwitchPath(bad, id, 123, 0, "relay") {
		t.Fatal("captcha interrupted")
	}
	state := runtimeState{PathStartedAt: 100}
	if pathEgressReady(state, 107) || pathEgressReady(state, 108) || !pathEgressReady(state, 109) {
		t.Fatal("old/in-flight probe attributed to new path")
	}
	b := &broker{dir: t.TempDir()}
	enabled := true
	for _, q := range []request{{V: 1, Op: "status", AutoPaths: &enabled}, {V: 1, Op: "switch-path-if-current", Path: "relay"}, {V: 1, Op: "status", ExpectedEpoch: 1}, {V: 1, Op: "status", RecoveryPath: "direct"}} {
		if r := b.dispatch(q); r.OK || r.Error != "INVALID_REQUEST" {
			t.Fatal("path fields reached unrelated IPC")
		}
	}
}
