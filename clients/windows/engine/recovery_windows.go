package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc/mgr"
)

// Called only with broker.mu held, across guard, stop, profile write and start.
func (b *broker) connectAttempt(q request) response {
	fail := func(code string) response { return response{Error: code, State: "error"} }
	recovering := q.Op == "recover-if-current"
	r := b.status()
	if recovering && !canRecover(r, q.ExpectedProfile, q.ExpectedAttempt, q.ExpectedEpoch) {
		return fail("CONNECTION_CHANGED")
	}
	if !recovering && (!r.OK || r.State != "stopped" && !(r.State == "error" && !r.TunnelActive)) {
		return fail("ALREADY_ACTIVE_OR_UNAVAILABLE")
	}
	data, e := readSecret(filepath.Join(b.dir, "profile.dpapi"), "FreeTurn profile v1")
	if e != nil {
		return fail("PROFILE_MISSING")
	}
	p, e := parseProfile(string(data))
	if e != nil {
		return fail("PROFILE_UNSUPPORTED_OR_INVALID")
	}
	previous, e := loadConnectionOptions(b.dir)
	if e != nil {
		return fail("CONFIG_SAVE_FAILED")
	}
	routing := q.SystemRouting
	advanced := q.AdvancedCaptcha != nil && *q.AdvancedCaptcha
	forceManual := q.ForceManualCaptcha != nil && *q.ForceManualCaptcha
	if recovering {
		fallback, err := parseProfile(q.Profile)
		if err != nil || !sameRecoveryKey(p, fallback) || profileIdentity(q.Profile) == q.ExpectedProfile {
			return fail("RECOVERY_PROFILE_INVALID")
		}
		p = fallback
		data = []byte(strings.TrimSpace(q.Profile))
		routing = previous.SystemRouting
		advanced = previous.AdvancedCaptcha
		forceManual = previous.ForceManualCaptcha
	}
	auto := !recovering && q.AutoPaths != nil && *q.AutoPaths
	path := ""
	if p.Kind == "wireguard" {
		path, _ = canonicalPath(string(data))
	}
	if auto {
		path = "direct"
		if _, err := coreForPath(string(data), "relay", advanced, forceManual); err != nil {
			return fail("AUTO_PATH_PROFILE_INVALID")
		}
	}
	if recovering && q.RecoveryPath != "" {
		path = q.RecoveryPath
	}
	if auto || recovering && q.RecoveryPath != "" {
		if _, err := coreForPath(string(data), path, advanced, forceManual); err != nil {
			return fail("AUTO_PATH_PROFILE_INVALID")
		}
	}
	compiled, e := prepareSystemRouting(routing, p.WG)
	if e != nil {
		return fail(safeRuntimeError(e.Error()))
	}
	if recovering {
		// Validation may take time. Recheck health immediately before mutation,
		// so a now-healthy/cancelled attempt is left alone.
		r = b.status()
		if !canRecover(r, q.ExpectedProfile, q.ExpectedAttempt, q.ExpectedEpoch) {
			return fail("CONNECTION_CHANGED")
		}
		if b.socks != nil {
			b.socks.Close()
			b.socks = nil
		}
	}
	if recovering && r.TunnelActive {
		m, err := mgr.Connect()
		if err != nil {
			return fail("SCM_UNAVAILABLE")
		}
		err = stopOwn(m, tunnelName, "--tunnel")
		m.Disconnect()
		if err != nil {
			return fail("TUNNEL_STOP_FAILED")
		}
		if !canRecover(b.status(), q.ExpectedProfile, q.ExpectedAttempt, q.ExpectedEpoch) {
			return fail("CONNECTION_CHANGED")
		}
	}
	if recovering {
		// The old runtime can persist its sticky DNS privacy requirement while
		// validation is running. Never replace that newer journal requirement.
		latest, err := loadConnectionOptions(b.dir)
		if err != nil {
			return fail("CONFIG_SAVE_FAILED")
		}
		if latest.Cancelled || latest.AttemptID != q.ExpectedAttempt || latest.ProfileIdentity != q.ExpectedProfile {
			return fail("CONNECTION_CHANGED")
		}
		previous.FakeDNSRequired = previous.FakeDNSRequired || latest.FakeDNSRequired
	}
	if _, e = selectUnderlay(); e != nil {
		return fail("PHYSICAL_UPLINK_REQUIRED")
	}
	options := connectionOptions{AdvancedCaptcha: advanced, ForceManualCaptcha: forceManual, AttemptID: uint64(time.Now().UnixNano()), Started: time.Now().Unix(), FakeDNSRequired: previous.FakeDNSRequired, ProfileIdentity: profileIdentity(string(data)), AutoPaths: auto, InitialPath: path}
	if compiled != nil {
		options.SystemRouting = compiled.systemPolicy
	}
	if recovering {
		if e = writeSecret(filepath.Join(b.dir, "profile.dpapi"), "FreeTurn profile v1", data); e != nil {
			return fail("PROFILE_SAVE_FAILED")
		}
	}
	encoded, _ := json.Marshal(options)
	if e = writeSecret(filepath.Join(b.dir, "options.dpapi"), "FreeTurn connection options v1", encoded); e != nil {
		return fail("CONFIG_SAVE_FAILED")
	}
	if p.WG != "" {
		if e = writeSecret(filepath.Join(b.dir, "FTM.conf.dpapi"), "FTM", []byte(p.WG)); e != nil {
			return fail("CONFIG_SAVE_FAILED")
		}
	}
	if err := os.Remove(filepath.Join(b.dir, "transport-path.dpapi")); err != nil && !os.IsNotExist(err) {
		return fail("CONFIG_SAVE_FAILED")
	}
	os.Remove(filepath.Join(b.dir, "runtime.dpapi"))
	b.generation++
	b.recoveryCancelled = false
	b.diagnosticStage = ""
	b.probeConfirmed = time.Time{}
	b.probeAttempt = time.Time{}
	m, e := mgr.Connect()
	if e != nil {
		return fail("SCM_UNAVAILABLE")
	}
	defer m.Disconnect()
	s, e := ownService(m, tunnelName, "--tunnel")
	if e != nil {
		return fail("TUNNEL_SERVICE_UNAVAILABLE")
	}
	defer s.Close()
	if e = s.Start(); e != nil {
		return fail("TUNNEL_START_FAILED")
	}
	return response{OK: true, State: "starting", HasProfile: true, ConfiguredProfileIdentity: options.ProfileIdentity, LastAttemptID: options.AttemptID, AutoPaths: auto, RuntimePath: path}
}

func canRecover(r response, identity string, attempt uint64, epochs ...uint64) bool {
	epoch := uint64(0)
	if len(epochs) > 0 {
		epoch = epochs[0]
	}
	if r.PathPending || r.PathEpoch != epoch {
		return false
	}
	if !r.OK || !validProfileIdentity(identity) || attempt == 0 || r.ConfiguredProfileIdentity != identity || r.LastAttemptID != attempt || r.State == "connected" || r.State == "captcha" || r.State == "stopping" || r.Captcha != "" {
		return false
	}
	if r.TunnelActive {
		return matchesRuntime(r, identity, attempt, epoch)
	}
	return r.State == "stopped" || r.State == "error"
}

// Called under broker.mu before any manual/revocation stop. The in-memory gate
// is unconditional; persist it when possible, without making stop depend on I/O.
// If disk state cannot be saved, this gate lasts until the broker is restarted.
func (b *broker) cancelRecovery() {
	b.recoveryCancelled = true
	options, err := loadConnectionOptions(b.dir)
	if err != nil || options.AttemptID == 0 || options.Cancelled {
		return
	}
	options.Cancelled = true
	encoded, _ := json.Marshal(options)
	_ = writeSecret(filepath.Join(b.dir, "options.dpapi"), "FreeTurn connection options v1", encoded)
}

func sameRecoveryKey(current, fallback *profile) bool {
	if current == nil || fallback == nil || current.Kind != "wireguard" || fallback.Kind != "wireguard" || !safeWG(current.WG) || !safeWG(fallback.WG) {
		return false
	}
	a, aExtensions, err := memoryWGConfig(current.WG)
	if err != nil {
		return false
	}
	b, bExtensions, err := memoryWGConfig(fallback.WG)
	return err == nil && a.Interface.PrivateKey == b.Interface.PrivateKey && aExtensions == bExtensions
}
