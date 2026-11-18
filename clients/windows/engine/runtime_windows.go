package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"golang.org/x/sys/windows/svc"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/samosvalishe/free-turn-proxy/mobile"
	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/driver"
)

type events struct {
	mu    sync.Mutex
	state runtimeState
}

func (s *events) OnLog(level, message string, _ int64) {
	stage, code := coreLogDiagnostic(level, message)
	eventCode := coreEventCode(level, message)
	if stage == "" && code == "" && eventCode == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.appendEventLocked(level, eventCode, logStream(message), 0, 0)
	if stage != "" && s.state.State != "connected" && s.state.State != "error" {
		s.stageLocked(stage)
	}
	if code != "" {
		s.state.ErrorCode = code
	}
}
func (s *events) OnState(state string, streams, total int, errorMessage string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if streams != s.state.Streams || total != s.state.TotalStreams {
		s.appendEventLocked("info", "STREAMS_CHANGED", -1, streams, total)
	}
	if state != s.state.State {
		eventCode := map[string]string{"connecting": "SESSION_CONNECTING", "connected": "SESSION_READY", "error": "SESSION_ERROR"}[state]
		s.appendEventLocked("info", eventCode, -1, 0, 0)
	}
	switch state {
	case "idle", "connecting", "connected", "error", "captcha":
		s.state.State = state
	default:
		s.state.State = "connecting"
	}
	if streams > s.state.Streams {
		s.state.LastProgress = time.Now().Unix()
	}
	switch s.state.State {
	case "connected":
		s.stageLocked("relay_ready")
		s.state.ErrorCode = ""
	case "error":
		if s.state.Stage != "error" {
			s.state.FailureStage = s.state.Stage
		}
		s.stageLocked("error")
		_, code := coreLogDiagnostic("error", errorMessage)
		if code != "" && (code != "TRANSPORT_ERROR" || s.state.ErrorCode == "") {
			s.state.ErrorCode = code
		}
	case "captcha":
		s.stageLocked("captcha")
	case "connecting":
		if s.state.Stage == "" {
			s.stageLocked("transport_start")
		}
	}
	s.state.Streams = streams
	s.state.TotalStreams = total
}
func localCaptcha(raw string) bool {
	u, e := url.Parse(raw)
	return e == nil && u.Scheme == "http" && (u.Host == "127.0.0.1:8765" || u.Host == "localhost:8765" || u.Host == "[::1]:8765") && u.User == nil && len(raw) < 8192
}
func (s *events) OnCaptcha(raw string, manual bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if raw == "" || localCaptcha(raw) {
		if raw != "" {
			s.state.CaptchaID++
		}
		s.state.Captcha = raw
		s.state.Manual = manual
		if raw != "" {
			s.stageLocked("captcha")
		}
	}
}

func runTunnel(dir string) (result error) {
	if e := requireSystem(); e != nil {
		return e
	}
	options, e := loadConnectionOptions(dir)
	if e != nil {
		return e
	}
	startupStage := "profile_check"
	var sink *events
	defer func() {
		if result != nil && options.AttemptID != 0 {
			if sink != nil && systemRoutingEnabled(options.SystemRouting) {
				sink.mu.Lock()
				if sink.state.SystemRouting != nil && validSystemSetupStage(sink.state.SystemRouting.SetupStage) {
					startupStage = sink.state.SystemRouting.SetupStage
				}
				sink.mu.Unlock()
			}
			report := failureReport{AttemptID: options.AttemptID, Code: safeRuntimeError(result.Error()), At: time.Now().Unix(), Stage: startupStage}
			data, _ := json.Marshal(report)
			writeSecret(filepath.Join(dir, "failure.dpapi"), "FreeTurn failure v1", data)
		}
	}()
	// These files are accessible only to SYSTEM/admin and are never supplied by IPC.
	data, e := readSecret(filepath.Join(dir, "profile.dpapi"), "FreeTurn profile v1")
	if e != nil {
		return errors.New("PROFILE_MISSING")
	}
	p, e := parseProfile(string(data))
	if e != nil {
		return e
	}
	identity := profileIdentity(string(data))
	if options.Cancelled || options.ProfileIdentity != "" && options.ProfileIdentity != identity {
		return errors.New("CONFIG_MISMATCH")
	}
	systemPolicy, e := prepareSystemRouting(options.SystemRouting, p.WG)
	if e != nil {
		return e
	}
	core, path, epoch, e := effectivePathCore(dir, string(data), options)
	if e != nil {
		return e
	}
	if p.WG != "" {
		wg, e := readSecret(filepath.Join(dir, "FTM.conf.dpapi"), "FTM")
		if e != nil || string(wg) != p.WG {
			return errors.New("CONFIG_MISMATCH")
		}
	}
	protect, e := selectUnderlay()
	if e != nil {
		return e
	}
	coreState := filepath.Join(dir, "Core")
	if e = secureDirectory(coreState, privateACL); e != nil {
		return e
	}
	conf.PresetRootDirectory(dir)
	sink = &events{state: runtimeState{PID: os.Getpid(), State: "connecting", CaptchaID: uint64(time.Now().UnixNano()), Started: time.Now().Unix(), EventSession: options.AttemptID}}
	sink.state.ProfileIdentity = identity
	sink.state.PathMode = path
	sink.state.PathEpoch = epoch
	sink.state.PathStartedAt = time.Now().Unix()
	sink.state.Effective, e = describeEffective(string(data), core)
	if e != nil {
		return e
	}
	if systemRoutingEnabled(options.SystemRouting) {
		sink.state.SystemRouting = &systemRuntimeReport{Requested: true}
	}
	sink.stageLocked("transport_start")
	startupStage = "transport_start"
	mobile.SetLogBuffer(false)
	mobile.SetEventSink(sink)
	mobile.SetStateDir(coreState)
	mobile.SetProtect(protect)
	if e = mobile.Start(core); e != nil {
		return errors.New("TRANSPORT_START_FAILED")
	}
	defer mobile.Stop()
	stopPaths := startPathWorker(dir, string(data), options, sink, func(core string) error { return mobile.Restart(core, 0) })
	defer stopPaths()
	// DIRECT must originate in this tunnel-service SID, which owns WireGuard's
	// process-specific firewall exception. The broker SID must not be whitelisted.
	if p.WG != "" && !systemRoutingEnabled(options.SystemRouting) {
		relay, e := startDirectRelay(protect.v4)
		if e == nil {
			defer relay.Close()
		}
	} // DIRECT failure must not break the existing full-tunnel path.
	done := make(chan struct{})
	defer close(done)
	go func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		var lastWritten []byte
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if snapshot := mobile.GetState(); snapshot != nil {
					sink.mu.Lock()
					switching := sink.state.PathSwitching
					sink.mu.Unlock()
					if !switching {
						sink.OnState(snapshot.State, snapshot.Streams, snapshot.Total, snapshot.ErrMsg)
					}
				}
				sink.mu.Lock()
				state := sink.state
				state.Events = append([]coreEvent(nil), sink.state.Events...)
				sink.mu.Unlock()
				state.Updated = time.Now().Unix()
				b, _ := json.Marshal(state)
				if !bytes.Equal(lastWritten, b) {
					if writeSecret(filepath.Join(dir, "runtime.dpapi"), "FreeTurn runtime v1", b) == nil {
						lastWritten = b
					}
				}
			}
		}
	}()
	if p.WG == "" {
		return svc.Run(tunnelName, &forwarderService{})
	}
	if systemRoutingEnabled(options.SystemRouting) {
		startupStage = "system_routing_start"
		host, _, _ := net.SplitHostPort(p.Peer)
		expected, _ := netip.ParseAddr(host)
		service := &systemTunnelService{rawWG: p.WG, policy: systemPolicy, expected: expected, sink: sink, dir: dir, options: options}
		if e := svc.Run(tunnelName, service); e != nil {
			return e
		}
		return service.result
	}
	startupStage = "wireguard_start"
	return officialTunnel(filepath.Join(dir, "FTM.conf.dpapi"))
}

// Standalone forwarding owns no adapter, DNS, firewall or system routes. The
// upstream core owns only its validated loopback listener; defer Stop closes it.
type forwarderService struct{}

func (*forwarderService) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for change := range requests {
		switch change.Cmd {
		case svc.Interrogate:
			status <- change.CurrentStatus
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending}
			return false, 0
		}
	}
	return false, 0
}

func readHandshake() (bool, uint64, uint64) {
	a, e := driver.OpenAdapter("FTM")
	if e != nil {
		return false, 0, 0
	}
	defer a.Close()
	c, e := a.Configuration()
	if e != nil || c.PeerCount != 1 {
		return false, 0, 0
	}
	p := c.FirstPeer()
	if p.LastHandshake < 116444736000000000 {
		return false, p.RxBytes, p.TxBytes
	}
	handshake := time.Unix(0, int64((p.LastHandshake-116444736000000000)*100))
	age := time.Since(handshake)
	return age >= 0 && age < 3*time.Minute, p.RxBytes, p.TxBytes
}
