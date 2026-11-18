package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"freeturn.local/windows/internal/legacylock"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const brokerName = "FreeTurnManager"
const tunnelName = "WireGuardTunnel$FTM"
const pipeName = `\\.\pipe\FreeTurnManager.v1`
const driverHash = "b1b85e072c45d81358be29d94c599dc76652f912be8c0f0a41e2d5d89a6461d3"

func pipeACL(sid string) string { return "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12008b;;;" + sid + ")" }

type request struct {
	V                  int           `json:"v"`
	Op                 string        `json:"op"`
	Profile            string        `json:"profile,omitempty"`
	AdvancedCaptcha    *bool         `json:"advancedCaptcha,omitempty"`
	ForceManualCaptcha *bool         `json:"forceManualCaptcha,omitempty"`
	Socks              *socksOptions `json:"socks,omitempty"`
	SystemRouting      *systemPolicy `json:"systemRouting,omitempty"`
	ExpectedProfile    string        `json:"expectedProfile,omitempty"`
	ExpectedAttempt    uint64        `json:"expectedAttempt,omitempty"`
	ExpectedEpoch      uint64        `json:"expectedEpoch,omitempty"`
	AutoPaths          *bool         `json:"autoPaths,omitempty"`
	Path               string        `json:"path,omitempty"`
	RecoveryPath       string        `json:"recoveryPath,omitempty"`
}
type response struct {
	OK                        bool                 `json:"ok"`
	Error                     string               `json:"error,omitempty"`
	State                     string               `json:"state"`
	HasProfile                bool                 `json:"hasProfile"`
	Transport                 string               `json:"transport,omitempty"`
	Handshake                 bool                 `json:"handshake"`
	Rx                        uint64               `json:"rx"`
	Tx                        uint64               `json:"tx"`
	Captcha                   string               `json:"captcha,omitempty"`
	Manual                    bool                 `json:"manual"`
	Capabilities              []string             `json:"capabilities,omitempty"`
	CaptchaID                 uint64               `json:"captchaId,omitempty"`
	Started                   int64                `json:"started,omitempty"`
	Streams                   int                  `json:"streams,omitempty"`
	TotalStreams              int                  `json:"totalStreams,omitempty"`
	Kind                      string               `json:"kind,omitempty"`
	Listen                    string               `json:"listen,omitempty"`
	SocksPort                 int                  `json:"socksPort,omitempty"`
	Stage                     string               `json:"stage,omitempty"`
	StageSince                int64                `json:"stageSince,omitempty"`
	LastProgress              int64                `json:"lastProgress,omitempty"`
	DiagnosticError           string               `json:"diagnosticError,omitempty"`
	TunnelActive              bool                 `json:"tunnelActive"`
	ServiceVersion            string               `json:"serviceVersion"`
	ServiceWin32Code          uint32               `json:"serviceWin32Code,omitempty"`
	ServiceSpecificCode       uint32               `json:"serviceSpecificCode,omitempty"`
	FailureStage              string               `json:"failureStage,omitempty"`
	Events                    []coreEvent          `json:"events,omitempty"`
	EventSession              uint64               `json:"eventSession,omitempty"`
	SystemRouting             *systemRuntimeReport `json:"systemRouting,omitempty"`
	ConfiguredProfileIdentity string               `json:"configuredProfileIdentity,omitempty"`
	RuntimeProfileIdentity    string               `json:"runtimeProfileIdentity,omitempty"`
	ConnectionID              uint64               `json:"connectionId,omitempty"`
	LastAttemptID             uint64               `json:"lastAttemptId,omitempty"`
	AutoPaths                 bool                 `json:"autoPaths,omitempty"`
	RuntimePath               string               `json:"runtimePath,omitempty"`
	PathEpoch                 uint64               `json:"pathEpoch,omitempty"`
	PathPending               bool                 `json:"pathPending,omitempty"`
	Effective                 *effectiveSettings   `json:"effective,omitempty"`
}
type runtimeState struct {
	SystemRouting   *systemRuntimeReport
	Events          []coreEvent
	EventSequence   uint64
	EventSession    uint64
	ProfileIdentity string
	PathMode        string
	PathEpoch       uint64
	PathStartedAt   int64
	PathSwitching   bool
	Effective       *effectiveSettings
	PID             int
	Updated         int64
	State           string
	Streams         int
	Captcha         string
	Manual          bool
	CaptchaID       uint64
	Started         int64
	TotalStreams    int
	Stage           string
	StageSince      int64
	LastProgress    int64
	ErrorCode       string
	FailureStage    string
}

func requireSystem() error {
	t, e := windows.OpenCurrentProcessToken()
	if e != nil {
		return e
	}
	defer t.Close()
	u, e := t.GetTokenUser()
	if e != nil {
		return e
	}
	if !u.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return errors.New("SYSTEM_REQUIRED")
	}
	return nil
}

func isElevated() bool {
	t, e := windows.OpenCurrentProcessToken()
	if e != nil {
		return false
	}
	defer t.Close()
	return t.IsElevated()
}

func ownService(m *mgr.Mgr, name, mode string) (*mgr.Service, error) {
	s, e := m.OpenService(name)
	if e != nil {
		return nil, e
	}
	c, e := s.Config()
	if e != nil {
		s.Close()
		return nil, e
	}
	d, e := installDir()
	if e != nil {
		s.Close()
		return nil, e
	}
	// mgr.CreateService uses EscapeArg for every command line element.
	expected := windows.EscapeArg(filepath.Join(d, "FreeTurn.Engine.exe")) + " " + mode
	if !strings.EqualFold(c.BinaryPathName, expected) || c.ServiceStartName != "LocalSystem" {
		s.Close()
		return nil, errors.New("SERVICE_NAME_COLLISION")
	}
	return s, nil
}

func stopOwn(m *mgr.Mgr, name, mode string) error {
	s, e := ownService(m, name, mode)
	if e != nil {
		if e == windows.ERROR_SERVICE_DOES_NOT_EXIST {
			return nil
		}
		return e
	}
	defer s.Close()
	deadline := time.Now().Add(40 * time.Second)
	sent := false
	for time.Now().Before(deadline) {
		q, e := s.Query()
		if e != nil {
			return e
		}
		if q.State == svc.Stopped {
			return nil
		}
		if !sent && q.State != svc.StartPending && q.State != svc.StopPending {
			if _, e = s.Control(svc.Stop); e != nil {
				return e
			}
			sent = true
		}
		time.Sleep(150 * time.Millisecond)
	}
	return errors.New("STOP_TIMEOUT")
}

// Explicit UAC setup only. Does not start a VPN, configure autoconnect or change
// another product's services. Fixed binary paths, fixed service names and args.
func install(sidText string) error {
	if !isElevated() {
		return errors.New("ADMIN_REQUIRED")
	}
	sid, e := windows.StringToSid(sidText)
	if e != nil || !strings.HasPrefix(sidText, "S-1-5-21-") {
		return errors.New("INVALID_USER_SID")
	}
	if _, _, kind, e := sid.LookupAccount(""); e != nil || kind != windows.SidTypeUser {
		return errors.New("INVALID_USER_SID")
	}
	retainedData, e := dataDir()
	if e != nil {
		return e
	}
	if e := existingOwnerBeforeInstall(retainedData, sidText); e != nil {
		return e
	}
	m, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	for _, name := range []string{brokerName, tunnelName} {
		s, e := m.OpenService(name)
		if e == nil {
			s.Close()
			return errors.New("ALREADY_INSTALLED")
		}
		if e != windows.ERROR_SERVICE_DOES_NOT_EXIST {
			return e
		}
	}
	if e = legacylock.Remove(); e != nil {
		return errors.New("OBSOLETE_NETWORK_RULES_CLEANUP_FAILED")
	}
	d, e := installDir()
	if e != nil {
		return e
	}
	data, e := dataDir()
	if e != nil {
		return e
	}
	if e = secureDirectory(d, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)"); e != nil {
		return e
	}
	if e = secureDirectory(data, privateACL); e != nil {
		return e
	}
	source, e := os.Executable()
	if e != nil {
		return e
	}
	dll, e := os.ReadFile(filepath.Join(filepath.Dir(source), "wireguard.dll"))
	if e != nil {
		return errors.New("DRIVER_MISSING")
	}
	sum := sha256.Sum256(dll)
	if hex.EncodeToString(sum[:]) != driverHash {
		return errors.New("DRIVER_CHECKSUM")
	}
	b, e := os.ReadFile(source)
	if e != nil {
		return e
	}
	if e = atomicPrivate(filepath.Join(d, "FreeTurn.Engine.exe"), b); e != nil {
		return e
	}
	if e = atomicPrivate(filepath.Join(d, "wireguard.dll"), dll); e != nil {
		return e
	}
	if e = atomicPrivate(filepath.Join(data, "owner.sid"), []byte(sidText)); e != nil {
		return e
	}
	created := []*mgr.Service{}
	success := false
	defer func() {
		for _, s := range created {
			if !success {
				s.Delete()
			}
			s.Close()
		}
	}()
	for _, item := range []struct{ name, mode string }{{tunnelName, "--tunnel"}, {brokerName, "--broker"}} {
		start := uint32(mgr.StartManual)
		if item.name == brokerName {
			start = mgr.StartAutomatic
		}
		s, e := m.CreateService(item.name, filepath.Join(d, "FreeTurn.Engine.exe"), mgr.Config{DisplayName: item.name, StartType: start, ServiceType: windows.SERVICE_WIN32_OWN_PROCESS, ErrorControl: mgr.ErrorNormal, SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED}, item.mode)
		if e != nil {
			return e
		}
		created = append(created, s)
	}
	if e = created[1].Start(); e != nil {
		return e
	}
	success = true
	return nil
}

func uninstall() error {
	if !isElevated() {
		return errors.New("ADMIN_REQUIRED")
	}
	m, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	// Validate both before touching either one.
	for _, item := range []struct{ name, mode string }{{tunnelName, "--tunnel"}, {brokerName, "--broker"}} {
		s, e := ownService(m, item.name, item.mode)
		if e != nil {
			if e == windows.ERROR_SERVICE_DOES_NOT_EXIST {
				continue
			}
			return e
		}
		s.Close()
	}
	for _, item := range []struct{ name, mode string }{{brokerName, "--broker"}, {tunnelName, "--tunnel"}} {
		if e = stopOwn(m, item.name, item.mode); e != nil {
			return e
		}
		s, e := ownService(m, item.name, item.mode)
		if e != nil {
			if e == windows.ERROR_SERVICE_DOES_NOT_EXIST {
				continue
			}
			return e
		}
		e = s.Delete()
		s.Close()
		if e != nil {
			return e
		}
	}
	if e = legacylock.Remove(); e != nil {
		return errors.New("OBSOLETE_NETWORK_RULES_CLEANUP_FAILED")
	}
	// Preserve the encrypted profile. No recursive deletion or foreign adapters.
	return nil
}

type broker struct {
	mu                sync.Mutex
	dir               string
	closing           bool
	recoveryCancelled bool
	generation        uint64
	probeBusy         bool
	probeAttempt      time.Time
	probeConfirmed    time.Time
	probePathEpoch    uint64
	socks             *socksServer
	diagnosticStage   string
	diagnosticSince   int64
}

func (b *broker) status() (r response) {
	r = response{OK: true, State: "stopped", Stage: "stopped", ServiceVersion: engineVersion, Capabilities: []string{"advanced-captcha-v1", "direct-relay-transport-v1", "loopback-forwarder-v1", "socks-tcp-v1", "socks-domain-routing-v1", "connection-stages-v1", "socket-protection-v2"}}
	r.Capabilities = append(r.Capabilities, systemRoutingCapabilities()...)
	r.Capabilities = append(r.Capabilities, "runtime-profile-identity-v1", "network-recovery-v1", "routing-bundle-v1")
	r.Capabilities = append(r.Capabilities, "managed-recovery-v1", "transport-path-v1", "effective-settings-v1")
	defer func() {
		if r.Stage != b.diagnosticStage {
			b.diagnosticStage = r.Stage
			b.diagnosticSince = time.Now().Unix()
		}
		if b.diagnosticSince > r.StageSince {
			r.StageSince = b.diagnosticSince
		}
		if r.LastProgress < r.StageSince {
			r.LastProgress = r.StageSince
		}
		if b.socks != nil {
			r.SocksPort = b.socks.port
		}
	}()
	if data, e := readSecret(filepath.Join(b.dir, "profile.dpapi"), "FreeTurn profile v1"); e == nil {
		var p *profile
		p, e = parseProfile(string(data))
		if e == nil {
			r.Kind, r.Listen = p.Kind, p.Listen
			r.ConfiguredProfileIdentity = profileIdentity(string(data))
			if options, err := loadConnectionOptions(b.dir); err == nil && !b.recoveryCancelled && !options.Cancelled && options.ProfileIdentity == r.ConfiguredProfileIdentity {
				r.LastAttemptID = options.AttemptID
				r.AutoPaths = options.AutoPaths
				r.RuntimePath = options.InitialPath
				if options.AutoPaths {
					if journal, err := loadPathJournal(b.dir, options.AttemptID, options.ProfileIdentity); err == nil && journal != nil {
						r.PathEpoch = journal.Epoch
						r.RuntimePath = journal.Target
					}
				}
			}
		}
		r.HasProfile = e == nil
	}
	m, e := mgr.Connect()
	if e != nil {
		r.OK = false
		r.Error = "SCM_UNAVAILABLE"
		return r
	}
	defer m.Disconnect()
	s, e := ownService(m, tunnelName, "--tunnel")
	if e != nil {
		r.OK = false
		r.Error = "TUNNEL_SERVICE_UNAVAILABLE"
		return r
	}
	defer s.Close()
	q, e := s.Query()
	if e != nil {
		r.OK = false
		r.Error = "SCM_UNAVAILABLE"
		return r
	}
	if q.State == svc.Stopped {
		if data, e := readSecret(filepath.Join(b.dir, "runtime.dpapi"), "FreeTurn runtime v1"); e == nil {
			var prior runtimeState
			if json.Unmarshal(data, &prior) == nil {
				r.Events = publicEvents(prior.Events)
				r.EventSession = prior.EventSession
			}
		}
		if code, stage := serviceExitDiagnostic(q); code != "" {
			r.State = "error"
			r.Stage = "error"
			r.DiagnosticError = code
			r.FailureStage = stage
			r.ServiceWin32Code = q.Win32ExitCode
			r.ServiceSpecificCode = q.ServiceSpecificExitCode
		}
		if options, e := loadConnectionOptions(b.dir); e == nil && options.AttemptID != 0 {
			data, e := readSecret(filepath.Join(b.dir, "failure.dpapi"), "FreeTurn failure v1")
			var failure failureReport
			if e == nil && json.Unmarshal(data, &failure) == nil && failure.AttemptID == options.AttemptID {
				r.State = "error"
				r.Stage = "error"
				r.DiagnosticError = safeRuntimeError(failure.Code)
				r.Started = options.Started
				r.StageSince = failure.At
				r.FailureStage = failure.Stage
			}
		}
		return r
	}
	r.TunnelActive = true
	r.Stage = "service_start"
	r.State = "starting"
	if q.State == svc.StopPending {
		r.State = "stopping"
		r.Stage = "stopping"
		return r
	}
	data, e := readSecret(filepath.Join(b.dir, "runtime.dpapi"), "FreeTurn runtime v1")
	var state runtimeState
	if e != nil || json.Unmarshal(data, &state) != nil || state.PID != int(q.ProcessId) || time.Now().Unix()-state.Updated > 6 {
		return r
	}
	r.Transport = state.State
	if options, err := loadConnectionOptions(b.dir); err == nil {
		r.RuntimeProfileIdentity, r.ConnectionID = runtimeIdentity(state, options, int(q.ProcessId), time.Now())
	}
	if r.RuntimeProfileIdentity != "" {
		r.Effective = state.Effective
	}
	r.SystemRouting = state.SystemRouting
	r.Events = publicEvents(state.Events)
	r.EventSession = state.EventSession
	r.Captcha = state.Captcha
	r.Manual = state.Manual
	r.CaptchaID = state.CaptchaID
	r.Started, r.Streams, r.TotalStreams = state.Started, state.Streams, state.TotalStreams
	r.Stage, r.StageSince, r.LastProgress, r.DiagnosticError = state.Stage, state.StageSince, state.LastProgress, state.ErrorCode
	r.FailureStage = state.FailureStage
	if options, err := loadConnectionOptions(b.dir); err != nil {
		return r
	} else if b.pathStatus(&r, state, options) {
		return r
	}
	if state.State == "error" {
		r.State = "error"
		r.Stage = "error"
		if r.DiagnosticError == "" {
			r.DiagnosticError = "TRANSPORT_ERROR"
		}
		return r
	}
	if r.Captcha != "" {
		r.State = "captcha"
	} else if q.State == svc.Running {
		r.State = "tunnel_unverified"
	}
	if r.Kind == "tcp-forwarder" || r.Kind == "udp-forwarder" {
		if r.Captcha == "" && q.State == svc.Running {
			r.State = "proxy_unverified"
			if state.State == "connected" {
				r.State = "proxy_ready"
			}
		}
		return r
	}
	if applySystemRoutingStatus(&r, state, q.State == svc.Running, time.Now()) {
		if r.AutoPaths && r.State == "connected" && (state.SystemRouting == nil || state.SystemRouting.EgressEpoch != state.PathEpoch || !pathEgressReady(state, state.SystemRouting.EgressAt)) {
			r.State = "handshake"
			r.Stage = "egress_check"
		}
		return r
	}
	r.Handshake, r.Rx, r.Tx = readHandshake()
	if q.State == svc.Running && state.State == "connected" {
		b.maybeProbe()
	}
	if r.Handshake && state.State == "connected" {
		r.State = "handshake"
		if !b.probeConfirmed.IsZero() && time.Since(b.probeConfirmed) < 30*time.Second && (!r.AutoPaths || pathEgressReady(state, b.probeConfirmed.Unix())) {
			r.State = "connected"
		}
	} else {
		b.probeConfirmed = time.Time{}
	}
	if r.State == "connected" {
		r.Stage = "connected"
		r.DiagnosticError = ""
	} else if r.Handshake && state.State == "connected" {
		r.Stage = "egress_check"
	} else if state.State == "connected" {
		r.Stage = "handshake_wait"
	}
	return r
}

func (b *broker) dispatch(q request) response {
	b.mu.Lock()
	defer b.mu.Unlock()
	fail := func(code string) response { return response{Error: code, State: "error"} }
	if b.closing {
		return fail("SERVICE_STOPPING")
	}
	if q.V != 1 || q.Op != "import" && q.Op != "recover-if-current" && q.Profile != "" || q.Op != "connect" && q.AdvancedCaptcha != nil || q.Op != "connect" && q.ForceManualCaptcha != nil || q.Op != "connect" && q.SystemRouting != nil || q.Op != "socks-start" && q.Socks != nil {
		return fail("INVALID_REQUEST")
	}
	if q.Op == "disconnect-if-current" || q.Op == "recover-if-current" || q.Op == "switch-path-if-current" || q.Op == "network-reconnect-if-current" {
		if !validProfileIdentity(q.ExpectedProfile) || q.ExpectedAttempt == 0 || q.ExpectedEpoch > 2 {
			return fail("INVALID_REQUEST")
		}
	} else if q.ExpectedProfile != "" || q.ExpectedAttempt != 0 || q.ExpectedEpoch != 0 {
		return fail("INVALID_REQUEST")
	}
	if q.Op != "connect" && q.AutoPaths != nil || q.Op != "switch-path-if-current" && q.Path != "" || q.Op != "recover-if-current" && q.RecoveryPath != "" || q.RecoveryPath != "" && !validPath(q.RecoveryPath) {
		return fail("INVALID_REQUEST")
	}
	switch q.Op {
	case "status":
		return b.status()
	case "network-reconnect-if-current":
		return b.reconnectNetwork(q)
	case "switch-path-if-current":
		return b.switchPath(q)
	case "socks-start":
		r := b.status()
		if q.Socks == nil || r.State != "connected" || r.Kind != "wireguard" {
			return fail("SOCKS_REQUIRES_VERIFIED_VPN")
		}
		if r.SystemRouting != nil && r.SystemRouting.Requested {
			return fail("SOCKS_SYSTEM_ROUTING_UNAVAILABLE")
		}
		if b.socks != nil {
			return fail("SOCKS_ALREADY_RUNNING")
		}
		policy, e := compileRouting(q.Socks.Routing)
		if e != nil {
			return fail("ROUTING_POLICY_INVALID")
		}
		data, e := readSecret(filepath.Join(b.dir, "profile.dpapi"), "FreeTurn profile v1")
		if e != nil {
			return fail("PROFILE_MISSING")
		}
		p, e := parseProfile(string(data))
		if e != nil {
			return fail("PROFILE_UNSUPPORTED_OR_INVALID")
		}
		dial, e := tunnelSOCKSDial(p)
		if e != nil {
			return fail("SOCKS_TUNNEL_UNAVAILABLE")
		}
		var direct socksDial
		if policy.NeedsDirect() {
			direct = tunnelDirectDial
		}
		dial = routedSOCKSDial(policy, dial, direct)
		b.socks, e = startSOCKS(*q.Socks, dial)
		if e != nil {
			return fail("SOCKS_START_FAILED")
		}
		return b.status()
	case "socks-stop":
		if b.socks != nil {
			b.socks.Close()
			b.socks = nil
		}
		return b.status()
	case "import":
		r := b.status()
		if !r.OK || r.State != "stopped" && !(r.State == "error" && !r.TunnelActive) {
			return fail("STOP_BEFORE_IMPORT")
		}
		if _, e := parseProfile(q.Profile); e != nil {
			return fail("PROFILE_UNSUPPORTED_OR_INVALID")
		}
		if e := os.Remove(filepath.Join(b.dir, "failure.dpapi")); e != nil && !os.IsNotExist(e) {
			return fail("CONFIG_SAVE_FAILED")
		}
		if e := writeSecret(filepath.Join(b.dir, "profile.dpapi"), "FreeTurn profile v1", []byte(strings.TrimSpace(q.Profile))); e != nil {
			return fail("PROFILE_SAVE_FAILED")
		}
		return b.status()
	case "connect", "recover-if-current":
		return b.connectAttempt(q)
	case "disconnect", "disconnect-if-current":
		if q.Op == "disconnect-if-current" && !matchesRuntime(b.status(), q.ExpectedProfile, q.ExpectedAttempt, q.ExpectedEpoch) {
			return fail("CONNECTION_CHANGED")
		}
		b.cancelRecovery()
		// A diagnostic file or unavailable state disk must not block manual stop.
		_ = os.Remove(filepath.Join(b.dir, "failure.dpapi"))
		if b.socks != nil {
			b.socks.Close()
			b.socks = nil
		}
		b.generation++
		b.probeConfirmed = time.Time{}
		m, e := mgr.Connect()
		if e != nil {
			return fail("SCM_UNAVAILABLE")
		}
		defer m.Disconnect()
		if e = stopOwn(m, tunnelName, "--tunnel"); e != nil {
			return fail("TUNNEL_STOP_FAILED")
		}
		return b.status()
	default:
		return fail("UNKNOWN_OPERATION")
	}
}

func readRequest(c net.Conn) (request, error) {
	var q request
	c.SetDeadline(time.Now().Add(45 * time.Second))
	r := bufio.NewReaderSize(io.LimitReader(c, maxSystemMessage+1), maxSystemMessage+1)
	line, e := r.ReadBytes('\n')
	if e != nil || len(line) > maxSystemMessage || !uniqueJSON(line) {
		return q, errors.New("INVALID_REQUEST")
	}
	d := json.NewDecoder(bytes.NewReader(line))
	d.DisallowUnknownFields()
	e = d.Decode(&q)
	return q, e
}

func (b *broker) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	sidData, e := os.ReadFile(filepath.Join(b.dir, "owner.sid"))
	if e != nil {
		return false, 1
	}
	sid := string(sidData)
	if _, e = windows.StringToSid(sid); e != nil {
		return false, 1
	}
	// No FILE_CREATE_PIPE_INSTANCE (0x4) for the UI SID. The UI opens with
	// GENERIC_READ | FILE_WRITE_DATA, rather than broad GENERIC_WRITE.
	listener, e := winio.ListenPipe(pipeName, &winio.PipeConfig{SecurityDescriptor: pipeACL(sid), InputBufferSize: maxMessage, OutputBufferSize: 4096})
	if e != nil {
		return false, 2
	}
	defer listener.Close()
	watchDone := make(chan struct{})
	defer close(watchDone)
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-watchDone:
				return
			case <-ticker.C:
				b.mu.Lock()
				if !b.closing && b.socks != nil {
					r := b.status()
					if r.State != "connected" {
						b.socks.Close()
						b.socks = nil
					}
				}
				b.mu.Unlock()
			}
		}
	}()
	// Bound concurrent clients, deadlines and payloads. A connection has one request.
	sem := make(chan struct{}, 8)
	go func() {
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			select {
			case sem <- struct{}{}:
				go func() {
					defer func() { <-sem; c.Close() }()
					q, e := readRequest(c)
					if e != nil {
						return
					}
					json.NewEncoder(c).Encode(b.dispatch(q))
				}()
			default:
				c.Close()
			}
		}
	}()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for q := range requests {
		switch q.Cmd {
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending}
			listener.Close()
			b.mu.Lock()
			b.closing = true
			if b.socks != nil {
				b.socks.Close()
				b.socks = nil
			}
			m, e := mgr.Connect()
			if e == nil {
				e = stopOwn(m, tunnelName, "--tunnel")
				m.Disconnect()
			}
			b.mu.Unlock()
			if e != nil {
				// Application failure, not Win32 ERROR_PATH_NOT_FOUND (3).
				return true, 3
			}
			return false, 0
		case svc.Interrogate:
			status <- q.CurrentStatus
		}
	}
	return false, 0
}
