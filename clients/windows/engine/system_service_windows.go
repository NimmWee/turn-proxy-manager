package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/windows/svc"
)

type systemRuntimeReport struct {
	PublicationRevision int64  `json:"publicationRevision,omitempty"`
	CatalogSHA256       string `json:"catalogSHA256,omitempty"`
	LastError           string `json:"lastError,omitempty"`
	SetupStage          string `json:"setupStage,omitempty"`
	Requested           bool   `json:"requested"`
	Active              bool   `json:"active"`
	Handshake           bool   `json:"handshake"`
	Rx                  uint64 `json:"rx"`
	Tx                  uint64 `json:"tx"`
	EgressAt            int64  `json:"egressAt,omitempty"`
	EgressEpoch         uint64 `json:"egressEpoch,omitempty"`
	DirectFlows         uint64 `json:"directFlows"`
	VPNFlows            uint64 `json:"vpnFlows"`
	BlockedFlows        uint64 `json:"blockedFlows"`
	DNSQueries          uint64 `json:"dnsQueries"`
	DNSErrors           uint64 `json:"dnsErrors"`
	LocalDNSReady       bool   `json:"localDNSReady"`
	MDNSConfigured      bool   `json:"mdnsConfigured"`
	AppRules            int    `json:"appRules"`
	UnknownAppFlows     uint64 `json:"unknownAppFlows"`
}

func (s *events) setSystemReport(report systemRuntimeReport) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if report.SetupStage == "" && s.state.SystemRouting != nil {
		report.SetupStage = s.state.SystemRouting.SetupStage
	}
	s.state.SystemRouting = &report // immutable snapshot for the existing DPAPI writer
}

func validSystemSetupStage(stage string) bool {
	switch stage {
	case "system_routing_start", "system_dns_cache", "system_routing_preflight", "system_adapter_start", "system_firewall_start", "system_network_config", "system_wireguard_start", "system_stack_start", "system_routes_publish", "system_routing_ready":
		return true
	default:
		return false
	}
}
func (s *events) systemProgress(stage string) {
	if !validSystemSetupStage(stage) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	report := systemRuntimeReport{Requested: true}
	if s.state.SystemRouting != nil {
		report = *s.state.SystemRouting
	}
	report.SetupStage = stage
	s.state.SystemRouting = &report
	s.stageLocked(stage)
}

type systemTunnelService struct {
	rawWG    string
	policy   *compiledSystemPolicy
	expected netip.Addr
	sink     *events
	result   error
	start    func(context.Context) (*systemRuntime, error)
	dir      string
	options  connectionOptions
}

func (s *systemTunnelService) startOwnedRuntime(ctx context.Context) (*systemRuntime, error) {
	if e := requireSystem(); e != nil {
		return nil, e
	}
	if ctx.Err() != nil {
		return nil, errors.New("SYSTEM_ROUTING_CANCELLED")
	}
	s.sink.systemProgress("system_dns_cache")
	leases, journal, e := openFakeDNSJournalContext(ctx, filepath.Join(s.dir, "routing-identities.dpapi"), s.options.FakeDNSRequired)
	if e != nil {
		return nil, e
	}
	if !s.options.FakeDNSRequired {
		s.options.FakeDNSRequired = true
		data, e := json.Marshal(s.options)
		if e != nil || writeSecret(filepath.Join(s.dir, "options.dpapi"), "FreeTurn connection options v1", data) != nil {
			journal.Close()
			return nil, errors.New("SYSTEM_DNS_CACHE_WRITE_FAILED")
		}
	}
	r, e := startSystemRuntime(ctx, s.rawWG, s.policy, systemDirectResolvers(s.policy), leases, s.sink.systemProgress)
	if e != nil {
		journal.Close()
		return nil, e
	}
	r.identities = journal
	return r, nil
}

func (s *systemTunnelService) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.sink.setSystemReport(systemRuntimeReport{Requested: true})
	s.sink.mu.Lock()
	s.sink.stageLocked("system_routing_start")
	s.sink.mu.Unlock()
	status <- svc.Status{State: svc.StartPending, CheckPoint: 1, WaitHint: 45000}
	// SCM Running means the process accepts controls, not that VPN is ready.
	// Windows cannot reliably deliver Stop during StartPending. Keep the async
	// network startup cancellable; broker still requires Active+WG+egress proof.
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	type started struct {
		runtime *systemRuntime
		err     error
	}
	startup := make(chan started, 1)
	go func() {
		start := s.start
		if start == nil {
			start = s.startOwnedRuntime
		}
		r, e := start(ctx)
		startup <- started{r, e}
	}()
	timer := time.NewTicker(2 * time.Second)
	defer timer.Stop()
	checkpoint := uint32(1)
	stopping := false
	var runtime *systemRuntime
starting:
	for {
		select {
		case ready := <-startup:
			if ready.err != nil {
				if stopping && ready.err.Error() != "SYSTEM_NETWORK_ROLLBACK_FAILED" && ready.err.Error() != "SYSTEM_TUN_CLOSE_FAILED" {
					return false, 0
				}
				s.result = ready.err
				return true, 1
			}
			runtime = ready.runtime
			break starting
		case change, ok := <-requests:
			if !ok || change.Cmd == svc.Stop || change.Cmd == svc.Shutdown {
				if !ok {
					requests = nil
				}
				stopping = true
				cancel()
				status <- svc.Status{State: svc.StopPending, CheckPoint: checkpoint, WaitHint: 45000}
			} else if change.Cmd == svc.Interrogate {
				status <- change.CurrentStatus
			}
		case <-timer.C:
			checkpoint++
			if stopping {
				status <- svc.Status{State: svc.StopPending, CheckPoint: checkpoint, WaitHint: 45000}
			} else {
				status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
			}
		}
	}
	defer func() {
		if e := runtime.Close(); e != nil {
			s.result = e
		}
		s.sink.setSystemReport(systemRuntimeReport{Requested: true})
	}()
	if stopping || ctx.Err() != nil {
		return false, 0
	}
	stopReporter := startSystemReporter(ctx, runtime, s.expected, s.sink)
	defer stopReporter() // reporter/probe finish before closing the WG device
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for change := range requests {
		switch change.Cmd {
		case svc.Interrogate:
			status <- change.CurrentStatus
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending, WaitHint: 15000}
			cancel()
			return false, 0
		}
	}
	cancel()
	return false, 0
}

// The tunnel service owns both direct/VPN sockets. Broker reads this numeric
// DPAPI report and never receives a WFP bypass or raw WireGuard IPC/config.
func startSystemReporter(parent context.Context, runtime *systemRuntime, expected netip.Addr, sink *events) func() {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		timer := time.NewTicker(time.Second)
		defer timer.Stop()
		var probes sync.WaitGroup
		defer probes.Wait()
		type probeResult struct {
			ok    bool
			epoch uint64
			at    int64
		}
		results := make(chan probeResult, 1)
		busy := false
		lastAttempt := time.Time{}
		confirmed := int64(0)
		confirmedEpoch := uint64(0)
		lastError := ""
		update := func() {
			if ctx.Err() != nil {
				return
			}
			sink.mu.Lock()
			epoch, switching := sink.state.PathEpoch, sink.state.PathSwitching
			sink.mu.Unlock()
			if epoch != confirmedEpoch {
				confirmed = 0
				confirmedEpoch = epoch
			}
			health := runtime.memory.Health()
			c := &runtime.handler.router.counters
			currentError := runtime.handler.router.leases.LastError()
			if currentError != "" && currentError != lastError {
				lastError = currentError
				sink.mu.Lock()
				sink.appendEventLocked("error", currentError, -1, 0, 0)
				sink.mu.Unlock()
			}
			catalogHash := systemCatalogSHA256
			if policy := runtime.handler.router.policy; policy.Catalog != nil {
				catalogHash = policy.Catalog.SHA256
			}
			sink.setSystemReport(systemRuntimeReport{PublicationRevision: runtime.handler.router.policy.PublicationRevision, CatalogSHA256: catalogHash, Requested: true, Active: true, Handshake: health.Handshake, Rx: health.Rx, Tx: health.Tx, EgressAt: confirmed, EgressEpoch: confirmedEpoch, DirectFlows: c.Direct.Load(), VPNFlows: c.VPN.Load(), BlockedFlows: c.Blocked.Load(), DNSQueries: c.DNSQueries.Load(), DNSErrors: c.DNSErrors.Load(), LastError: currentError, LocalDNSReady: runtime.localDNSReady, MDNSConfigured: runtime.mdnsConfigured, AppRules: len(runtime.handler.router.policy.apps), UnknownAppFlows: c.UnknownApp.Load()})
			if !busy && !switching && time.Since(lastAttempt) >= 10*time.Second {
				busy = true
				lastAttempt = time.Now()
				probes.Add(1)
				go func() {
					defer probes.Done()
					ok := probeEgressVia(ctx, func(c context.Context, network, address string) (net.Conn, error) {
						if address != "api.ipify.org:443" {
							return nil, errors.New("EGRESS_ENDPOINT_INVALID")
						}
						// Custom netstack DNS and TCP remain inside WG. No OS/default dialer.
						return runtime.memory.Net.DialContext(c, "tcp4", address)
					}, expected)
					select {
					case results <- probeResult{ok, epoch, time.Now().Unix()}:
					case <-ctx.Done():
					}
				}()
			}
		}
		update()
		for {
			select {
			case <-ctx.Done():
				return
			case result := <-results:
				busy = false
				sink.mu.Lock()
				epoch, switching := sink.state.PathEpoch, sink.state.PathSwitching
				sink.mu.Unlock()
				if result.ok && !switching && result.epoch == epoch {
					confirmed = result.at
					confirmedEpoch = result.epoch
				}
				update()
			case <-timer.C:
				update()
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { cancel(); <-done }) }
}
