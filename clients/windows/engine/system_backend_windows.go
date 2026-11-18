package main

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/windnsapi"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/firewall"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

type systemRuntime struct {
	cancel         context.CancelFunc
	adapter        tun.Tun
	firewall       bool
	memory         *memoryWG
	handler        *systemHandler
	stack          tun.Stack
	stackStarted   bool
	published      *systemPublishedNetwork
	once           sync.Once
	closeError     error
	identities     *fakeDNSJournal
	localDNSReady  bool
	mdnsConfigured bool
}

// MUTATING entry point, deliberately not exposed by preview/check commands.
// Only the explicit opt-in tunnel-service branch calls it; WGNT stays default.
// Build with with_gvisor: the library's system stack silently adds a persistent
// broad inbound firewall rule on Start, so it is intentionally never selected.
func startSystemRuntime(parent context.Context, rawWG string, policy *compiledSystemPolicy, directResolvers []netip.AddrPort, leases *fakeDNS, progress func(string)) (runtime *systemRuntime, result error) {
	stage := func(s string) {
		if progress != nil {
			progress(s)
		}
	}
	if !tun.WithGVisor {
		return nil, errors.New("SYSTEM_ROUTING_BUILD_REQUIRED")
	}
	if policy == nil || !policy.Enabled || !safeWG(rawWG) {
		return nil, errSystemRouting
	}
	if leases == nil || leases.persist == nil {
		return nil, errors.New("SYSTEM_DNS_CACHE_INVALID")
	}
	if e := requireSystem(); e != nil {
		return nil, e
	}
	vpnResolvers, e := systemProfileDNS(rawWG)
	if e != nil {
		return nil, e
	}
	if !validSystemResolvers(vpnResolvers) || !validSystemResolvers(directResolvers) {
		return nil, errors.New("SYSTEM_DNS_SERVER_INVALID")
	}
	stage("system_routing_preflight")
	plan, e := preflightSystemNetwork()
	if e != nil {
		return nil, e
	}
	if parent.Err() != nil {
		return nil, errors.New("SYSTEM_ROUTING_CANCELLED")
	}
	ctx, cancel := context.WithCancel(parent)
	owner := &systemRuntime{cancel: cancel, localDNSReady: len(plan.LocalDNS) > 0}
	defer func() {
		if result != nil {
			if cleanup := owner.Close(); cleanup != nil {
				result = cleanup
			}
		}
	}()
	options := tun.Options{Name: systemTunName, Inet4Address: []netip.Prefix{systemTunAddress}, MTU: 1280, AutoRoute: false, DNSMode: tun.DNSModeDisabled, EXP_ExternalConfiguration: true, Logger: logger.NOP()}
	// No implicit adapter adoption: preflight rejected a name collision above.
	stage("system_adapter_start")
	adapter, e := tun.New(options)
	if e != nil {
		return nil, errors.New("SYSTEM_TUN_CREATE_FAILED")
	}
	owner.adapter = adapter
	if ctx.Err() != nil {
		return nil, errors.New("SYSTEM_ROUTING_CANCELLED")
	}
	native, ok := adapter.(interface{ LUID() uint64 })
	if !ok || native.LUID() == 0 {
		return nil, errors.New("SYSTEM_TUN_IDENTITY_FAILED")
	}
	luid := winipcfg.LUID(native.LUID())
	if luid == plan.LUID {
		return nil, errors.New("SYSTEM_TUN_IDENTITY_FAILED")
	}
	// Strict service-SID firewall precedes all route publication. No API/broker
	// process exception and no application/physical route exclusion are added.
	stage("system_firewall_start")
	if firewall.EnableFirewall(uint64(luid), false, []netip.Addr{systemTunGateway}) != nil {
		return nil, errors.New("SYSTEM_FIREWALL_FAILED")
	}
	owner.firewall = true
	if ctx.Err() != nil {
		return nil, errors.New("SYSTEM_ROUTING_CANCELLED")
	}
	stage("system_network_config")
	if luid.AddIPAddress(systemTunAddress) != nil {
		return nil, errors.New("SYSTEM_TUN_ADDRESS_FAILED")
	}
	iface, e := luid.IPInterface(windows.AF_INET)
	if e != nil {
		return nil, errors.New("SYSTEM_TUN_OPTIONS_FAILED")
	}
	iface.ForwardingEnabled = false
	iface.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
	iface.DadTransmits = 0
	iface.ManagedAddressConfigurationSupported = false
	iface.OtherStatefulConfigurationSupported = false
	iface.NLMTU = 1280
	iface.UseAutomaticMetric = false
	iface.Metric = 0
	if iface.Set() != nil {
		return nil, errors.New("SYSTEM_TUN_OPTIONS_FAILED")
	}
	stage("system_wireguard_start")
	owner.memory, e = startMemoryWG(rawWG)
	if e != nil {
		return nil, e
	}
	router := &systemFlowRouter{policy: policy, leases: leases, direct: boundSystemDial(plan.LUID, plan.Index, plan.Source), vpn: memorySystemDial(owner.memory)}
	router.owner = lookupSystemAppOwner
	dns := newSystemDNS(policy, leases, newSystemDNSExchange(router.direct, router.vpn, directResolvers, vpnResolvers))
	dns.localExchange = newSystemDNSExchange(router.direct, nil, plan.LocalDNS, nil)
	if policy.Presets.LANDirect && plan.MDNS.valid() {
		link := plan.MDNS
		dns.mdnsExchange = newSystemMDNSExchange(link, func(ctx context.Context) (systemMDNSPacketConn, error) { return openSystemMDNS(ctx, plan.LUID, link) }, func() error { return systemMDNSCurrent(plan.LUID, link) })
		owner.mdnsConfigured = true
	}
	owner.handler = newSystemHandler(ctx, router, dns)
	stage("system_stack_start")
	owner.stack, e = tun.NewStack("gvisor", tun.StackOptions{Context: ctx, Tun: adapter, TunOptions: options, Handler: owner.handler, Logger: logger.NOP(), UDPTimeout: 60 * time.Second, UDPNATMax: 2048})
	if e != nil {
		return nil, errors.New("SYSTEM_STACK_CREATE_FAILED")
	}
	if owner.stack.Start() != nil {
		return nil, errors.New("SYSTEM_STACK_START_FAILED")
	}
	owner.stackStarted = true
	if ctx.Err() != nil {
		return nil, errors.New("SYSTEM_ROUTING_CANCELLED")
	}
	// NativeTun.Start/UpdateRouteOptions are intentionally unused; they mutate
	// routes/DNS internally. Explicit publication gives ordered rollback ownership.
	stage("system_routes_publish")
	owner.published, e = publishSystemNetwork(systemPublishOps{
		AddRoute: func(p netip.Prefix) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return luid.AddRoute(p, systemTunGateway, 0)
		},
		DeleteRoute: func(p netip.Prefix) error { return luid.DeleteRoute(p, systemTunGateway) },
		SetDNS: func(a []netip.Addr) error {
			if len(a) > 0 && ctx.Err() != nil {
				return ctx.Err()
			}
			return luid.SetDNS(windows.AF_INET, a, nil)
		},
		FlushDNS: windnsapi.FlushResolverCache,
	}, plan.Capture, owner.firewall && owner.stackStarted)
	if e != nil {
		return nil, e
	}
	stage("system_routing_ready")
	return owner, nil
}
func validSystemResolvers(servers []netip.AddrPort) bool {
	if len(servers) == 0 || len(servers) > 4 {
		return false
	}
	for _, s := range servers {
		if !s.IsValid() || !publicIPv4(s.Addr()) || s.Port() != 53 {
			return false
		}
	}
	return true
}
func (s *systemRuntime) Close() error {
	s.once.Do(func() {
		// First withdraw DNS/routes while the restrictive firewall still exists.
		if s.published != nil {
			s.closeError = s.published.Close()
		}
		s.cancel()
		// Unblock the endpoint's native Read before waiting for flow workers.
		if s.adapter != nil {
			if s.adapter.Close() != nil {
				s.closeError = errors.New("SYSTEM_TUN_CLOSE_FAILED")
			}
		}
		if s.handler != nil {
			s.handler.Close()
		}
		if s.stack != nil && s.stackStarted {
			s.stack.Close()
		}
		if s.memory != nil {
			s.memory.Close()
		}
		if s.identities != nil {
			if e := s.identities.Close(); e != nil && s.closeError == nil {
				s.closeError = e
			}
		}
		if s.firewall {
			firewall.DisableFirewall()
		}
	})
	return s.closeError
}
