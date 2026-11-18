package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type systemDial func(context.Context, string, string) (net.Conn, error)
type systemFlowCounters struct{ Direct, VPN, Blocked, DNSQueries, DNSErrors, UnknownApp atomic.Uint64 }
type systemFlowRouter struct {
	policy      *compiledSystemPolicy
	leases      *fakeDNS
	direct, vpn systemDial
	refresh     func(context.Context, string) error
	counters    systemFlowCounters
	owner       systemAppLookup
}

func isKnownBitTorrent(payload []byte) bool {
	if len(payload) >= 20 && payload[0] == 19 && string(payload[1:20]) == "BitTorrent protocol" {
		return true
	}
	if len(payload) > 12 && payload[0] == 'd' && payload[len(payload)-1] == 'e' {
		s := string(payload)
		return containsAll(s, "1:y1:q", "1:t") && (containsAny(s, "1:q9:get_peers", "1:q13:announce_peer", "1:q9:find_node", "1:q4:ping"))
	}
	return false
}
func containsAll(s string, parts ...string) bool {
	for _, p := range parts {
		if !strings.Contains(s, p) {
			return false
		}
	}
	return true
}
func containsAny(s string, parts ...string) bool {
	for _, p := range parts {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}
func (r *systemFlowRouter) targets(destination netip.AddrPort, protocol string) (routingDecision, []netip.Addr, error) {
	if !destination.IsValid() || destination.Port() == 0 {
		return routingDecision{}, nil, errSystemRouting
	}
	ip := destination.Addr()
	if !ip.Is4() {
		r.counters.Blocked.Add(1)
		return routingDecision{}, nil, errors.New("SYSTEM_IPV6_BLOCKED")
	}
	if netip.MustParsePrefix("198.18.0.0/15").Contains(ip) {
		lease, ok := r.leases.Lookup(ip)
		if !ok {
			r.counters.Blocked.Add(1)
			return routingDecision{}, nil, errors.New("DNS_LEASE_UNKNOWN")
		}
		if lease.Host == "" {
			return routingDecision{}, nil, errors.New("DNS_IDENTITY_REQUIRED")
		}
		if len(lease.Addresses) == 0 {
			decision := r.policy.DecideFlow(lease.Host, netip.Addr{}, destination.Port(), protocol)
			if decision.Action == "block" {
				r.counters.Blocked.Add(1)
				return decision, nil, errors.New("SYSTEM_FLOW_BLOCKED")
			}
			return decision, nil, nil // known identity; Dial must resolve it first
		}
		decision := lease.Decision
		if decision.Action != "vpn" && decision.Action != "direct" {
			return decision, nil, errSystemRouting
		}
		for _, address := range lease.Addresses {
			check := r.policy.DecideFlow(lease.Host, address, destination.Port(), protocol)
			if check.Action == "block" {
				r.counters.Blocked.Add(1)
				return routingDecision{}, nil, errors.New("SYSTEM_FLOW_BLOCKED")
			}
			if check.Rule == "protected-management" {
				decision = check
			}
		}
		return decision, lease.Addresses, nil
	}
	decision := r.policy.DecideFlow("", ip, destination.Port(), protocol)
	if decision.Action == "block" {
		r.counters.Blocked.Add(1)
		return decision, nil, errors.New("SYSTEM_FLOW_BLOCKED")
	}
	return decision, []netip.Addr{ip}, nil
}
func (r *systemFlowRouter) Dial(ctx context.Context, network string, destination netip.AddrPort) (net.Conn, error) {
	return r.dial(ctx, network, destination, nil)
}
func (r *systemFlowRouter) dial(ctx context.Context, network string, destination netip.AddrPort, owner *systemAppOwner) (net.Conn, error) {
	if network != "tcp4" && network != "udp4" {
		return nil, errSystemRouting
	}
	if r.policy.Enabled && len(r.policy.apps) > 0 && owner == nil {
		r.counters.Blocked.Add(1)
		r.counters.UnknownApp.Add(1)
		return nil, errSystemApp
	}
	if lease, ok := r.leases.Lookup(destination.Addr()); ok && (len(lease.Addresses) == 0 || !lease.Expires.IsZero() && !time.Now().Before(lease.Expires)) {
		if lease.Host == "" {
			return nil, errors.New("DNS_IDENTITY_REQUIRED")
		}
		if r.refresh == nil || r.refresh(ctx, lease.Host) != nil {
			return nil, errors.New("DNS_LEASE_REFRESH_FAILED")
		}
		updated, ok := r.leases.Lookup(destination.Addr())
		if !ok || len(updated.Addresses) == 0 || updated.Expires.IsZero() || !time.Now().Before(updated.Expires) {
			return nil, errors.New("DNS_LEASE_EXPIRED")
		}
	}
	decision, addresses, e := r.targets(destination, network)
	if e != nil {
		return nil, e
	}
	if owner != nil {
		decision = r.policy.applicationDecision(decision, owner.Path)
		if decision.Action == "block" {
			r.counters.Blocked.Add(1)
			return nil, errors.New("SYSTEM_FLOW_BLOCKED")
		}
	}
	dial := r.vpn
	if decision.Action == "direct" {
		dial = r.direct
	}
	if dial == nil {
		return nil, errors.New("SYSTEM_PATH_UNAVAILABLE")
	}
	var last error
	for _, ip := range addresses {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if owner != nil && owner.Current() != nil {
			r.counters.Blocked.Add(1)
			r.counters.UnknownApp.Add(1)
			return nil, errSystemApp
		}
		c, e := dial(ctx, network, net.JoinHostPort(ip.String(), strconv.Itoa(int(destination.Port()))))
		if e == nil {
			if owner != nil && owner.Current() != nil {
				c.Close()
				r.counters.Blocked.Add(1)
				r.counters.UnknownApp.Add(1)
				return nil, errSystemApp
			}
			if decision.Action == "direct" {
				r.counters.Direct.Add(1)
			} else {
				r.counters.VPN.Add(1)
			}
			return c, nil
		}
		last = e
	}
	// Retry only addresses on the already selected path. Never fall back to DIRECT.
	if last != nil {
		return nil, errors.New("SYSTEM_PATH_FAILED")
	}
	return nil, errors.New("SYSTEM_PATH_UNAVAILABLE")
}
