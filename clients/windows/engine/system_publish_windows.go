package main

import (
	"errors"
	"net/netip"
	"sync"
)

// All operations are scoped to a newly owned adapter. No physical-interface
// DNS/routes are edited. The runtime installs WFP and starts handlers FIRST.
type systemPublishOps struct {
	AddRoute    func(netip.Prefix) error
	DeleteRoute func(netip.Prefix) error
	SetDNS      func([]netip.Addr) error
	FlushDNS    func() error
}
type systemPublishedNetwork struct {
	ops          systemPublishOps
	routes       []netip.Prefix
	dnsAttempted bool
	once         sync.Once
	closeError   error
}

func publishSystemNetwork(ops systemPublishOps, routes []netip.Prefix, ready bool) (published *systemPublishedNetwork, result error) {
	if !ready || len(routes) == 0 || len(routes) > 4098 || ops.AddRoute == nil || ops.DeleteRoute == nil || ops.SetDNS == nil || ops.FlushDNS == nil {
		return nil, errors.New("SYSTEM_NETWORK_NOT_READY")
	}
	seen := map[netip.Prefix]bool{}
	for _, p := range routes {
		if !p.IsValid() || !p.Addr().Is4() || p != p.Masked() || seen[p] {
			return nil, errSystemRouting
		}
		seen[p] = true
	}
	owned := &systemPublishedNetwork{ops: ops}
	defer func() {
		if result != nil {
			if cleanup := owned.Close(); cleanup != nil {
				result = cleanup
			}
		}
	}()
	for _, p := range routes {
		if ops.AddRoute(p) != nil {
			return nil, errors.New("SYSTEM_ROUTE_APPLY_FAILED")
		}
		owned.routes = append(owned.routes, p)
	}
	owned.dnsAttempted = true // A failing OS DNS operation can have partially applied.
	if ops.SetDNS([]netip.Addr{systemTunGateway}) != nil {
		return nil, errors.New("SYSTEM_DNS_APPLY_FAILED")
	}
	if ops.FlushDNS() != nil {
		return nil, errors.New("SYSTEM_DNS_FLUSH_FAILED")
	}
	return owned, nil
}
func (p *systemPublishedNetwork) Close() error {
	p.once.Do(func() {
		failed := false
		if p.dnsAttempted && p.ops.SetDNS(nil) != nil {
			failed = true
		}
		for i := len(p.routes) - 1; i >= 0; i-- {
			if p.ops.DeleteRoute(p.routes[i]) != nil {
				failed = true
			}
		}
		if p.dnsAttempted && p.ops.FlushDNS() != nil {
			failed = true
		}
		if failed {
			p.closeError = errors.New("SYSTEM_NETWORK_ROLLBACK_FAILED")
		}
	})
	return p.closeError
}
