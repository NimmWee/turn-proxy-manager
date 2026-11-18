package main

import (
	"errors"
	"net/netip"

	tun "github.com/sagernet/sing-tun"
)

func systemRoutingEnabled(policy *systemPolicy) bool { return policy != nil && policy.Enabled }

func systemRoutingCapabilities() []string {
	if !tun.WithGVisor {
		return nil
	}
	return []string{"system-routing-ipv4-v1", "system-mdns-oneshot-ipv4-v1", "system-app-path-ipv4-v1", "awg1-userspace-ipv4-v1", "awg2-bounded-userspace-ipv4-v1", "awg3-bounded-userspace-ipv4-v1"}
}

func systemRuntimeErrorCode(code string) bool {
	switch code {
	case "AWG_SYSTEM_BACKEND_REQUIRED", "SYSTEM_DNS_CACHE_INVALID", "SYSTEM_DNS_CACHE_WRITE_FAILED", "SYSTEM_DNS_CACHE_FULL":
		return true
	case "SYSTEM_ROUTING_BUILD_REQUIRED", "SYSTEM_ROUTING_POLICY_INVALID", "SYSTEM_ROUTING_CATALOG_REQUIRED", "SYSTEM_ROUTING_CATALOG_HASH", "SYSTEM_PROFILE_NETWORK_UNSUPPORTED", "SYSTEM_PRIVATE_DNS_UNSUPPORTED", "SYSTEM_DNS_SERVER_INVALID", "SYSTEM_ADAPTER_READ_FAILED", "SYSTEM_TUN_NAME_IN_USE", "SYSTEM_TUN_RANGE_IN_USE", "SYSTEM_UPLINK_MISSING", "SYSTEM_UPLINK_ADDRESS_REQUIRED", "SYSTEM_ROUTE_READ_FAILED", "SYSTEM_ROUTE_TABLE_TOO_LARGE", "SYSTEM_ROUTING_CANCELLED", "SYSTEM_TUN_CREATE_FAILED", "SYSTEM_TUN_IDENTITY_FAILED", "SYSTEM_FIREWALL_FAILED", "SYSTEM_TUN_ADDRESS_FAILED", "SYSTEM_TUN_OPTIONS_FAILED", "SYSTEM_STACK_CREATE_FAILED", "SYSTEM_STACK_START_FAILED", "SYSTEM_NETWORK_NOT_READY", "SYSTEM_ROUTE_APPLY_FAILED", "SYSTEM_DNS_APPLY_FAILED", "SYSTEM_DNS_FLUSH_FAILED", "SYSTEM_NETWORK_ROLLBACK_FAILED", "SYSTEM_TUN_CLOSE_FAILED", "WG_MEMORY_CONFIG_INVALID", "WG_MEMORY_IPV4_REQUIRED", "WG_MEMORY_START_FAILED", "WG_LOOPBACK_REQUIRED":
		return true
	default:
		return false
	}
}

// Pure pre-SCM validation. No privileged reads/writes, adapters, routes or DNS.
func prepareSystemRouting(policy *systemPolicy, rawWG string) (*compiledSystemPolicy, error) {
	if isAWG(rawWG) && !systemRoutingEnabled(policy) {
		return nil, errors.New("AWG_SYSTEM_BACKEND_REQUIRED")
	}
	if policy == nil {
		return nil, nil
	}
	catalog, e := loadSystemCatalog()
	if e != nil {
		return nil, e
	}
	compiled, e := compileSystemPolicy(policy, catalog)
	if e != nil {
		return nil, e
	}
	if !policy.Enabled {
		return compiled, nil
	}
	if !tun.WithGVisor {
		return nil, errors.New("SYSTEM_ROUTING_BUILD_REQUIRED")
	}
	if _, e = systemProfileDNS(rawWG); e != nil {
		return nil, e
	}
	return compiled, nil
}
func systemProfileDNS(rawWG string) ([]netip.AddrPort, error) {
	if !safeWG(rawWG) {
		return nil, errors.New("SYSTEM_PROFILE_NETWORK_UNSUPPORTED")
	}
	config, _, e := memoryWGConfig(rawWG)
	if e != nil {
		return nil, errors.New("SYSTEM_PROFILE_NETWORK_UNSUPPORTED")
	}
	if len(config.Interface.Addresses) != 1 || !netip.MustParsePrefix("10.77.43.0/24").Contains(config.Interface.Addresses[0].Addr()) {
		return nil, errors.New("SYSTEM_PROFILE_NETWORK_UNSUPPORTED")
	}
	servers := []netip.AddrPort{}
	for _, ip := range config.Interface.DNS {
		if !publicIPv4(ip) {
			return nil, errors.New("SYSTEM_PRIVATE_DNS_UNSUPPORTED")
		}
		servers = append(servers, netip.AddrPortFrom(ip, 53))
	}
	if !validSystemResolvers(servers) {
		return nil, errors.New("SYSTEM_DNS_SERVER_INVALID")
	}
	return servers, nil
}
func systemDirectResolvers(p *compiledSystemPolicy) []netip.AddrPort {
	result := []netip.AddrPort{}
	for _, s := range p.DirectDNS {
		ip, e := netip.ParseAddr(s)
		if e != nil {
			return nil
		}
		result = append(result, netip.AddrPortFrom(ip, 53))
	}
	return result
}
