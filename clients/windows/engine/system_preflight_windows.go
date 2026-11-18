package main

import (
	"errors"
	"net/netip"
	"sort"
	"strings"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const systemTunName = "FreeTurn Router"

var systemTunAddress = netip.MustParsePrefix("198.19.255.253/30")
var systemTunGateway = netip.MustParseAddr("198.19.255.254")
var systemFakeRange = netip.MustParsePrefix("198.18.0.0/15")

type systemNetworkPlan struct {
	Index    uint32
	LUID     winipcfg.LUID
	Source   netip.Addr
	Capture  []netip.Prefix
	LocalDNS []netip.AddrPort
	MDNS     systemMDNSLink
}

// Capture each more-specific physical route with its two children. Merely
// adding /0 leaves on-link LAN and ISP routes outside TUN. Preserve prefixes:
// aggregating these children would recreate the original route/metric race.
func planSystemCapture(routes []netip.Prefix, local []netip.Addr) ([]netip.Prefix, error) {
	if len(routes) > 2048 {
		return nil, errors.New("SYSTEM_ROUTE_TABLE_TOO_LARGE")
	}
	owned := map[netip.Prefix]bool{netip.MustParsePrefix("0.0.0.0/1"): true, netip.MustParsePrefix("128.0.0.0/1"): true}
	for _, p := range routes {
		if !p.IsValid() || !p.Addr().Is4() || p != p.Masked() {
			return nil, errSystemRouting
		}
		if p.Bits() == 0 {
			continue
		}
		if p.Overlaps(systemFakeRange) {
			return nil, errors.New("SYSTEM_TUN_RANGE_IN_USE")
		}
		if !p.Addr().IsGlobalUnicast() || p.Addr().IsLoopback() || p.Addr().IsLinkLocalUnicast() {
			continue
		}
		if p.Bits() == 32 {
			own := false
			for _, ip := range local {
				if p.Addr() == ip {
					own = true
					break
				}
			}
			if !own {
				owned[p] = true
			}
			continue
		}
		bits := p.Bits() + 1
		first := netip.PrefixFrom(p.Addr(), bits)
		raw := p.Addr().As4()
		bit := p.Bits()
		raw[bit/8] |= 1 << uint(7-bit%8)
		owned[first] = true
		owned[netip.PrefixFrom(netip.AddrFrom4(raw), bits)] = true
	}
	result := make([]netip.Prefix, 0, len(owned))
	for p := range owned {
		result = append(result, p)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Bits() != result[j].Bits() {
			return result[i].Bits() > result[j].Bits()
		}
		return result[i].Addr().Less(result[j].Addr())
	})
	return result, nil
}

// READ ONLY. Never create/open a TUN, flush DNS, install WFP or change a route
// during preview/validation. An existing named adapter is not adopted implicitly.
func preflightSystemNetwork() (*systemNetworkPlan, error) {
	uplink, e := selectUnderlay()
	if e != nil {
		return nil, e
	}
	adapters, e := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, 0)
	if e != nil {
		return nil, errors.New("SYSTEM_ADAPTER_READ_FAILED")
	}
	var chosen *winipcfg.IPAdapterAddresses
	local := []netip.Addr{}
	for _, adapter := range adapters {
		if strings.EqualFold(adapter.FriendlyName(), systemTunName) {
			return nil, errors.New("SYSTEM_TUN_NAME_IN_USE")
		}
		for address := adapter.FirstUnicastAddress; address != nil; address = address.Next {
			ip, ok := netip.AddrFromSlice(address.Address.IP())
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if systemFakeRange.Contains(ip) {
				return nil, errors.New("SYSTEM_TUN_RANGE_IN_USE")
			}
			if ip.Is4() {
				local = append(local, ip)
			}
		}
		if adapter.IfIndex == uplink.v4 {
			chosen = adapter
		}
	}
	if chosen == nil {
		return nil, errors.New("SYSTEM_UPLINK_MISSING")
	}
	var source netip.Addr
	var prefix netip.Prefix
	for a := chosen.FirstUnicastAddress; a != nil; a = a.Next {
		ip, ok := netip.AddrFromSlice(a.Address.IP())
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if a.DadState == 4 && ip.Is4() && ip.IsGlobalUnicast() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
			source = ip
			prefix = netip.PrefixFrom(ip, int(a.OnLinkPrefixLength)).Masked()
			break
		}
	}
	if !source.IsValid() {
		return nil, errors.New("SYSTEM_UPLINK_ADDRESS_REQUIRED")
	}
	table, e := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if e != nil {
		return nil, errors.New("SYSTEM_ROUTE_READ_FAILED")
	}
	routes := []netip.Prefix{}
	connected := []netip.Prefix{}
	for _, r := range table {
		prefix := r.DestinationPrefix.Prefix()
		if prefix.IsValid() && prefix.Bits() > 0 && prefix.Overlaps(systemFakeRange) {
			return nil, errors.New("SYSTEM_TUN_RANGE_IN_USE")
		}
		if r.InterfaceLUID == chosen.LUID && !r.Loopback {
			routes = append(routes, prefix)
			if r.NextHop.Addr().IsUnspecified() {
				connected = append(connected, prefix)
			}
		}
	}
	capture, e := planSystemCapture(routes, local)
	if e != nil {
		return nil, e
	}
	candidates := []netip.Addr{}
	for d := chosen.FirstDNSServerAddress; d != nil; d = d.Next {
		if ip, ok := netip.AddrFromSlice(d.Address.IP()); ok {
			candidates = append(candidates, ip.Unmap())
		}
	}
	return &systemNetworkPlan{Index: chosen.IfIndex, LUID: chosen.LUID, Source: source, Capture: capture, LocalDNS: localSystemResolvers(candidates, connected), MDNS: systemMDNSLink{Index: chosen.IfIndex, Source: source, Prefix: prefix}}, nil
}
