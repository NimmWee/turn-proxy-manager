package main

import (
	"net/netip"
	"testing"
)

func TestSystemPolicyProtectedAndDomainPrecedence(t *testing.T) {
	p, e := compileSystemPolicy(&systemPolicy{V: 1, Enabled: true, Presets: systemPresets{RussianDirect: true, LANDirect: true, YouTubeVPN: true, PushVPN: true, ConnectivityDirect: true, BlockBitTorrent: true, SplitDNS: true}, Rules: []domainRule{{Domain: "example.com", Action: "direct", Subdomains: true}, {Domain: "blocked.example.com", Action: "block", Subdomains: true}}}, &systemCatalog{RUSuffix: []string{"ru"}, VPNYouTube: []string{"youtube.com"}, VPNPush: []string{"push.apple.com"}, Connectivity: []string{"connectivitycheck.gstatic.com"}, RUPrefixes: []netip.Prefix{netip.MustParsePrefix("8.8.8.0/24")}})
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct{ host, ip, protocol, want string }{
		{"example.com", "10.77.43.1", "udp4", "block"}, {"example.com", "10.77.43.1", "tcp4", "vpn"},
		{"video.youtube.com", "8.8.8.8", "tcp", "vpn"}, {"push.apple.com", "8.8.8.8", "tcp", "vpn"}, {"site.ru", "1.1.1.1", "tcp", "direct"}, {"blocked.example.com", "1.1.1.1", "tcp", "block"}, {"example.com", "169.254.169.254", "tcp", "block"}, {"example.com", "10.77.43.1", "tcp", "vpn"}, {"other.com", "192.168.1.2", "tcp", "direct"}, {"connectivitycheck.gstatic.com", "1.1.1.1", "tcp", "direct"}, {"other.com", "2606:4700:4700::1111", "tcp", "block"}, {"site.ru", "1.1.1.1", "bittorrent", "block"},
	} {
		r := p.DecideSystem(tc.host, netip.MustParseAddr(tc.ip), tc.protocol)
		if r.Action != tc.want {
			t.Fatalf("decision %s/%s = %s, want %s", tc.host, tc.protocol, r.Action, tc.want)
		}
	}
}

func TestSystemDNSLeaseIsolation(t *testing.T) {
	leases := newFakeDNS(2)
	a, e := leases.Assign("one.example.com", routingDecision{Action: "direct"})
	if e != nil {
		t.Fatal(e)
	}
	b, e := leases.Assign("two.example.com", routingDecision{Action: "vpn"})
	if e != nil || a == b {
		t.Fatal("shared destination domains were collapsed")
	}
	if _, e = leases.Assign("three.example.com", routingDecision{Action: "vpn"}); e == nil {
		t.Fatal("lease limit did not fail closed")
	}
	x, ok := leases.Lookup(a)
	if !ok || x.Host != "one.example.com" || x.Decision.Action != "direct" {
		t.Fatal("fake-IP route lost")
	}
	if _, ok := leases.Lookup(netip.MustParseAddr("198.19.255.255")); ok {
		t.Fatal("unknown fake IP accepted")
	}
}
