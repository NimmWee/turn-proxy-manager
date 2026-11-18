package main

import (
	"net/netip"
	"testing"
)

func TestSystemCaptureLANRoutesAndCollision(t *testing.T) {
	source := netip.MustParseAddr("192.168.1.5")
	input := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("192.168.1.5/32"), netip.MustParsePrefix("8.8.8.8/32")}
	routes, e := planSystemCapture(input, []netip.Addr{source})
	if e != nil {
		t.Fatal(e)
	}
	seen := map[string]bool{}
	for _, p := range routes {
		seen[p.String()] = true
	}
	for _, s := range []string{"0.0.0.0/1", "128.0.0.0/1", "192.168.1.0/25", "192.168.1.128/25", "8.8.8.8/32"} {
		if !seen[s] {
			t.Fatal("capture missing " + s)
		}
	}
	if seen["192.168.1.0/24"] || seen["192.168.1.5/32"] || input[1].String() != "192.168.1.0/24" {
		t.Fatal("routes merged, source overridden or caller changed")
	}
	for _, collision := range []string{"198.18.0.0/16", "198.19.255.254/32", "128.0.0.0/1"} {
		if _, e := planSystemCapture([]netip.Prefix{netip.MustParsePrefix(collision)}, nil); e == nil {
			t.Fatal("fake range collision accepted")
		}
	}
}
