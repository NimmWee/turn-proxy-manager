package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestSystemFlowDoesNotFallbackOrDialBlocked(t *testing.T) {
	policy, _ := compileSystemPolicy(&systemPolicy{V: 1, Enabled: true, Rules: []domainRule{{Domain: "one.example.com", Action: "direct"}}}, nil)
	leases := newFakeDNS(8)
	ip, _ := leases.Assign("one.example.com", routingDecision{Action: "direct"})
	leases.SetAddresses(ip, []netip.Addr{netip.MustParseAddr("1.1.1.1")})
	directCalls, vpnCalls := 0, 0
	router := &systemFlowRouter{policy: policy, leases: leases, direct: func(context.Context, string, string) (net.Conn, error) {
		directCalls++
		return nil, errors.New("synthetic")
	}, vpn: func(context.Context, string, string) (net.Conn, error) {
		vpnCalls++
		return nil, errors.New("synthetic")
	}}
	if _, e := router.Dial(context.Background(), "tcp4", netip.AddrPortFrom(ip, 443)); e == nil || directCalls != 1 || vpnCalls != 0 {
		t.Fatal("DIRECT fell back or did not fail closed")
	}
	if _, e := router.Dial(context.Background(), "tcp4", netip.MustParseAddrPort("169.254.169.254:80")); e == nil || directCalls != 1 || vpnCalls != 0 {
		t.Fatal("metadata was dialed")
	}
	if !isKnownBitTorrent(append([]byte{19}, []byte("BitTorrent protocol")...)) || isKnownBitTorrent([]byte{0xc0, 0, 0, 0, 1, 12, 34, 56}) {
		t.Fatal("plaintext torrent/QUIC classification incorrect")
	}
}

func TestSystemFlowRefreshesExpiredDNSBeforeDial(t *testing.T) {
	p, _ := compileSystemPolicy(&systemPolicy{V: 1, Enabled: true}, nil)
	leases := newFakeDNS(4)
	fake, _ := leases.Assign("example.com", routingDecision{Action: "vpn"})
	leases.setAddressesUntil(fake, []netip.Addr{netip.MustParseAddr("8.8.8.8")}, time.Now().Add(-time.Second))
	calls := 0
	r := &systemFlowRouter{policy: p, leases: leases, vpn: func(_ context.Context, _, addr string) (net.Conn, error) {
		calls++
		if addr != "9.9.9.9:443" {
			t.Error("expired address dialed")
		}
		a, b := net.Pipe()
		b.Close()
		return a, nil
	}}
	if _, e := r.Dial(context.Background(), "tcp4", netip.AddrPortFrom(fake, 443)); e == nil || calls != 0 {
		t.Fatal("expired DNS used without refresh")
	}
	r.refresh = func(context.Context, string) error { return errors.New("resolver unavailable") }
	if _, e := r.Dial(context.Background(), "tcp4", netip.AddrPortFrom(fake, 443)); e == nil || calls != 0 {
		t.Fatal("failed refresh fell back to stale DNS")
	}
	r.refresh = func(_ context.Context, host string) error {
		if host != "example.com" {
			t.Error("host identity lost")
		}
		return leases.setAddressesUntil(fake, []netip.Addr{netip.MustParseAddr("9.9.9.9")}, time.Now().Add(time.Minute))
	}
	c, e := r.Dial(context.Background(), "tcp4", netip.AddrPortFrom(fake, 443))
	if e != nil || calls != 1 {
		t.Fatal("fresh address was not used")
	}
	c.Close()
}
