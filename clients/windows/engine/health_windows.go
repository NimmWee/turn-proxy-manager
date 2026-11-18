package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"time"
)

// Called with broker.mu held, only after the tunnel service and transport are
// running. The probe also triggers the first WG handshake if needed.
// Binding the tunnel source address prevents a direct-route success
// from being reported as a working VPN. No profile-supplied URLs are requested.
func (b *broker) maybeProbe() {
	if b.probeBusy || time.Since(b.probeAttempt) < 10*time.Second {
		return
	}
	data, e := readSecret(filepath.Join(b.dir, "profile.dpapi"), "FreeTurn profile v1")
	if e != nil {
		return
	}
	p, e := parseProfile(string(data))
	if e != nil {
		return
	}
	wg, _, e := memoryWGConfig(p.WG)
	if e != nil {
		return
	}
	var source net.IP
	for _, a := range wg.Interface.Addresses {
		if a.Addr().Is4() {
			source = net.ParseIP(a.Addr().String())
			break
		}
	}
	if source == nil {
		return
	}
	host, _, _ := net.SplitHostPort(p.Peer)
	expected, e := netip.ParseAddr(host)
	if e != nil {
		return
	}
	generation := b.generation
	b.probeBusy = true
	b.probeAttempt = time.Now()
	go func() {
		ok := probeEgress(source, expected)
		b.mu.Lock()
		defer b.mu.Unlock()
		b.probeBusy = false
		if generation == b.generation && ok && !b.closing {
			b.probeConfirmed = time.Now()
		}
	}()
}

func probeEgress(source net.IP, expected netip.Addr) bool {
	dialer := &net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: source}}
	return probeEgressVia(context.Background(), func(ctx context.Context, _, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp4", addr)
	}, expected)
}

func probeEgressVia(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), expected netip.Addr) bool {
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != "api.ipify.org:443" {
			return nil, net.InvalidAddrError("EGRESS_ENDPOINT_INVALID")
		}
		return dial(ctx, network, addr)
	}, ForceAttemptHTTP2: false}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 7 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	request, e := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ipify.org", nil)
	if e != nil {
		return false
	}
	r, e := client.Do(request)
	if e != nil {
		return false
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return false
	}
	data, e := io.ReadAll(io.LimitReader(r.Body, 65))
	if e != nil || len(data) > 64 {
		return false
	}
	address, e := netip.ParseAddr(strings.TrimSpace(string(data)))
	return e == nil && address == expected
}
