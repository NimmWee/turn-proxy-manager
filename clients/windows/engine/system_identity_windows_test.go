package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSystemOpaqueTCPIdentityRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.dpapi")
	leases, j, e := openFakeDNSJournal(path, false)
	if e != nil {
		t.Fatal(e)
	}
	ip, _ := leases.Assign("one.example.com", routingDecision{Action: "vpn"})
	j.Close()
	leases, j, e = openFakeDNSJournal(path, true)
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	for _, host := range []string{"two.example.com", "one.example.com"} {
		a, b := net.Pipe()
		payload := []byte("GET /private HTTP/1.1\r\nHost: " + host + "\r\n\r\nbody")
		go func() { defer b.Close(); b.Write(payload) }()
		c, e := recoverSystemIdentity(a, leases, ip)
		if host == "two.example.com" {
			if e == nil {
				t.Fatal("mismatched HTTP identity accepted")
			}
		} else {
			if e != nil {
				t.Fatal("matching HTTP identity refused")
			}
			got, _ := io.ReadAll(c)
			if !bytes.Equal(got, payload) {
				t.Fatal("HTTP payload modified")
			}
		}
		a.Close()
	}
	// Real Go TLS ClientHello, including current extensions. Capture bytes without
	// completing TLS or emitting a server handshake to the application's socket.
	ip2, _ := leases.Assign("tls.example.com", routingDecision{Action: "vpn"})
	j.Close()
	leases, j, e = openFakeDNSJournal(path, true)
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	a, b := net.Pipe()
	client := tls.Client(b, &tls.Config{ServerName: "tls.example.com"})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		client.HandshakeContext(ctx)
		b.Close()
	}()
	recovered, e := recoverSystemIdentity(a, leases, ip2)
	if e != nil || recovered == nil {
		t.Fatal("TLS SNI recovery failed")
	}
	a.Close()
	lease, _ := leases.Lookup(ip2)
	if lease.Host != "tls.example.com" {
		t.Fatal("SNI was not bound to existing identity")
	}
	// Unknown fake IP and stale UDP remain closed rather than guessing public DNS.
	if leases.Recover(netip.MustParseAddr("198.18.3.3"), "tls.example.com") {
		t.Fatal("unknown fake IP accepted")
	}
}

func TestSystemOpaqueIdentityOversizeAndUnknownCannotDial(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bounded.dpapi")
	leases, j, e := openFakeDNSJournal(path, false)
	if e != nil {
		t.Fatal(e)
	}
	ip, _ := leases.Assign("one.example.com", routingDecision{Action: "vpn"})
	j.Close()
	leases, j, e = openFakeDNSJournal(path, true)
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	policy, _ := compileSystemPolicy(&systemPolicy{V: 1, Enabled: true}, nil)
	calls := 0
	router := &systemFlowRouter{policy: policy, leases: leases, vpn: func(context.Context, string, string) (net.Conn, error) { calls++; return nil, nil }}
	router.refresh = func(context.Context, string) error { calls++; return nil }
	if _, e = router.Dial(context.Background(), "udp4", netip.AddrPortFrom(ip, 443)); e == nil || calls != 0 {
		t.Fatal("opaque UDP guessed identity or dialed")
	}
	a, b := net.Pipe()
	go func() {
		defer b.Close()
		b.Write([]byte("GET / HTTP/1.1\r\nX-Padding: " + strings.Repeat("a", maxSystemIdentityBytes) + "\r\nHost: one.example.com\r\n\r\n"))
	}()
	_, e = recoverSystemIdentity(a, leases, ip)
	a.Close()
	if e == nil {
		t.Fatal("oversize identity accepted")
	}
	lease, _ := leases.Lookup(ip)
	if lease.Host != "" {
		t.Fatal("failed recovery bound hostname")
	}
}
