package main

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestSystemDNSExchangeTCPRetryStaysOnSelectedPath(t *testing.T) {
	// Windows has independent TCP/UDP excluded ranges. Let each allocator pick
	// its own port; the fake dialer below retains the logical DNS address check.
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	udp, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer udp.Close()
	serverErrors := make(chan error, 2)
	go func() {
		data := make([]byte, 4096)
		udp.SetDeadline(time.Now().Add(3 * time.Second))
		n, peer, e := udp.ReadFrom(data)
		if e != nil {
			serverErrors <- e
			return
		}
		q := new(dns.Msg)
		e = q.Unpack(data[:n])
		if e != nil {
			serverErrors <- e
			return
		}
		r := new(dns.Msg)
		r.SetReply(q)
		r.Truncated = true
		wire, _ := r.Pack()
		_, e = udp.WriteTo(wire, peer)
		serverErrors <- e
	}()
	go func() {
		listener.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second))
		c, e := listener.Accept()
		if e != nil {
			serverErrors <- e
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		dc := &dns.Conn{Conn: c}
		q, e := dc.ReadMsg()
		if e != nil {
			serverErrors <- e
			return
		}
		r := new(dns.Msg)
		r.SetReply(q)
		serverErrors <- dc.WriteMsg(r)
	}()
	directCalls := 0
	networks := []string{}
	exchange := newSystemDNSExchange(func(context.Context, string, string) (net.Conn, error) { directCalls++; return nil, net.ErrClosed }, func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "1.1.1.1:53" {
			t.Error("wrong logical DNS server")
		}
		networks = append(networks, network)
		target := listener.Addr().String()
		if network == "udp4" {
			target = udp.LocalAddr().String()
		}
		return (&net.Dialer{}).DialContext(ctx, network, target)
	}, nil, []netip.AddrPort{netip.MustParseAddrPort("1.1.1.1:53")})
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	r, e := exchange(ctx, routingDecision{Action: "vpn"}, q)
	if e != nil || !validSystemDNSResponse(q, r) || directCalls != 0 || len(networks) != 2 || networks[0] != "udp4" || networks[1] != "tcp4" {
		t.Fatal("DNS TCP retry changed path or failed")
	}
	for i := 0; i < 2; i++ {
		if e := <-serverErrors; e != nil {
			t.Fatal(e)
		}
	}
}
