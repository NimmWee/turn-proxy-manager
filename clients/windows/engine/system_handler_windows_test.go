package main

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

func TestSystemHandlerTCPOverEncryptedMemoryWGAndCancellation(t *testing.T) {
	local, remote := memoryWGPair(t)
	server, e := remote.Net.ListenTCPAddrPort(netip.MustParseAddrPort("10.21.32.1:8080"))
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	go func() {
		c, e := server.Accept()
		if e == nil {
			defer c.Close()
			io.Copy(c, c)
		}
	}()
	p, e := compileSystemPolicy(&systemPolicy{V: 1, Enabled: true, Presets: systemPresets{LANDirect: true, BlockBitTorrent: true}}, nil)
	if e != nil {
		t.Fatal(e)
	}
	leases := newFakeDNS(8)
	ip, _ := leases.Assign("vpn.example.com", routingDecision{Action: "vpn"})
	leases.SetAddresses(ip, []netip.Addr{netip.MustParseAddr("10.21.32.1")})
	router := &systemFlowRouter{policy: p, leases: leases, vpn: memorySystemDial(local), direct: func(context.Context, string, string) (net.Conn, error) {
		t.Error("VPN flow attempted DIRECT")
		return nil, net.ErrClosed
	}}
	h := newSystemHandler(context.Background(), router, nil)
	defer h.Close()
	app, inbound := net.Pipe()
	defer app.Close()
	dest := M.SocksaddrFrom(ip, 8080)
	if h.JudgeFlow(6, netip.MustParseAddrPort("192.168.1.5:5000"), dest.AddrPort(), nil).Action != tun.ActionAccept {
		t.Fatal("valid flow rejected")
	}
	done := make(chan struct{})
	go func() { h.NewConnectionEx(context.Background(), inbound, M.Socksaddr{}, dest, nil); close(done) }()
	app.SetDeadline(time.Now().Add(4 * time.Second))
	if _, e = app.Write([]byte("encrypted routed echo")); e != nil {
		t.Fatal(e)
	}
	answer := make([]byte, len("encrypted routed echo"))
	if _, e = io.ReadFull(app, answer); e != nil || string(answer) != "encrypted routed echo" {
		t.Fatal("flow did not traverse handler/WG/return path")
	}
	h.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancel left TCP flow alive")
	}
	if router.counters.VPN.Load() != 1 || router.counters.Direct.Load() != 0 {
		t.Fatal("wrong path counters")
	}
	if h.JudgeFlow(6, netip.MustParseAddrPort("192.168.1.5:5000"), dest.AddrPort(), nil).Action != tun.ActionReject {
		t.Fatal("closed handler accepted new flow")
	}
}

func TestSystemHandlerBlocksTorrentBeforeSendingPayload(t *testing.T) {
	src, input := net.Pipe()
	dst, output := net.Pipe()
	defer src.Close()
	defer dst.Close()
	defer output.Close()
	done := make(chan error, 1)
	go func() { defer input.Close(); done <- copySystemTCP(output, input, true) }()
	src.SetDeadline(time.Now().Add(time.Second))
	src.Write([]byte{19})
	src.Write([]byte("BitTorrent protocol"))
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("plaintext torrent passed")
		}
	case <-time.After(time.Second):
		t.Fatal("sniffer stalled")
	}
	dst.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	b := make([]byte, 1)
	if n, _ := dst.Read(b); n != 0 {
		t.Fatal("blocked payload sent upstream")
	}
}

type systemTestPacketConn struct {
	*net.UDPConn
	destination M.Socksaddr
	mu          sync.Mutex
	peer        *net.UDPAddr
}

func (c *systemTestPacketConn) ReadPacket(b *buf.Buffer) (M.Socksaddr, error) {
	data := make([]byte, 65535)
	n, peer, e := c.ReadFromUDP(data)
	if e != nil {
		return M.Socksaddr{}, e
	}
	c.mu.Lock()
	c.peer = peer
	c.mu.Unlock()
	_, e = b.Write(data[:n])
	return c.destination, e
}
func (c *systemTestPacketConn) WritePacket(b *buf.Buffer, destination M.Socksaddr) error {
	defer b.Release()
	if destination != c.destination {
		return net.ErrClosed
	}
	c.mu.Lock()
	peer := c.peer
	c.mu.Unlock()
	if peer == nil {
		return net.ErrClosed
	}
	_, e := c.WriteToUDP(b.Bytes(), peer)
	return e
}

func TestSystemHandlerUDPEncryptedReturnAndCancellation(t *testing.T) {
	local, remote := memoryWGPair(t)
	server, e := remote.Net.ListenUDPAddrPort(netip.MustParseAddrPort("10.21.32.1:5300"))
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	go func() {
		b := make([]byte, 256)
		n, peer, e := server.ReadFrom(b)
		if e == nil {
			server.WriteTo(b[:n], peer)
		}
	}()
	p, _ := compileSystemPolicy(&systemPolicy{V: 1, Enabled: true, Presets: systemPresets{LANDirect: true}}, nil)
	leases := newFakeDNS(8)
	ip, _ := leases.Assign("udp.example.com", routingDecision{Action: "vpn"})
	leases.SetAddresses(ip, []netip.Addr{netip.MustParseAddr("10.21.32.1")})
	h := newSystemHandler(context.Background(), &systemFlowRouter{policy: p, leases: leases, vpn: memorySystemDial(local)}, nil)
	defer h.Close()
	ingress, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer ingress.Close()
	app, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer app.Close()
	destination := M.SocksaddrFrom(ip, 5300)
	done := make(chan struct{})
	go func() {
		h.NewPacketConnectionEx(context.Background(), &systemTestPacketConn{UDPConn: ingress, destination: destination}, M.Socksaddr{}, destination, nil)
		close(done)
	}()
	app.SetDeadline(time.Now().Add(4 * time.Second))
	app.WriteToUDP([]byte("routed UDP"), ingress.LocalAddr().(*net.UDPAddr))
	b := make([]byte, 256)
	n, _, e := app.ReadFromUDP(b)
	if e != nil || string(b[:n]) != "routed UDP" {
		t.Fatal("UDP did not traverse handler and encrypted WG")
	}
	h.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("UDP flow survived cancellation")
	}
}
