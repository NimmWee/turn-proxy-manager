//go:build windows && with_gvisor

package main

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	awgtun "github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"github.com/miekg/dns"
	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/logger"
)

// A packet-level replacement for Wintun, confined to Go memory. Neither this
// fixture nor the test calls NativeTun.New/Start, WFP, SCM or OS routing APIs.
type systemPacketTestTun struct {
	endpoint *channel.Endpoint
	app      awgtun.Device
	mu       sync.Mutex
}

func (*systemPacketTestTun) Name() (string, error)                { return "memory-only", nil }
func (*systemPacketTestTun) Start() error                         { return nil }
func (*systemPacketTestTun) UpdateRouteOptions(tun.Options) error { return nil }
func (*systemPacketTestTun) Read([]byte) (int, error)             { return 0, io.ErrClosedPipe }
func (t *systemPacketTestTun) Write(b []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, e := t.app.Write([][]byte{b}, 0)
	return len(b), e
}
func (t *systemPacketTestTun) Close() error { t.endpoint.Close(); return nil }
func (t *systemPacketTestTun) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	return t.endpoint, stack.NICOptions{}, nil
}
func (t *systemPacketTestTun) WritePacket(pkt *stack.PacketBuffer) (int, error) {
	data := []byte{}
	for _, s := range pkt.AsSlices() {
		data = append(data, s...)
	}
	return t.Write(data)
}

func TestSystemPacketsDNSAndEncryptedTCPUDP(t *testing.T) {
	local, remote := memoryWGPair(t)
	tcp, e := remote.Net.ListenTCPAddrPort(netip.MustParseAddrPort("10.21.32.1:8080"))
	if e != nil {
		t.Fatal(e)
	}
	defer tcp.Close()
	go func() {
		c, e := tcp.Accept()
		if e == nil {
			defer c.Close()
			io.Copy(c, c)
		}
	}()
	udp, e := remote.Net.ListenUDPAddrPort(netip.MustParseAddrPort("10.21.32.1:8081"))
	if e != nil {
		t.Fatal(e)
	}
	defer udp.Close()
	go func() {
		b := make([]byte, 256)
		n, peer, e := udp.ReadFrom(b)
		if e == nil {
			udp.WriteTo(b[:n], peer)
		}
	}()
	p, e := compileSystemPolicy(&systemPolicy{V: 1, Enabled: true, Presets: systemPresets{LANDirect: true, BlockBitTorrent: true}, Rules: []domainRule{{Domain: "echo.example.com", Action: "vpn"}}, AppRules: []systemAppRule{{Path: `C:\Apps\PacketFixture.exe`, Action: "vpn"}}}, nil)
	if e != nil {
		t.Fatal(e)
	}
	leases := newFakeDNS(8)
	router := &systemFlowRouter{policy: p, leases: leases, vpn: memorySystemDial(local), direct: func(context.Context, string, string) (net.Conn, error) {
		t.Error("packet selected DIRECT")
		return nil, net.ErrClosed
	}}
	router.owner = func(_ context.Context, network string, source, destination netip.AddrPort) (*systemAppOwner, error) {
		if source.Addr() != systemTunAddress.Addr() || source.Port() == 0 || destination.Port() == 0 {
			t.Error("original application tuple lost at packet handler")
		}
		return &systemAppOwner{Path: `C:\Apps\PacketFixture.exe`, check: func() error { return nil }}, nil
	}
	resolver := newSystemDNS(p, leases, func(_ context.Context, d routingDecision, q *dns.Msg) (*dns.Msg, error) {
		if d.Action != "vpn" {
			t.Error("wrong DNS path")
		}
		r := new(dns.Msg)
		r.SetReply(q)
		r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("10.21.32.1")}}
		return r, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	h := newSystemHandler(ctx, router, resolver)
	appDevice, app, e := netstack.CreateNetTUN([]netip.Addr{systemTunAddress.Addr()}, []netip.Addr{systemTunGateway}, 1280)
	if e != nil {
		t.Fatal(e)
	}
	virtual := &systemPacketTestTun{endpoint: channel.New(256, 1280, ""), app: appDevice}
	outer, e := tun.NewStack("gvisor", tun.StackOptions{Context: ctx, Tun: virtual, TunOptions: tun.Options{Name: "memory-only", Inet4Address: []netip.Prefix{systemTunAddress}, MTU: 1280}, Handler: h, Logger: logger.NOP(), UDPTimeout: time.Minute, UDPNATMax: 64})
	if e != nil {
		t.Fatal(e)
	}
	if e = outer.Start(); e != nil {
		t.Fatal(e)
	}
	bridgeCtx, stopBridge := context.WithCancel(context.Background())
	returned := make(chan struct{})
	outgoing := make(chan struct{})
	go func() {
		defer close(returned)
		for {
			pkt := virtual.endpoint.ReadContext(bridgeCtx)
			if pkt == nil {
				return
			}
			if bridgeCtx.Err() != nil {
				pkt.DecRef()
				return
			}
			virtual.WritePacket(pkt)
			pkt.DecRef()
		}
	}()
	go func() {
		defer close(outgoing)
		frames := [][]byte{make([]byte, 65535)}
		sizes := make([]int, 1)
		for {
			n, e := appDevice.Read(frames, sizes, 0)
			if e != nil {
				return
			}
			for i := 0; i < n; i++ {
				data := append([]byte(nil), frames[i][:sizes[i]]...)
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
				virtual.endpoint.InjectInbound(header.IPv4ProtocolNumber, pkt)
				pkt.DecRef()
			}
		}
	}()
	defer func() {
		h.Close()
		outer.Close()
		stopBridge()
		<-returned
		appDevice.Close()
		<-outgoing
		virtual.Close()
	}()
	c, e := app.DialContext(ctx, "tcp4", "echo.example.com:8080")
	if e != nil {
		t.Fatal("packet DNS/TCP failed", e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write([]byte("packet TCP"))
	b := make([]byte, len("packet TCP"))
	if _, e = io.ReadFull(c, b); e != nil || string(b) != "packet TCP" {
		t.Fatal("packet TCP echo failed")
	}
	u, e := app.DialContext(ctx, "udp4", "echo.example.com:8081")
	if e != nil {
		t.Fatal("packet DNS/UDP failed", e)
	}
	defer u.Close()
	u.SetDeadline(time.Now().Add(3 * time.Second))
	u.Write([]byte("packet UDP"))
	b = make([]byte, 256)
	n, e := u.Read(b)
	if e != nil || string(b[:n]) != "packet UDP" {
		t.Fatal("packet UDP echo failed")
	}
	if router.counters.VPN.Load() != 2 || router.counters.Direct.Load() != 0 || router.counters.DNSQueries.Load() < 2 {
		t.Fatal("packet paths/counters incorrect")
	}
}
