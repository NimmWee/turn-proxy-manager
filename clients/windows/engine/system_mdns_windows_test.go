package main

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/miekg/dns"
	"golang.org/x/sys/windows"
)

func mdnsTestLink() systemMDNSLink {
	return systemMDNSLink{Index: 7, Source: netip.MustParseAddr("192.168.1.10"), Prefix: netip.MustParsePrefix("192.168.1.0/24")}
}
func mdnsTestInfo(l systemMDNSLink) []byte {
	h := int(unsafe.Sizeof(windows.WSACMSGHDR{}))
	word := int(unsafe.Sizeof(uintptr(0)))
	b := make([]byte, h+8)
	if word == 8 {
		binary.LittleEndian.PutUint64(b, uint64(len(b)))
	} else {
		binary.LittleEndian.PutUint32(b, uint32(len(b)))
	}
	binary.LittleEndian.PutUint32(b[word:], windows.IPPROTO_IP)
	binary.LittleEndian.PutUint32(b[word+4:], windows.IP_PKTINFO)
	a := l.Source.As4()
	copy(b[h:], a[:])
	binary.LittleEndian.PutUint32(b[h+4:], l.Index)
	return b
}
func mdnsTestResponse(q *dns.Msg) *dns.Msg {
	r := new(dns.Msg)
	r.SetReply(q)
	r.Authoritative = true
	r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120}, A: net.IPv4(192, 168, 1, 20)}}
	return r
}

type mdnsTestPacket struct {
	wire, info []byte
	peer       netip.AddrPort
	flags      int
}
type mdnsTestConn struct {
	onWrite func(*dns.Msg)
	packets []mdnsTestPacket
	closed  chan struct{}
	once    sync.Once
}

func (c *mdnsTestConn) SetDeadline(time.Time) error { return nil }
func (c *mdnsTestConn) Close() error {
	c.once.Do(func() {
		if c.closed != nil {
			close(c.closed)
		}
	})
	return nil
}
func (c *mdnsTestConn) WriteToUDPAddrPort(b []byte, to netip.AddrPort) (int, error) {
	q := new(dns.Msg)
	if to != systemMDNSTarget || q.Unpack(b) != nil || q.Id == 0 || q.RecursionDesired || len(q.Extra) != 0 {
		return 0, errors.New("bad fixture query")
	}
	if c.onWrite != nil {
		c.onWrite(q)
	}
	return len(b), nil
}
func (c *mdnsTestConn) ReadMsgUDPAddrPort(b, oob []byte) (int, int, int, netip.AddrPort, error) {
	if len(c.packets) == 0 {
		if c.closed != nil {
			<-c.closed
		}
		return 0, 0, 0, netip.AddrPort{}, errors.New("fixture exhausted")
	}
	p := c.packets[0]
	c.packets = c.packets[1:]
	return copy(b, p.wire), copy(oob, p.info), p.flags, p.peer, nil
}

func TestSystemMDNSProtocolFilteringAndFreshQuery(t *testing.T) {
	link := mdnsTestLink()
	q := new(dns.Msg)
	q.SetQuestion("NAS.local.", dns.TypeA)
	q.Id = 1234
	c := &mdnsTestConn{}
	c.onWrite = func(sent *dns.Msg) {
		good := mdnsTestResponse(sent)
		wire, _ := good.Pack()
		packet := mdnsTestPacket{wire: wire, info: mdnsTestInfo(link), peer: netip.MustParseAddrPort("192.168.1.20:5353")}
		badID := good.Copy()
		badID.Id++
		wrong, _ := badID.Pack()
		other := link
		other.Index++
		c.packets = []mdnsTestPacket{{wire: wrong, info: packet.info, peer: packet.peer}, {wire: wire, info: mdnsTestInfo(other), peer: packet.peer}, {wire: wire, info: packet.info, peer: netip.MustParseAddrPort("8.8.8.8:5353")}, {wire: wire, info: packet.info, peer: packet.peer, flags: windows.MSG_CTRUNC}, packet}
	}
	exchange := newSystemMDNSExchange(link, func(context.Context) (systemMDNSPacketConn, error) { return c, nil }, func() error { return nil })
	r, e := exchange(context.Background(), routingDecision{Action: "direct", Rule: "mdns"}, q)
	if e != nil || r.Id != 1234 || r.Question[0] != q.Question[0] || len(r.Answer) != 1 || r.Answer[0].Header().Ttl != 10 {
		t.Fatal("legacy query/filter/TTL/original correlation failed")
	}
	for _, mutate := range []func(*dns.Msg){
		func(r *dns.Msg) { r.Id++ }, func(r *dns.Msg) { r.Truncated = true }, func(r *dns.Msg) { r.Authoritative = false },
		func(r *dns.Msg) { r.Answer[0].(*dns.A).Hdr.Class = 0x8001 }, func(r *dns.Msg) { r.Answer[0].(*dns.A).A = net.ParseIP("10.77.43.1") },
		func(r *dns.Msg) { r.Answer[0].(*dns.A).A = net.ParseIP("192.168.2.1") }, func(r *dns.Msg) { r.Answer[0].(*dns.A).A = net.ParseIP("192.168.1.255") },
		func(r *dns.Msg) {
			r.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET}, Target: "public.example.com."}}
		},
	} {
		r := mdnsTestResponse(q)
		mutate(r)
		if systemMDNSResponse(q, r, link) != nil {
			t.Fatal("unsafe mDNS reply accepted")
		}
	}
	r = mdnsTestResponse(q)
	r.Answer = append([]dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 3}, Target: "real.local."}}, r.Answer...)
	r.Answer[1].Header().Name = "real.local."
	if good := systemMDNSResponse(q, r, link); good == nil || good.Answer[0].Header().Ttl != 3 {
		t.Fatal("local CNAME not safely flattened")
	}
	if _, _, ok := systemMDNSPacketInfo(append(mdnsTestInfo(link), mdnsTestInfo(link)...)); ok {
		t.Fatal("duplicate packet info")
	}
	bad := mdnsTestInfo(link)
	bad[0] = 1
	if _, _, ok := systemMDNSPacketInfo(bad); ok {
		t.Fatal("invalid control length")
	}
}

func TestSystemMDNSBoundedCancelAndStaleLink(t *testing.T) {
	link := mdnsTestLink()
	q := new(dns.Msg)
	q.SetQuestion("nas.local.", dns.TypeA)
	started := make(chan struct{}, 4)
	exchange := newSystemMDNSExchange(link, func(context.Context) (systemMDNSPacketConn, error) {
		started <- struct{}{}
		return &mdnsTestConn{closed: make(chan struct{})}, nil
	}, func() error { return nil })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := exchange(ctx, routingDecision{Action: "direct", Rule: "mdns"}, q); e == nil {
				t.Error("empty reply succeeded")
			}
		}()
	}
	for i := 0; i < 4; i++ {
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("fixture not started")
		}
	}
	if _, e := exchange(ctx, routingDecision{Action: "direct", Rule: "mdns"}, q); e == nil {
		t.Fatal("unbounded concurrent query")
	}
	cancel()
	wg.Wait()
	called := false
	stale := newSystemMDNSExchange(link, func(context.Context) (systemMDNSPacketConn, error) { called = true; return nil, nil }, func() error { return errors.New("changed") })
	if _, e := stale(context.Background(), routingDecision{Action: "direct", Rule: "mdns"}, q); e == nil || called {
		t.Fatal("stale uplink opened socket")
	}
}

func TestSystemMDNSWindowsPacketInfoLoopback(t *testing.T) {
	// Native WSARecvMsg layout proof, confined to loopback; never multicast/WFP.
	cfg := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var inner error
		e := raw.Control(func(fd uintptr) {
			inner = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, windows.IP_PKTINFO, 1)
		})
		if e != nil {
			return e
		}
		return inner
	}}
	p, e := cfg.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	c := p.(*net.UDPConn)
	c.SetDeadline(time.Now().Add(2 * time.Second))
	sender, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer sender.Close()
	if _, e = sender.WriteToUDP([]byte("local packet info"), c.LocalAddr().(*net.UDPAddr)); e != nil {
		t.Fatal(e)
	}
	b, oob := make([]byte, 128), make([]byte, 128)
	_, n, flags, _, e := c.ReadMsgUDPAddrPort(b, oob)
	if e != nil {
		t.Fatal(e)
	}
	ip, index, ok := systemMDNSPacketInfo(oob[:n])
	if !ok || flags != 0 || ip != netip.MustParseAddr("127.0.0.1") || index == 0 {
		t.Fatal("Windows packet-info decoder mismatch")
	}
}

func TestSystemMDNSLocalScopeAndNoPublicFallback(t *testing.T) {
	if systemNameScope("printer.local") != "mdns" {
		t.Fatal(".local still refused instead of private mDNS dispatch")
	}
	p, _ := compileSystemPolicy(&systemPolicy{V: 1, Enabled: true, Presets: systemPresets{LANDirect: true}}, nil)
	calls := 0
	server := newSystemDNS(p, newFakeDNS(8), func(context.Context, routingDecision, *dns.Msg) (*dns.Msg, error) {
		t.Fatal("local name reached public DNS")
		return nil, nil
	})
	server.mdnsExchange = func(_ context.Context, d routingDecision, q *dns.Msg) (*dns.Msg, error) {
		calls++
		r := new(dns.Msg)
		r.SetReply(q)
		r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10}, A: net.IPv4(192, 168, 1, 20)}}
		return r, nil
	}
	q := new(dns.Msg)
	q.SetQuestion("printer.local.", dns.TypeA)
	wire, _ := q.Pack()
	raw, e := server.Answer(context.Background(), wire)
	r := new(dns.Msg)
	if e != nil || r.Unpack(raw) != nil || r.Rcode != 0 || len(r.Answer) != 1 || calls != 1 || len(server.leases.byIP) != 0 {
		t.Fatal("mDNS response not delivered without durable identity")
	}
	p.Presets.LANDirect = false
	raw, e = server.Answer(context.Background(), wire)
	if e != nil || r.Unpack(raw) != nil || r.Rcode != dns.RcodeRefused || calls != 1 {
		t.Fatal("LAN-off queried mDNS")
	}
	p.Presets.LANDirect = true
	server.localExchange = func(context.Context, routingDecision, *dns.Msg) (*dns.Msg, error) {
		t.Fatal("mDNS entered unicast DNS")
		return nil, nil
	}
	for _, kind := range []uint16{dns.TypeAAAA, dns.TypeHTTPS, dns.TypeSVCB} {
		q.Question[0].Qtype = kind
		wire, _ = q.Pack()
		raw, e = server.Answer(context.Background(), wire)
		if e != nil || r.Unpack(raw) != nil || r.Rcode != 0 || len(r.Answer) != 0 || calls != 1 {
			t.Fatal("non-IPv4 local query escaped or resolved")
		}
	}
	server.mdnsExchange = func(context.Context, routingDecision, *dns.Msg) (*dns.Msg, error) { calls++; return nil, errSystemMDNS }
	q.Question[0].Qtype = dns.TypeA
	wire, _ = q.Pack()
	raw, e = server.Answer(context.Background(), wire)
	if e != nil || r.Unpack(raw) != nil || r.Rcode != dns.RcodeServerFailure || calls != 2 {
		t.Fatal("failed mDNS fell back or returned stale result")
	}
	for _, source := range []string{"192.168.1.0", "192.168.1.255", "10.77.43.1", "8.8.8.8"} {
		link := mdnsTestLink()
		link.Source = netip.MustParseAddr(source)
		if link.valid() {
			t.Fatal("unsafe source accepted")
		}
	}
}
