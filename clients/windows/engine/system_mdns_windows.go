package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"time"
	"unsafe"

	"github.com/miekg/dns"
	"golang.org/x/sys/windows"
)

var systemMDNSTarget = netip.MustParseAddrPort("224.0.0.251:5353")
var errSystemMDNS = errors.New("SYSTEM_MDNS_UNAVAILABLE")

type systemMDNSLink struct {
	Index  uint32
	Source netip.Addr
	Prefix netip.Prefix
}

func (l systemMDNSLink) valid() bool {
	if l.Index == 0 || !privateSystemAddress(l.Source) || !l.Prefix.IsValid() || !l.Prefix.Addr().Is4() || l.Prefix != l.Prefix.Masked() || !l.Prefix.Contains(l.Source) || !systemMDNSHostAddress(l.Source, l.Prefix) {
		return false
	}
	for _, base := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		p := netip.MustParsePrefix(base)
		if l.Prefix.Bits() >= p.Bits() && p.Contains(l.Prefix.Addr()) {
			return true
		}
	}
	return false
}
func (l systemMDNSLink) address(ip netip.Addr) bool {
	if !l.valid() || !privateSystemAddress(ip) || !l.Prefix.Contains(ip) {
		return false
	}
	return systemMDNSHostAddress(ip, l.Prefix)
}
func systemMDNSHostAddress(ip netip.Addr, prefix netip.Prefix) bool {
	if prefix.Bits() < 31 {
		first := prefix.Addr().As4()
		value := ip.As4()
		n := binary.BigEndian.Uint32(value[:])
		start := binary.BigEndian.Uint32(first[:])
		last := start | uint32((uint64(1)<<uint(32-prefix.Bits()))-1)
		if n == start || n == last {
			return false
		}
	}
	return true
}

type systemMDNSPacketConn interface {
	SetDeadline(time.Time) error
	WriteToUDPAddrPort([]byte, netip.AddrPort) (int, error)
	ReadMsgUDPAddrPort([]byte, []byte) (int, int, int, netip.AddrPort, error)
	Close() error
}

// A legacy one-shot query uses an ephemeral source port and gets unicast replies.
// No mDNS group membership, persistent listener, name cache or public fallback.
func newSystemMDNSExchange(link systemMDNSLink, open func(context.Context) (systemMDNSPacketConn, error), current func() error) systemDNSExchange {
	slots := make(chan struct{}, 4)
	return func(parent context.Context, decision routingDecision, q *dns.Msg) (*dns.Msg, error) {
		if parent.Err() != nil || !link.valid() || open == nil || current == nil || decision.Action != "direct" || decision.Rule != "mdns" || q == nil || len(q.Question) != 1 || q.Question[0].Qtype != dns.TypeA || q.Question[0].Qclass != dns.ClassINET || systemNameScope(strings.ToLower(strings.TrimSuffix(q.Question[0].Name, "."))) != "mdns" {
			return nil, errSystemMDNS
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			return nil, errSystemMDNS
		}
		ctx, cancel := context.WithTimeout(parent, 2*time.Second)
		defer cancel()
		if current() != nil || ctx.Err() != nil {
			return nil, errSystemMDNS
		}
		c, e := open(ctx)
		if e != nil {
			return nil, errSystemMDNS
		}
		defer c.Close()
		stop := context.AfterFunc(ctx, func() { c.Close() })
		defer stop()
		deadline, _ := ctx.Deadline()
		if c.SetDeadline(deadline) != nil {
			return nil, errSystemMDNS
		}
		request := new(dns.Msg)
		request.SetQuestion(strings.ToLower(q.Question[0].Name), dns.TypeA)
		request.RecursionDesired = false
		var id [2]byte
		if _, e = rand.Read(id[:]); e != nil {
			return nil, errSystemMDNS
		}
		request.Id = binary.BigEndian.Uint16(id[:])
		if request.Id == 0 {
			request.Id = 1
		}
		wire, e := request.Pack()
		if e != nil || current() != nil || ctx.Err() != nil {
			return nil, errSystemMDNS
		}
		if n, e := c.WriteToUDPAddrPort(wire, systemMDNSTarget); e != nil || n != len(wire) {
			return nil, errSystemMDNS
		}
		data, control := make([]byte, 4097), make([]byte, 128)
		for received := 0; received < 64; received++ {
			n, on, flags, peer, e := c.ReadMsgUDPAddrPort(data, control)
			if e != nil || ctx.Err() != nil || current() != nil {
				return nil, errSystemMDNS
			}
			if on < 0 || on > len(control) {
				continue
			}
			destination, index, ok := systemMDNSPacketInfo(control[:on])
			if n < 12 || n > 4096 || flags&(windows.MSG_TRUNC|windows.MSG_CTRUNC) != 0 || !ok || destination != link.Source || index != link.Index || peer.Port() != 5353 || !link.address(peer.Addr()) {
				continue
			}
			response := new(dns.Msg)
			if response.Unpack(data[:n]) != nil {
				continue
			}
			accepted := systemMDNSResponse(request, response, link)
			if accepted == nil {
				continue
			}
			accepted.Id = q.Id
			accepted.Question = append([]dns.Question(nil), q.Question...)
			for _, rr := range accepted.Answer {
				rr.Header().Name = q.Question[0].Name
			}
			if current() != nil || ctx.Err() != nil {
				return nil, errSystemMDNS
			}
			return accepted, nil
		}
		return nil, errSystemMDNS
	}
}

// Strict legacy response; flatten only .local CNAMEs, never forward extra records.
func systemMDNSResponse(q, r *dns.Msg, link systemMDNSLink) *dns.Msg {
	if r == nil || !r.Response || !r.Authoritative || r.Truncated || r.Opcode != dns.OpcodeQuery || r.Rcode != dns.RcodeSuccess || r.Id != q.Id || len(r.Question) != 1 || r.Question[0].Qtype != dns.TypeA || r.Question[0].Qclass != dns.ClassINET || !strings.EqualFold(r.Question[0].Name, q.Question[0].Name) || len(r.Answer)+len(r.Ns)+len(r.Extra) > 256 {
		return nil
	}
	name := strings.ToLower(q.Question[0].Name)
	seen := map[string]bool{name: true}
	ttl := uint32(10)
	for depth := 0; depth < 8; depth++ {
		alias := ""
		for _, rr := range r.Answer {
			if c, ok := rr.(*dns.CNAME); ok && strings.EqualFold(c.Hdr.Name, name) {
				if c.Hdr.Class != dns.ClassINET || alias != "" {
					return nil
				}
				alias = strings.ToLower(c.Target)
				if c.Hdr.Ttl < ttl {
					ttl = c.Hdr.Ttl
				}
			}
		}
		if alias == "" {
			break
		}
		if seen[alias] || depth == 7 || systemNameScope(strings.TrimSuffix(alias, ".")) != "mdns" {
			return nil
		}
		seen[alias] = true
		name = alias
	}
	result := new(dns.Msg)
	result.SetReply(q)
	for _, rr := range r.Answer {
		if a, ok := rr.(*dns.A); ok && strings.EqualFold(a.Hdr.Name, name) {
			ip, ok := netip.AddrFromSlice(a.A)
			if !ok || a.Hdr.Class != dns.ClassINET || !link.address(ip.Unmap()) || len(result.Answer) >= 32 {
				return nil
			}
			if a.Hdr.Ttl < ttl {
				ttl = a.Hdr.Ttl
			}
			result.Answer = append(result.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: append([]byte(nil), a.A...)})
		}
	}
	if len(result.Answer) == 0 {
		return nil
	}
	for _, rr := range result.Answer {
		rr.Header().Ttl = ttl
	}
	return result
}

// WSACMSGHDR is pointer-sized/aligned; IN_PKTINFO is address + uint32 index.
func systemMDNSPacketInfo(control []byte) (netip.Addr, uint32, bool) {
	word := int(unsafe.Sizeof(uintptr(0)))
	header := int(unsafe.Sizeof(windows.WSACMSGHDR{}))
	found := false
	var destination netip.Addr
	var index uint32
	for len(control) > 0 {
		if len(control) < header {
			return netip.Addr{}, 0, false
		}
		var size uint64
		if word == 8 {
			size = binary.LittleEndian.Uint64(control)
		} else {
			size = uint64(binary.LittleEndian.Uint32(control))
		}
		if size < uint64(header) || size > uint64(len(control)) {
			return netip.Addr{}, 0, false
		}
		n := int(size)
		if binary.LittleEndian.Uint32(control[word:]) == windows.IPPROTO_IP && binary.LittleEndian.Uint32(control[word+4:]) == windows.IP_PKTINFO {
			if found || n != header+int(unsafe.Sizeof(windows.IN_PKTINFO{})) {
				return netip.Addr{}, 0, false
			}
			found = true
			destination = netip.AddrFrom4([4]byte(control[header : header+4]))
			index = binary.LittleEndian.Uint32(control[header+4:])
		}
		next := (n + word - 1) &^ (word - 1)
		if next >= len(control) {
			if n != len(control) && next != len(control) {
				return netip.Addr{}, 0, false
			}
			break
		}
		control = control[next:]
	}
	return destination, index, found && index != 0
}
