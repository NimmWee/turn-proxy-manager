package main

import (
	"context"
	"net"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
	"golang.org/x/net/idna"
)

// Classify before public policy/resolution. Private/special names must never be
// sent to public resolvers, including when split DNS or LAN bypass is disabled.
func systemNameScope(host string) string {
	normalized, e := idna.Lookup.ToASCII(host)
	if e != nil || normalized != host || len(host) == 0 || len(host) > 253 {
		return "refuse"
	}
	if _, e := netip.ParseAddr(host); e == nil {
		return "refuse"
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "refuse"
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "refuse"
			}
		}
	}
	suffix := func(base string) bool { return host == base || strings.HasSuffix(host, "."+base) }
	if suffix("localhost") {
		return "localhost"
	}
	if strings.HasSuffix(host, ".local") {
		return "mdns"
	}
	for _, name := range []string{"local", "invalid", "onion", "alt"} {
		if suffix(name) {
			return "refuse"
		}
	}
	for _, name := range []string{"home.arpa", "lan", "home", "internal", "corp", "intranet", "test"} {
		if suffix(name) {
			return "private"
		}
	}
	if !strings.Contains(host, ".") {
		return "private"
	}
	return "public"
}

func privateSystemAddress(ip netip.Addr) bool {
	return ip.Is4() && ip.IsPrivate() && !netip.MustParsePrefix("10.77.43.0/24").Contains(ip)
}

// Only configured private DNS on an actual connected private prefix. A /0 or
// public supernet cannot make an arbitrary RFC1918 resolver eligible.
func localSystemResolvers(candidates []netip.Addr, connected []netip.Prefix) []netip.AddrPort {
	result := []netip.AddrPort{}
	seen := map[netip.Addr]bool{}
	for _, ip := range candidates {
		if !privateSystemAddress(ip) || seen[ip] {
			continue
		}
		eligible := false
		for _, p := range connected {
			if !p.IsValid() || !p.Addr().Is4() || p != p.Masked() || !p.Contains(ip) {
				continue
			}
			for _, base := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
				private := netip.MustParsePrefix(base)
				if p.Bits() >= private.Bits() && private.Contains(p.Addr()) {
					eligible = true
				}
			}
		}
		if eligible {
			seen[ip] = true
			result = append(result, netip.AddrPortFrom(ip, 53))
			if len(result) == 4 {
				break
			}
		}
	}
	return result
}

func (s *systemDNS) answerLocal(ctx context.Context, q *dns.Msg, host, scope string) ([]byte, error) {
	reply := new(dns.Msg)
	reply.SetReply(q)
	reply.RecursionAvailable = true
	finish := func(code int) ([]byte, error) { reply.Rcode = code; return reply.Pack() }
	kind := q.Question[0].Qtype
	if scope == "refuse" {
		return finish(dns.RcodeRefused)
	}
	if scope == "private" || scope == "mdns" {
		if !s.policy.Presets.LANDirect {
			return finish(dns.RcodeRefused)
		}
		// Public-domain editor BLOCK still wins where its namespace is supported.
		if decision, e := s.policy.custom.Decide(host); e == nil && decision.Action == "block" {
			return finish(dns.RcodeRefused)
		}
	}
	if kind == dns.TypeAAAA || kind == dns.TypeHTTPS || kind == dns.TypeSVCB {
		return finish(dns.RcodeSuccess)
	}
	if kind != dns.TypeA {
		return finish(dns.RcodeRefused)
	}
	if scope == "localhost" {
		reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(127, 0, 0, 1)}}
		return finish(dns.RcodeSuccess)
	}
	exchange := s.localExchange
	if scope == "mdns" {
		exchange = s.mdnsExchange
	}
	if exchange == nil {
		return finish(dns.RcodeServerFailure)
	}
	rule := "private-dns"
	if scope == "mdns" {
		rule = "mdns"
	}
	response, e := exchange(ctx, routingDecision{Action: "direct", Rule: rule}, q.Copy())
	if e != nil || !validSystemDNSResponse(q, response) {
		return finish(dns.RcodeServerFailure)
	}
	if response.Rcode != dns.RcodeSuccess {
		return finish(response.Rcode)
	}
	current := host
	ttl := uint32(60)
	if scope == "mdns" {
		ttl = 10
	}
	seen := map[string]bool{host: true}
	for depth := 0; depth < 8; depth++ {
		alias := ""
		for _, rr := range response.Answer {
			if c, ok := rr.(*dns.CNAME); ok && strings.EqualFold(c.Hdr.Name, current+".") {
				if c.Hdr.Class != dns.ClassINET || alias != "" {
					return finish(dns.RcodeServerFailure)
				}
				alias = strings.TrimSuffix(strings.ToLower(c.Target), ".")
				if c.Hdr.Ttl < ttl {
					ttl = c.Hdr.Ttl
				}
			}
		}
		if alias == "" {
			break
		}
		if systemNameScope(alias) != scope {
			return finish(dns.RcodeRefused)
		}
		if seen[alias] || depth == 7 {
			return finish(dns.RcodeServerFailure)
		}
		if d, e := s.policy.custom.Decide(alias); e == nil && d.Action == "block" {
			return finish(dns.RcodeRefused)
		}
		seen[alias] = true
		current = alias
	}
	addresses := []netip.Addr{}
	for _, rr := range response.Answer {
		a, ok := rr.(*dns.A)
		if !ok || !strings.EqualFold(a.Hdr.Name, current+".") {
			continue
		}
		ip, ok := netip.AddrFromSlice(a.A)
		if !ok || a.Hdr.Class != dns.ClassINET || !privateSystemAddress(ip.Unmap()) {
			return finish(dns.RcodeRefused)
		}
		if len(addresses) >= 32 {
			return finish(dns.RcodeServerFailure)
		}
		addresses = append(addresses, ip.Unmap())
		if a.Hdr.Ttl < ttl {
			ttl = a.Hdr.Ttl
		}
	}
	// Flatten validated CNAMEs; no extra records, no fake cache, no durable names.
	for _, ip := range addresses {
		reply.Answer = append(reply.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: net.IP(ip.AsSlice())})
	}
	return finish(dns.RcodeSuccess)
}
