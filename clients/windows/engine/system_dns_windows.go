package main

import (
	"context"
	"errors"
	"github.com/miekg/dns"
	"net"
	"net/netip"
	"strings"
	"time"
)

type systemDNSExchange func(context.Context, routingDecision, *dns.Msg) (*dns.Msg, error)
type systemDNS struct {
	policy        *compiledSystemPolicy
	leases        *fakeDNS
	exchange      systemDNSExchange
	localExchange systemDNSExchange
	mdnsExchange  systemDNSExchange
}

func newSystemDNS(p *compiledSystemPolicy, leases *fakeDNS, exchange systemDNSExchange) *systemDNS {
	return &systemDNS{policy: p, leases: leases, exchange: exchange}
}
func (s *systemDNS) Answer(ctx context.Context, wire []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if len(wire) < 12 || len(wire) > 4096 {
		return nil, errors.New("DNS_QUERY_INVALID")
	}
	q := new(dns.Msg)
	if q.Unpack(wire) != nil || q.Response || q.Opcode != dns.OpcodeQuery || len(q.Question) != 1 || q.Question[0].Qclass != dns.ClassINET {
		return nil, errors.New("DNS_QUERY_INVALID")
	}
	reply := new(dns.Msg)
	reply.SetReply(q)
	reply.RecursionAvailable = true
	finish := func(code int) ([]byte, error) { reply.Rcode = code; return reply.Pack() }
	host := strings.TrimSuffix(strings.ToLower(q.Question[0].Name), ".")
	if scope := systemNameScope(host); scope != "public" {
		return s.answerLocal(ctx, q, host, scope)
	}
	decision := s.policy.DecideFlow(host, netip.Addr{}, 443, "dns")
	if decision.Action == "block" {
		return finish(dns.RcodeRefused)
	}
	// No IPv6 egress is claimed; HTTPS/SVCB address hints must not bypass fake-IP.
	kind := q.Question[0].Qtype
	if kind == dns.TypeAAAA || kind == dns.TypeHTTPS || kind == dns.TypeSVCB {
		return finish(dns.RcodeSuccess)
	}
	if kind != dns.TypeA {
		return finish(dns.RcodeRefused)
	}
	// A CNAME can upgrade a RU DIRECT name to a required VPN service. Resolve
	// again on that path before accepting addresses; never downgrade VPN on error.
	var response *dns.Msg
	var minimumTTL uint32
	current := host
	for round := 0; round < 2; round++ {
		resolverDecision := decision
		if !s.policy.Presets.SplitDNS {
			resolverDecision = routingDecision{Action: "vpn", Rule: "dns-default"}
		}
		var e error
		response, e = s.exchange(ctx, resolverDecision, q.Copy())
		if e != nil || !validSystemDNSResponse(q, response) {
			return finish(dns.RcodeServerFailure)
		}
		if response.Rcode != dns.RcodeSuccess {
			return finish(response.Rcode)
		}
		before := decision.Action
		minimumTTL = 60
		chain := map[string]bool{host: true}
		current = host
		for depth := 0; depth < 8; depth++ {
			alias := ""
			for _, rr := range response.Answer {
				if c, ok := rr.(*dns.CNAME); ok && strings.EqualFold(c.Hdr.Name, current+".") {
					if c.Hdr.Class != dns.ClassINET {
						return finish(dns.RcodeServerFailure)
					}
					if c.Hdr.Ttl < minimumTTL {
						minimumTTL = c.Hdr.Ttl
					}
					alias = strings.TrimSuffix(strings.ToLower(c.Target), ".")
					break
				}
			}
			if alias == "" {
				break
			}
			if chain[alias] {
				return finish(dns.RcodeServerFailure)
			}
			chain[alias] = true
			current = alias
			if systemNameScope(alias) != "public" {
				return finish(dns.RcodeRefused)
			}
			aliasDecision := s.policy.DecideFlow(alias, netip.Addr{}, 443, "dns")
			if aliasDecision.Action == "block" {
				return finish(dns.RcodeRefused)
			}
			// Explicit admin intent wins over presets, but an alias can never bypass BLOCK.
			if decision.Rule == "default" || decision.Rule == "ru-domain" {
				if aliasDecision.Rule == "youtube" || aliasDecision.Rule == "push" {
					decision = aliasDecision
				}
			}
			if depth == 7 {
				return finish(dns.RcodeServerFailure)
			}
		}
		if s.policy.Presets.SplitDNS && before != decision.Action {
			if round == 1 {
				return finish(dns.RcodeServerFailure)
			}
			continue
		}
		break
	}
	addresses := make([]netip.Addr, 0, 4)
	for _, rr := range response.Answer {
		a, ok := rr.(*dns.A)
		if !ok || a.Hdr.Class != dns.ClassINET || !strings.EqualFold(a.Hdr.Name, current+".") {
			continue
		}
		parsed, ok := netip.AddrFromSlice(a.A)
		if !ok {
			continue
		}
		ip := parsed.Unmap()
		if a.Hdr.Ttl < minimumTTL {
			minimumTTL = a.Hdr.Ttl
		}
		check := s.policy.DecideFlow(host, ip, 443, "dns")
		if check.Action == "block" {
			return finish(dns.RcodeRefused)
		}
		if len(addresses) < 32 {
			addresses = append(addresses, ip)
		}
	}
	if len(addresses) == 0 {
		return finish(dns.RcodeSuccess)
	}
	// Country-address fallback is evaluated after a privacy-preserving initial
	// DNS lookup; an ambiguous mixed country pool remains VPN.
	if decision.Rule == "default" {
		allDirect := true
		for _, ip := range addresses {
			if s.policy.DecideFlow(host, ip, 443, "dns").Action != "direct" {
				allDirect = false
			}
		}
		if allDirect {
			decision = routingDecision{Action: "direct", Rule: "ru-address"}
		}
	}
	ip, e := s.leases.Assign(host, decision)
	if e != nil {
		return finish(dns.RcodeServerFailure)
	}
	// TTL0 is sent unchanged (no client caching); allow one second solely for
	// delivery of this answer to the immediately following connect. A stale
	// fake-IP flow must re-resolve on its selected path, never dial expired IPs.
	validFor := time.Duration(minimumTTL) * time.Second
	if validFor == 0 {
		validFor = time.Second
	}
	if s.leases.setAddressesUntil(ip, addresses, time.Now().Add(validFor)) != nil {
		return finish(dns.RcodeServerFailure)
	}
	reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: minimumTTL}, A: net.IP(ip.AsSlice())}}
	return finish(dns.RcodeSuccess)
}

func validSystemDNSResponse(q, r *dns.Msg) bool {
	return r != nil && r.Response && !r.Truncated && r.Id == q.Id && r.Opcode == q.Opcode && len(r.Question) == 1 && r.Question[0] == q.Question[0] && len(r.Answer) <= 256
}
