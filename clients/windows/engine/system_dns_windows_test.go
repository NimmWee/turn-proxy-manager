package main

import (
	"context"
	"github.com/miekg/dns"
	"net"
	"net/netip"
	"testing"
)

func TestSystemDNSBlockAliasesAndSharedIP(t *testing.T) {
	policy, e := compileSystemPolicy(&systemPolicy{V: 1, Enabled: true, Rules: []domainRule{{Domain: "one.example.com", Action: "direct", Subdomains: false}, {Domain: "blocked.example.com", Action: "block", Subdomains: true}}}, nil)
	if e != nil {
		t.Fatal(e)
	}
	calls := 0
	exchange := func(_ context.Context, decision routingDecision, q *dns.Msg) (*dns.Msg, error) {
		calls++
		r := new(dns.Msg)
		r.SetReply(q)
		name := q.Question[0].Name
		if name == "alias.example.com." {
			r.Answer = append(r.Answer, &dns.CNAME{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "blocked.example.com."})
			return r, nil
		}
		r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("1.1.1.1")}}
		return r, nil
	}
	server := newSystemDNS(policy, newFakeDNS(8), exchange)
	query := func(name string, kind uint16) *dns.Msg {
		t.Helper()
		q := new(dns.Msg)
		q.SetQuestion(name+".", kind)
		wire, _ := q.Pack()
		answer, e := server.Answer(context.Background(), wire)
		if e != nil {
			t.Fatal(e)
		}
		r := new(dns.Msg)
		if r.Unpack(answer) != nil {
			t.Fatal("invalid DNS reply")
		}
		return r
	}
	if r := query("blocked.example.com", dns.TypeA); r.Rcode != dns.RcodeRefused || calls != 0 {
		t.Fatal("BLOCK did DNS")
	}
	if r := query("alias.example.com", dns.TypeA); r.Rcode != dns.RcodeRefused {
		t.Fatal("CNAME bypassed BLOCK")
	}
	first := query("one.example.com", dns.TypeA)
	second := query("two.example.com", dns.TypeA)
	if len(first.Answer) != 1 || len(second.Answer) != 1 {
		t.Fatal("fake DNS reply absent")
	}
	a := first.Answer[0].(*dns.A).A.String()
	b := second.Answer[0].(*dns.A).A.String()
	if a == b {
		t.Fatal("shared IP collapsed per-domain routing")
	}
	lease, ok := server.leases.Lookup(netip.MustParseAddr(a))
	if !ok || lease.Decision.Action != "direct" {
		t.Fatal("DNS path lost direct intent")
	}
	before := calls
	if r := query("one.example.com", dns.TypeAAAA); r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 || calls != before {
		t.Fatal("IPv6 query leaked or was advertised")
	}
}

func TestSystemDNSCNAMEPathSwitchAndNoFallback(t *testing.T) {
	p, e := compileSystemPolicy(&systemPolicy{V: 1, Enabled: true, Presets: systemPresets{RussianDirect: true, YouTubeVPN: true, SplitDNS: true}}, &systemCatalog{RUSuffix: []string{"ru"}, VPNYouTube: []string{"youtube.com"}})
	if e != nil {
		t.Fatal(e)
	}
	calls := []string{}
	server := newSystemDNS(p, newFakeDNS(8), func(_ context.Context, d routingDecision, q *dns.Msg) (*dns.Msg, error) {
		calls = append(calls, d.Action)
		r := new(dns.Msg)
		r.SetReply(q)
		addr := "1.1.1.1"
		if d.Action == "vpn" {
			addr = "8.8.8.8"
		}
		r.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET}, Target: "youtube.com."}, &dns.A{Hdr: dns.RR_Header{Name: "youtube.com.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP(addr)}}
		return r, nil
	})
	q := new(dns.Msg)
	q.SetQuestion("video.ru.", dns.TypeA)
	wire, _ := q.Pack()
	answer, e := server.Answer(context.Background(), wire)
	if e != nil {
		t.Fatal(e)
	}
	r := new(dns.Msg)
	r.Unpack(answer)
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 || len(calls) != 2 || calls[0] != "direct" || calls[1] != "vpn" {
		t.Fatal("CNAME was not resolved again over selected VPN path")
	}
	lease, ok := server.leases.Lookup(netip.MustParseAddr(r.Answer[0].(*dns.A).A.String()))
	if !ok || lease.Decision.Action != "vpn" || lease.Addresses[0].String() != "8.8.8.8" {
		t.Fatal("stale DIRECT answer accepted for VPN alias")
	}
}
