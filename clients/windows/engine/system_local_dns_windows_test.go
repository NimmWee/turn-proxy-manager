package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

func TestSystemPrivateNamesNeverReachPublicDNS(t *testing.T) {
	p, _ := compileSystemPolicy(&systemPolicy{V: 1, Enabled: true, Presets: systemPresets{LANDirect: true}}, nil)
	calls := 0
	server := newSystemDNS(p, newFakeDNS(8), func(context.Context, routingDecision, *dns.Msg) (*dns.Msg, error) { calls++; return nil, nil })
	for _, name := range []string{"printer", "nas.home.arpa", "router.lan", "db.corp", "storage.intranet", "dev.test", "printer.local", "localhost", "example.invalid", "example.onion", "example.alt"} {
		q := new(dns.Msg)
		q.SetQuestion(name+".", dns.TypeA)
		wire, _ := q.Pack()
		answer, e := server.Answer(context.Background(), wire)
		if e != nil {
			t.Fatal(e)
		}
		r := new(dns.Msg)
		r.Unpack(answer)
		if calls != 0 {
			t.Fatalf("private name escaped to public DNS: %s", name)
		}
		if name == "localhost" && (r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "127.0.0.1") {
			t.Fatal("localhost not served locally")
		}
	}
}

func TestSystemPrivateDNSAnswerNeverCreatesFakeIdentity(t *testing.T) {
	p, _ := compileSystemPolicy(&systemPolicy{V: 1, Enabled: true, Presets: systemPresets{LANDirect: true}}, nil)
	leases := newFakeDNS(8)
	server := newSystemDNS(p, leases, nil)
	calls := 0
	answerIP := "192.168.1.20"
	server.localExchange = func(_ context.Context, d routingDecision, q *dns.Msg) (*dns.Msg, error) {
		calls++
		if d.Action != "direct" {
			t.Fatal("private query chose VPN")
		}
		r := new(dns.Msg)
		r.SetReply(q)
		r.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 15}, Target: "device.home.arpa."}, &dns.A{Hdr: dns.RR_Header{Name: "device.home.arpa.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.ParseIP(answerIP)}}
		return r, nil
	}
	query := func() *dns.Msg {
		q := new(dns.Msg)
		q.SetQuestion("printer.", dns.TypeA)
		wire, _ := q.Pack()
		answer, e := server.Answer(context.Background(), wire)
		if e != nil {
			t.Fatal(e)
		}
		r := new(dns.Msg)
		r.Unpack(answer)
		return r
	}
	r := query()
	if r.Rcode != 0 || len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != answerIP || len(leases.byIP) != 0 {
		t.Fatal("local A was not returned as real private address")
	}
	for _, ip := range []string{"1.1.1.1", "169.254.169.254", "10.77.43.1", "100.64.0.1", "127.0.0.1"} {
		answerIP = ip
		r = query()
		if r.Rcode != dns.RcodeRefused || len(r.Answer) != 0 {
			t.Fatal("unsafe local answer accepted")
		}
	}
	p.Presets.LANDirect = false
	before := calls
	r = query()
	if r.Rcode != dns.RcodeRefused || calls != before {
		t.Fatal("LAN-off performed query")
	}
}

func TestSystemLocalResolverEligibility(t *testing.T) {
	candidates := []netip.Addr{netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("10.77.43.1"), netip.MustParseAddr("10.1.1.1"), netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("169.254.169.254")}
	got := localSystemResolvers(candidates, []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("10.77.43.0/24")})
	if len(got) != 1 || got[0].String() != "192.168.1.1:53" {
		t.Fatal("resolver eligibility admitted public/off-link/protected/duplicate DNS")
	}
}

func TestSystemDNSPrivateScopeCannotCrossResolverPaths(t *testing.T) {
	p, _ := compileSystemPolicy(&systemPolicy{V: 1, Enabled: true, Presets: systemPresets{LANDirect: true}}, nil)
	publicCalls, localCalls := 0, 0
	s := newSystemDNS(p, newFakeDNS(8), func(_ context.Context, _ routingDecision, q *dns.Msg) (*dns.Msg, error) {
		publicCalls++
		r := new(dns.Msg)
		r.SetReply(q)
		r.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET}, Target: "secret.corp."}, &dns.A{Hdr: dns.RR_Header{Name: "secret.corp.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("192.168.1.20")}}
		return r, nil
	})
	s.localExchange = func(context.Context, routingDecision, *dns.Msg) (*dns.Msg, error) {
		localCalls++
		return nil, errors.New("synthetic unavailable")
	}
	query := func(host string) *dns.Msg {
		q := new(dns.Msg)
		q.SetQuestion(host+".", dns.TypeA)
		wire, _ := q.Pack()
		raw, e := s.Answer(context.Background(), wire)
		if e != nil {
			t.Fatal(e)
		}
		r := new(dns.Msg)
		r.Unpack(raw)
		return r
	}
	if r := query("secret.corp"); r.Rcode != dns.RcodeServerFailure || publicCalls != 0 || localCalls != 1 {
		t.Fatal("local DNS failure fell back to public DNS")
	}
	if r := query("alias.example.com"); r.Rcode != dns.RcodeRefused || publicCalls != 1 || localCalls != 1 {
		t.Fatal("public CNAME entered private namespace")
	}
}
