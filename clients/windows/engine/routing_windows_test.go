package main

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestRoutingPolicyBoundariesAndPrecedence(t *testing.T) {
	p, e := compileRouting(&routingPolicy{V: 1, Rules: []domainRule{
		{Domain: " Example.COM. ", Action: "direct", Subdomains: true},
		{Domain: "login.example.com", Action: "vpn"},
		{Domain: "blocked.example.com", Action: "block", Subdomains: true},
		{Domain: "ok.blocked.example.com", Action: "direct"},
		{Domain: "пример.рф", Action: "direct", Subdomains: true},
	}})
	if e != nil {
		t.Fatal(e)
	}
	for host, want := range map[string]string{"example.com": "direct", "cdn.example.com": "direct", "login.example.com": "vpn", "cdn.login.example.com": "direct", "notexample.com": "vpn", "ok.blocked.example.com": "block", "WWW.ПРИМЕР.РФ.": "direct", "1.1.1.1": "vpn"} {
		got, e := p.Decide(host)
		if e != nil || got.Action != want {
			t.Errorf("routing boundary mismatch for synthetic host %q", host)
		}
	}
	for _, bad := range []string{"com", "co.uk", "github.io", "https://example.com/path", "user@example.com", "example.com:443", "*.example.com", "1.1.1.1", "localhost", "foo.local", "example..com", "-bad.com", "exa mple.com"} {
		if _, e := compileRouting(&routingPolicy{V: 1, Rules: []domainRule{{Domain: bad, Action: "direct"}}}); e == nil {
			t.Errorf("unsafe policy domain accepted: %q", bad)
		}
	}
	if _, e := compileRouting(&routingPolicy{V: 1, Rules: []domainRule{{Domain: "example.com", Action: "direct"}, {Domain: "EXAMPLE.COM.", Action: "vpn"}}}); e == nil {
		t.Fatal("conflicting policy accepted")
	}
	if _, e := compileRouting(&routingPolicy{V: 2}); e == nil {
		t.Fatal("unknown version accepted")
	}
	if _, e := compileRouting(&routingPolicy{V: 1, Rules: make([]domainRule, 301)}); e == nil {
		t.Fatal("unbounded policy accepted")
	}
}

func TestRoutingNeverFallsBackOrDialsBlockedHost(t *testing.T) {
	p, e := compileRouting(&routingPolicy{V: 1, Rules: []domainRule{{Domain: "direct.example.com", Action: "direct"}, {Domain: "blocked.example.com", Action: "block"}}})
	if e != nil {
		t.Fatal(e)
	}
	vpn, direct := 0, 0
	route := routedSOCKSDial(p, func(context.Context, string) (net.Conn, error) { vpn++; return nil, errors.New("SYNTHETIC_VPN_DOWN") }, func(context.Context, string) (net.Conn, error) {
		direct++
		return nil, errors.New("SYNTHETIC_DIRECT_DOWN")
	})
	for _, host := range []string{"blocked.example.com:443", "default.example.com:443", "direct.example.com:443", "http://bad.example.com:443"} {
		if _, e := route(context.Background(), host); e == nil {
			t.Fatal("unexpected dial success")
		}
	}
	if vpn != 1 || direct != 1 {
		t.Fatalf("blocked/invalid dial or cross-route fallback: vpn=%d direct=%d", vpn, direct)
	}
}

func TestRoutingCommandRejectsAmbiguousOrExtendedPolicy(t *testing.T) {
	for _, data := range []string{`{"policy":{"v":1,"v":1,"rules":[]}}`, `{"policy":{"v":1,"rules":[],"shell":"bad"}}`, `{"policy":{"v":1,"rules":[]}} {}`, `{"policy":{"v":1,"rules":[{"domain":"example.com","action":"direct","path":"bad"}]}}`} {
		if _, e := checkRouting([]byte(data)); e == nil {
			t.Fatal("ambiguous/extended routing command accepted")
		}
	}
	result, e := checkRouting([]byte(`{"policy":{"v":1,"rules":[{"domain":"EXAMPLE.COM.","action":"direct","subdomains":true}]},"host":"a.example.com"}`))
	if e != nil || result["scope"] != "socks-tcp-ipv4" || result["networkChanged"] != false {
		t.Fatal("offline routing preview failed")
	}
}
