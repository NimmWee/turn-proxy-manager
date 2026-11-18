package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

type domainRule struct {
	Domain     string `json:"domain"`
	Action     string `json:"action"`
	Subdomains bool   `json:"subdomains"`
}
type routingPolicy struct {
	V     int          `json:"v"`
	Rules []domainRule `json:"rules"`
}
type routingDecision struct {
	Action string `json:"action"`
	Rule   string `json:"rule,omitempty"`
}
type routingCheck struct {
	Policy *routingPolicy `json:"policy"`
	Host   string         `json:"host,omitempty"`
}

var errRouting = errors.New("ROUTING_POLICY_INVALID")
var domainIDNA = idna.New(idna.MapForLookup(), idna.BidiRule(), idna.StrictDomainName(true), idna.ValidateLabels(true), idna.VerifyDNSLength(true))

// No resolver calls here. Normalized hostnames are matched before any DNS/dial.
func routingDomain(raw string) (string, error) {
	if len(raw) > 1024 || strings.ContainsAny(raw, "/\\:@*?#[]%\x00\r\n\t ") {
		return "", errRouting
	}
	raw = strings.NewReplacer("。", ".", "．", ".", "｡", ".").Replace(raw)
	ascii, e := domainIDNA.ToASCII(strings.TrimSuffix(raw, "."))
	if e != nil {
		return "", errRouting
	}
	name := strings.TrimSuffix(strings.ToLower(ascii), ".")
	if len(name) > 253 || !strings.Contains(name, ".") {
		return "", errRouting
	}
	if _, e = netip.ParseAddr(name); e == nil {
		return "", errRouting
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errRouting
		}
	}
	suffix, _ := publicsuffix.PublicSuffix(name)
	if suffix == name || suffix == "local" || suffix == "localhost" || suffix == "internal" || suffix == "lan" || suffix == "home" || suffix == "invalid" || suffix == "onion" {
		return "", errRouting
	}
	// Numeric/unknown suffixes cannot turn IPv4-like strings into domain bypasses.
	if _, e = publicsuffix.EffectiveTLDPlusOne(name); e != nil {
		return "", errRouting
	}
	digitOnly := true
	for _, c := range suffix {
		if c < '0' || c > '9' {
			digitOnly = false
		}
	}
	if digitOnly {
		return "", errRouting
	}
	return name, nil
}
func compileRouting(input *routingPolicy) (*routingPolicy, error) {
	if input == nil {
		return &routingPolicy{V: 1, Rules: []domainRule{}}, nil
	}
	if input.V != 1 || len(input.Rules) > 300 {
		return nil, errRouting
	}
	result := &routingPolicy{V: 1, Rules: []domainRule{}}
	seen := map[string]string{}
	for _, r := range input.Rules {
		domain, e := routingDomain(strings.TrimSpace(r.Domain))
		if e != nil {
			return nil, errRouting
		}
		if r.Action != "vpn" && r.Action != "direct" && r.Action != "block" {
			return nil, errRouting
		}
		key := domain
		if r.Subdomains {
			key += "/suffix"
		} else {
			key += "/exact"
		}
		if old, ok := seen[key]; ok {
			if old != r.Action {
				return nil, errRouting
			}
			continue
		}
		seen[key] = r.Action
		r.Domain = domain
		result.Rules = append(result.Rules, r)
	}
	return result, nil
}
func (p *routingPolicy) Decide(host string) (routingDecision, error) {
	if ip, e := netip.ParseAddr(host); e == nil {
		if !publicIPv4(ip) {
			return routingDecision{}, errRouting
		}
		return routingDecision{Action: "vpn"}, nil
	}
	domain, e := routingDomain(host)
	if e != nil {
		return routingDecision{}, e
	}
	result := routingDecision{Action: "vpn"}
	best := -1
	for _, r := range p.Rules {
		if domain != r.Domain && !(r.Subdomains && strings.HasSuffix(domain, "."+r.Domain)) {
			continue
		}
		if r.Action == "block" {
			return routingDecision{Action: "block", Rule: r.Domain}, nil
		}
		score := len(r.Domain) * 2
		if !r.Subdomains {
			score++
		}
		if score > best {
			best = score
			result = routingDecision{Action: r.Action, Rule: r.Domain}
		}
	}
	return result, nil
}
func (p *routingPolicy) NeedsDirect() bool {
	for _, r := range p.Rules {
		if r.Action == "direct" {
			return true
		}
	}
	return false
}

func routedSOCKSDial(policy *routingPolicy, vpn, direct socksDial) socksDial {
	return func(ctx context.Context, address string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, errRouting
		}
		decision, e := policy.Decide(host)
		if e != nil || decision.Action == "block" {
			return nil, errRouting
		}
		if _, e := netip.ParseAddr(host); e != nil {
			host, e = routingDomain(host)
			if e != nil {
				return nil, errRouting
			}
		}
		target := vpn
		if decision.Action == "direct" {
			target = direct
		}
		if target == nil {
			return nil, errors.New("ROUTING_PATH_UNAVAILABLE")
		}
		// An error is returned unchanged. Never retry through the other interface.
		return target(ctx, net.JoinHostPort(host, port))
	}
}

func checkRouting(data []byte) (map[string]any, error) {
	if len(data) > maxMessage || !uniqueJSON(data) {
		return nil, errRouting
	}
	var input routingCheck
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&input) != nil {
		return nil, errRouting
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, errRouting
	}
	policy, e := compileRouting(input.Policy)
	if e != nil {
		return nil, e
	}
	result := map[string]any{"ok": true, "policy": policy, "scope": "socks-tcp-ipv4", "networkChanged": false}
	if input.Host != "" {
		decision, e := policy.Decide(input.Host)
		if e != nil {
			return nil, e
		}
		result["decision"] = decision
	}
	return result, nil
}
