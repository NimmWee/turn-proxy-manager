package main

import (
	"errors"
	"net/netip"
	"regexp"
	"strings"

	"go4.org/netipx"
)

type systemPresets struct {
	RussianDirect      bool `json:"russianDirect"`
	LANDirect          bool `json:"lanDirect"`
	YouTubeVPN         bool `json:"youtubeVPN"`
	PushVPN            bool `json:"pushVPN"`
	ConnectivityDirect bool `json:"connectivityDirect"`
	BlockBitTorrent    bool `json:"blockBitTorrent"`
	SplitDNS           bool `json:"splitDNS"`
}
type systemPolicy struct {
	PublicationRevision int64                `json:"publicationRevision,omitempty"`
	Catalog             *systemCatalogUpdate `json:"catalog,omitempty"`
	V                   int                  `json:"v"`
	Enabled             bool                 `json:"enabled"`
	Presets             systemPresets        `json:"presets"`
	Rules               []domainRule         `json:"rules"`
	DirectDNS           []string             `json:"directDNS,omitempty"`
	AppRules            []systemAppRule      `json:"appRules,omitempty"`
}
type systemCatalog struct {
	RUSuffix, RUExact, VPNYouTube, VPNPush, Connectivity []string
	RUPrefixes                                           []netip.Prefix
	RU, YouTube, Push, Checks                            presetPatterns
	GeoIP                                                systemGeoIPInfo
}
type presetPatterns struct {
	Suffix  []string `json:"suffix"`
	Exact   []string `json:"exact"`
	Regex   []string `json:"regex"`
	Keyword []string `json:"keyword"`
}
type presetMatcher struct {
	suffix, exact map[string]bool
	regex         []*regexp.Regexp
	keyword       []string
}

func compilePreset(p presetPatterns, suffix, exact []string) (presetMatcher, error) {
	m := presetMatcher{suffix: map[string]bool{}, exact: map[string]bool{}, keyword: append([]string(nil), p.Keyword...)}
	for _, list := range [][]string{p.Suffix, suffix} {
		for _, s := range list {
			m.suffix[s] = true
		}
	}
	for _, list := range [][]string{p.Exact, exact} {
		for _, s := range list {
			m.exact[s] = true
		}
	}
	for _, s := range p.Regex {
		r, e := regexp.Compile(s)
		if e != nil {
			return m, errSystemRouting
		}
		m.regex = append(m.regex, r)
	}
	return m, nil
}
func (m presetMatcher) matches(host string) bool {
	if host == "" {
		return false
	}
	if m.exact[host] {
		return true
	}
	for s := host; ; {
		if m.suffix[s] {
			return true
		}
		i := strings.IndexByte(s, '.')
		if i < 0 {
			break
		}
		s = s[i+1:]
	}
	for _, r := range m.regex {
		if r.MatchString(host) {
			return true
		}
	}
	for _, s := range m.keyword {
		if strings.Contains(host, s) {
			return true
		}
	}
	return false
}

type compiledSystemPolicy struct {
	*systemPolicy
	custom                    *routingPolicy
	ru, youtube, push, checks presetMatcher
	ruIP                      *netipx.IPSet
	apps                      map[string]string
}

var errSystemRouting = errors.New("SYSTEM_ROUTING_POLICY_INVALID")

func compileSystemPolicy(policy *systemPolicy, catalog *systemCatalog) (*compiledSystemPolicy, error) {
	if policy == nil || policy.V != 1 || policy.PublicationRevision < 0 || policy.PublicationRevision > 9007199254740991 {
		return nil, errSystemRouting
	}
	if policy.Catalog != nil {
		var e error
		catalog, e = updatedSystemCatalog(policy.Catalog)
		if e != nil {
			return nil, e
		}
	}
	custom, e := compileRouting(&routingPolicy{V: 1, Rules: policy.Rules})
	if e != nil {
		return nil, errSystemRouting
	}
	if catalog == nil {
		catalog = &systemCatalog{}
	}
	if policy.Enabled && policy.Presets.RussianDirect && len(catalog.RUSuffix)+len(catalog.RU.Suffix) == 0 {
		return nil, errors.New("SYSTEM_ROUTING_CATALOG_REQUIRED")
	}
	copyPolicy := *policy
	copyPolicy.Rules = append([]domainRule{}, custom.Rules...)
	copyPolicy.DirectDNS = append([]string(nil), policy.DirectDNS...)
	if len(copyPolicy.DirectDNS) == 0 {
		copyPolicy.DirectDNS = []string{"77.88.8.8", "77.88.8.1"}
	}
	if len(copyPolicy.DirectDNS) > 4 {
		return nil, errSystemRouting
	}
	seenDNS := map[netip.Addr]bool{}
	for _, s := range copyPolicy.DirectDNS {
		ip, e := netip.ParseAddr(s)
		if e != nil || !publicIPv4(ip) || seenDNS[ip] {
			return nil, errSystemRouting
		}
		seenDNS[ip] = true
	}
	result := &compiledSystemPolicy{systemPolicy: &copyPolicy, custom: custom}
	if len(policy.AppRules) > 64 {
		return nil, errSystemRouting
	}
	result.apps = map[string]string{}
	copyPolicy.AppRules = nil
	for _, rule := range policy.AppRules {
		path, e := systemAppPath(rule.Path)
		key := strings.ToLower(path)
		if e != nil || result.apps[key] != "" || (rule.Action != "direct" && rule.Action != "vpn" && rule.Action != "block") {
			return nil, errSystemRouting
		}
		result.apps[key] = rule.Action
		copyPolicy.AppRules = append(copyPolicy.AppRules, systemAppRule{Path: path, Action: rule.Action})
	}
	if result.ru, e = compilePreset(catalog.RU, catalog.RUSuffix, catalog.RUExact); e != nil {
		return nil, e
	}
	if result.youtube, e = compilePreset(catalog.YouTube, catalog.VPNYouTube, nil); e != nil {
		return nil, e
	}
	if result.push, e = compilePreset(catalog.Push, catalog.VPNPush, nil); e != nil {
		return nil, e
	}
	if result.checks, e = compilePreset(catalog.Checks, catalog.Connectivity, nil); e != nil {
		return nil, e
	}
	var builder netipx.IPSetBuilder
	for _, prefix := range catalog.RUPrefixes {
		if !prefix.IsValid() || !prefix.Addr().Is4() {
			return nil, errSystemRouting
		}
		builder.AddPrefix(prefix)
	}
	result.ruIP, e = builder.IPSet()
	if e != nil {
		return nil, errSystemRouting
	}
	return result, nil
}
func reservedSystemIP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	if !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return true
	}
	for _, prefix := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "168.63.129.16/32"} {
		if netip.MustParsePrefix(prefix).Contains(ip) {
			return true
		}
	}
	return false
}
func (p *compiledSystemPolicy) DecideSystem(host string, ip netip.Addr, protocol string) routingDecision {
	return p.DecideFlow(host, ip, 443, protocol)
}
func (p *compiledSystemPolicy) DecideFlow(host string, ip netip.Addr, port uint16, protocol string) routingDecision {
	block := func(reason string) routingDecision { return routingDecision{Action: "block", Rule: reason} }
	if !p.Enabled {
		return routingDecision{Action: "vpn", Rule: "disabled"}
	}
	if p.Presets.BlockBitTorrent && protocol == "bittorrent" {
		return block("bittorrent")
	}
	if reservedSystemIP(ip) {
		return block("reserved-or-ipv6")
	}
	var custom routingDecision
	if host != "" {
		normalized, e := routingDomain(host)
		if e != nil {
			return block("invalid-domain")
		}
		host = normalized
		custom, e = p.custom.Decide(host)
		if e != nil {
			return block("invalid-domain")
		}
		if custom.Action == "block" {
			return custom
		}
	}
	// Baseline management stays in VPN even with an explicit DIRECT rule.
	// Other private VPS services remain closed; BLOCK still has highest priority.
	if netip.MustParsePrefix("10.77.43.0/24").Contains(ip) {
		if ip == netip.MustParseAddr("10.77.43.1") && port == 443 && (protocol == "tcp" || protocol == "tcp4" || protocol == "dns") {
			return routingDecision{Action: "vpn", Rule: "protected-management"}
		}
		return block("protected-private")
	}
	if ip.IsPrivate() {
		if p.Presets.LANDirect {
			if custom.Rule != "" {
				return custom
			}
			return routingDecision{Action: "direct", Rule: "lan"}
		}
		return block("lan-disabled")
	}
	if custom.Rule != "" {
		return custom
	}
	if p.Presets.YouTubeVPN && p.youtube.matches(host) {
		return routingDecision{Action: "vpn", Rule: "youtube"}
	}
	if p.Presets.PushVPN && p.push.matches(host) {
		return routingDecision{Action: "vpn", Rule: "push"}
	}
	if p.Presets.ConnectivityDirect && p.checks.matches(host) {
		return routingDecision{Action: "direct", Rule: "connectivity"}
	}
	if p.Presets.RussianDirect {
		if p.ru.matches(host) {
			return routingDecision{Action: "direct", Rule: "ru-domain"}
		}
		if p.ruIP.Contains(ip) {
			return routingDecision{Action: "direct", Rule: "ru-address"}
		}
	}
	return routingDecision{Action: "vpn", Rule: "default"}
}
