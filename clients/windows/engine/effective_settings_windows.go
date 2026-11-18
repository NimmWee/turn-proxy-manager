package main

import (
	"encoding/json"
)

// Deliberate allowlist. Never expose raw core/share, DNS addresses, VK links,
// client ID, keys or arbitrary strings in status/inspection.
type effectiveSettings struct {
	RequestedStreams     int    `json:"requestedStreams"`
	StreamLimit          int    `json:"streamLimit"`
	StreamsPerCredential int    `json:"streamsPerCredential"`
	Provider             string `json:"provider"`
	Transport            string `json:"transport"`
	DNSMode              string `json:"dnsMode"`
	ManualCaptcha        bool   `json:"manualCaptcha"`
	AdvancedCaptcha      bool   `json:"advancedCaptcha"`
	WireGuardMTU         int    `json:"wireGuardMTU"`
	VPNProtocol          string `json:"vpnProtocol"`
}
type settingsCore struct {
	Provider string `json:"provider"`
	Turn     struct {
		N         int    `json:"n"`
		Transport string `json:"transport"`
	} `json:"turn"`
	VK struct {
		SPC      int  `json:"streamsPerCred"`
		Manual   bool `json:"manualCaptcha"`
		Advanced bool `json:"advancedCaptcha"`
	} `json:"vk"`
	DNS struct {
		Mode string `json:"mode"`
	} `json:"dns"`
}

func describeEffective(raw, core string) (*effectiveSettings, error) {
	p, err := parseProfile(raw)
	if err != nil {
		return nil, errProfile
	}
	var requested, actual settingsCore
	if json.Unmarshal([]byte(p.Core), &requested) != nil || json.Unmarshal([]byte(core), &actual) != nil {
		return nil, errProfile
	}
	if requested.Turn.N < 1 || requested.Turn.N > 32 || actual.Turn.N < 1 || actual.Turn.N > 32 || actual.VK.SPC < 1 || actual.VK.SPC > 16 ||
		actual.Provider != "vk" && actual.Provider != "direct" || actual.Turn.Transport != "tcp" && actual.Turn.Transport != "udp" || actual.DNS.Mode != "auto" && actual.DNS.Mode != "plain" && actual.DNS.Mode != "doh" {
		return nil, errProfile
	}
	mtu := 0
	if p.WG != "" {
		wg, _, err := memoryWGConfig(p.WG)
		if err != nil {
			return nil, errProfile
		}
		mtu = int(wg.Interface.MTU)
	}
	transport := actual.Turn.Transport
	if actual.Provider == "direct" {
		transport = "dtls"
	}
	protocol := ""
	if p.WG != "" {
		protocol = "wireguard"
		if p.AWG {
			protocol = awgProtocol(p.WG)
		}
	}
	return &effectiveSettings{requested.Turn.N, actual.Turn.N, actual.VK.SPC, actual.Provider, transport, actual.DNS.Mode, actual.VK.Manual, actual.VK.Advanced, mtu, protocol}, nil
}
