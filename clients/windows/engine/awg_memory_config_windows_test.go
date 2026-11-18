package main

import (
	tun "github.com/sagernet/sing-tun"
	"strings"
	"testing"
)

const reviewAWG1 = "Jc = 3\nJmin = 40\nJmax = 70\nS1 = 15\nS2 = 30\nH1 = 101\nH2 = 102\nH3 = 103\nH4 = 104\n"

func TestMemoryAmneziaWGEncryptedTCPAndUDP(t *testing.T) {
	// Custom headers and padding must actually handshake; stripping them would
	// no longer be a proof of the AWG backend. Traffic remains loopback-only.
	local, remote := memoryWGPairWithExtensions(t, reviewAWG1)
	testMemoryWireGuardTraffic(t, local, remote)
	raw, e := local.device.IpcGet()
	if e != nil {
		t.Fatal("AWG private inspection unavailable")
	}
	for _, expected := range []string{"h1=101\n", "h2=102\n", "h3=103\n", "h4=104\n", "s1=15\n", "s2=30\n", "jc=3\n"} {
		if !strings.Contains(raw, expected) {
			t.Fatal("AWG extension not applied")
		}
	}
}

func TestMemoryAWGConfigBoundsAndPublicGate(t *testing.T) {
	base := fixture()["wg"].(string)
	with := func(extensions string) string {
		return strings.Replace(base, "[Interface]\n", "[Interface]\n"+extensions, 1)
	}
	config, ipc, e := memoryWGConfig(with(reviewAWG1))
	if e != nil || config == nil || ipc != "jc=3\njmin=40\njmax=70\ns1=15\ns2=30\nh1=101\nh2=102\nh3=103\nh4=104\n" {
		t.Fatal("bounded AWG1 translation failed")
	}
	if !safeWG(with(reviewAWG1)) {
		t.Fatal("bounded AWG1 profile rejected")
	}
	for _, raw := range []string{
		with("Jc = 17\n"), with("Jc = 3\n"), with("Jmin = 71\nJmax = 70\n"),
		with("Jmax = 1281\n"), with("S1 = 513\n"), with("H1 = 4294967296\n"),
		with("H1 = 0\n"), with("H1 = 2\n"), with("H1 = 101\nH2 = 101\n"),
		with("H1 = 200-100\n"), with("I1 = <r -1>\n"), with("S3 = 513\n"),
		with("Jc = 0\nJc = 0\n"), with("Jc = +0\n"), with("Jc = 00\n"),
		base + "\nJc = 1\n", with("S1 = 5\x00\n"), strings.Repeat("#", 17000),
	} {
		if _, _, e := memoryWGConfig(raw); e != errMemoryWGConfig {
			t.Fatal("invalid or unsupported AWG accepted; no raw config printed")
		}
	}
	if _, ipc, e := memoryWGConfig(base); e != nil || ipc != "" {
		t.Fatal("ordinary WG changed")
	}
}

func TestAWGProfileRequiresExplicitBackendAndPreservesProtocol(t *testing.T) {
	value := fixture()
	value["wg"] = strings.Replace(value["wg"].(string), "[Interface]\n", "[Interface]\n"+reviewAWG1, 1)
	raw := share(value)
	p, e := parseProfile(raw)
	if e != nil {
		t.Fatal("AWG1 import failed")
	}
	for _, policy := range []*systemPolicy{nil, {V: 1, Enabled: false}} {
		if _, e := prepareSystemRouting(policy, p.WG); e == nil || e.Error() != "AWG_SYSTEM_BACKEND_REQUIRED" {
			t.Fatal("AWG may reach WGNT or silently enable routing")
		}
	}
	if _, e := prepareSystemRouting(&systemPolicy{V: 1, Enabled: true, DirectDNS: []string{"77.88.8.8"}}, p.WG); tun.WithGVisor && e != nil || !tun.WithGVisor && (e == nil || e.Error() != "SYSTEM_ROUTING_BUILD_REQUIRED") {
		t.Fatal("explicit AWG backend/build gate failed pure validation")
	}
	for _, path := range []string{"direct", "relay"} {
		core, e := coreForPath(raw, path, false, false)
		if e != nil {
			t.Fatal("AWG transport switch rejected")
		}
		report, e := describeEffective(raw, core)
		if e != nil || report.WireGuardMTU != 1280 || report.VPNProtocol != "amneziawg1" {
			t.Fatal("AWG effective settings lost")
		}
	}
	ordinary, e := parseProfile(share(fixture()))
	if e != nil || sameRecoveryKey(p, ordinary) {
		t.Fatal("AWG recovery can downgrade to ordinary WG")
	}
	changed := *p
	changed.WG = strings.Replace(p.WG, "H1 = 101", "H1 = 111", 1)
	if sameRecoveryKey(p, &changed) || !sameRecoveryKey(p, p) {
		t.Fatal("AWG recovery lost extension identity")
	}
}
