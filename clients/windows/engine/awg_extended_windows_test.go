package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const reviewAWG2 = "Jc = 3\nJmin = 40\nJmax = 70\nS1 = 15\nS2 = 30\nS3 = 12\nS4 = 16\nH1 = 100-109\nH2 = 200-209\nH3 = 300-309\nH4 = 400-409\nI1 = <b 0xd100000001><rc 8><t><r 50>\nI5 = <rd 8>\n"

func reviewAWG3() string {
	return "S1 = 12\nS2 = 12\nS3 = 12\nS4 = 12\nH1 = 100-109\nH2 = 200-209\nH3 = 300-309\nH4 = 400-409\nHeaderProtectionKey = " + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("\x04", 32))) + "\nContentPaddingAddition = 4-12\nRekeyAfterTime = 90-140\nRekeyTimeout = 5\nRejectAfterTime = 180\nKeepaliveTimeout = 10-15\nMaxHandshakeAttempts = 18\nRandomTrailers = on\nDisableCookies = off\n"
}

func TestAWG3WrongHeaderKeyCannotHandshake(t *testing.T) {
	good := reviewAWG3()
	wrong := strings.Replace(good, base64.StdEncoding.EncodeToString([]byte(strings.Repeat("\x04", 32))), base64.StdEncoding.EncodeToString([]byte(strings.Repeat("\x05", 32))), 1)
	local, remote := memoryWGPairDifferentExtensions(t, wrong, good)
	ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
	defer cancel()
	c, e := local.Net.DialContext(ctx, "tcp", "10.21.32.1:8081")
	if c != nil {
		c.Close()
	}
	if e == nil || local.Health().Handshake || remote.Health().Handshake {
		t.Fatal("mismatched header key unexpectedly authenticated")
	}
}

func TestExtendedAWGProfilesPreserveBoundedParamsAndRefuseDowngrade(t *testing.T) {
	for _, test := range []struct{ ext, protocol string }{{reviewAWG2, "amneziawg2"}, {reviewAWG3(), "amneziawg3"}} {
		value := fixture()
		value["wg"] = strings.Replace(value["wg"].(string), "[Interface]\n", "[Interface]\n"+test.ext, 1)
		raw := share(value)
		p, e := parseProfile(raw)
		if e != nil || p.WG != value["wg"] {
			t.Fatal("extended AWG import lost or rejected fields")
		}
		report, e := describeEffective(raw, p.Core)
		if e != nil || report.VPNProtocol != test.protocol {
			t.Fatal("AWG protocol family lost")
		}
		encoded, _ := json.Marshal(report)
		if strings.Contains(string(encoded), "HeaderProtectionKey") || strings.Contains(string(encoded), "0xd100") || strings.Contains(string(encoded), base64.StdEncoding.EncodeToString([]byte(strings.Repeat("\x04", 32)))) {
			t.Fatal("AWG private parameters escaped effective metadata")
		}
		if _, e := prepareSystemRouting(nil, p.WG); e == nil || e.Error() != "AWG_SYSTEM_BACKEND_REQUIRED" {
			t.Fatal("extended AWG may reach WGNT")
		}
		_, ipc, e := memoryWGConfig(p.WG)
		if e != nil || !strings.Contains(ipc, "s4=") {
			t.Fatal("extensions lost")
		}
		changed := *p
		changed.WG = strings.Replace(p.WG, "H1 = 100-109", "H1 = 110-119", 1)
		if sameRecoveryKey(p, &changed) || !sameRecoveryKey(p, p) {
			t.Fatal("extended AWG recovery downgrade")
		}
	}
}

func TestAWG2And3BoundsRejectUnsafeRangesCPSKeyAndTimers(t *testing.T) {
	base := fixture()["wg"].(string)
	with := func(ext string) string { return strings.Replace(base, "[Interface]\n", "[Interface]\n"+ext, 1) }
	for _, ext := range []string{
		"H1 = 100-200\nH2 = 150-250\n", "H1 = 0-4294967295\n", "H1 = 200-100\n", "H1 = 01-10\n",
		"I1 = <r -1>\n", "I1 = <r 1281>\n", "I1 = garbage<r 10>\n", "I1 = <r 1 ignored>\n", "I1 = <unknown>\n", "I1 = <d>\n", "I1 = <t 5>\n", "I1 = <b 0x1>\n", "I1 = " + strings.Repeat("<r 1>", 13) + "\n",
		"S4 = 65\n", "ContentPaddingAddition = 65\n", "S4 = 60\nContentPaddingAddition = 8\n", "RekeyTimeout = 0-5\n", "RekeyAfterTime = 1\n", "RejectAfterTime = 3600\n", "MaxHandshakeAttempts = 1000\n", "RandomTrailers = maybe\n",
		"HeaderProtectionKey = INVALID_PRIVATE_INPUT\n", "HeaderProtectionKey = " + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n",
		strings.Replace(reviewAWG3(), "S4 = 12", "S4 = 11", 1), "RekeyAfterTime = 140\nRejectAfterTime = 120\n",
	} {
		if _, _, e := memoryWGConfig(with(ext)); e != errMemoryWGConfig {
			t.Fatal("unsafe AWG accepted; raw fields suppressed")
		}
	}
}

func TestMemoryAWG2AndAWG3EncryptedTCPAndUDP(t *testing.T) {
	for _, test := range []struct{ name, ext string }{{"AWG2", reviewAWG2}, {"AWG3", reviewAWG3()}} {
		t.Run(test.name, func(t *testing.T) {
			local, remote := memoryWGPairWithExtensions(t, test.ext)
			testMemoryWireGuardTraffic(t, local, remote)
			raw, e := local.device.IpcGet()
			if e != nil {
				t.Fatal("private state unavailable")
			}
			for _, field := range []string{"h1=100-109\n", "s3=12\n", "s4="} {
				if !strings.Contains(raw, field) {
					t.Fatal("AWG2/3 fields not applied")
				}
			}
			if test.name == "AWG3" && !strings.Contains(raw, "header_protection_key="+strings.Repeat("04", 32)+"\n") {
				t.Fatal("header key not applied")
			}
		})
	}
}
