package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Read-only opaque physical IPv4 fingerprint. Own TUN/route publication does
// not change it. No addresses/interface names are exported or journalled.
func physicalNetworkFingerprint() (string, error) {
	p, e := selectUnderlay()
	if e != nil {
		return "", e
	}
	luid, e := winipcfg.LUIDFromIndex(p.v4)
	if e != nil {
		return "", e
	}
	rows, e := winipcfg.GetUnicastIPAddressTable(windows.AF_INET)
	if e != nil {
		return "", e
	}
	parts := []string{fmt.Sprint(p.v4, luid)}
	for _, row := range rows {
		if row.InterfaceLUID == luid && row.DadState == winipcfg.DadStatePreferred {
			parts = append(parts, fmt.Sprint(row.Address.Addr(), "/", row.OnLinkPrefixLength))
		}
	}
	routes, e := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if e != nil {
		return "", e
	}
	for _, row := range routes {
		if row.InterfaceLUID == luid && row.DestinationPrefix.PrefixLength == 0 {
			parts = append(parts, row.NextHop.Addr().String())
		}
	}
	if len(parts) < 3 {
		return "", errors.New("PHYSICAL_UPLINK_REQUIRED")
	}
	adapters, e := winipcfg.GetAdaptersAddresses(windows.AF_INET, 0)
	if e != nil {
		return "", e
	}
	for _, adapter := range adapters {
		if adapter.LUID == luid {
			for dns := adapter.FirstDNSServerAddress; dns != nil; dns = dns.Next {
				parts = append(parts, fmt.Sprint("dns:", dns.Address.IP()))
			}
		}
	}
	sort.Strings(parts)
	hash := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(hash[:]), nil
}
func canNetworkRecover(r response, id string, attempt, epoch uint64) bool {
	return r.OK && validProfileIdentity(id) && attempt != 0 && r.ConfiguredProfileIdentity == id && r.LastAttemptID == attempt && r.PathEpoch == epoch && !r.PathPending && r.State != "captcha" && r.Captcha == "" && r.State != "stopping" && (!r.TunnelActive || r.RuntimeProfileIdentity == id && r.ConnectionID == attempt)
}

// broker.mu held across compare/stop/options/start. Reuses exact SYSTEM profile,
// keys and routing; freezes current transport until next explicit manual Connect
// instead of granting a new automatic path-switch budget on every WiFi flap.
func (b *broker) reconnectNetwork(q request) response {
	fail := func(code string) response { return response{Error: code, State: "error"} }
	r := b.status()
	if b.recoveryCancelled || !canNetworkRecover(r, q.ExpectedProfile, q.ExpectedAttempt, q.ExpectedEpoch) {
		return fail("CONNECTION_CHANGED")
	}
	if _, e := physicalNetworkFingerprint(); e != nil {
		return fail("PHYSICAL_UPLINK_REQUIRED")
	}
	options, e := loadConnectionOptions(b.dir)
	if e != nil || options.Cancelled || options.AttemptID != q.ExpectedAttempt || options.ProfileIdentity != q.ExpectedProfile {
		return fail("CONNECTION_CHANGED")
	}
	if b.socks != nil {
		b.socks.Close()
		b.socks = nil
	}
	m, e := mgr.Connect()
	if e != nil {
		return fail("SCM_UNAVAILABLE")
	}
	defer m.Disconnect()
	if e = stopOwn(m, tunnelName, "--tunnel"); e != nil {
		return fail("TUNNEL_STOP_FAILED")
	}
	latest, e := loadConnectionOptions(b.dir)
	if e != nil || latest.Cancelled || latest.AttemptID != q.ExpectedAttempt || latest.ProfileIdentity != q.ExpectedProfile {
		return fail("CONNECTION_CHANGED")
	}
	options.FakeDNSRequired = options.FakeDNSRequired || latest.FakeDNSRequired
	if _, e = physicalNetworkFingerprint(); e != nil {
		return fail("PHYSICAL_UPLINK_REQUIRED")
	}
	options.AttemptID = uint64(time.Now().UnixNano())
	options.Started = time.Now().Unix()
	options.AutoPaths = false
	if validPath(r.RuntimePath) {
		options.InitialPath = r.RuntimePath
	}
	encoded, e := json.Marshal(options)
	if e != nil || writeSecret(filepath.Join(b.dir, "options.dpapi"), "FreeTurn connection options v1", encoded) != nil {
		return fail("CONFIG_SAVE_FAILED")
	}
	_ = os.Remove(filepath.Join(b.dir, "runtime.dpapi"))
	b.generation++
	b.probeConfirmed = time.Time{}
	b.probeAttempt = time.Time{}
	b.diagnosticStage = ""
	s, e := ownService(m, tunnelName, "--tunnel")
	if e != nil {
		return fail("TUNNEL_SERVICE_UNAVAILABLE")
	}
	defer s.Close()
	if s.Start() != nil {
		return fail("TUNNEL_START_FAILED")
	}
	return response{OK: true, State: "starting", HasProfile: true, ConfiguredProfileIdentity: options.ProfileIdentity, LastAttemptID: options.AttemptID, RuntimePath: options.InitialPath}
}
