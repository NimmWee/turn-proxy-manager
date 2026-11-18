package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"strings"
	"testing"
)

func TestRoutingCatalogueUpdateFailClosed(t *testing.T) {
	var packed bytes.Buffer
	w := gzip.NewWriter(&packed)
	w.Write(systemCatalogJSON)
	w.Close()
	update := &systemCatalogUpdate{systemCatalogSHA256, base64.StdEncoding.EncodeToString(packed.Bytes())}
	c, e := updatedSystemCatalog(update)
	if e != nil || c.GeoIP.IPv4Prefixes != 12902 {
		t.Fatal("valid pinned catalogue rejected")
	}
	bad := *update
	bad.SHA256 = strings.Repeat("0", 64)
	if _, e = updatedSystemCatalog(&bad); e == nil {
		t.Fatal("tampered update accepted")
	}
	packed.Reset()
	w = gzip.NewWriter(&packed)
	w.Write(bytes.Repeat([]byte("x"), 1024*1024+1))
	w.Close()
	bad = *update
	bad.Gzip = base64.StdEncoding.EncodeToString(packed.Bytes())
	if _, e = updatedSystemCatalog(&bad); e == nil {
		t.Fatal("gzip expansion accepted")
	}
	policy := &systemPolicy{V: 1, Enabled: true, Catalog: update}
	compiled, e := compileSystemPolicy(policy, nil)
	if e != nil || compiled.Catalog.SHA256 != systemCatalogSHA256 {
		t.Fatal("update lost during compile")
	}
}
func TestNetworkRecoveryRejectsChangedSessionAndManualStop(t *testing.T) {
	id := strings.Repeat("a", 64)
	r := response{OK: true, State: "connected", ConfiguredProfileIdentity: id, RuntimeProfileIdentity: id, LastAttemptID: 12, ConnectionID: 12, PathEpoch: 1, TunnelActive: true}
	if !canNetworkRecover(r, id, 12, 1) {
		t.Fatal("healthy exact runtime must support network handover")
	}
	variants := []response{r, r, r, r, r, r, r}
	variants[0].LastAttemptID = 13
	variants[1].ConfiguredProfileIdentity = strings.Repeat("b", 64)
	variants[2].PathEpoch = 2
	variants[3].PathPending = true
	variants[4].Captcha = "SYNTHETIC"
	variants[5].State = "stopping"
	variants[6].ConnectionID = 13
	for _, v := range variants {
		if canNetworkRecover(v, id, 12, 1) {
			t.Fatal("stale/captcha session accepted")
		}
	}
	r.LastAttemptID = 0
	r.TunnelActive = false
	r.State = "stopped"
	if canNetworkRecover(r, id, 12, 1) {
		t.Fatal("cancelled manual intent accepted")
	}
}
