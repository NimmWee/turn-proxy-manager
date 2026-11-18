package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSystemDNSJournalPersistsOpaqueIdentityOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "opaque.dpapi")
	leases, journal, e := openFakeDNSJournal(path, false)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { journal.Close() })
	ip, e := leases.Assign("sensitive.example.com", routingDecision{Action: "vpn"})
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := os.ReadFile(path)
	start := len(fakeDNSJournalHeader) + 4 + int(binary.LittleEndian.Uint32(raw[len(fakeDNSJournalHeader):]))
	size := int(binary.LittleEndian.Uint32(raw[start:]))
	plain, e := journal.aead.Open(nil, nil, raw[start+4:start+4+size], nil)
	if e != nil {
		t.Fatal("cannot inspect synthetic record")
	}
	var record map[string]any
	if json.Unmarshal(plain, &record) != nil || record["v"] != float64(2) || record["host"] != nil || record["id"] == nil || bytes.Contains(plain, []byte("sensitive")) {
		t.Fatal("durable DNS record contains hostname or non-opaque identity")
	}
	journal.Close()
	restored, reopened, e := openFakeDNSJournal(path, true)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	old, _ := restored.Lookup(ip)
	if old.Host != "" {
		t.Fatal("hostname restored from durable cache")
	}
	got, e := restored.Assign("sensitive.example.com", routingDecision{Action: "direct"})
	if e != nil || got != ip {
		t.Fatal("opaque identity changed across reconnect")
	}
}

func TestSystemDNSJournalMigratesLegacyWithoutChangingKeysOrIPs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.dpapi")
	_, j, e := openFakeDNSJournal(path, false)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := os.ReadFile(path)
	copy(raw, []byte(legacyFakeDNSJournalHeader))
	for i, host := range []string{"one.example.com", "two.example.com"} {
		plain, _ := json.Marshal(fakeDNSIdentity{V: 1, Host: host, IP: netip.AddrFrom4([4]byte{198, 18, 0, byte(i + 2)})})
		sealed := j.aead.Seal(nil, nil, plain, nil)
		var length [4]byte
		binary.LittleEndian.PutUint32(length[:], uint32(len(sealed)))
		raw = append(raw, length[:]...)
		raw = append(raw, sealed...)
	}
	j.entries = 2
	if j.saveHead() != nil {
		t.Fatal("head fixture")
	}
	j.Close()
	if os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("legacy fixture")
	}
	beforeHead, _ := os.ReadFile(path + ".head")
	leases, j, e := openFakeDNSJournal(path, true)
	if e != nil {
		t.Fatal("valid legacy migration refused")
	}
	keyEnd := len(fakeDNSJournalHeader) + 4 + int(binary.LittleEndian.Uint32(raw[len(fakeDNSJournalHeader):]))
	migrated, _ := os.ReadFile(path)
	if string(migrated[:len(fakeDNSJournalHeader)]) != fakeDNSJournalHeader || !bytes.Equal(raw[len(fakeDNSJournalHeader):keyEnd], migrated[len(fakeDNSJournalHeader):keyEnd]) {
		t.Fatal("migration changed DPAPI key")
	}
	afterHead, _ := os.ReadFile(path + ".head")
	if !bytes.Equal(beforeHead, afterHead) {
		t.Fatal("migration changed committed high-water mark")
	}
	got, e := leases.Assign("two.example.com", routingDecision{Action: "direct"})
	if e != nil || got.String() != "198.18.0.3" {
		t.Fatal("migration reassigned IP")
	}
	j.Close()
	leases, j, e = openFakeDNSJournal(path, true)
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	lease, _ := leases.Lookup(got)
	if lease.Host != "" {
		t.Fatal("migrated hostname persisted")
	}
}

func TestSystemDNSJournalStableIdentityAcrossReconnect(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identities.dpapi")
	leases, journal, e := openFakeDNSJournal(path, false)
	if e != nil {
		t.Fatal("synthetic DPAPI journal creation failed")
	}
	first, e := leases.Assign("one.example.com", routingDecision{Action: "vpn"})
	if e != nil {
		t.Fatal(e)
	}
	second, e := leases.Assign("two.example.com", routingDecision{Action: "direct"})
	if e != nil {
		t.Fatal(e)
	}
	leases.SetAddresses(first, []netip.Addr{netip.MustParseAddr("8.8.8.8")})
	journal.Close()
	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, []byte("example.com")) {
		t.Fatal("identity history was not encrypted")
	}
	restored, reopened, e := openFakeDNSJournal(path, true)
	if e != nil {
		t.Fatal("journal replay failed")
	}
	defer reopened.Close()
	// Reversed lookup order and changed policy must keep hostname identity,
	// while old decisions and resolved server/profile IPs are never restored.
	old, ok := restored.Lookup(first)
	if !ok || len(old.Addresses) != 0 || old.Decision.Action != "" || old.Host != "" {
		t.Fatal("stale route/address restored")
	}
	got, e := restored.Assign("two.example.com", routingDecision{Action: "vpn"})
	if e != nil || got != second {
		t.Fatal("reconnect reassigned stale app fake IP")
	}
	policy, _ := compileSystemPolicy(&systemPolicy{V: 1, Enabled: true}, nil)
	calls := 0
	router := &systemFlowRouter{policy: policy, leases: restored, vpn: func(_ context.Context, _, address string) (net.Conn, error) {
		calls++
		if address != "1.1.1.1:443" {
			t.Error("old real IP used")
		}
		a, b := net.Pipe()
		b.Close()
		return a, nil
	}}
	router.refresh = func(_ context.Context, host string) error {
		ip, e := restored.Assign(host, routingDecision{Action: "vpn"})
		if e != nil {
			return e
		}
		return restored.setAddressesUntil(ip, []netip.Addr{netip.MustParseAddr("1.1.1.1")}, time.Now().Add(time.Minute))
	}
	if _, _, e := router.targets(netip.AddrPortFrom(first, 443), "tcp"); e == nil {
		t.Fatal("opaque identity guessed a target before DNS/SNI")
	}
	if restored.Recover(first, "two.example.com") || !restored.Recover(first, "one.example.com") {
		t.Fatal("opaque recovery did not authenticate hostname")
	}
	if _, _, e := router.targets(netip.AddrPortFrom(first, 443), "tcp"); e != nil {
		t.Fatal("known restored identity could not reach resolver")
	}
	c, e := router.Dial(context.Background(), "tcp4", netip.AddrPortFrom(first, 443))
	if e != nil || calls != 1 {
		t.Fatal("restored identity did not resolve on current path")
	}
	c.Close()
	third, e := restored.Assign("three.example.com", routingDecision{Action: "vpn"})
	if e != nil || third == first || third == second {
		t.Fatal("persisted pool reused an identity")
	}
}

func TestSystemDNSJournalCorruptionAndWriteFailureFailClosed(t *testing.T) {
	folder := t.TempDir()
	missing := filepath.Join(folder, "missing.dpapi")
	if _, _, e := openFakeDNSJournal(missing, true); e == nil {
		t.Fatal("missing required history recreated")
	}
	if _, e := os.Stat(missing); !os.IsNotExist(e) {
		t.Fatal("refused history modified filesystem")
	}
	path := filepath.Join(folder, "history.dpapi")
	leases, journal, e := openFakeDNSJournal(path, false)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = leases.Assign("private-history.example.com", routingDecision{Action: "vpn"}); e != nil {
		t.Fatal(e)
	}
	journal.Close()
	raw, _ := os.ReadFile(path)
	raw[len(raw)-1] ^= 1
	os.WriteFile(path, raw, 0600)
	if _, _, e = openFakeDNSJournal(path, true); e == nil || e.Error() != "SYSTEM_DNS_CACHE_INVALID" {
		t.Fatal("corrupt identity history reset or leaked details")
	}
	path = filepath.Join(folder, "failure.dpapi")
	leases, journal, e = openFakeDNSJournal(path, false)
	if e != nil {
		t.Fatal(e)
	}
	journal.Close()
	if _, e = leases.Assign("uncommitted.example.com", routingDecision{Action: "vpn"}); e == nil {
		t.Fatal("unpersisted identity issued")
	}
	if len(leases.byIP) != 0 || leases.next != netip.MustParseAddr("198.18.0.1") {
		t.Fatal("failed append advanced identity allocator")
	}
	if _, e = leases.Assign("another.example.com", routingDecision{Action: "vpn"}); e == nil {
		t.Fatal("poisoned journal accepted another answer")
	}
}

func TestSystemDNSJournalRejectsCommittedBoundaryTruncation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.dpapi")
	leases, journal, e := openFakeDNSJournal(path, false)
	if e != nil {
		t.Fatal(e)
	}
	leases.Assign("one.example.com", routingDecision{Action: "vpn"})
	leases.Assign("two.example.com", routingDecision{Action: "vpn"})
	journal.Close()
	raw, _ := os.ReadFile(path)
	keySize := int(binary.LittleEndian.Uint32(raw[len(fakeDNSJournalHeader):]))
	start := len(fakeDNSJournalHeader) + 4 + keySize
	firstSize := int(binary.LittleEndian.Uint32(raw[start:]))
	if os.WriteFile(path, raw[:start+4+firstSize], 0600) != nil {
		t.Fatal("fixture truncation failed")
	}
	if _, _, e := openFakeDNSJournal(path, true); e == nil {
		t.Fatal("committed fake IP could be reused after truncation")
	}
}
