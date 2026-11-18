package main

import (
	"errors"
	"net/netip"
	"sync"
	"time"
)

type fakeDNSLease struct {
	Host      string
	Decision  routingDecision
	Addresses []netip.Addr
	Expires   time.Time
}
type fakeDNS struct {
	mu        sync.Mutex
	limit     int
	byHost    map[string]netip.Addr
	byID      map[string]netip.Addr
	identity  func(string) string
	byIP      map[netip.Addr]fakeDNSLease
	next      netip.Addr
	persist   func(string, netip.Addr) error
	lastError string
}

const maxFakeDNSIdentities = 131066 // /15 minus network start and outer TUN /30

func newFakeDNS(limit int) *fakeDNS {
	if limit < 1 || limit > maxFakeDNSIdentities {
		limit = 32768
	}
	return &fakeDNS{limit: limit, byHost: map[string]netip.Addr{}, byID: map[string]netip.Addr{}, byIP: map[netip.Addr]fakeDNSLease{}, next: netip.MustParseAddr("198.18.0.1")}
}
func (d *fakeDNS) Assign(host string, decision routingDecision) (netip.Addr, error) {
	domain, e := routingDomain(host)
	if e != nil || decision.Action != "direct" && decision.Action != "vpn" {
		return netip.Addr{}, errSystemRouting
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.identity != nil {
		if ip, ok := d.byID[d.identity(domain)]; ok {
			old := d.byIP[ip]
			if old.Host != "" && old.Host != domain {
				return netip.Addr{}, errSystemRouting
			}
			old.Host = domain
			d.byIP[ip] = old
			d.byHost[domain] = ip
		}
	}
	if ip, ok := d.byHost[domain]; ok {
		old := d.byIP[ip]
		if old.Decision.Action == "" {
			old.Decision = decision
			d.byIP[ip] = old
		}
		if old.Decision.Action != decision.Action {
			return netip.Addr{}, errors.New("DNS_POLICY_CHANGED")
		}
		return ip, nil
	}
	if len(d.byIP) >= d.limit {
		d.lastError = "SYSTEM_DNS_CACHE_FULL"
		return netip.Addr{}, errors.New("DNS_LEASE_LIMIT")
	}
	// Persist identity BEFORE any DNS answer can expose this address. Never
	// reuse across sessions: applications retain their own DNS caches too.
	next := d.next.Next()
	if !systemFakeRange.Contains(next) || netip.MustParseAddr("198.19.255.251").Less(next) {
		return netip.Addr{}, errors.New("DNS_LEASE_LIMIT")
	}
	if d.persist != nil {
		if e := d.persist(domain, next); e != nil {
			d.lastError = "SYSTEM_DNS_CACHE_WRITE_FAILED"
			return netip.Addr{}, e
		}
	}
	d.next = next
	d.byHost[domain] = d.next
	d.byIP[d.next] = fakeDNSLease{Host: domain, Decision: decision}
	if d.identity != nil {
		d.byID[d.identity(domain)] = d.next
	}
	return d.next, nil
}

// Recover only an existing opaque identity; never create a name/IP association
// from untrusted application bytes unless its keyed digest already matches.
func (d *fakeDNS) Recover(ip netip.Addr, host string) bool {
	domain, e := routingDomain(host)
	if e != nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	lease, ok := d.byIP[ip]
	if !ok || d.identity == nil || d.byID[d.identity(domain)] != ip || lease.Host != "" && lease.Host != domain {
		return false
	}
	lease.Host = domain
	d.byIP[ip] = lease
	d.byHost[domain] = ip
	return true
}

func (d *fakeDNS) LastError() string { d.mu.Lock(); defer d.mu.Unlock(); return d.lastError }
func (d *fakeDNS) Lookup(ip netip.Addr) (fakeDNSLease, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	lease, ok := d.byIP[ip]
	lease.Addresses = append([]netip.Addr(nil), lease.Addresses...)
	return lease, ok
}
func (d *fakeDNS) SetAddresses(ip netip.Addr, addresses []netip.Addr) error {
	return d.setAddressesUntil(ip, addresses, time.Time{})
}
func (d *fakeDNS) setAddressesUntil(ip netip.Addr, addresses []netip.Addr, expires time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	lease, ok := d.byIP[ip]
	if !ok || len(addresses) == 0 || len(addresses) > 32 {
		return errSystemRouting
	}
	lease.Addresses = append([]netip.Addr(nil), addresses...)
	lease.Expires = expires
	d.byIP[ip] = lease
	return nil
}
