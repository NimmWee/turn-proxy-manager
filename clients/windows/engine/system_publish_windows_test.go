package main

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestSystemNetworkPublishRollbackKeepsOwnership(t *testing.T) {
	routes := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1")}
	for _, failure := range []string{"route", "dns", "flush", ""} {
		t.Run(failure, func(t *testing.T) {
			events := []string{}
			added := 0
			flushes := 0
			ops := systemPublishOps{
				AddRoute: func(p netip.Prefix) error {
					events = append(events, "add:"+p.String())
					added++
					if failure == "route" && added == 2 {
						return errors.New("synthetic failure")
					}
					return nil
				},
				DeleteRoute: func(p netip.Prefix) error { events = append(events, "delete:"+p.String()); return nil },
				SetDNS: func(a []netip.Addr) error {
					if len(a) == 0 {
						events = append(events, "clear-dns")
						return nil
					}
					events = append(events, "set-dns")
					if failure == "dns" {
						return errors.New("partial DNS mutation")
					}
					return nil
				},
				FlushDNS: func() error {
					events = append(events, "flush")
					flushes++
					if failure == "flush" && flushes == 1 {
						return errors.New("flush failure")
					}
					return nil
				},
			}
			if _, e := publishSystemNetwork(ops, routes, false); e == nil || len(events) != 0 {
				t.Fatal("network touched before firewall/handler readiness")
			}
			published, e := publishSystemNetwork(ops, routes, true)
			if failure == "" {
				if e != nil {
					t.Fatal(e)
				}
				published.Close()
				before := len(events)
				published.Close()
				if len(events) != before {
					t.Fatal("cleanup not idempotent")
				}
			} else if e == nil {
				t.Fatal("failure ignored")
			}
			all := strings.Join(events, ",")
			if failure == "route" {
				if strings.Contains(all, "set-dns") || strings.Contains(all, "delete:128") || !strings.HasSuffix(all, "delete:0.0.0.0/1") {
					t.Fatal("failed route cleanup touched an unowned route or DNS")
				}
			} else if !strings.Contains(all, "clear-dns,delete:128.0.0.0/1,delete:0.0.0.0/1,flush") {
				t.Fatal("DNS/route rollback order incorrect")
			}
		})
	}
}
