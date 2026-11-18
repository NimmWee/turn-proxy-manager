package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

func TestSystemApplicationRulesStrictAndProtected(t *testing.T) {
	p, e := compileSystemPolicy(&systemPolicy{V: 1, Enabled: true, AppRules: []systemAppRule{{Path: `C:\Apps\Browser.exe`, Action: "direct"}}}, nil)
	if e != nil || p.appAction(`c:\apps\browser.EXE`) != "direct" {
		t.Fatal("application rule not compiled")
	}
	off, _ := compileSystemPolicy(&systemPolicy{V: 1, AppRules: []systemAppRule{{Path: `C:\Apps\Browser.exe`, Action: "direct"}}}, nil)
	if off.applicationDecision(routingDecision{Action: "vpn", Rule: "disabled"}, `C:\Apps\Browser.exe`).Action != "vpn" {
		t.Fatal("disabled system mode applied app rules")
	}
	for _, path := range []string{`browser.exe`, `\\server\share\app.exe`, `C:\Apps\*.exe`, `C:\Apps\app.exe:stream`, `C:\Apps\..\app.exe`, `C:\Apps\app.exe `} {
		if _, e := systemAppPath(path); e == nil {
			t.Fatal("unsafe application selector accepted")
		}
	}
}

func TestSystemApplicationOwnerAmbiguityAndNativeLoopback(t *testing.T) {
	source := netip.MustParseAddrPort("127.0.0.1:32123")
	dst := netip.MustParseAddrPort("127.0.0.1:32124")
	rows := []systemAppEndpoint{{Local: source, PID: 10}, {Local: netip.AddrPortFrom(netip.IPv4Unspecified(), source.Port()), PID: 11}}
	if _, e := systemAppEndpointPID(rows, "udp4", source, dst); e == nil {
		t.Fatal("ambiguous UDP owner selected")
	}
	rows[1].PID = 10
	if pid, e := systemAppEndpointPID(rows, "udp4", source, dst); e != nil || pid != 10 {
		t.Fatal("unique UDP owner lost")
	}
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	client, e := net.Dial("tcp4", listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	peer, e := listener.Accept()
	if e != nil {
		t.Fatal(e)
	}
	defer peer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	o, e := lookupSystemAppOwner(ctx, "tcp4", client.LocalAddr().(*net.TCPAddr).AddrPort(), client.RemoteAddr().(*net.TCPAddr).AddrPort())
	if e != nil {
		t.Fatal("native TCP owner lookup failed")
	}
	defer o.Close()
	exe, _ := os.Executable()
	if !strings.EqualFold(o.Path, exe) || o.Current() != nil {
		t.Fatal("native TCP executable binding wrong")
	}
	udp, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if e != nil {
		t.Fatal(e)
	}
	defer udp.Close()
	u, e := lookupSystemAppOwner(ctx, "udp4", netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(udp.LocalAddr().(*net.UDPAddr).Port)), dst)
	if e != nil {
		t.Fatal("native wildcard UDP lookup failed")
	}
	defer u.Close()
	if !strings.EqualFold(u.Path, exe) || u.Current() != nil {
		t.Fatal("native UDP executable binding wrong")
	}
}

func TestSystemApplicationDialProtectsPathAndOwner(t *testing.T) {
	path := `C:\Apps\Browser.exe`
	source := netip.MustParseAddrPort("192.168.1.10:30001")
	destination := netip.MustParseAddrPort("1.1.1.1:443")
	for _, action := range []string{"direct", "vpn", "block"} {
		p, _ := compileSystemPolicy(&systemPolicy{V: 1, Enabled: true, AppRules: []systemAppRule{{Path: path, Action: action}}}, nil)
		calls := []string{}
		released := false
		valid := true
		dial := func(name string) systemDial {
			return func(context.Context, string, string) (net.Conn, error) {
				calls = append(calls, name)
				a, b := net.Pipe()
				b.Close()
				return a, nil
			}
		}
		r := &systemFlowRouter{policy: p, leases: newFakeDNS(1), direct: dial("direct"), vpn: dial("vpn"), owner: func(context.Context, string, netip.AddrPort, netip.AddrPort) (*systemAppOwner, error) {
			return &systemAppOwner{Path: path, check: func() error {
				if !valid {
					return errSystemApp
				}
				return nil
			}, release: func() { released = true }}, nil
		}}
		c, e := r.DialSource(context.Background(), "tcp4", source, destination)
		if action == "block" {
			if e == nil || len(calls) != 0 || !released {
				t.Fatal("blocked app dialed or leaked handle")
			}
		} else {
			if e != nil || len(calls) != 1 || calls[0] != action {
				t.Fatal("wrong application path")
			}
			c.Close()
			if !released {
				t.Fatal("owner handle leaked")
			}
		}
		calls = nil
		r.owner = func(context.Context, string, netip.AddrPort, netip.AddrPort) (*systemAppOwner, error) {
			return nil, errSystemApp
		}
		if c, e = r.DialSource(context.Background(), "tcp4", source, destination); e == nil || c != nil || len(calls) != 0 {
			t.Fatal("unknown owner escaped")
		}
		if p.applicationDecision(routingDecision{Action: "block", Rule: "reserved"}, path).Action != "block" {
			t.Fatal("app bypassed BLOCK")
		}
		if action == "direct" && p.applicationDecision(routingDecision{Action: "vpn", Rule: "protected-management"}, path).Action != "vpn" {
			t.Fatal("management bypassed")
		}
		valid = false
	}
	p, _ := compileSystemPolicy(&systemPolicy{V: 1, Enabled: true}, nil)
	r := &systemFlowRouter{policy: p, leases: newFakeDNS(1), vpn: func(context.Context, string, string) (net.Conn, error) { a, b := net.Pipe(); b.Close(); return a, nil }, owner: func(context.Context, string, netip.AddrPort, netip.AddrPort) (*systemAppOwner, error) {
		t.Fatal("lookup without rules")
		return nil, errSystemApp
	}}
	if c, e := r.DialSource(context.Background(), "tcp4", source, destination); e != nil {
		t.Fatal(e)
	} else {
		c.Close()
	}
}

func TestSystemApplicationStaleDialAndUDPDelivery(t *testing.T) {
	path := `C:\Apps\Browser.exe`
	p, _ := compileSystemPolicy(&systemPolicy{V: 1, Enabled: true, AppRules: []systemAppRule{{Path: path, Action: "direct"}}}, nil)
	valid := true
	released := false
	owner := func(context.Context, string, netip.AddrPort, netip.AddrPort) (*systemAppOwner, error) {
		return &systemAppOwner{Path: path, check: func() error {
			if valid {
				return nil
			}
			return errSystemApp
		}, release: func() { released = true }}, nil
	}
	r := &systemFlowRouter{policy: p, leases: newFakeDNS(1), owner: owner, direct: func(context.Context, string, string) (net.Conn, error) {
		valid = false
		a, b := net.Pipe()
		b.Close()
		return a, nil
	}}
	if c, e := r.DialSource(context.Background(), "tcp4", netip.MustParseAddrPort("192.168.1.1:10000"), netip.MustParseAddrPort("1.1.1.1:443")); e == nil || c != nil || !released {
		t.Fatal("late stale owner committed")
	}
	a, b := net.Pipe()
	defer b.Close()
	o := &systemAppOwner{Path: path, check: func() error { return errors.New("reused endpoint") }}
	c := &systemAppConn{Conn: a, owner: o, udp: true}
	if n, e := c.Write([]byte("must not leave")); n != 0 || e == nil {
		t.Fatal("stale UDP sent")
	}
	a, b = net.Pipe()
	defer b.Close()
	c = &systemAppConn{Conn: a, owner: &systemAppOwner{Path: path, check: func() error { return errSystemApp }}, udp: true}
	go func() { b.Write([]byte("discard")) }()
	if n, e := c.Read(make([]byte, 32)); n != 0 || e == nil {
		t.Fatal("stale UDP delivered")
	}
}
