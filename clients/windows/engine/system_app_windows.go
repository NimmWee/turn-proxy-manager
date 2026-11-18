package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

type systemAppRule struct {
	Path   string `json:"path"`
	Action string `json:"action"`
}

func (systemAppRule) String() string { return "Application rule (path omitted)" }

var errSystemApp = errors.New("SYSTEM_APP_OWNER_UNKNOWN")

func systemAppPath(raw string) (string, error) {
	if len(raw) < 7 || len(raw) > 1024 || !utf8.ValidString(raw) || raw[1] != ':' || raw[2] != '\\' || !(raw[0] >= 'A' && raw[0] <= 'Z' || raw[0] >= 'a' && raw[0] <= 'z') || !strings.EqualFold(filepath.Ext(raw), ".exe") || filepath.Clean(raw) != raw {
		return "", errSystemRouting
	}
	if strings.ContainsAny(raw[2:], "\x00\r\n\t/:*?\"<>|%") {
		return "", errSystemRouting
	}
	for _, c := range raw {
		if unicode.IsControl(c) {
			return "", errSystemRouting
		}
	}
	for _, part := range strings.Split(raw[3:], `\`) {
		if part == "" || part == "." || part == ".." || strings.TrimSpace(part) != part || strings.HasSuffix(part, ".") {
			return "", errSystemRouting
		}
	}
	return raw, nil
}
func (p *compiledSystemPolicy) appAction(path string) string { return p.apps[strings.ToLower(path)] }
func (p *compiledSystemPolicy) applicationDecision(base routingDecision, path string) routingDecision {
	if !p.Enabled || base.Action == "block" {
		return base
	}
	action := p.appAction(path)
	if action == "block" {
		return routingDecision{Action: "block", Rule: "application"}
	}
	if base.Rule == "protected-management" || action == "" {
		return base
	}
	return routingDecision{Action: action, Rule: "application"}
}

// The process handle stays held for the lifetime of the attributed connection.
type systemAppOwner struct {
	Path    string
	check   func() error
	release func()
	mu      sync.Mutex
	closed  bool
}

func (o *systemAppOwner) String() string { return "Application owner (private identity omitted)" }
func (o *systemAppOwner) Current() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.check == nil {
		return errSystemApp
	}
	return o.check()
}
func (o *systemAppOwner) Close() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.closed {
		o.closed = true
		if o.release != nil {
			o.release()
		}
	}
}

type systemAppLookup func(context.Context, string, netip.AddrPort, netip.AddrPort) (*systemAppOwner, error)

type systemAppConn struct {
	net.Conn
	owner  *systemAppOwner
	udp    bool
	failed func()
	once   sync.Once
}

func (c *systemAppConn) invalid() error {
	if e := c.owner.Current(); e != nil {
		c.once.Do(func() {
			if c.failed != nil {
				c.failed()
			}
		})
		c.Close()
		return errSystemApp
	}
	return nil
}
func (c *systemAppConn) Write(b []byte) (int, error) {
	if c.udp {
		if e := c.invalid(); e != nil {
			return 0, e
		}
	}
	return c.Conn.Write(b)
}
func (c *systemAppConn) Read(b []byte) (int, error) {
	n, e := c.Conn.Read(b)
	if c.udp && n > 0 {
		if fault := c.invalid(); fault != nil {
			return 0, fault
		}
	}
	return n, e
}
func (c *systemAppConn) Close() error { e := c.Conn.Close(); c.owner.Close(); return e }
func (c *systemAppConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return c.Close()
}

func (r *systemFlowRouter) DialSource(ctx context.Context, network string, source, destination netip.AddrPort) (net.Conn, error) {
	if !r.policy.Enabled || len(r.policy.apps) == 0 {
		return r.Dial(ctx, network, destination)
	}
	unknown := func() { r.counters.Blocked.Add(1); r.counters.UnknownApp.Add(1) }
	if r.owner == nil || ctx.Err() != nil || !source.IsValid() || !source.Addr().Is4() || source.Port() == 0 {
		unknown()
		return nil, errSystemApp
	}
	o, e := r.owner(ctx, network, source, destination)
	if e != nil || o == nil {
		if o != nil {
			o.Close()
		}
		unknown()
		return nil, errSystemApp
	}
	if _, e = systemAppPath(o.Path); e != nil || o.Current() != nil {
		o.Close()
		unknown()
		return nil, errSystemApp
	}
	c, e := r.dial(ctx, network, destination, o)
	if e != nil {
		o.Close()
		return nil, e
	}
	return &systemAppConn{Conn: c, owner: o, udp: network == "udp4", failed: unknown}, nil
}
