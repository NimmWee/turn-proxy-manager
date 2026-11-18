package main

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"golang.zx2c4.com/wireguard/windows/driver"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"io"
	"math/bits"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type socksOptions struct {
	Port     int            `json:"port"`
	User     string         `json:"user"`
	Password string         `json:"password"`
	Routing  *routingPolicy `json:"routing,omitempty"`
}
type socksDial func(context.Context, string) (net.Conn, error)

func serveSOCKS(ctx context.Context, c net.Conn, options socksOptions, dial socksDial) error {
	c.SetDeadline(time.Now().Add(10 * time.Second))
	var head [4]byte
	if _, e := io.ReadFull(c, head[:2]); e != nil || head[0] != 5 || head[1] == 0 {
		return errors.New("SOCKS_PROTOCOL")
	}
	methods := make([]byte, int(head[1]))
	if _, e := io.ReadFull(c, methods); e != nil {
		return e
	}
	supported := false
	for _, m := range methods {
		supported = supported || m == 2
	}
	if !supported {
		c.Write([]byte{5, 255})
		return errors.New("SOCKS_AUTH_REQUIRED")
	}
	if _, e := c.Write([]byte{5, 2}); e != nil {
		return e
	}
	if _, e := io.ReadFull(c, head[:2]); e != nil || head[0] != 1 || head[1] == 0 {
		return errors.New("SOCKS_AUTH")
	}
	user := make([]byte, int(head[1]))
	if _, e := io.ReadFull(c, user); e != nil {
		return e
	}
	if _, e := io.ReadFull(c, head[:1]); e != nil || head[0] == 0 {
		return errors.New("SOCKS_AUTH")
	}
	password := make([]byte, int(head[0]))
	if _, e := io.ReadFull(c, password); e != nil {
		return e
	}
	if subtle.ConstantTimeCompare(user, []byte(options.User))&subtle.ConstantTimeCompare(password, []byte(options.Password)) != 1 {
		c.Write([]byte{1, 1})
		return errors.New("SOCKS_AUTH")
	}
	if _, e := c.Write([]byte{1, 0}); e != nil {
		return e
	}
	reply := func(code byte) { c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0}) }
	if _, e := io.ReadFull(c, head[:]); e != nil || head[0] != 5 || head[2] != 0 {
		return errors.New("SOCKS_PROTOCOL")
	}
	if head[1] != 1 {
		reply(7)
		return errors.New("SOCKS_CONNECT_ONLY")
	}
	host := ""
	switch head[3] {
	case 1:
		var ip [4]byte
		if _, e := io.ReadFull(c, ip[:]); e != nil {
			return e
		}
		host = net.IP(ip[:]).String()
	case 3:
		if _, e := io.ReadFull(c, head[:1]); e != nil || head[0] == 0 {
			return errors.New("SOCKS_DOMAIN")
		}
		domain := make([]byte, int(head[0]))
		if _, e := io.ReadFull(c, domain); e != nil {
			return e
		}
		host = string(domain)
		if strings.ContainsAny(host, "\x00/\\\r\n") {
			reply(8)
			return errors.New("SOCKS_DOMAIN")
		}
	default:
		reply(8)
		return errors.New("SOCKS_IPV4_ONLY")
	}
	var port [2]byte
	if _, e := io.ReadFull(c, port[:]); e != nil {
		return e
	}
	number := binary.BigEndian.Uint16(port[:])
	if number == 0 {
		reply(8)
		return errors.New("SOCKS_PORT")
	}
	remote, e := dial(ctx, net.JoinHostPort(host, strconv.Itoa(int(number))))
	if e != nil {
		reply(4)
		return errors.New("SOCKS_DESTINATION")
	}
	defer remote.Close()
	reply(0)
	closed := make(chan struct{})
	defer close(closed)
	go func() {
		select {
		case <-ctx.Done():
			c.Close()
			remote.Close()
		case <-closed:
		}
	}()
	client := idleConn{c}
	target := idleConn{remote}
	done := make(chan error, 2)
	go func() {
		_, e := io.Copy(&target, &client)
		if tcp, ok := remote.(*net.TCPConn); ok {
			tcp.CloseWrite()
		} else if half, ok := remote.(interface{ CloseWrite() error }); ok {
			half.CloseWrite()
		}
		done <- e
	}()
	go func() {
		_, e := io.Copy(&client, &target)
		if tcp, ok := c.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
		done <- e
	}()
	if e := <-done; e != nil {
		c.Close()
		remote.Close()
	}
	<-done
	return nil
}

type idleConn struct{ net.Conn }

func (c *idleConn) Read(p []byte) (int, error) {
	c.SetReadDeadline(time.Now().Add(2 * time.Minute))
	return c.Conn.Read(p)
}
func (c *idleConn) Write(p []byte) (int, error) {
	c.SetWriteDeadline(time.Now().Add(2 * time.Minute))
	return c.Conn.Write(p)
}

type socksServer struct {
	listener net.Listener
	cancel   context.CancelFunc
	mu       sync.Mutex
	clients  map[net.Conn]bool
	closed   bool
	port     int
}

func startSOCKS(options socksOptions, dial socksDial) (*socksServer, error) {
	if _, e := compileRouting(options.Routing); e != nil {
		return nil, e
	}
	if options.Port < 1024 || options.Port > 65535 || options.Port == 8765 || len(options.User) < 1 || len(options.User) > 255 || len(options.Password) < 12 || len(options.Password) > 255 {
		return nil, errors.New("SOCKS_OPTIONS_INVALID")
	}
	listener, e := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(options.Port)))
	if e != nil {
		return nil, errors.New("SOCKS_LISTENER_FAILED")
	}
	ctx, cancel := context.WithCancel(context.Background())
	server := &socksServer{listener: listener, cancel: cancel, clients: map[net.Conn]bool{}, port: options.Port}
	go func() {
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			server.mu.Lock()
			if server.closed || len(server.clients) >= 32 {
				server.mu.Unlock()
				c.Close()
				continue
			}
			server.clients[c] = true
			server.mu.Unlock()
			go func() {
				defer c.Close()
				defer func() { server.mu.Lock(); delete(server.clients, c); server.mu.Unlock() }()
				serveSOCKS(ctx, c, options, dial)
			}()
		}
	}()
	return server, nil
}
func (s *socksServer) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	s.cancel()
	s.listener.Close()
	for c := range s.clients {
		c.Close()
	}
}
func publicIPv4(ip netip.Addr) bool {
	if !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, blocked := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "168.63.129.16/32"} {
		if netip.MustParsePrefix(blocked).Contains(ip) {
			return false
		}
	}
	return true
}

// Bind BOTH the source address and interface LUID. A missing/replaced adapter
// cannot silently send SOCKS or DNS traffic over the physical internet path.
func tunnelSOCKSDial(p *profile) (socksDial, error) {
	if p.WG == "" {
		return nil, errors.New("SOCKS_REQUIRES_WG")
	}
	wg, _, e := memoryWGConfig(p.WG)
	if e != nil {
		return nil, errProfile
	}
	var source, dns netip.Addr
	for _, a := range wg.Interface.Addresses {
		if a.Addr().Is4() {
			source = a.Addr()
			break
		}
	}
	for _, a := range wg.Interface.DNS {
		if a.Is4() {
			dns = a
			break
		}
	}
	if !source.IsValid() || !dns.IsValid() {
		return nil, errors.New("SOCKS_IPV4_REQUIRED")
	}
	adapter, e := driver.OpenAdapter("FTM")
	if e != nil {
		return nil, errors.New("SOCKS_ADAPTER_REQUIRED")
	}
	luid := adapter.LUID()
	adapter.Close()
	row, e := luid.Interface()
	if e != nil {
		return nil, e
	}
	index := row.InterfaceIndex
	return interfaceSOCKSDial(luid, index, source, dns), nil
}

// The physical path is selected once per listener and never falls back to a
// system resolver/default dialer. Missing addresses/interfaces require restart.
func physicalSOCKSDialForIndex(index uint32) (socksDial, error) {
	adapters, e := winipcfg.GetAdaptersAddresses(2, 0)
	if e != nil {
		return nil, e
	}
	for _, a := range adapters {
		if a.IfIndex != index {
			continue
		}
		row, e := a.LUID.Interface()
		if e != nil || row.OperStatus != winipcfg.IfOperStatusUp || row.InterfaceAndOperStatusFlags&winipcfg.IAOSFHardwareInterface == 0 {
			return nil, errors.New("SOCKS_PHYSICAL_REQUIRED")
		}
		var source, dns netip.Addr
		for address := a.FirstUnicastAddress; address != nil; address = address.Next {
			if address.DadState != 4 {
				continue
			}
			ip, ok := netip.AddrFromSlice(address.Address.IP())
			if ok {
				ip = ip.Unmap()
				if ip.Is4() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
					source = ip
					break
				}
			}
		}
		for address := a.FirstDNSServerAddress; address != nil; address = address.Next {
			ip, ok := netip.AddrFromSlice(address.Address.IP())
			if ok {
				ip = ip.Unmap()
				if ip.Is4() && ip.IsGlobalUnicast() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
					dns = ip
					break
				}
			}
		}
		if !source.IsValid() || !dns.IsValid() {
			return nil, errors.New("SOCKS_PHYSICAL_DNS_REQUIRED")
		}
		return interfaceSOCKSDial(a.LUID, a.IfIndex, source, dns), nil
	}
	return nil, errors.New("SOCKS_PHYSICAL_REQUIRED")
}

func interfaceSOCKSDial(luid winipcfg.LUID, index uint32, source, dns netip.Addr) socksDial {
	control := func(_, _ string, raw syscall.RawConn) error {
		current, e := winipcfg.LUIDFromIndex(index)
		if e != nil || current != luid {
			return errors.New("SOCKS_ADAPTER_CHANGED")
		}
		if _, e = luid.IPAddress(source); e != nil {
			return errors.New("SOCKS_ADDRESS_REMOVED")
		}
		row, e := luid.Interface()
		if e != nil || row.OperStatus != winipcfg.IfOperStatusUp {
			return errors.New("SOCKS_ADAPTER_DOWN")
		}
		var inner error
		e = raw.Control(func(fd uintptr) {
			inner = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, 31, int(bits.ReverseBytes32(index)))
		})
		if e != nil {
			return e
		}
		return inner
	}
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		d := net.Dialer{Timeout: 5 * time.Second, Control: control}
		if strings.HasPrefix(network, "tcp") {
			d.LocalAddr = &net.TCPAddr{IP: net.IP(source.AsSlice())}
		} else {
			d.LocalAddr = &net.UDPAddr{IP: net.IP(source.AsSlice())}
		}
		return d.DialContext(ctx, network, net.JoinHostPort(dns.String(), "53"))
	}}
	return func(parent context.Context, address string) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(parent, 10*time.Second)
		defer cancel()
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, e
		}
		var addresses []netip.Addr
		if literal, e := netip.ParseAddr(host); e == nil {
			addresses = []netip.Addr{literal}
		} else {
			resolved, e := resolver.LookupIP(ctx, "ip4", host+".") // Absolute name: never append the system DNS search suffix.
			if e != nil {
				return nil, e
			}
			for _, ip := range resolved {
				if parsed, ok := netip.AddrFromSlice(ip); ok {
					addresses = append(addresses, parsed.Unmap())
				}
			}
		}
		for _, ip := range addresses {
			if !publicIPv4(ip) {
				continue
			}
			d := net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.IP(source.AsSlice())}, Control: control}
			if c, e := d.DialContext(ctx, "tcp4", net.JoinHostPort(ip.String(), port)); e == nil {
				return c, nil
			}
		}
		return nil, errors.New("SOCKS_DESTINATION_BLOCKED")
	}
}
