package main

import (
	"context"
	"errors"
	"math/bits"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// Numeric addresses only. Domain resolution is exclusively the policy DNS layer.
// Check LUID, preferred source address and link before every socket, including UDP.
func boundSystemDial(luid winipcfg.LUID, index uint32, source netip.Addr) systemDial {
	return func(parent context.Context, network, address string) (net.Conn, error) {
		destination, e := netip.ParseAddrPort(address)
		if e != nil || !destination.Addr().Is4() || destination.Port() == 0 || !source.Is4() || source.IsLoopback() || (network != "tcp4" && network != "udp4") {
			return nil, errSystemRouting
		}
		control := func(_, _ string, raw syscall.RawConn) error {
			current, e := winipcfg.LUIDFromIndex(index)
			if e != nil || current != luid {
				return errors.New("SYSTEM_UPLINK_CHANGED")
			}
			address, e := luid.IPAddress(source)
			if e != nil || address.DadState != 4 {
				return errors.New("SYSTEM_UPLINK_ADDRESS_REMOVED")
			}
			row, e := luid.Interface()
			if e != nil || row.OperStatus != winipcfg.IfOperStatusUp || row.InterfaceAndOperStatusFlags&winipcfg.IAOSFHardwareInterface == 0 {
				return errors.New("SYSTEM_UPLINK_DOWN")
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
		d := net.Dialer{Timeout: 5 * time.Second, Control: control}
		if network == "tcp4" {
			d.LocalAddr = &net.TCPAddr{IP: net.IP(source.AsSlice())}
		} else {
			d.LocalAddr = &net.UDPAddr{IP: net.IP(source.AsSlice())}
		}
		c, e := d.DialContext(parent, network, destination.String())
		if e != nil {
			return nil, errors.New("SYSTEM_DIRECT_DIAL_FAILED")
		}
		return c, nil
	}
}

func memorySystemDial(w *memoryWG) systemDial {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		dst, e := netip.ParseAddrPort(address)
		if e != nil || !dst.Addr().Is4() || dst.Port() == 0 || (network != "tcp4" && network != "udp4") {
			return nil, errSystemRouting
		}
		c, e := w.Net.DialContext(ctx, network, address)
		if e != nil {
			return nil, errors.New("SYSTEM_VPN_DIAL_FAILED")
		}
		return c, nil
	}
}

// Retry a truncated UDP answer over TCP on the SAME selected path/server.
// Never consult net.DefaultResolver or switch VPN/DIRECT after a failure.
func newSystemDNSExchange(direct, vpn systemDial, directServers, vpnServers []netip.AddrPort) systemDNSExchange {
	directServers = append([]netip.AddrPort(nil), directServers...)
	vpnServers = append([]netip.AddrPort(nil), vpnServers...)
	return func(parent context.Context, decision routingDecision, q *dns.Msg) (*dns.Msg, error) {
		dial, servers := vpn, vpnServers
		if decision.Action == "direct" {
			dial, servers = direct, directServers
		} else if decision.Action != "vpn" {
			return nil, errSystemRouting
		}
		if dial == nil || len(servers) == 0 || len(servers) > 4 {
			return nil, errors.New("SYSTEM_DNS_PATH_UNAVAILABLE")
		}
		for _, server := range servers {
			if !server.IsValid() || !server.Addr().Is4() || server.Port() != 53 || server.Addr().IsLoopback() || server.Addr().IsLinkLocalUnicast() || !server.Addr().IsGlobalUnicast() {
				return nil, errors.New("SYSTEM_DNS_SERVER_INVALID")
			}
			for _, network := range []string{"udp4", "tcp4"} {
				ctx, cancel := context.WithTimeout(parent, 2*time.Second)
				c, e := dial(ctx, network, server.String())
				if e != nil {
					cancel()
					break
				}
				deadline, _ := ctx.Deadline()
				c.SetDeadline(deadline)
				stop := context.AfterFunc(ctx, func() { c.Close() })
				dc := &dns.Conn{Conn: c, UDPSize: 4096}
				var r *dns.Msg
				if dc.WriteMsg(q) == nil {
					r, e = dc.ReadMsg()
				} else {
					e = errors.New("DNS_WRITE_FAILED")
				}
				stop()
				c.Close()
				cancel()
				if e != nil {
					break
				}
				if r != nil && r.Truncated && network == "udp4" {
					continue
				}
				if !validSystemDNSResponse(q, r) {
					break
				}
				return r, nil
			}
		}
		return nil, errors.New("SYSTEM_DNS_PATH_FAILED")
	}
}
