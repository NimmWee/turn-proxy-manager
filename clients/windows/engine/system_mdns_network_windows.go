package main

import (
	"context"
	"math/bits"
	"net"
	"net/netip"
	"syscall"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func systemMDNSCurrent(luid winipcfg.LUID, link systemMDNSLink) error {
	if !link.valid() {
		return errSystemMDNS
	}
	current, e := winipcfg.LUIDFromIndex(link.Index)
	if e != nil || current != luid {
		return errSystemMDNS
	}
	address, e := luid.IPAddress(link.Source)
	if e != nil || address.DadState != 4 || int(address.OnLinkPrefixLength) != link.Prefix.Bits() {
		return errSystemMDNS
	}
	row, e := luid.Interface()
	if e != nil || row.OperStatus != winipcfg.IfOperStatusUp || row.InterfaceAndOperStatusFlags&winipcfg.IAOSFHardwareInterface == 0 {
		return errSystemMDNS
	}
	return nil
}

func openSystemMDNS(parent context.Context, luid winipcfg.LUID, link systemMDNSLink) (systemMDNSPacketConn, error) {
	if requireSystem() != nil || parent.Err() != nil || systemMDNSCurrent(luid, link) != nil {
		return nil, errSystemMDNS
	}
	config := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		if systemMDNSCurrent(luid, link) != nil {
			return errSystemMDNS
		}
		var result error
		e := raw.Control(func(fd uintptr) {
			socket := syscall.Handle(fd)
			if result = syscall.SetsockoptInt(socket, syscall.IPPROTO_IP, 31, int(bits.ReverseBytes32(link.Index))); result != nil {
				return
			}
			if result = syscall.SetsockoptInet4Addr(socket, syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, link.Source.As4()); result != nil {
				return
			}
			if result = syscall.SetsockoptInt(socket, syscall.IPPROTO_IP, syscall.IP_MULTICAST_TTL, 255); result != nil {
				return
			}
			result = syscall.SetsockoptInt(socket, syscall.IPPROTO_IP, 19, 1) // IP_PKTINFO
		})
		if e != nil {
			return e
		}
		return result
	}}
	packet, e := config.ListenPacket(parent, "udp4", netip.AddrPortFrom(link.Source, 0).String())
	if e != nil {
		return nil, errSystemMDNS
	}
	c, ok := packet.(*net.UDPConn)
	if !ok {
		packet.Close()
		return nil, errSystemMDNS
	}
	local, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok || local.Port == 5353 {
		c.Close()
		return nil, errSystemMDNS
	}
	return c, nil
}
