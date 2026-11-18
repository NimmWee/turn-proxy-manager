package main

import (
	"errors"
	"math/bits"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

type protector struct{ v4, v6 uint32 }

// Read-only selection. Only up physical interfaces with a default route count;
// reject another active default-route VPN instead of silently nesting tunnels.
func selectUnderlay() (*protector, error) {
	p := &protector{}
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		routes, e := winipcfg.GetIPForwardTable2(family)
		if e != nil {
			return nil, e
		}
		best := uint64(^uint64(0))
		var index uint32
		physical := false
		for _, r := range routes {
			if r.DestinationPrefix.PrefixLength != 0 || r.Loopback {
				continue
			}
			i, e := r.InterfaceLUID.Interface()
			if e != nil || i.OperStatus != winipcfg.IfOperStatusUp {
				continue
			}
			f, e := r.InterfaceLUID.IPInterface(family)
			if e != nil {
				continue
			}
			metric := uint64(r.Metric) + uint64(f.Metric)
			if metric < best {
				best = metric
				index = r.InterfaceIndex
				physical = i.InterfaceAndOperStatusFlags&winipcfg.IAOSFHardwareInterface != 0
			}
		}
		if index != 0 && !physical {
			return nil, errors.New("OTHER_VPN_OR_NONPHYSICAL_UPLINK")
		}
		if family == windows.AF_INET {
			p.v4 = index
		} else {
			p.v6 = index
		}
	}
	if p.v4 == 0 {
		return nil, errors.New("NO_IPV4_PHYSICAL_UPLINK")
	}
	return p, nil
}

func (p *protector) Protect(fd int) bool {
	h := syscall.Handle(fd)
	// Go invokes Control before bind/connect. Winsock getsockname returns
	// WSAEINVAL for that valid unbound socket; query its protocol instead.
	const soProtocolInfoW = 0x2005
	var info windows.WSAProtocolInfo
	size := int32(unsafe.Sizeof(info))
	if windows.Getsockopt(windows.Handle(fd), windows.SOL_SOCKET, soProtocolInfoW, (*byte)(unsafe.Pointer(&info)), &size) != nil || size != int32(unsafe.Sizeof(info)) {
		return false
	}
	switch info.AddressFamily {
	case windows.AF_INET:
		// Windows IP_UNICAST_IF expects the IPv4 index in network byte order.
		return p.v4 != 0 && syscall.SetsockoptInt(h, syscall.IPPROTO_IP, 31, int(bits.ReverseBytes32(p.v4))) == nil
	case windows.AF_INET6:
		return p.v6 != 0 && syscall.SetsockoptInt(h, syscall.IPPROTO_IPV6, 31, int(p.v6)) == nil
	}
	return false
}
