package main

import (
	"golang.org/x/sys/windows"
	"net"
	"syscall"
	"testing"
)

// Control runs before bind/connect. Exercise real Winsock without sending data,
// changing routes, starting a VPN or relying on an external server.
func TestProtectUnboundWindowsSockets(t *testing.T) {
	var data windows.WSAData
	if err := windows.WSAStartup(0x202, &data); err != nil {
		t.Fatal(err)
	}
	defer windows.WSACleanup()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var index uint32
	for _, i := range interfaces {
		if i.Flags&net.FlagLoopback != 0 {
			index = uint32(i.Index)
			break
		}
	}
	if index == 0 {
		t.Fatal("loopback interface missing")
	}
	p := protector{v4: index, v6: index}
	for _, test := range []struct {
		name                                    string
		family, kind, protocol, level, expected int
	}{
		{"tcp4", syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP, syscall.IPPROTO_IP, int(index)},
		{"udp4", syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP, syscall.IPPROTO_IP, int(index)},
		{"tcp6", syscall.AF_INET6, syscall.SOCK_STREAM, syscall.IPPROTO_TCP, syscall.IPPROTO_IPV6, int(index)},
		{"udp6", syscall.AF_INET6, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP, syscall.IPPROTO_IPV6, int(index)},
	} {
		t.Run(test.name, func(t *testing.T) {
			fd, e := syscall.Socket(test.family, test.kind, test.protocol)
			if e != nil {
				t.Fatal(e)
			}
			defer syscall.Closesocket(fd)
			_, before := syscall.Getsockname(fd)
			t.Logf("unbound Getsockname: %v", before)
			if !p.Protect(int(fd)) {
				t.Fatal("protect rejected a valid unbound Windows socket")
			}
			actual, e := syscall.GetsockoptInt(fd, test.level, 31)
			if e != nil || uint32(actual) != uint32(test.expected) {
				t.Fatal("underlay interface was not assigned", e)
			}
			if (&protector{}).Protect(int(fd)) {
				t.Fatal("missing underlay must fail closed")
			}
		})
	}
	if p.Protect(-1) {
		t.Fatal("invalid socket accepted")
	}
}
