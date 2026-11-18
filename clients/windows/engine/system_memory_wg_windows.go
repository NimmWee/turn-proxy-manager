package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	awgconn "github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// WireGuard's encrypted side is loopback-only: FreeTurn owns all external
// transport. This cannot emit WG packets directly to a profile-supplied host.
type loopbackWGBind struct {
	mu     sync.Mutex
	socket *net.UDPConn
	port   uint16
}

func (b *loopbackWGBind) Open(port uint16) ([]awgconn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.socket != nil {
		return nil, 0, awgconn.ErrBindAlreadyOpen
	}
	c, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if e != nil {
		return nil, 0, e
	}
	b.socket = c
	b.port = uint16(c.LocalAddr().(*net.UDPAddr).Port)
	receive := func(buffers [][]byte, sizes []int, endpoints []awgconn.Endpoint) (int, error) {
		n, addr, e := c.ReadFromUDPAddrPort(buffers[0])
		if e != nil {
			return 0, e
		}
		if !addr.Addr().IsLoopback() {
			return 0, errors.New("WG_LOOPBACK_REQUIRED")
		}
		sizes[0] = n
		endpoints[0] = &awgconn.StdNetEndpoint{AddrPort: addr}
		return 1, nil
	}
	return []awgconn.ReceiveFunc{receive}, b.port, nil
}
func (b *loopbackWGBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.socket == nil {
		return nil
	}
	e := b.socket.Close()
	b.socket = nil
	return e
}
func (*loopbackWGBind) SetMark(uint32) error { return nil }
func (*loopbackWGBind) BatchSize() int       { return 1 }
func (*loopbackWGBind) ParseEndpoint(raw string) (awgconn.Endpoint, error) {
	addr, e := netip.ParseAddrPort(raw)
	if e != nil || !addr.Addr().Is4() || !addr.Addr().IsLoopback() || addr.Port() == 0 {
		return nil, errors.New("WG_LOOPBACK_REQUIRED")
	}
	return &awgconn.StdNetEndpoint{AddrPort: addr}, nil
}
func (b *loopbackWGBind) Send(buffers [][]byte, endpoint awgconn.Endpoint) error {
	ep, ok := endpoint.(*awgconn.StdNetEndpoint)
	if !ok || !ep.Addr().IsLoopback() {
		return errors.New("WG_LOOPBACK_REQUIRED")
	}
	b.mu.Lock()
	c := b.socket
	b.mu.Unlock()
	if c == nil {
		return net.ErrClosed
	}
	for _, payload := range buffers {
		if _, e := c.WriteToUDPAddrPort(payload, ep.AddrPort); e != nil {
			return e
		}
	}
	return nil
}

type memoryWG struct {
	Net    *netstack.Net
	device *device.Device
	bind   *loopbackWGBind
}

func startMemoryWG(raw string) (*memoryWG, error) {
	config, extensions, e := memoryWGConfig(raw)
	if e != nil || len(config.Peers) != 1 {
		return nil, errors.New("WG_MEMORY_CONFIG_INVALID")
	}
	var addresses []netip.Addr
	for _, prefix := range config.Interface.Addresses {
		if prefix.Addr().Is4() {
			addresses = append(addresses, prefix.Addr())
		}
	}
	if len(addresses) != 1 {
		return nil, errors.New("WG_MEMORY_IPV4_REQUIRED")
	}
	mtu := int(config.Interface.MTU)
	if mtu == 0 {
		mtu = 1280
	}
	if mtu < 1280 || mtu > 9000 {
		return nil, errors.New("WG_MEMORY_CONFIG_INVALID")
	}
	var dns []netip.Addr
	for _, ip := range config.Interface.DNS {
		if ip.Is4() {
			dns = append(dns, ip)
		}
	}
	tun, network, e := netstack.CreateNetTUN(addresses, dns, mtu)
	if e != nil {
		return nil, errors.New("WG_MEMORY_START_FAILED")
	}
	bind := &loopbackWGBind{}
	dev := device.NewDevice(tun, bind, device.NewLogger(device.LogLevelSilent, ""))
	peer := config.Peers[0]
	var ipc strings.Builder
	fmt.Fprintf(&ipc, "private_key=%s\nlisten_port=0\n", hex.EncodeToString(config.Interface.PrivateKey[:]))
	ipc.WriteString(extensions) // Device settings must precede the first peer.
	fmt.Fprintf(&ipc, "replace_peers=true\npublic_key=%s\npreshared_key=%s\n", hex.EncodeToString(peer.PublicKey[:]), hex.EncodeToString(peer.PresharedKey[:]))
	if !peer.Endpoint.IsEmpty() {
		if peer.Endpoint.Host != "127.0.0.1" || peer.Endpoint.Port == 0 {
			dev.Close()
			return nil, errors.New("WG_LOOPBACK_REQUIRED")
		}
		fmt.Fprintf(&ipc, "endpoint=127.0.0.1:%d\n", peer.Endpoint.Port)
	}
	fmt.Fprintf(&ipc, "persistent_keepalive_interval=%d\nreplace_allowed_ips=true\n", peer.PersistentKeepalive)
	for _, prefix := range peer.AllowedIPs {
		fmt.Fprintf(&ipc, "allowed_ip=%s\n", prefix.String())
	}
	// Never include config, keys, IPC text or raw parser errors in a failure.
	if dev.IpcSet(ipc.String()) != nil {
		dev.Close()
		return nil, errors.New("WG_MEMORY_CONFIG_INVALID")
	}
	if dev.Up() != nil {
		dev.Close()
		return nil, errors.New("WG_MEMORY_START_FAILED")
	}
	return &memoryWG{network, dev, bind}, nil
}
func (w *memoryWG) Close() { w.device.Close() }

type systemWGHealth struct {
	Handshake bool   `json:"handshake"`
	Rx        uint64 `json:"rx"`
	Tx        uint64 `json:"tx"`
}

// IpcGet contains private configuration too. Only these numeric counters leave
// this function; neither raw output nor parser errors are journaled/returned.
func (w *memoryWG) Health() systemWGHealth {
	data, e := w.device.IpcGet()
	if e != nil {
		return systemWGHealth{}
	}
	var result systemWGHealth
	var seconds, nanos uint64
	peers := 0
	for _, line := range strings.Split(data, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if key == "public_key" {
			peers++
			continue
		}
		if key != "rx_bytes" && key != "tx_bytes" && key != "last_handshake_time_sec" && key != "last_handshake_time_nsec" {
			continue
		}
		n, e := strconv.ParseUint(value, 10, 64)
		if e != nil {
			return systemWGHealth{}
		}
		switch key {
		case "rx_bytes":
			result.Rx = n
		case "tx_bytes":
			result.Tx = n
		case "last_handshake_time_sec":
			seconds = n
		case "last_handshake_time_nsec":
			nanos = n
		}
	}
	if peers != 1 || seconds > uint64(time.Now().Unix()) || nanos >= 1_000_000_000 {
		return systemWGHealth{}
	}
	age := time.Since(time.Unix(int64(seconds), int64(nanos)))
	result.Handshake = seconds != 0 && age >= 0 && age < 3*time.Minute
	return result
}
