package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// This adapter has no OS/network setup side effects. The lifecycle owner must
// supply a TUN, restricted firewall, explicit dial paths and immutable policy.
type systemHandler struct {
	ctx            context.Context
	cancel         context.CancelFunc
	router         *systemFlowRouter
	dns            *systemDNS
	mu             sync.Mutex
	closed         bool
	wg             sync.WaitGroup
	flows, queries chan struct{}
}

var _ tun.Handler = (*systemHandler)(nil)
var errSystemBitTorrent = errors.New("SYSTEM_BITTORRENT_BLOCKED")

func newSystemHandler(parent context.Context, router *systemFlowRouter, dns *systemDNS) *systemHandler {
	ctx, cancel := context.WithCancel(parent)
	h := &systemHandler{ctx: ctx, cancel: cancel, router: router, dns: dns, flows: make(chan struct{}, 2048), queries: make(chan struct{}, 128)}
	if dns != nil {
		router.refresh = h.refreshDNS
	}
	return h
}

func (h *systemHandler) refreshDNS(ctx context.Context, host string) error {
	if !h.acquire(h.queries) {
		return errors.New("SYSTEM_DNS_BUSY")
	}
	defer h.release(h.queries)
	q := new(dns.Msg)
	q.SetQuestion(host+".", dns.TypeA)
	wire, e := q.Pack()
	if e != nil {
		return errSystemRouting
	}
	answer, e := h.answerDNS(ctx, wire)
	if e != nil {
		return e
	}
	r := new(dns.Msg)
	if r.Unpack(answer) != nil || r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
		return errors.New("DNS_LEASE_REFRESH_FAILED")
	}
	return nil
}
func (h *systemHandler) acquire(slots chan struct{}) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.ctx.Err() != nil {
		return false
	}
	select {
	case slots <- struct{}{}:
		h.wg.Add(1)
		return true
	default:
		return false
	}
}
func (h *systemHandler) release(slots chan struct{}) { <-slots; h.wg.Done() }
func (h *systemHandler) Close() {
	h.mu.Lock()
	h.closed = true
	h.cancel()
	h.mu.Unlock()
	h.wg.Wait()
}
func (h *systemHandler) flowContext(parent context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(h.ctx, cancel)
	if h.ctx.Err() != nil {
		cancel()
	}
	return ctx, func() { stop(); cancel() }
}
func (h *systemHandler) JudgeFlow(network uint8, source, destination netip.AddrPort, first []byte) tun.FlowVerdict {
	reject := tun.FlowVerdict{Action: tun.ActionReject}
	if h.ctx.Err() != nil || !source.Addr().Is4() || !destination.IsValid() || !destination.Addr().Is4() || destination.Port() == 0 || (network != 6 && network != 17) {
		return reject
	}
	// All ordinary port-53 queries are answered here, even when an application
	// names another resolver. No arbitrary original DNS destination is dialed.
	if destination.Port() == 53 {
		if network == 17 {
			return tun.FlowVerdict{Action: tun.ActionHijackDNS}
		}
		return tun.FlowVerdict{Action: tun.ActionAccept}
	}
	if h.router.policy.Presets.BlockBitTorrent && isKnownBitTorrent(first) {
		h.router.counters.Blocked.Add(1)
		return reject
	}
	if network == 6 {
		if lease, ok := h.router.leases.Lookup(destination.Addr()); ok && lease.Host == "" {
			// Handler must authenticate a bounded ClientHello/Host before Dial.
			return tun.FlowVerdict{Action: tun.ActionAccept}
		}
	}
	protocol := "tcp4"
	if network == 17 {
		protocol = "udp4"
	}
	if _, _, e := h.router.targets(destination, protocol); e != nil {
		return reject
	}
	return tun.FlowVerdict{Action: tun.ActionAccept}
}
func (h *systemHandler) answerDNS(ctx context.Context, payload []byte) ([]byte, error) {
	h.router.counters.DNSQueries.Add(1)
	answer, e := h.dns.Answer(ctx, payload)
	if e != nil {
		h.router.counters.DNSErrors.Add(1)
	} else {
		response := new(dns.Msg)
		if response.Unpack(answer) != nil || response.Rcode != dns.RcodeSuccess {
			h.router.counters.DNSErrors.Add(1)
		}
	}
	return answer, e
}
func (h *systemHandler) NewDNSPacket(payload []byte, source, destination M.Socksaddr, writer N.PacketWriter) {
	if destination.Port != 53 || !destination.IsIPv4() || len(payload) > 4096 || !h.acquire(h.queries) {
		return
	}
	copyPayload := append([]byte(nil), payload...)
	go func() {
		defer h.release(h.queries)
		answer, e := h.answerDNS(h.ctx, copyPayload)
		if e != nil || h.ctx.Err() != nil {
			return
		}
		b := buf.NewSize(len(answer))
		b.Write(answer)
		// PacketWriter owns and releases b, including its error path.
		_ = writer.WritePacket(b, destination)
	}()
}
func (h *systemHandler) NewConnectionEx(parent context.Context, c net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer c.Close()
	if onClose != nil {
		defer onClose(nil)
	}
	if !destination.IsIPv4() || !h.acquire(h.flows) {
		return
	}
	defer h.release(h.flows)
	ctx, cancel := h.flowContext(parent)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if destination.Port == 53 {
		h.serveTCPDNS(ctx, c)
		return
	}
	if lease, ok := h.router.leases.Lookup(destination.Addr); ok && lease.Host == "" {
		replayed, e := recoverSystemIdentity(c, h.router.leases, destination.Addr)
		if e != nil {
			h.router.counters.Blocked.Add(1)
			return
		}
		c = replayed
	}
	dialCtx, done := context.WithTimeout(ctx, 8*time.Second)
	remote, e := h.router.DialSource(dialCtx, "tcp4", source.AddrPort(), destination.AddrPort())
	done()
	if e != nil {
		return
	}
	defer remote.Close()
	stopRemote := context.AfterFunc(ctx, func() { remote.Close() })
	defer stopRemote()
	finished := make(chan struct{}, 1)
	go func() { io.Copy(c, remote); systemCloseWrite(c); finished <- struct{}{} }()
	e = copySystemTCP(remote, c, h.router.policy.Presets.BlockBitTorrent)
	if errors.Is(e, errSystemBitTorrent) {
		h.router.counters.Blocked.Add(1)
	}
	if e != nil {
		remote.Close()
		c.Close()
	} else {
		systemCloseWrite(remote)
	}
	<-finished
}
func systemCloseWrite(c net.Conn) {
	if half, ok := c.(interface{ CloseWrite() error }); ok {
		half.CloseWrite()
	} else {
		c.Close()
	}
}

// Only hold a possible plaintext BitTorrent prefix. Ordinary TLS/HTTP payloads
// go through immediately; no blanket sniffing delay on every connection.
func copySystemTCP(dst, src net.Conn, block bool) error {
	if !block {
		_, e := io.Copy(dst, src)
		return e
	}
	payload := make([]byte, 32768)
	n, e := src.Read(payload)
	if n == 0 {
		return e
	}
	if payload[0] == 19 && n < 20 {
		src.SetReadDeadline(time.Now().Add(2 * time.Second))
		extra, readErr := io.ReadFull(src, payload[n:20])
		n += extra
		src.SetReadDeadline(time.Time{})
		if readErr != nil {
			return errors.New("SYSTEM_PREFIX_INCOMPLETE")
		}
	}
	if isKnownBitTorrent(payload[:n]) {
		return errSystemBitTorrent
	}
	if _, err := dst.Write(payload[:n]); err != nil {
		return err
	}
	if e != nil {
		if e == io.EOF {
			return nil
		}
		return e
	}
	_, e = io.Copy(dst, src)
	return e
}
func (h *systemHandler) serveTCPDNS(ctx context.Context, c net.Conn) {
	for count := 0; count < 64 && ctx.Err() == nil; count++ {
		c.SetDeadline(time.Now().Add(10 * time.Second))
		var header [2]byte
		if _, e := io.ReadFull(c, header[:]); e != nil {
			return
		}
		size := int(binary.BigEndian.Uint16(header[:]))
		if size < 12 || size > 4096 {
			return
		}
		request := make([]byte, size)
		if _, e := io.ReadFull(c, request); e != nil {
			return
		}
		if !h.acquire(h.queries) {
			return
		}
		answer, e := h.answerDNS(ctx, request)
		h.release(h.queries)
		if e != nil {
			return
		}
		binary.BigEndian.PutUint16(header[:], uint16(len(answer)))
		if _, e = c.Write(append(header[:], answer...)); e != nil {
			return
		}
	}
}
func (h *systemHandler) NewPacketConnectionEx(parent context.Context, c N.PacketConn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer c.Close()
	if onClose != nil {
		defer onClose(nil)
	}
	if !destination.IsIPv4() || destination.Port == 53 || !h.acquire(h.flows) {
		return
	}
	defer h.release(h.flows)
	ctx, cancel := h.flowContext(parent)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	first := buf.NewPacket()
	defer first.Release()
	c.SetReadDeadline(time.Now().Add(60 * time.Second))
	dst, e := c.ReadPacket(first)
	if e != nil || dst != destination {
		return
	}
	if h.router.policy.Presets.BlockBitTorrent && isKnownBitTorrent(first.Bytes()) {
		h.router.counters.Blocked.Add(1)
		return
	}
	dialCtx, done := context.WithTimeout(ctx, 8*time.Second)
	remote, e := h.router.DialSource(dialCtx, "udp4", source.AddrPort(), destination.AddrPort())
	done()
	if e != nil {
		return
	}
	defer remote.Close()
	stopRemote := context.AfterFunc(ctx, func() { remote.Close() })
	defer stopRemote()
	remote.SetDeadline(time.Now().Add(60 * time.Second))
	if _, e = remote.Write(first.Bytes()); e != nil {
		return
	}
	finished := make(chan struct{}, 1)
	go func() {
		defer func() { c.Close(); finished <- struct{}{} }()
		reply := make([]byte, 65535)
		for {
			n, e := remote.Read(reply)
			if e != nil {
				return
			}
			b := buf.NewSize(n)
			b.Write(reply[:n])
			if c.WritePacket(b, destination) != nil {
				return
			}
		}
	}()
	for ctx.Err() == nil {
		first.Reset()
		c.SetReadDeadline(time.Now().Add(60 * time.Second))
		dst, e = c.ReadPacket(first)
		if e != nil || dst != destination {
			break
		}
		if h.router.policy.Presets.BlockBitTorrent && isKnownBitTorrent(first.Bytes()) {
			h.router.counters.Blocked.Add(1)
			break
		}
		remote.SetDeadline(time.Now().Add(60 * time.Second))
		if _, e = remote.Write(first.Bytes()); e != nil {
			break
		}
	}
	remote.Close()
	c.Close()
	<-finished
}
