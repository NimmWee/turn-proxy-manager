package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const directPipe = `\\.\pipe\FreeTurnManager.Direct.v1`
const directPipeACL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"

// Authenticate BOTH ends before sending a domain or creating a network socket.
// Only fixed, installed LocalSystem services are accepted; UI has no pipe ACE.
func verifyServicePipe(c net.Conn, server bool, name, mode string) error {
	fd, ok := c.(interface{ Fd() uintptr })
	if !ok {
		return errors.New("UNTRUSTED_INTERNAL_PIPE")
	}
	var pid, session uint32
	var e error
	if server {
		e = windows.GetNamedPipeServerProcessId(windows.Handle(fd.Fd()), &pid)
	} else {
		e = windows.GetNamedPipeClientProcessId(windows.Handle(fd.Fd()), &pid)
	}
	if e == nil {
		e = windows.ProcessIdToSessionId(pid, &session)
	}
	if e != nil || session != 0 {
		return errors.New("UNTRUSTED_INTERNAL_PIPE")
	}
	m, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	service, e := ownService(m, name, mode)
	if e != nil {
		return e
	}
	defer service.Close()
	state, e := service.Query()
	if e != nil || state.State != svc.Running || state.ProcessId != pid {
		return errors.New("UNTRUSTED_INTERNAL_PIPE")
	}
	return nil
}

func tunnelDirectDial(ctx context.Context, address string) (net.Conn, error) {
	return dialDirectRelay(ctx, address, directPipe)
}
func dialDirectRelay(ctx context.Context, address, pipe string) (net.Conn, error) {
	if _, e := directAddress(address); e != nil {
		return nil, e
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c, e := winio.DialPipeAccessImpLevel(ctx, pipe, uint32(windows.GENERIC_READ|windows.GENERIC_WRITE), winio.PipeImpLevelAnonymous)
	if e != nil {
		return nil, e
	}
	accepted := false
	defer func() {
		if !accepted {
			c.Close()
		}
	}()
	if e = verifyServicePipe(c, true, tunnelName, "--tunnel"); e != nil {
		return nil, e
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	payload := make([]byte, 2+len(address))
	binary.BigEndian.PutUint16(payload, uint16(len(address)))
	copy(payload[2:], address)
	if _, e = c.Write(payload); e != nil {
		return nil, e
	}
	var status [1]byte
	if _, e = io.ReadFull(c, status[:]); e != nil || status[0] != 0 {
		return nil, errors.New("DIRECT_UNAVAILABLE")
	}
	c.SetDeadline(time.Time{})
	accepted = true
	return c, nil
}

func directAddress(address string) (string, error) {
	if len(address) > 1024 {
		return "", errRouting
	}
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		return "", errRouting
	}
	host, e = routingDomain(host)
	if e != nil {
		return "", e
	}
	n, e := strconv.Atoi(port)
	if e != nil || n < 1 || n > 65535 {
		return "", errRouting
	}
	return net.JoinHostPort(host, strconv.Itoa(n)), nil
}

type directRelay struct {
	listener net.Listener
	mu       sync.Mutex
	clients  map[net.Conn]bool
	closed   bool
	cancel   context.CancelFunc
}

func startDirectRelay(index uint32) (*directRelay, error) {
	// Missing physical DNS only disables DIRECT requests; the old VPN path remains
	// available. Never replace a missing DNS with a global/system resolver.
	dial, dialError := physicalSOCKSDialForIndex(index)
	listener, e := winio.ListenPipe(directPipe, &winio.PipeConfig{SecurityDescriptor: directPipeACL, MessageMode: true, InputBufferSize: 4096, OutputBufferSize: 4096})
	if e != nil {
		return nil, errors.New("DIRECT_PIPE_UNAVAILABLE")
	}
	ctx, cancel := context.WithCancel(context.Background())
	relay := &directRelay{listener: listener, clients: map[net.Conn]bool{}, cancel: cancel}
	go func() {
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			relay.mu.Lock()
			if relay.closed || len(relay.clients) >= 32 {
				relay.mu.Unlock()
				c.Close()
				continue
			}
			relay.clients[c] = true
			relay.mu.Unlock()
			go func() {
				defer c.Close()
				defer func() { relay.mu.Lock(); delete(relay.clients, c); relay.mu.Unlock() }()
				if verifyServicePipe(c, false, brokerName, "--broker") != nil {
					return
				}
				if dialError != nil {
					c.Write([]byte{1})
					return
				}
				serveDirectRelay(ctx, c, dial)
			}()
		}
	}()
	return relay, nil
}
func (r *directRelay) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	r.cancel()
	r.listener.Close()
	for c := range r.clients {
		c.Close()
	}
}

func serveDirectRelay(ctx context.Context, c net.Conn, dial socksDial) error {
	c.SetDeadline(time.Now().Add(10 * time.Second))
	var size [2]byte
	if _, e := io.ReadFull(c, size[:]); e != nil {
		return e
	}
	length := binary.BigEndian.Uint16(size[:])
	if length == 0 || length > 1024 {
		return errRouting
	}
	data := make([]byte, int(length))
	if _, e := io.ReadFull(c, data); e != nil {
		return e
	}
	address, e := directAddress(string(data))
	if e != nil {
		return e
	}
	remote, e := dial(ctx, address)
	if e != nil {
		c.Write([]byte{1})
		return e
	}
	defer remote.Close()
	if _, e = c.Write([]byte{0}); e != nil {
		return e
	}
	c.SetDeadline(time.Time{})
	done := make(chan error, 2)
	client, target := idleConn{c}, idleConn{remote}
	go func() {
		_, e := io.Copy(&target, &client)
		if tcp, ok := remote.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
		done <- e
	}()
	go func() {
		_, e := io.Copy(&client, &target)
		if half, ok := c.(interface{ CloseWrite() error }); ok {
			half.CloseWrite()
		}
		done <- e
	}()
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-ctx.Done():
			c.Close()
			remote.Close()
		case <-finished:
		}
	}()
	if e := <-done; e != nil {
		c.Close()
		remote.Close()
	}
	<-done
	return nil
}
