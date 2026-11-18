package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

const maxSystemIdentityBytes = 16 * 1024

var errSystemIdentity = errors.New("DNS_IDENTITY_REQUIRED")

// This read-only ClientHello/HTTP inspection is used ONLY for a restored opaque
// fake-IP identity. No remote socket exists yet. Standard-library TLS parsing
// avoids a second hand-written TLS parser. All generated server bytes are sunk;
// the original application bytes are replayed unchanged after authentication.
func recoverSystemIdentity(c net.Conn, leases *fakeDNS, ip netip.Addr) (net.Conn, error) {
	if lease, ok := leases.Lookup(ip); !ok || lease.Host != "" {
		return nil, errSystemIdentity
	}
	if c.SetReadDeadline(time.Now().Add(2*time.Second)) != nil {
		return nil, errSystemIdentity
	}
	defer c.SetReadDeadline(time.Time{})
	var captured bytes.Buffer
	reader := bufio.NewReader(io.TeeReader(io.LimitReader(c, maxSystemIdentityBytes), &captured))
	first, e := reader.Peek(1)
	if e != nil {
		return nil, errSystemIdentity
	}
	host := ""
	if first[0] == 22 {
		probe := &systemHelloConn{Conn: c, reader: reader}
		server := tls.Server(probe, &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			host = hello.ServerName
			return nil, errSystemIdentity
		}})
		_ = server.Handshake() // intentional callback abort, no TLS/session interception
	} else if first[0] >= 'A' && first[0] <= 'Z' {
		request, err := http.ReadRequest(reader)
		if err != nil || request.URL.IsAbs() || request.Method == "CONNECT" {
			return nil, errSystemIdentity
		}
		host = request.Host
		if strings.Contains(host, ":") {
			name, port, err := net.SplitHostPort(host)
			if err != nil || port == "" {
				return nil, errSystemIdentity
			}
			host = name
		}
	}
	if !leases.Recover(ip, host) {
		return nil, errSystemIdentity
	}
	return &systemReplayConn{Conn: c, reader: io.MultiReader(bytes.NewReader(captured.Bytes()), c)}, nil
}

type systemHelloConn struct {
	net.Conn
	reader io.Reader
}

func (c *systemHelloConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c *systemHelloConn) Write(p []byte) (int, error) { return len(p), nil }

type systemReplayConn struct {
	net.Conn
	reader io.Reader
}

func (c *systemReplayConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (c *systemReplayConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return c.Conn.Close()
}
