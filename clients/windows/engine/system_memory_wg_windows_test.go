package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/netip"
	"testing"
	"time"
)

func TestMemoryWireGuardEncryptedTCPAndUDP(t *testing.T) {
	local, remote := memoryWGPair(t)
	testMemoryWireGuardTraffic(t, local, remote)
}

func memoryWGPair(t *testing.T) (*memoryWG, *memoryWG) {
	return memoryWGPairWithExtensions(t, "")
}

func memoryWGPairWithExtensions(t *testing.T, extensions string) (*memoryWG, *memoryWG) {
	return memoryWGPairDifferentExtensions(t, extensions, extensions)
}

func memoryWGPairDifferentExtensions(t *testing.T, clientExtensions, serverExtensions string) (*memoryWG, *memoryWG) {
	t.Helper()
	client, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	server, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	encode := base64.StdEncoding.EncodeToString
	config := func(key, peer []byte, ip, allowed string, port uint16, extensions string) string {
		endpoint := ""
		if port != 0 {
			endpoint = fmt.Sprintf("Endpoint = 127.0.0.1:%d\n", port)
		}
		return fmt.Sprintf("[Interface]\n%sPrivateKey = %s\nAddress = %s/32\nMTU = 1280\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\n%s", extensions, encode(key), ip, encode(peer), allowed, endpoint)
	}
	remote, e := startMemoryWG(config(server.Bytes(), client.PublicKey().Bytes(), "10.21.32.1", "10.21.32.2", 0, serverExtensions))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(remote.Close)
	local, e := startMemoryWG(config(client.Bytes(), server.PublicKey().Bytes(), "10.21.32.2", "10.21.32.1", remote.bind.port, clientExtensions))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(local.Close)
	return local, remote
}

func testMemoryWireGuardTraffic(t *testing.T, local, remote *memoryWG) {
	listener, e := remote.Net.ListenTCPAddrPort(netip.MustParseAddrPort("10.21.32.1:8080"))
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	go func() {
		c, e := listener.Accept()
		if e == nil {
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			io.Copy(c, c)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, e := local.Net.DialContext(ctx, "tcp", "10.21.32.1:8080")
	if e != nil {
		t.Fatal("in-memory encrypted TCP did not connect")
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, e = c.Write([]byte("synthetic TCP")); e != nil {
		t.Fatal(e)
	}
	payload := make([]byte, len("synthetic TCP"))
	if _, e = io.ReadFull(c, payload); e != nil || string(payload) != "synthetic TCP" {
		t.Fatal("encrypted TCP payload mismatch")
	}
	udp, e := remote.Net.ListenUDPAddrPort(netip.MustParseAddrPort("10.21.32.1:5300"))
	if e != nil {
		t.Fatal(e)
	}
	defer udp.Close()
	go func() {
		buffer := make([]byte, 2048)
		udp.SetReadDeadline(time.Now().Add(5 * time.Second))
		for i := 0; i < 2; i++ {
			n, addr, e := udp.ReadFrom(buffer)
			if e != nil {
				return
			}
			udp.WriteTo(buffer[:n], addr)
		}
	}()
	u, e := local.Net.DialUDPAddrPort(netip.AddrPort{}, netip.MustParseAddrPort("10.21.32.1:5300"))
	if e != nil {
		t.Fatal(e)
	}
	defer u.Close()
	u.SetDeadline(time.Now().Add(5 * time.Second))
	for _, payload := range [][]byte{[]byte("synthetic UDP"), bytes.Repeat([]byte{0x5a}, 1252)} {
		u.Write(payload)
		buffer := make([]byte, 2048)
		n, e := u.Read(buffer)
		if e != nil || !bytes.Equal(buffer[:n], payload) {
			t.Fatal("encrypted small/MTU-sized UDP payload mismatch")
		}
	}
	health := local.Health()
	if !health.Handshake || health.Rx == 0 || health.Tx == 0 {
		t.Fatal("encrypted session health unavailable")
	}
}
