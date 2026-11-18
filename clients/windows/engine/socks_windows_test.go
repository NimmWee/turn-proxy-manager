package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

func TestSOCKSAuthAndConnectAreBoundedBeforeDial(t *testing.T) {
	for _, correct := range []bool{false, true} {
		client, server := net.Pipe()
		ctx, cancel := context.WithCancel(context.Background())
		dialed := make(chan bool, 1)
		done := make(chan error, 1)
		go func() {
			defer server.Close()
			done <- serveSOCKS(ctx, server, socksOptions{User: "user", Password: "SYNTHETIC_PASSWORD"}, func(context.Context, string) (net.Conn, error) {
				dialed <- true
				a, b := net.Pipe()
				go func() { defer b.Close(); data := make([]byte, 4); io.ReadFull(b, data); b.Write(data) }()
				return a, nil
			})
		}()
		client.SetDeadline(time.Now().Add(3 * time.Second))
		client.Write([]byte{5, 1, 2})
		reply := make([]byte, 2)
		if _, e := io.ReadFull(client, reply); e != nil || reply[0] != 5 || reply[1] != 2 {
			t.Fatal("SOCKS authentication negotiation failed")
		}
		password := "wrong"
		if correct {
			password = "SYNTHETIC_PASSWORD"
		}
		auth := append([]byte{1, 4}, []byte("user")...)
		auth = append(auth, byte(len(password)))
		auth = append(auth, []byte(password)...)
		client.Write(auth)
		io.ReadFull(client, reply)
		if !correct {
			if reply[1] == 0 {
				t.Fatal("wrong SOCKS password accepted")
			}
			select {
			case <-dialed:
				t.Fatal("dial before authentication")
			default:
			}
			client.Close()
			cancel()
			continue
		}
		if reply[1] != 0 {
			t.Fatal("valid SOCKS credentials rejected")
		}
		client.Write([]byte{5, 1, 0, 1, 203, 0, 113, 1, 1, 187})
		response := make([]byte, 10)
		if _, e := io.ReadFull(client, response); e != nil || response[1] != 0 {
			t.Fatal("SOCKS CONNECT failed")
		}
		client.Write([]byte("ping"))
		echo := make([]byte, 4)
		if _, e := io.ReadFull(client, echo); e != nil || string(echo) != "ping" {
			t.Fatal("SOCKS stream data changed")
		}
		client.Close()
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("SOCKS cleanup hung")
		}
	}
}

func TestSOCKSRejectsPrivateMetadataAndRequiresCredentials(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.100.100.200", "168.63.129.16", "::1", "192.0.2.1"} {
		if publicIPv4(netip.MustParseAddr(raw)) {
			t.Fatal("non-public or metadata destination accepted")
		}
	}
	if !publicIPv4(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("public IPv4 rejected")
	}
	if _, e := startSOCKS(socksOptions{Port: 1080}, nil); e == nil {
		t.Fatal("anonymous SOCKS listener accepted")
	}
}

func TestSOCKSStopClosesPendingClients(t *testing.T) {
	reserved, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := reserved.Addr().(*net.TCPAddr).Port
	reserved.Close()
	server, e := startSOCKS(socksOptions{Port: port, User: "user", Password: "SYNTHETIC_PASSWORD"}, func(context.Context, string) (net.Conn, error) { return nil, errors.New("NO_EXTERNAL_DIAL") })
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	c, e := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	c.Write([]byte{5, 1, 2})
	reply := make([]byte, 2)
	if _, e = io.ReadFull(c, reply); e != nil {
		t.Fatal("listener did not accept synthetic client")
	}
	server.Close()
	if _, e = c.Read(reply); e == nil {
		t.Fatal("SOCKS stop left accepted connection open")
	}
}
