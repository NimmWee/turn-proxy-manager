package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func TestDirectRelayRefusesSpoofedServerBeforeSendingDomain(t *testing.T) {
	token, e := windows.OpenCurrentProcessToken()
	if e != nil {
		t.Fatal(e)
	}
	defer token.Close()
	user, e := token.GetTokenUser()
	if e != nil {
		t.Fatal(e)
	}
	name := fmt.Sprintf(`\\.\pipe\FreeTurn.Direct.test.%d.%d`, os.Getpid(), time.Now().UnixNano())
	listener, e := winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: "D:P(A;;GA;;;" + user.User.Sid.String() + ")"})
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	received := make(chan int, 1)
	go func() {
		c, e := listener.Accept()
		if e != nil {
			received <- -1
			return
		}
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		var bytes [8]byte
		n, _ := c.Read(bytes[:])
		received <- n
	}()
	if c, e := dialDirectRelay(context.Background(), "private-domain.example.com:443", name); e == nil {
		c.Close()
		t.Fatal("interactive spoofed server authenticated as SYSTEM tunnel")
	}
	select {
	case n := <-received:
		if n != 0 {
			t.Fatal("domain sent to unauthenticated pipe")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("spoof check timed out")
	}
}

func TestDirectRelayBoundedFramingAndSyntheticStream(t *testing.T) {
	for _, address := range []string{"example.com:443", "127.0.0.1:443", "https://example.com:443"} {
		client, server := net.Pipe()
		done := make(chan error, 1)
		dialed := false
		go func() {
			defer server.Close()
			done <- serveDirectRelay(context.Background(), server, func(_ context.Context, target string) (net.Conn, error) {
				dialed = true
				if target != "example.com:443" {
					return nil, errRouting
				}
				a, b := net.Pipe()
				go func() { defer b.Close(); var data [4]byte; io.ReadFull(b, data[:]); b.Write(data[:]) }()
				return a, nil
			})
		}()
		client.SetDeadline(time.Now().Add(3 * time.Second))
		payload := make([]byte, 2+len(address))
		binary.BigEndian.PutUint16(payload, uint16(len(address)))
		copy(payload[2:], address)
		client.Write(payload)
		if address == "example.com:443" {
			var status [1]byte
			if _, e := io.ReadFull(client, status[:]); e != nil || status[0] != 0 {
				t.Fatal("synthetic relay failed")
			}
			client.Write([]byte("ping"))
			var echo [4]byte
			if _, e := io.ReadFull(client, echo[:]); e != nil || string(echo[:]) != "ping" {
				t.Fatal("relay altered stream")
			}
		}
		client.Close()
		select {
		case e := <-done:
			if address != "example.com:443" && (e == nil || dialed) {
				t.Fatal("invalid/private target reached dialer")
			}
		case <-time.After(4 * time.Second):
			t.Fatal("relay cleanup hung")
		}
	}
	for _, data := range [][]byte{{0, 0}, {4, 1}} {
		a, b := net.Pipe()
		done := make(chan error, 1)
		go func() {
			defer b.Close()
			done <- serveDirectRelay(context.Background(), b, func(context.Context, string) (net.Conn, error) {
				t.Error("oversized frame dialed")
				return nil, errRouting
			})
		}()
		a.SetDeadline(time.Now().Add(time.Second))
		a.Write(data)
		a.Close()
		if e := <-done; e == nil {
			t.Fatal("unbounded frame accepted")
		}
	}
}

func TestDirectRelayMessagePipePreservesTCPHalfClose(t *testing.T) {
	token, e := windows.OpenCurrentProcessToken()
	if e != nil {
		t.Fatal(e)
	}
	defer token.Close()
	user, e := token.GetTokenUser()
	if e != nil {
		t.Fatal(e)
	}
	name := fmt.Sprintf(`\\.\pipe\FreeTurn.Direct.half.%d.%d`, os.Getpid(), time.Now().UnixNano())
	pipe, e := winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: "D:P(A;;GA;;;" + user.User.Sid.String() + ")", MessageMode: true})
	if e != nil {
		t.Fatal(e)
	}
	defer pipe.Close()
	echo, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer echo.Close()
	go func() {
		c, e := echo.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		body, _ := io.ReadAll(c)
		if string(body) == "ping" {
			c.Write([]byte("response after upload EOF"))
		}
	}()
	done := make(chan error, 1)
	go func() {
		c, e := pipe.Accept()
		if e != nil {
			done <- e
			return
		}
		defer c.Close()
		done <- serveDirectRelay(context.Background(), c, func(ctx context.Context, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp4", echo.Addr().String())
		})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client, e := winio.DialPipeContext(ctx, name)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	address := "example.com:443"
	payload := make([]byte, 2+len(address))
	binary.BigEndian.PutUint16(payload, uint16(len(address)))
	copy(payload[2:], address)
	client.Write(payload)
	var status [1]byte
	if _, e = io.ReadFull(client, status[:]); e != nil || status[0] != 0 {
		t.Fatal("message pipe setup failed")
	}
	client.Write([]byte("ping"))
	if e = client.(interface{ CloseWrite() error }).CloseWrite(); e != nil {
		t.Fatal(e)
	}
	reply, e := io.ReadAll(client)
	if e != nil || string(reply) != "response after upload EOF" {
		t.Fatal("half-close truncated TCP response")
	}
	client.Close()
	select {
	case <-done:
	case <-time.After(4 * time.Second):
		t.Fatal("half-close relay cleanup hung")
	}
}
