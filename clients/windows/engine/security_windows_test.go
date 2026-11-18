package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func TestPrivateStorageRoundTripAndWrongPurpose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.dpapi")
	secret := []byte("SYNTHETIC_KEY_DO_NOT_ECHO")
	if e := writeSecret(path, "purpose one", secret); e != nil {
		t.Fatal("DPAPI write failed")
	}
	cipher, e := os.ReadFile(path)
	if e != nil || bytes.Contains(cipher, secret) {
		t.Fatal("plaintext persisted")
	}
	plain, e := readSecret(path, "purpose one")
	if e != nil || !bytes.Equal(plain, secret) {
		t.Fatal("DPAPI roundtrip failed")
	}
	if _, e = readSecret(path, "purpose two"); e == nil {
		t.Fatal("wrong DPAPI purpose accepted")
	}
	if e = writeSecret(path, "purpose one", []byte("replacement")); e != nil {
		t.Fatal("atomic replacement failed")
	}
	plain, e = readSecret(path, "purpose one")
	if e != nil || string(plain) != "replacement" {
		t.Fatal("replacement not durable")
	}
}

func TestRealNamedPipeHasBoundedProtocolAndRestrictedUserACL(t *testing.T) {
	token, e := windows.OpenCurrentProcessToken()
	if e != nil {
		t.Fatal(e)
	}
	defer token.Close()
	user, e := token.GetTokenUser()
	if e != nil {
		t.Fatal(e)
	}
	sid := user.User.Sid.String()
	descriptor, e := windows.SecurityDescriptorFromString(pipeACL(sid))
	if e != nil {
		t.Fatal(e)
	}
	acl, _, e := descriptor.DACL()
	if e != nil {
		t.Fatal(e)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if e = windows.GetAce(acl, 2, &ace); e != nil {
		t.Fatal(e)
	}
	if ace.Mask&4 != 0 || (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String() != sid {
		t.Fatal("UI can create pipe instances or has incorrect SID")
	}
	name := fmt.Sprintf(`\\.\pipe\FreeTurnManager.test.%d.%d`, os.Getpid(), time.Now().UnixNano())
	listener, e := winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: pipeACL(sid), InputBufferSize: maxMessage, OutputBufferSize: 4096})
	if e != nil {
		t.Fatal(e)
	}
	if !isElevated() {
		path, _ := windows.UTF16PtrFromString(name)
		h, e := windows.CreateNamedPipe(path, windows.PIPE_ACCESS_DUPLEX, windows.PIPE_REJECT_REMOTE_CLIENTS, windows.PIPE_UNLIMITED_INSTANCES, 4096, maxMessage, 50, nil)
		if e == nil {
			windows.CloseHandle(h)
			listener.Close()
			t.Fatal("UI user created a server pipe instance")
		}
		if e != windows.ERROR_ACCESS_DENIED {
			listener.Close()
			t.Fatalf("unexpected pipe create result: %v", e)
		}
	} else {
		t.Log("Elevated token: user ACE checked; non-admin kernel denial NOT RUN")
	}
	listener.Close()
	// Framing uses a current-user server, not a SYSTEM impersonation. The
	// privileged UI-to-service integration is explicitly NOT RUN here.
	name += ".framing"
	listener, e = winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: "D:P(A;;GA;;;" + sid + ")", InputBufferSize: maxMessage, OutputBufferSize: 4096})
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	// Positive control: identical CreateNamedPipe parameters must succeed with
	// a full-access user ACE, so a mismatch is not mistaken for ACL enforcement.
	path, _ := windows.UTF16PtrFromString(name)
	h, e := windows.CreateNamedPipe(path, windows.PIPE_ACCESS_DUPLEX, windows.PIPE_REJECT_REMOTE_CLIENTS, windows.PIPE_UNLIMITED_INSTANCES, 4096, maxMessage, 50, nil)
	if e != nil {
		t.Fatalf("pipe ACL positive control failed: %v", e)
	}
	windows.CloseHandle(h)
	result := make(chan error, 1)
	go func() {
		c, e := listener.Accept()
		if e != nil {
			result <- e
			return
		}
		defer c.Close()
		q, e := readRequest(c)
		if e == nil && (q.V != 1 || q.Op != "status") {
			e = fmt.Errorf("unexpected request")
		}
		result <- e
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client, e := winio.DialPipeAccess(ctx, name, windows.GENERIC_READ|windows.FILE_WRITE_DATA)
	if e != nil {
		t.Fatal(e)
	}
	if e = json.NewEncoder(client).Encode(request{V: 1, Op: "status"}); e != nil {
		t.Fatal(e)
	}
	client.Close()
	if e = <-result; e != nil {
		t.Fatal(e)
	}
}

func TestIPCRejectsAmbiguousAndUnknownCommandsBeforeDispatch(t *testing.T) {
	for _, input := range []string{"{\"v\":1,\"V\":1,\"op\":\"status\"}\n", "{\"v\":1,\"op\":\"status\",\"command\":\"SECRET\"}\n"} {
		a, b := net.Pipe()
		go func() { defer a.Close(); a.Write([]byte(input)) }()
		_, e := readRequest(b)
		b.Close()
		if e == nil {
			t.Fatal("ambiguous/unknown field accepted")
		}
	}
	b := &broker{}
	r := b.dispatch(request{V: 1, Op: "exec", Profile: "SECRET"})
	if r.OK || r.Error != "INVALID_REQUEST" {
		t.Fatal("unexpected command reached system operations")
	}
}
