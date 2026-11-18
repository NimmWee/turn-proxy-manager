// Diagnostic fixture copied only into an isolated Pion TURN module by the runner.
package proto

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestReviewTURNFraming(t *testing.T) {
	stun := make([]byte, 20)
	stun[1] = 1 // Binding Request; no attributes.
	binary.BigEndian.PutUint32(stun[4:8], 0x2112a442)
	channel := func(size int) []byte {
		frame := make([]byte, 4+(size+3)/4*4)
		frame[0], frame[1] = 0x40, 1
		binary.BigEndian.PutUint16(frame[2:4], uint16(size))
		for i := 4; i < 4+size; i++ {
			frame[i] = byte(i)
		}
		return frame
	}
	frames := [][]byte{stun, channel(1280), channel(5), channel(33), stun}
	all := bytes.Join(frames, nil)
	for _, chunk := range []int{1, 3, 11, 2048} {
		t.Run(string(rune('A'+chunk%26)), func(t *testing.T) {
			reader, writer := net.Pipe()
			defer reader.Close()
			reader.SetDeadline(time.Now().Add(5 * time.Second))
			done := make(chan error, 1)
			go func() {
				defer writer.Close()
				for offset := 0; offset < len(all); {
					end := offset + chunk
					if end > len(all) {
						end = len(all)
					}
					n, err := writer.Write(all[offset:end])
					if err != nil {
						done <- err
						return
					}
					offset += n
				}
				done <- nil
			}()
			conn := NewSTUNConn(reader)
			payload := make([]byte, 4096)
			for i, expected := range frames {
				n, _, err := conn.ReadFrom(payload)
				if err != nil || n != len(expected) || !bytes.Equal(payload[:n], expected) {
					t.Fatalf("frame %d lost boundary/content: n=%d err=%v", i, n, err)
				}
				// Overwriting the returned buffer must not corrupt a buffered next frame.
				for j := range payload {
					payload[j] = 0xa5
				}
			}
			if _, _, err := conn.ReadFrom(payload); err != io.EOF {
				t.Fatalf("expected EOF, got %v", err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
