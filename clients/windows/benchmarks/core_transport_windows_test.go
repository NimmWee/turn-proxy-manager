//go:build windows

// Diagnostic fixture copied into an isolated core source tree by the runner.
// Only loopback sockets and ephemeral synthetic credentials are used.
package udprelay

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/pion/dtls/v3"
	"github.com/pion/logging"
	"github.com/pion/turn/v5"
	"github.com/samosvalishe/free-turn-proxy/internal/clientsdb"
	"github.com/samosvalishe/free-turn-proxy/internal/logx"
	"github.com/samosvalishe/free-turn-proxy/internal/proxy/udpserver"
	"github.com/samosvalishe/free-turn-proxy/internal/transport/dtlsdial"
	"github.com/samosvalishe/free-turn-proxy/internal/transport/turndial"
	"github.com/samosvalishe/free-turn-proxy/internal/wire"
	"golang.org/x/sys/windows"
)

// The runner inserts one increment into the temporary listener's overflow path.
var reviewQueueDrops atomic.Uint64

type reviewFixture struct {
	client    *net.UDPConn
	local     net.PacketConn
	cancel    context.CancelFunc
	runDone   chan error
	connected atomic.Int32
	closers   []func()
}

func reviewListen(t *testing.T) *net.UDPConn {
	t.Helper()
	c, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	return c
}

func newReviewFixture(t *testing.T, path string, streams int) *reviewFixture {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	f := &reviewFixture{cancel: cancel, runDone: make(chan error, 1)}
	t.Cleanup(func() {
		cancel()
		if f.local != nil {
			_ = f.local.SetReadDeadline(time.Now())
		}
		if f.runDone != nil {
			select {
			case <-f.runDone:
			case <-time.After(8 * time.Second):
				t.Error("core teardown timed out")
			}
		}
		for i := len(f.closers) - 1; i >= 0; i-- {
			f.closers[i]()
		}
	})
	backend := reviewListen(t)
	// Only the traffic generator/sink get larger buffers. Core/TURN retain defaults.
	_ = backend.SetReadBuffer(4 << 20)
	f.closers = append(f.closers, func() { _ = backend.Close() })
	go func() {
		var b [2048]byte
		for {
			n, a, e := backend.ReadFromUDPAddrPort(b[:])
			if e != nil {
				return
			}
			_, _ = backend.WriteToUDPAddrPort(b[:n], a)
		}
	}()
	key := make([]byte, 32)
	if _, e := rand.Read(key); e != nil {
		t.Fatal("synthetic key generation failed")
	}
	cert, e := dtlsdial.GenerateSelfSignedCert()
	if e != nil {
		t.Fatal("synthetic certificate failed")
	}
	obf, e := wire.Listen(wire.ProfileRTPOpus3, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, key)
	if e != nil {
		t.Fatal(e)
	}
	server, e := dtls.NewListenerWithOptions(obf, dtls.WithCertificates(cert), dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret), dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256), dtls.WithConnectionIDGenerator(dtls.RandomCIDGenerator(8)))
	if e != nil {
		_ = obf.Close()
		t.Fatal(e)
	}
	f.closers = append(f.closers, func() { _ = server.Close() })
	const syntheticID = "11111111111111111111111111111111"
	go func() {
		for {
			c, e := server.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				stop := context.AfterFunc(ctx, func() { _ = c.Close() })
				defer stop()
				if c.(*dtls.Conn).HandshakeContext(ctx) != nil {
					return
				}
				_, data, e := clientsdb.AcceptClientID(c, func(id string, mode byte) error {
					if id != syntheticID || mode != clientsdb.ModeUDP {
						return errors.New("synthetic identity mismatch")
					}
					return nil
				})
				if e == nil {
					udpserver.Handle(ctx, logx.Nop(), data, backend.LocalAddr().String())
				}
			}()
		}
	}()
	peer := server.Addr().(*net.UDPAddr)
	params := &Params{Profile: wire.ProfileRTPOpus3, ObfKey: key, ClientID: syntheticID}
	if path == "direct" {
		// The runner changes only this dialer's ephemeral bind to127.0.0.1.
		params.Dial = func(ctx context.Context, _ int) (*turndial.Stream, error) { return turndial.Direct(ctx, peer) }
	} else {
		quiet := logging.NewDefaultLoggerFactory()
		quiet.DefaultLogLevel = logging.LogLevelDisabled
		cfg := turn.ServerConfig{LoggerFactory: quiet, Realm: "local-review", AuthHandler: func(a *turn.RequestAttributes) (string, []byte, bool) {
			return a.Username, turn.GenerateAuthKey(a.Username, a.Realm, "synthetic-local-only"), true
		}}
		generator := &turn.RelayAddressGeneratorStatic{RelayAddress: net.ParseIP("127.0.0.1"), Address: "127.0.0.1"}
		permit := func(_ net.Addr, ip net.IP) bool { return ip.IsLoopback() }
		var address string
		if path == "udp" {
			pc := reviewListen(t)
			address = pc.LocalAddr().String()
			cfg.PacketConnConfigs = []turn.PacketConnConfig{{PacketConn: pc, RelayAddressGenerator: generator, PermissionHandler: permit}}
		} else {
			ln, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			address = ln.Addr().String()
			cfg.ListenerConfigs = []turn.ListenerConfig{{Listener: ln, RelayAddressGenerator: generator, PermissionHandler: permit}}
		}
		turnServer, err := turn.NewServer(cfg)
		if err != nil {
			t.Fatal(err)
		}
		f.closers = append(f.closers, func() { _ = turnServer.Close() })
		params.Dial = func(ctx context.Context, id int) (*turndial.Stream, error) {
			return turndial.Open(ctx, turndial.Config{TransportUDP: path == "udp", Log: logx.Nop(), StreamID: id}, peer, "local-review", "synthetic-local-only", address)
		}
	}
	f.local = reviewListen(t)
	f.closers = append(f.closers, func() { _ = f.local.Close() })
	f.client = reviewListen(t)
	_ = f.client.SetReadBuffer(4 << 20)
	f.closers = append(f.closers, func() { _ = f.client.Close() })
	go func() {
		f.runDone <- Run(ctx, &dtlsdial.Dialer{HandshakeTimeout: 5 * time.Second, HandshakeSem: make(chan struct{}, 2)}, NopAuth{}, logx.Nop(), &f.connected, nil, params, peer, f.local, streams)
	}()
	deadline := time.Now().Add(12 * time.Second)
	for f.connected.Load() != int32(streams) {
		select {
		case <-f.runDone:
			f.runDone = nil
			t.Fatal("core stopped during setup")
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("streams not ready: %d/%d", f.connected.Load(), streams)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return f
}

type reviewResult struct {
	Path              string  `json:"path"`
	Streams           int     `json:"streams"`
	Round             int     `json:"round"`
	TargetMbps        float64 `json:"targetMbps"`
	ActualSendMbps    float64 `json:"actualSendMbps"`
	EchoGoodputMbps   float64 `json:"echoGoodputMbps"`
	Sent              int     `json:"sent"`
	Received          int     `json:"received"`
	LostPercent       float64 `json:"lostPercent"`
	Duplicates        int     `json:"duplicates"`
	Reordered         int     `json:"reordered"`
	Corrupt           int     `json:"corrupt"`
	QueueDrops        uint64  `json:"coreQueueDrops"`
	RTT50ms           float64 `json:"rtt50ms"`
	RTT95ms           float64 `json:"rtt95ms"`
	CPUCorePercent    float64 `json:"combinedProcessCPUCorePercent"`
	AllocatedBytes    uint64  `json:"allocatedBytes"`
	GCs               uint32  `json:"gcs"`
	Seconds           float64 `json:"seconds"`
	SampleWallSeconds float64 `json:"sampleWallSeconds"`
}

var reviewCounterProc = windows.NewLazySystemDLL("kernel32.dll").NewProc("QueryPerformanceCounter")
var reviewFrequencyProc = windows.NewLazySystemDLL("kernel32.dll").NewProc("QueryPerformanceFrequency")

func reviewCounter(proc *windows.LazyProc) int64 {
	var value int64
	ok, _, _ := syscall.SyscallN(proc.Addr(), uintptr(unsafe.Pointer(&value)))
	if ok == 0 {
		panic("high resolution benchmark clock unavailable")
	}
	return value
}

func reviewCPU() uint64 {
	var created, exited, kernel, user windows.Filetime
	if windows.GetProcessTimes(windows.CurrentProcess(), &created, &exited, &kernel, &user) != nil {
		return 0
	}
	return (uint64(kernel.HighDateTime)<<32 | uint64(kernel.LowDateTime)) + (uint64(user.HighDateTime)<<32 | uint64(user.LowDateTime))
}

func reviewLoad(t *testing.T, f *reviewFixture, path string, streams, round int, rate float64, duration time.Duration) reviewResult {
	t.Helper()
	const size = 1280
	result := reviewResult{Path: path, Streams: streams, Round: round, TargetMbps: rate}
	packetCount := int(rate * 1e6 * duration.Seconds() / (size * 8))
	seen := make([]bool, packetCount)
	latencies := make([]float64, 0, packetCount)
	phase := uint64(time.Now().UnixNano())
	start := time.Now()
	frequency := reviewCounter(reviewFrequencyProc)
	startCounter := reviewCounter(reviewCounterProc)
	var latest int64
	var highest int
	var receive sync.WaitGroup
	receive.Add(1)
	_ = f.client.SetReadDeadline(start.Add(duration + 400*time.Millisecond))
	go func() {
		defer receive.Done()
		var b [2048]byte
		for {
			n, _, e := f.client.ReadFromUDPAddrPort(b[:])
			if e != nil {
				return
			}
			if n != size || binary.LittleEndian.Uint64(b[16:24]) != phase {
				continue
			}
			i := int(binary.LittleEndian.Uint64(b[:8]))
			if i < 0 || i >= packetCount {
				result.Corrupt++
				continue
			}
			valid := true
			for k := 24; k < n; k++ {
				if b[k] != byte(i+k) {
					valid = false
					break
				}
			}
			if !valid {
				result.Corrupt++
				continue
			}
			if seen[i] {
				result.Duplicates++
				continue
			}
			seen[i] = true
			result.Received++
			if i < highest {
				result.Reordered++
			} else {
				highest = i
			}
			now := reviewCounter(reviewCounterProc)
			latest = now
			latencies = append(latencies, float64(now-int64(binary.LittleEndian.Uint64(b[8:16])))*1000/float64(frequency))
		}
	}()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	q0 := reviewQueueDrops.Load()
	cpu := reviewCPU()
	var payload [size]byte
	target := f.local.LocalAddr().(*net.UDPAddr)
	// Millisecond pacing controls offered load rather than an unbounded UDP flood.
	for i := 0; i < packetCount; i++ {
		due := time.Duration(float64(i) * float64(duration) / float64(packetCount))
		if wait := due - time.Since(start); wait > 0 {
			time.Sleep(wait)
		}
		binary.LittleEndian.PutUint64(payload[:8], uint64(i))
		binary.LittleEndian.PutUint64(payload[8:16], uint64(reviewCounter(reviewCounterProc)))
		binary.LittleEndian.PutUint64(payload[16:24], phase)
		for k := 24; k < size; k++ {
			payload[k] = byte(i + k)
		}
		if _, e := f.client.WriteToUDPAddrPort(payload[:], target.AddrPort()); e != nil {
			t.Fatal("local generator write failed")
		}
		result.Sent++
	}
	sendElapsed := float64(reviewCounter(reviewCounterProc)-startCounter) / float64(frequency)
	receive.Wait()
	elapsed := time.Since(start)
	runtime.ReadMemStats(&after)
	result.QueueDrops = reviewQueueDrops.Load() - q0
	result.CPUCorePercent = float64(reviewCPU()-cpu) * 100 / 1e7 / elapsed.Seconds()
	result.AllocatedBytes = after.TotalAlloc - before.TotalAlloc
	result.GCs = after.NumGC - before.NumGC
	result.ActualSendMbps = float64(result.Sent*size*8) / sendElapsed / 1e6
	if latest > startCounter {
		result.EchoGoodputMbps = float64(result.Received*size*8) / (float64(latest-startCounter) / float64(frequency)) / 1e6
	}
	result.Seconds = sendElapsed
	result.SampleWallSeconds = elapsed.Seconds()
	result.LostPercent = 100 * float64(result.Sent-result.Received) / float64(result.Sent)
	sort.Float64s(latencies)
	if len(latencies) > 0 {
		result.RTT50ms = latencies[len(latencies)/2]
		result.RTT95ms = latencies[(len(latencies)-1)*95/100]
	}
	return result
}

func reviewInts(name string, defaults string) []int {
	value := os.Getenv(name)
	if value == "" {
		value = defaults
	}
	var out []int
	for _, s := range strings.Split(value, ",") {
		n, e := strconv.Atoi(s)
		if e != nil || n < 1 || n > 1000 {
			panic("invalid local benchmark option")
		}
		out = append(out, n)
	}
	return out
}

func TestLocalCoreTransportMatrix(t *testing.T) {
	if os.Getenv("FTM_CORE_LOCAL_BENCH") != "1" {
		t.Skip("explicit local benchmark only")
	}
	seconds, e := strconv.ParseFloat(os.Getenv("FTM_BENCH_SECONDS"), 64)
	if e != nil || seconds < 0.2 || seconds > 10 {
		t.Fatal("invalid duration")
	}
	rounds := reviewInts("FTM_BENCH_ROUNDS", "2")[0]
	paths := strings.Split(os.Getenv("FTM_BENCH_PATHS"), ",")
	for _, path := range paths {
		if path != "direct" && path != "tcp" && path != "udp" {
			t.Fatal("invalid loopback path")
		}
	}
	var results []reviewResult
	for _, path := range paths {
		for _, streams := range reviewInts("FTM_BENCH_STREAMS", "1,2,4,6,8") {
			t.Run(fmt.Sprintf("%s/%d", path, streams), func(t *testing.T) {
				f := newReviewFixture(t, path, streams)
				for round := 1; round <= rounds; round++ {
					for _, rate := range reviewInts("FTM_BENCH_RATES", "10,50,100") {
						r := reviewLoad(t, f, path, streams, round, float64(rate), time.Duration(seconds*float64(time.Second)))
						results = append(results, r)
						raw, _ := json.Marshal(r)
						fmt.Println("LOCAL_RESULT " + string(raw))
						if r.Corrupt > 0 || r.Received == 0 {
							t.Fatal("payload integrity or total delivery failure")
						}
					}
				}
			})
		}
	}
	report := map[string]any{"scope": "loopback-core-DTLS-rtpopus3-UDP-echo", "core": "pinned4.1.5", "variant": os.Getenv("FTM_BENCH_VARIANT"), "go": runtime.Version(), "gomaxprocs": runtime.GOMAXPROCS(0), "payloadBytes": 1280, "realVPN": "NOT RUN", "VK": "NOT RUN", "CPU": "combined client/server/TURN/generator process,100%=one logical core", "results": results}
	raw, _ := json.MarshalIndent(report, "", "  ")
	if e := os.WriteFile(os.Getenv("FTM_BENCH_OUTPUT"), raw, 0600); e != nil {
		t.Fatal("report write failed")
	}
}
