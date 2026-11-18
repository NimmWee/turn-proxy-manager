# FreeTurn core: performance review18.11.2026

Scope: user requested inspection/recommendations, not a core upgrade or optimisation implementation. No running VPN, services, network settings, VPS or production sources changed. No subagents. Research checkout `.references/core-review-7a76b33` and a local benchmark fixture are ignored working material; the pinned Windows core remains unchanged.

## Versions and evidence

- Remote HEAD/master: `7a76b3328b45b2af6003562191a0f7d5ee26ef9a`,17.11.2026, advanced CAPTCHA CLI/page-log changes.
- Our pinned core: releasev4.1.5, `f6b1f25767755d9bf34cbf78818b74c5062d7d0c`, configured in `clients/windows/dependencies.json` and Go replace.
- Normalised source comparison excluding Git metadata: only6 upstream files differ: docs/flags.md, docs/providers.md, internal/config/args.go, args_test.go, cliflags.go, internal/provider/vk/internal/captcha/manual/manual.go. The packet forwarding/transport code analysed is the same in our pinned version. Updating master alone is not an evidenced throughput optimisation.
- No existing Go benchmark functions/pprof wiring found by source search. Code review identifies candidates, not the actual bottleneck of the user's current connection.

## Priorities

### 1. Measure Direct versus VK Relay and TURN TCP versus UDP

`internal/transport/turndial/turndial.go:dialTransport` defaults to TCP for client→TURN; `TransportUDP` selects UDP. `proxy.mode=udp` is separately required for our WireGuard payload and must not be confused with TURN transport. No need to switch our WG to KCP/tcp mode. TCP loss can delay later packets on the same outer connection; UDP is a candidate where the operator permits it, not an unconditional improvement. Direct removes the VK TURN hop but still runs FreeTurn DTLS/obfuscation. It is available only when direct reachability works; no silent plaintext fallback/disabled masking recommendation.

Measure current path, confirmed traffic throughput, RTT/loss, CPU per core, memory/GC and retransmissions. CPU low + relay slow + direct fast suggests route/relay constraints; CPU saturated in crypto/copies/stack suggests a local bottleneck. This is a hypothesis test, not proof that all slow Relay is a VK cap.

### 2. TURN endpoint quality and bounded stream count

`internal/proxy/udprelay/dial.go:DialTURN` uses the first successful candidate from rawURLs; successful allocation is not a throughput/RTT ranking. A bounded selector using real path measurements and cooldown could avoid a consistently poor candidate. Credentials/quota/timeouts/security and existing address validation must remain; do not fan out unlimited allocations or brute-force arbitrary relays.

`udprelay/run.go` starts one session to warm the credentials cache, waits up to20s, then starts the rest. `listener.go` supplies one shared channel to ready stream workers; there is no explicit per-stream measured goodput/latency scheduler here. Increasing N does not guarantee speed; it increases DTLS/TURN sessions, resources, credential groups and quota risk. Our managed default N6/SPC3 is already conservative. Test N2/4/6/8 under the same stable conditions, observe actual ready streams and auth/quota events, then consider bounded adaptation. SPC is credential-sharing policy, not another independent bandwidth multiplier. Different paths can reorder encrypted WG datagrams and harm inner TCP under delay variance; measure before introducing a new scheduler.

### 3. Packet drops, queue residence and pacing

`udprelay/listener.go` has inboundQueueCap2000 and a nonblocking send. Full queue returns the Packet to the pool with no drop counter. This is intentional overload handling rather than proven defect, but it hides a useful cause of throughput collapse. Add aggregate queue/drop/high-water/age metrics before changing capacity. Larger queues can increase latency and RAM instead of speed. Keep datagram boundaries and bounded memory.

`internal/netconn/pktpipe.go` also silently drops when its fixed queue is full and returns successful len(b); do not substitute it for blocking/backpressured connutil as a mechanical optimisation.

`wire/shape/shape.go` applies an explicit timing delay when obf-timing>0. Managed manifests do not request timing (normal zero), so this is not an identified current cause. Check effective config before touching it. Any pacing optimisation must preserve required camouflage; RTP sequence-number gaps in rtpopus3 are not evidence that the codec intentionally drops user datagrams.

### 4. Reduce CPU/GC only when profiling points there

The hot UDP relay already uses packetPool and in-place obfuscation buffers; not every make([]byte) is per-packet (several are per session). It already has several sensible allocation reductions. connutil.LimitedAsyncPacketPipe(256KiB) adds intermediate copying/locks and stores packet lengths in a sliced int array; metadata allocations can be measured. Candidate work is a bounded ring/pool retaining required close/deadline/backpressure semantics, or reducing a whole intermediate copy after profiling. Do not remove crypto/auth or change nonce/DTLS/CID/anti-replay rules for speed.

`SinglePeerBind.BatchSize()` is1, and server UDP forwarding reads/writes a datagram at a time. Batch APIs/GSO/GRO are later, platform-specific candidates, mainly for CPU-bound Linux/VPS paths; this is not a drop-in Windows improvement and DTLS/TURN limits remain. Existing concurrent consumers and packet ordering must be retained.

### 5. MTU and Windows integration

Core default MTU1280 matches our managed profile. Encapsulation adds WG/DTLS/RTP/TURN/outer headers. Raising to1420 without path testing can introduce fragmentation/loss; keep1280 as baseline and measure the path. A bad MTU can cause sites to stall, whereas DNS tuning mainly changes lookup/start latency and does not inherently increase an established download's bitrate.

Our ordinary WGNT and optional system routing have different costs. System routing adds userspace gVisor/WG, fake DNS/flow decisions and, when EXE rules exist, owner-table checks (UDP ownership rechecked on send/delivery). Compare these paths before assigning all slowdown to upstream core. Improving owner attribution must preserve fail-closed ownership and avoid a stale PID/port cache that weakens app rules. No claim of measured WGNT/system throughput difference yet.

## Actual offline experiment

`performance_review_test.go` was added only in the ignored research checkout `internal/netconn`. It compares existing connutil pipe with existing upstream pooled PacketPipe,1280-byte payload, sequential write/read and bounded32-packet bursts with queues large enough for each burst. No sockets, services, auth or VPN. Both copies preserve packet lengths in this fixture; concurrent contention, loss, cancellation, pipe semantics and real networks are not benchmarked.

Command: `C:/VPNN/.toolchains/go/bin/go.exe test -run '^$' -bench BenchmarkReviewPacketPipe -benchmem -benchtime=300ms -count=3 ./internal/netconn`.

Environment: Windows/amd64, Intel i5-12400F, local Go1.27.3. Results:

| Case | ns/op samples | Allocation | Meaning |
| --- | --- | --- | --- |
| connutil,1 packet |63.12 /72.76 /65.92|8B,1 allocation/op|median65.92ns per write/read pair |
| pooled,1 packet |193.6 /176.5 /177.6|0B,0 allocations/op|median177.6ns;~2.69x slower in this fixture |
| connutil,32 packets |2234 /2344 /2315|504B,6 allocations/burst|median2315ns/burst |
| pooled,32 packets |6512 /6188 /6193|~1B,0 allocations/burst|median6193ns/burst;~2.68x slower |

This rejects a blind pooled-channel replacement as an evidenced optimisation. It does not prove connutil is optimal under concurrency and does not predict internet throughput or VPS CPU. Synthetic cache-local MB/s output must not be presented as VPN speed.

## Local transport experiment completed18.11

The loopback-only Windows transport fixture is now implemented and executed:90 paced observations (3 paths ×N1/2/4/6/8 ×10/50/100Mbps ×2),36 overload observations, separate CPU/alloc profiles and a temporary-only Pion single-copy A/B. Paced matrix:562440/562440 echoes, no corruption or core queue drops; overload has end-to-end loss. The candidate reduces cumulative allocation7.79% at matched100Mbps without proving a stable throughput gain. Product0.24/pinned sources unchanged. Methods, numbers, commands and limitations: [CORE_LOCAL_BENCHMARKS.md](CORE_LOCAL_BENCHMARKS.md).

## Real-network experiment, not started

First collect a reproducible real baseline on the authorised test setup: same server/client, fixed MTU1280, distinguish upload/download and single/multiple download streams. Compare Direct/Relay, then TURN TCP/UDP where supported, then bounded N values. Save only aggregate safe timings/counters; pprof and heap material stay private and out of Git. No public debug port. Instrument drops/queue age and per-session useful bytes; profile CPU/allocations only for the mode actually showing the bottleneck. Select one measured change, preserve wire compatibility and compare against the pinned baseline. No promised speed percentage without E2E measurements.

Primary sources:

- https://github.com/hackdiaz-dev/free-turn-proxy/tree/7a76b3328b45b2af6003562191a0f7d5ee26ef9a
- https://github.com/hackdiaz-dev/free-turn-proxy/blob/7a76b3328b45b2af6003562191a0f7d5ee26ef9a/internal/proxy/udprelay/listener.go
- https://github.com/hackdiaz-dev/free-turn-proxy/blob/7a76b3328b45b2af6003562191a0f7d5ee26ef9a/internal/proxy/udprelay/dial.go
- https://github.com/hackdiaz-dev/free-turn-proxy/blob/7a76b3328b45b2af6003562191a0f7d5ee26ef9a/internal/transport/turndial/turndial.go
- https://github.com/hackdiaz-dev/free-turn-proxy/blob/7a76b3328b45b2af6003562191a0f7d5ee26ef9a/internal/proxy/udprelay/loop.go
- https://github.com/cbeuw/connutil/blob/v1.0.1/bufferedPacketPipe.go
- https://github.com/hackdiaz-dev/free-turn-proxy/blob/7a76b3328b45b2af6003562191a0f7d5ee26ef9a/docs/troubleshooting.md
