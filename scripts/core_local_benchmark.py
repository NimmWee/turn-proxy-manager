"""Run a bounded loopback-only diagnostic against an isolated pinned core copy.

Does not connect a VPN, use VK, read profiles, change system networking, install
services or edit the pinned source. Results are not internet/VPS benchmarks.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def fingerprint(root):
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_file() and ".git" not in path.relative_to(root).parts:
            digest.update(path.relative_to(root).as_posix().encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go")
    parser.add_argument("--output", default=".local-cache/core-benchmark/transport.json")
    parser.add_argument("--paths", default="direct,tcp,udp")
    parser.add_argument("--streams", default="1,2,4,6,8")
    parser.add_argument("--rates", default="10,50,100")
    parser.add_argument("--rounds", type=int, default=2)
    parser.add_argument("--seconds", type=float, default=1.2)
    parser.add_argument("--cpu", type=int, default=2)
    parser.add_argument("--profile", action="store_true", help="Private CPU/alloc profiles beside the JSON report")
    parser.add_argument("--variant", choices=("baseline", "turn-single-copy"), default="baseline",
                        help="R&D only: patch a temporary TURN dependency copy, never installed code")
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("This fixture measures Windows loopback; Linux/VPS is separate")
    if not 1 <= args.cpu <= 16 or not 1 <= args.rounds <= 5 or not .2 <= args.seconds <= 10:
        parser.error("Benchmark duration/resources must remain bounded")
    for value, maximum in ((args.streams, 16), (args.rates, 500)):
        if not value or len(value.split(",")) > 8 or len(set(value.split(","))) != len(value.split(",")) or any(not s.isdecimal() or not 1 <= int(s) <= maximum for s in value.split(",")):
            parser.error("Invalid streams/rates")
    if not args.paths or len(set(args.paths.split(","))) != len(args.paths.split(",")) or any(s not in ("direct", "tcp", "udp") for s in args.paths.split(",")):
        parser.error("Only local direct/tcp/udp paths supported")
    sessions = len(args.paths.split(",")) * len(args.streams.split(","))
    estimate = sessions * (2 + len(args.rates.split(",")) * args.rounds * (args.seconds + .4))
    if estimate > 420:
        parser.error("Split the matrix into bounded runs (estimated maximum420s per invocation)")
    root = Path(__file__).resolve().parents[1]
    lock = json.loads((root / "clients/windows/dependencies.json").read_text(encoding="utf-8"))
    core = root / ".references" / lock["core"]["directory"]
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    before = fingerprint(core)
    with tempfile.TemporaryDirectory(prefix="ftm-local-core-") as folder:
        temporary = Path(folder).resolve()
        staged = temporary / "core"
        assert staged.is_relative_to(temporary)
        shutil.copytree(core, staged, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        fixture = staged / "internal/proxy/udprelay/local_performance_windows_test.go"
        shutil.copy2(root / "clients/windows/benchmarks/core_transport_windows_test.go", fixture)
        listener = staged / "internal/proxy/udprelay/listener.go"
        text = listener.read_text(encoding="utf-8")
        needle = "default:\n\t\t\tpacketPool.Put(pkt)"
        if text.count(needle) != 1:
            raise RuntimeError("Pinned listener changed; refuse diagnostic instrumentation")
        listener.write_text(text.replace(needle, "default:\n\t\t\treviewQueueDrops.Add(1)\n\t\t\tpacketPool.Put(pkt)"), encoding="utf-8")
        direct = staged / "internal/transport/turndial/direct.go"
        text = direct.read_text(encoding="utf-8")
        needle = 'ListenPacket(ctx, network, "")'
        if text.count(needle) != 1:
            raise RuntimeError("Pinned direct bind changed; refuse non-loopback benchmark")
        direct.write_text(text.replace(needle, 'ListenPacket(ctx, network, "127.0.0.1:0")'), encoding="utf-8")
        # Both arms use the same isolated module and framing checks. The candidate
        # removes only a redundant clone, preserving the framing/buffering logic.
        module = json.loads(subprocess.check_output(
            [args.go, "list", "-mod=readonly", "-m", "-json", "github.com/pion/turn/v5"], cwd=staged))
        if module.get("Version") != "v5.0.13" or "Replace" in module:
            raise RuntimeError("Pinned TURN dependency changed; review the experiment")
        turn_source = Path(module["Dir"])
        turn_before = fingerprint(turn_source)
        turn = temporary / "turn"
        assert turn.is_relative_to(temporary)
        shutil.copytree(turn_source, turn, copy_function=shutil.copyfile)
        shutil.copy2(root / "clients/windows/benchmarks/turn_framing_test.go", turn / "internal/proto/local_review_test.go")
        if args.variant == "turn-single-copy":
            source = turn / "internal/proto/stun_conn.go"
            text = source.read_text(encoding="utf-8")
            needle = "s.buff = append(s.buff, append([]byte{}, payload[:n]...)...)"
            if text.count(needle) != 1:
                raise RuntimeError("TURN parser changed; refuse experimental patch")
            source.write_text(text.replace(needle, "s.buff = append(s.buff, payload[:n]...)"), encoding="utf-8")
        subprocess.run([args.go, "mod", "edit", "-replace=github.com/pion/turn/v5=" + str(turn)], cwd=staged, check=True)
        environment = dict(os.environ, FTM_CORE_LOCAL_BENCH="1", FTM_BENCH_OUTPUT=str(output),
                           FTM_BENCH_PATHS=args.paths, FTM_BENCH_STREAMS=args.streams,
                           FTM_BENCH_RATES=args.rates, FTM_BENCH_ROUNDS=str(args.rounds),
                           FTM_BENCH_SECONDS=str(args.seconds), GOMAXPROCS=str(args.cpu),
                           GOMEMLIMIT="256MiB", FTM_BENCH_VARIANT=args.variant)
        subprocess.run([args.go, "test", "-mod=readonly", "-run", "Test(StunConn|ConsumeSingleTURNFrame|ReviewTURNFraming)",
                        "-count=1", "-timeout=30s", "./internal/proto"], cwd=turn, env=environment, check=True, timeout=60)
        command = [args.go, "test", "-mod=readonly", "-run", "^TestLocalCoreTransportMatrix$", "-v", "-count=1", "-timeout=8m", "./internal/proxy/udprelay"]
        if args.profile:
            command[2:2] = ["-cpuprofile=" + str(output.with_suffix(".cpu.pprof")),
                            "-memprofile=" + str(output.with_suffix(".alloc.pprof"))]
        result = subprocess.run(command, cwd=staged, env=environment, timeout=510)
    if fingerprint(core) != before or fingerprint(turn_source) != turn_before:
        raise RuntimeError("Pinned source changed during the benchmark; inspect without overwriting")
    if result.returncode == 0:
        report = json.loads(output.read_text(encoding="utf-8"))
        report["provenance"] = {"coreSourceSHA256": before, "turnVersion": module["Version"],
                                "turnSourceSHA256": turn_before,
                                "fixtureSHA256": hashlib.sha256((root / "clients/windows/benchmarks/core_transport_windows_test.go").read_bytes()).hexdigest(),
                                "variant": args.variant, "pinnedSourcesUnchanged": True}
        output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("Pinned source unchanged. Network/service configuration untouched by runner.")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
