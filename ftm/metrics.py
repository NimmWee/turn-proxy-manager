"""Small in-memory samples from Linux and WG."""

import datetime
from pathlib import Path
import shutil
import time

from .agent import _run
from .legacy import baseline_module

_previous_cpu = None
_cached = None
_cached_at = 0
_wg_cache = None


def _run_probe(args):
    return _run(args, timeout=1.5)


def wireguard_counters(state, runner=_run_probe):
    """Keep public keys only as internal join keys, never in a response."""
    global _wg_cache
    interface = baseline_module().iface(state)
    now = time.monotonic()
    if runner is _run_probe and _wg_cache is not None:
        cached_interface, sampled_at, counters = _wg_cache
        if cached_interface == interface and now - sampled_at < 5:
            return counters
    try:
        transfers = runner(["wg", "show", interface, "transfer"]).splitlines()
        handshakes = runner(["wg", "show", interface, "latest-handshakes"]).splitlines()
        by_peer = {}
        for line in transfers:
            peer, received, sent = line.split()
            received, sent = int(received), int(sent)
            if received < 0 or sent < 0:
                raise ValueError("Invalid WireGuard counters")
            by_peer[peer] = received, sent
        latest = {}
        wall = time.time()
        for line in handshakes:
            peer, timestamp = line.split()
            value = int(timestamp)
            latest[peer] = value if 0 < value <= wall else None
        counters = {key: (*by_peer.get(key, (None, None)), latest.get(key)) for key in by_peer.keys() | latest.keys()}
    except (RuntimeError, ValueError):
        counters = None
    if runner is _run_probe:
        _wg_cache = interface, now, counters
    return counters


def collect(state, runner=_run_probe):
    global _previous_cpu, _cached, _cached_at
    now = time.monotonic()
    if _cached is not None and now - _cached_at < 5:
        return _cached
    cpu_values = [int(value) for value in Path("/proc/stat").read_text().splitlines()[0].split()[1:9]]
    total, idle = sum(cpu_values), cpu_values[3] + cpu_values[4]
    cpu = None
    if _previous_cpu and total > _previous_cpu[0]:
        elapsed = total - _previous_cpu[0]
        cpu = round(max(0, min(100, 100 * (elapsed - idle + _previous_cpu[1]) / elapsed)), 1)
    _previous_cpu = total, idle
    memory = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, value = line.split(":", 1)
        memory[key] = int(value.split()[0]) * 1024
    counters = wireguard_counters(state, runner)
    if counters is not None:
        rx = sum(received or 0 for received, _, _ in counters.values())
        tx = sum(sent or 0 for _, sent, _ in counters.values())
        wall = time.time()
        recent = sum(1 for _, _, handshake in counters.values() if handshake is not None and 0 <= wall - handshake <= 180)
    else:
        rx = tx = recent = None
    try:
        disk_total, _, disk_free = shutil.disk_usage("/var/lib/ftm")
    except OSError:
        disk_total = disk_free = None
    _cached = {"sampled_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "cpu_pct": cpu, "memory_total_bytes": memory["MemTotal"],
               "memory_used_bytes": memory["MemTotal"] - memory["MemAvailable"],
               "disk_total_bytes": disk_total, "disk_free_bytes": disk_free,
               "rx_bytes": rx, "tx_bytes": tx, "recent_handshakes_estimate": recent,
               "uptime_seconds": int(float(Path("/proc/uptime").read_text().split()[0])),
               "traffic_scope": "current_wireguard_interface", "cpu_sample_ready": cpu is not None}
    _cached["vpn_metrics_available"] = counters is not None
    _cached_at = now
    return _cached
