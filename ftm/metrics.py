"""Small in-memory samples from Linux and WG; no credential-bearing wg dump."""

import datetime
from pathlib import Path
import time

from .agent import _run
from .legacy import baseline_module

_previous_cpu = None
_cached = None
_cached_at = 0


def collect(state, runner=_run):
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
    interface = baseline_module().iface(state)
    available = True
    try:
        transfers = runner(["wg", "show", interface, "transfer"]).splitlines()
        handshakes = runner(["wg", "show", interface, "latest-handshakes"]).splitlines()
        rx = tx = 0
        for line in transfers:
            _, received, sent = line.split()
            rx += int(received)
            tx += int(sent)
        wall = time.time()
        recent = sum(1 for line in handshakes if 0 < int(line.split()[1]) <= wall and wall - int(line.split()[1]) <= 180)
    except RuntimeError:
        rx = tx = recent = None
        available = False
    _cached = {"sampled_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "cpu_pct": cpu, "memory_total_bytes": memory["MemTotal"],
               "memory_used_bytes": memory["MemTotal"] - memory["MemAvailable"],
               "rx_bytes": rx, "tx_bytes": tx, "recent_handshakes_estimate": recent,
               "uptime_seconds": int(float(Path("/proc/uptime").read_text().split()[0])),
               "traffic_scope": "current_wireguard_interface", "cpu_sample_ready": cpu is not None}
    _cached["vpn_metrics_available"] = available
    _cached_at = now
    return _cached
