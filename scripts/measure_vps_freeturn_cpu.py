"""Read the FreeTurn cgroup counters during an operator-triggered speed test."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time


UNIT = "vps-vk.service"
CPU_FIELDS = ("usage_usec", "nr_periods", "nr_throttled", "throttled_usec")


def service_scope():
    properties = subprocess.run(
        ["systemctl", "show", UNIT, "-p", "ActiveState", "-p", "ControlGroup", "-p", "InvocationID"],
        check=True, capture_output=True, encoding="utf-8", timeout=5,
    ).stdout
    values = dict(line.split("=", 1) for line in properties.splitlines() if "=" in line)
    group = values.get("ControlGroup", "")
    if values.get("ActiveState") != "active" or not values.get("InvocationID") or group != "/system.slice/" + UNIT:
        raise ValueError("Service unavailable")
    directory = Path("/sys/fs/cgroup" + group)
    return directory, values["InvocationID"]


def read_cpu(directory):
    entries = dict(line.split() for line in (directory / "cpu.stat").read_text().splitlines())
    return {field: int(entries[field]) for field in CPU_FIELDS}


def sample(directory, interval):
    before = read_cpu(directory)
    start = time.monotonic()
    period_settings = (directory / "cpu.max").read_text().split()
    time.sleep(interval)
    after = read_cpu(directory)
    elapsed = time.monotonic() - start
    if (directory / "cpu.max").read_text().split() != period_settings:
        raise ValueError("CPU limit changed")
    quota, period = period_settings
    counts = {name: after[name] - before[name] for name in CPU_FIELDS}
    periods = counts["nr_periods"]
    if min(counts.values()) < 0 or counts["nr_throttled"] > periods:
        raise ValueError("CPU counters changed unexpectedly")
    return {"seconds": round(elapsed, 2), "quota_percent_of_one_core": None if quota == "max" else round(100 * int(quota) / int(period), 1),
            "used_percent_of_one_core": round(counts["usage_usec"] / elapsed / 10_000, 1),
            "periods": periods, "throttled_periods": counts["nr_throttled"], "throttled_ms": round(counts["throttled_usec"] / 1000, 1)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=int, choices=range(5, 61), default=20, metavar="5–60")
    args = parser.parse_args()
    if os.name != "posix":
        print("Linux systemd host required", file=sys.stderr)
        return 2
    try:
        directory, invocation = service_scope()
        result = sample(directory, args.seconds)
        if service_scope() != (directory, invocation):
            raise ValueError("FreeTurn service restarted")
    except (OSError, KeyError, ValueError, subprocess.SubprocessError):
        print("FreeTurn cgroup sample unavailable", file=sys.stderr)
        return 2
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
