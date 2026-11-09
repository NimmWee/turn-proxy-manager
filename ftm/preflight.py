"""Read-only host inventory for the future installer. No privileged commands."""

import os
from pathlib import Path
import re
import shutil
import sys


def parse_bound_ports(text, *, tcp):
    ports = set()
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 4 or (tcp and fields[3] != "0A"):
            continue
        try:
            ports.add(int(fields[1].rsplit(":", 1)[1], 16))
        except (ValueError, IndexError):
            continue
    return sorted(ports)


def evaluate(facts, vpn_port=56001, backend_port=51830):
    blockers = []
    if (facts["os_id"], facts["os_version"]) != ("ubuntu", "24.04"):
        blockers.append("requires_ubuntu_24_04")
    if not facts["root"]:
        blockers.append("apply_requires_root")
    if not facts["systemd"]:
        blockers.append("requires_systemd")
    # A nominal 1 GiB VM may report less memory after kernel reservations.
    if facts["mem_total_bytes"] is None or facts["mem_total_bytes"] < 900 * 1024 ** 2:
        blockers.append("less_than_target_1gib_memory")
    if facts["disk_free_bytes"] < 512 * 1024 ** 2:
        blockers.append("less_than_512mib_free_disk")
    if not facts["cpu_count"]:
        blockers.append("cpu_count_unknown")
    if facts["tcp_ports"] is None or facts["udp_ports"] is None:
        blockers.append("port_inventory_unavailable")
    else:
        if {80, 443} & set(facts["tcp_ports"]):
            blockers.append("web_ports_in_use")
        if not facts["legacy_state_exists"] and {vpn_port, backend_port} & set(facts["udp_ports"]):
            blockers.append("unowned_vpn_ports_in_use")
    return {"changes_system": False, "preflight_ready": not blockers, "installation_ready": False,
            "recommended_mode": "migrate" if facts["legacy_state_exists"] else "fresh",
            "facts": facts, "blockers": blockers,
            "missing_tools": sorted(name for name, found in facts["tools"].items() if not found),
            "not_checked": ["dns_tls_and_vpn_e2e", "offsite_backup_and_restore", "existing_service_health",
                            "firewall_ownership_and_rules", "system_clock_accuracy", "apply_and_rollback"]}


def collect():
    if sys.platform != "linux":
        raise ValueError("Предварительная проверка хоста доступна в Linux; целевая ОС — Ubuntu 24.04.")
    release = {}
    for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            release[key] = value.strip('"')
    memory = re.search(r"^MemTotal:\s+(\d+)\s+kB", Path("/proc/meminfo").read_text(), re.MULTILINE)

    def ports(protocol):
        found = set()
        for suffix in ("", "6"):
            try:
                text = Path(f"/proc/net/{protocol}{suffix}").read_text()
            except OSError:
                return None
            found.update(parse_bound_ports(text, tcp=protocol == "tcp"))
        return sorted(found)

    return {"os_id": release.get("ID"), "os_version": release.get("VERSION_ID"),
            "root": os.geteuid() == 0, "systemd": Path("/run/systemd/system").is_dir(),
            "cpu_count": os.cpu_count(), "mem_total_bytes": int(memory.group(1)) * 1024 if memory else None,
            "disk_free_bytes": shutil.disk_usage("/").free, "tcp_ports": ports("tcp"), "udp_ports": ports("udp"),
            "legacy_state_exists": Path("/var/lib/vps-vk/main/state.json").exists(),
            "tools": {name: shutil.which(name) is not None for name in ("ip", "wg", "iptables", "openssl", "systemctl")}}
