"""Read-only operator diagnostics; never install, reconcile or restart anything."""

import ipaddress
import os
from pathlib import Path
import stat
import subprocess

from .control import request
from .store import ValidationError


def status():
    return request("status", timeout=5)


def _active(service):
    try:
        return subprocess.run(["systemctl", "is-active", "--quiet", service], capture_output=True, timeout=5).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _private(path, mode):
    try:
        path = Path(path)
        value = path.lstat()
        return not path.is_symlink() and value.st_uid == 0 and stat.S_IMODE(value.st_mode) == mode
    except OSError:
        return False


def _api_loopback_only():
    addresses = []
    try:
        for table in ("tcp", "tcp6"):
            path = Path("/proc/net") / table
            if not path.exists():
                continue
            for line in path.read_text().splitlines()[1:]:
                columns = line.split()
                address, port = columns[1].split(":")
                if columns[3] != "0A" or int(port, 16) != 8080:
                    continue
                packed = bytes.fromhex(address)
                packed = b"".join(packed[index:index+4][::-1] for index in range(0, len(packed), 4))
                addresses.append(ipaddress.ip_address(packed))
        return bool(addresses) and all(address.is_loopback for address in addresses)
    except (OSError, ValueError, IndexError):
        return False


def doctor():
    if os.name != "posix" or os.geteuid() != 0:
        raise ValidationError("Диагностику установленного сервера нужно запускать от root")
    import pwd
    checks = {}
    vpn = None
    try:
        vpn = status()
        checks["vpn_consistent"] = vpn["consistent"]
    except (OSError, RuntimeError, ValueError, KeyError):
        checks["vpn_consistent"] = False
    for service in ("ftm-control", "ftm-api"):
        checks[service + "_active"] = _active(service)
    checks["root_sqlite_0600"] = _private("/var/lib/ftm/manager.sqlite3", 0o600)
    checks["root_metadata_directory_0700"] = _private("/var/lib/ftm", 0o700)
    checks["root_registry_directory_0700"] = _private("/var/lib/ftm-agent", 0o700)
    try:
        account = pwd.getpwnam("ftm-api")
        endpoint = Path("/run/ftm/control.sock").lstat()
        checks["protected_control_socket"] = (stat.S_ISSOCK(endpoint.st_mode) and endpoint.st_uid == 0
                                               and endpoint.st_gid == account.pw_gid and stat.S_IMODE(endpoint.st_mode) == 0o660)
    except (OSError, KeyError):
        checks["protected_control_socket"] = False
    checks["api_loopback_only"] = _api_loopback_only()
    tls = None
    if Path("/etc/ftm/https.json").exists():
        checks["ftm-caddy_active"] = _active("ftm-caddy")
        try:
            if vpn is None:
                raise ValueError()
            host = str(ipaddress.IPv4Address(vpn["endpoint"].rsplit(":", 1)[0]))
            from .https_probe import trusted_certificate
            tls = trusted_certificate(host)
            checks["trusted_https_chain_and_ip"] = True
        except (OSError, RuntimeError, ValueError, KeyError):
            checks["trusted_https_chain_and_ip"] = False
    return {"healthy": all(checks.values()), "checks": checks, "vpn": vpn, "tls": tls,
            "changes_system": False, "client_e2e_tested": False}
