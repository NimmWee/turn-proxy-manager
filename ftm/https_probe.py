"""Obtain and verify trusted IP TLS, serving only a neutral page until enabled."""

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import tarfile
import time
import urllib.request

from .agent import NetworkAgent, _atomic, _run
from .checkpoint import _read_encrypted, capture_live, open_checkpoint
from .installer import read_private_json
from .runtime import _trusted_directory
from .store import Store, ValidationError

ROOT = Path(__file__).resolve().parents[1]
TLS_WAIT_SECONDS = 150


def config(host, *, panel_slug=None):
    if not ipaddress.ip_address(host).is_global or ipaddress.ip_address(host).version != 4:
        raise ValidationError("Trusted IP TLS requires a public IPv4")
    if panel_slug is not None and (not isinstance(panel_slug, str) or not re.fullmatch(r"[a-f0-9]{32}", panel_slug)):
        raise ValidationError("Invalid panel route")
    panel = "" if panel_slug is None else """    @panel path /a/SLUG /a/SLUG/*
    handle @panel {
        reverse_proxy 127.0.0.1:8080
    }
""".replace("SLUG", panel_slug)
    return """{
    admin off
    persist_config off
    skip_install_trust
    default_sni HOST
    log default {
        format filter {
            wrap json
            fields {
                request delete
            }
        }
    }
}
https://HOST {
    tls {
        issuer acme {
            dir https://acme-v02.api.letsencrypt.org/directory
            profile shortlived
        }
    }
    header -Server
PANEL    handle {
        header Content-Type "text/plain; charset=utf-8"
        respond "Личная страница. Сервис готовится к запуску." 200
    }
}
""".replace("HOST", host).replace("PANEL", panel)


def trusted_certificate(host):
    context = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=5) as connection:
        with context.wrap_socket(connection, server_hostname=host) as tls:
            certificate = tls.getpeercert()
    expires = ssl.cert_time_to_seconds(certificate["notAfter"])
    if expires - time.time() < 86400:
        raise RuntimeError("TLS certificate expires too soon")
    return {"trusted_chain_and_ip_san": True, "not_after_utc": certificate["notAfter"],
            "issuer": ", ".join(value for row in certificate["issuer"] for key, value in row if key in ("organizationName", "commonName"))}


def firewall_rules(state):
    return [["iptables", "-w", "5", "-t", "filter", "-I", "INPUT", "-i", state["wan"],
             "-p", "tcp", "--dport", str(port), "-m", "comment", "--comment", "ftm-web-public", "-j", "ACCEPT"]
            for port in (80, 443)]


def rule_exists(rule):
    check = rule.copy()
    check[5] = "-C"
    return subprocess.run(check, capture_output=True, timeout=10).returncode == 0


def ensure_firewall():
    """Restore only our two scoped rules after boot; never flush any chain."""
    state = read_private_json("/var/lib/vps-vk/main/state.json", 1048576)
    NetworkAgent(state, config_dir="/etc/vps-vk/main", state_dir="/var/lib/ftm-agent")
    saved = read_private_json("/etc/ftm/https.json")
    if saved.get("mode") not in ("probe", "public") or saved.get("host") != state["endpoint"]:
        raise ValidationError("HTTPS probe identity must match the existing VPN")
    for rule in firewall_rules(state):
        if not rule_exists(rule):
            _run(rule)


def binary():
    lock = json.loads((ROOT / "caddy.lock.json").read_text())
    if (set(lock) != {"schema_version", "version", "platform", "url", "sha512", "checksum_source"}
            or lock["schema_version"] != 1 or lock["platform"] != "linux_amd64"
            or not re.fullmatch(r"\d+\.\d+\.\d+", lock["version"])
            or not re.fullmatch(r"[a-f0-9]{128}", lock["sha512"])):
        raise ValidationError("Invalid pinned Caddy artifact")
    expected_url = f"https://github.com/caddyserver/caddy/releases/download/v{lock['version']}/caddy_{lock['version']}_linux_amd64.tar.gz"
    if lock["url"] != expected_url:
        raise ValidationError("Unexpected Caddy artifact origin")
    directory = Path("/opt/ftm/caddy") / lock["version"]
    _trusted_directory(directory.parent)
    _trusted_directory(directory)
    archive = directory / "release.tar.gz"
    if not archive.exists():
        with urllib.request.urlopen(expected_url, timeout=45) as response:
            data = response.read(64 * 1024**2 + 1)
        if len(data) > 64 * 1024**2 or hashlib.sha512(data).hexdigest() != lock["sha512"]:
            raise ValidationError("Pinned Caddy checksum failed")
        _atomic(archive, data, mode=0o644)
    if archive.is_symlink() or hashlib.sha512(archive.read_bytes()).hexdigest() != lock["sha512"]:
        raise ValidationError("Cached Caddy archive differs from its pin")
    with tarfile.open(archive, "r:gz") as packaged:
        for name in ("caddy", "LICENSE", "README.md"):
            member = packaged.getmember(name)
            if not member.isfile() or member.size > 100 * 1024**2:
                raise ValidationError("Unexpected artifact member")
            with packaged.extractfile(member) as stream:
                _atomic(directory / name, stream.read(), mode=0o755 if name == "caddy" else 0o644)
            if name == "caddy":
                (directory / name).chmod(0o755)
    return directory / "caddy", lock["version"]


def install(checkpoint, offsite_sha256):
    import fcntl
    import pwd
    state = read_private_json("/var/lib/vps-vk/main/state.json", 1048576)
    host = state["endpoint"]
    proposed = config(host)
    directory = Path("/etc/ftm")
    if directory.is_symlink() or directory.stat().st_uid != 0 or directory.stat().st_mode & 0o077:
        raise ValidationError("Private root manager configuration required")
    saved_state = directory / "https.json"
    if saved_state.exists() and read_private_json(saved_state).get("mode") != "probe":
        raise ValidationError("Cannot replace an enabled public API with a probe")
    encrypted = _read_encrypted(checkpoint)
    if hashlib.sha256(encrypted).hexdigest() != offsite_sha256:
        raise ValidationError("Matching offsite checkpoint required")
    phrase = Path("/root/ftm-test-backup.pass")
    if phrase.is_symlink() or phrase.stat().st_uid != 0 or phrase.stat().st_mode & 0o077:
        raise ValidationError("Private recovery phrase required")
    snapshot = open_checkpoint(encrypted, phrase.read_text().strip())
    fd = os.open("/run/lock/vps-vk.lock", os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        agent = NetworkAgent(state, config_dir="/etc/vps-vk/main", state_dir="/var/lib/ftm-agent")
        if capture_live(Store("/var/lib/ftm/manager.sqlite3"), agent) != snapshot:
            raise ValidationError("Take a fresh checkpoint before enabling HTTPS")
    finally:
        os.close(fd)
    already_active = subprocess.run(["systemctl", "is-active", "--quiet", "ftm-caddy"], capture_output=True).returncode == 0
    if not already_active:
        for port in (80, 443):
            with socket.socket() as probe:
                try:
                    probe.bind(("0.0.0.0", port))
                except OSError:
                    raise ValidationError("A web port is owned by another service") from None
    executable, version = binary()
    try:
        account = pwd.getpwnam("ftm-caddy")
    except KeyError:
        _run(["/usr/sbin/useradd", "--system", "--user-group", "--home-dir", "/var/lib/ftm-caddy", "--no-create-home", "--shell", "/usr/sbin/nologin", "ftm-caddy"])
        account = pwd.getpwnam("ftm-caddy")
    if account.pw_uid == 0 or account.pw_gid == 0:
        raise ValidationError("Caddy account must be unprivileged")
    storage = Path("/var/lib/ftm-caddy")
    if storage.is_symlink():
        raise ValidationError("Caddy storage symlink rejected")
    storage.mkdir(mode=0o700, exist_ok=True)
    os.chown(storage, account.pw_uid, account.pw_gid)
    storage.chmod(0o700)
    checked = subprocess.run(["runuser", "-u", "ftm-caddy", "--", "env", "XDG_DATA_HOME=/var/lib/ftm-caddy",
                              str(executable), "validate", "--config", "-", "--adapter", "caddyfile"],
                             input=proposed.encode(), capture_output=True, timeout=30)
    if checked.returncode:
        raise RuntimeError("Pinned Caddy rejected the generated TLS configuration")
    unit = Path("/etc/systemd/system/ftm-caddy.service")
    caddyfile = directory / "Caddyfile"
    firewall_unit = Path("/etc/systemd/system/ftm-https-firewall.service")
    firewall_wrapper = Path("/usr/local/bin/ftm-https-firewall")
    if not Path("/opt/ftm/current/ftm/https_probe.py").is_file():
        raise ValidationError("Install the root-owned runtime with HTTPS support first")
    paths = (unit, caddyfile, saved_state, firewall_unit, firewall_wrapper)
    if any(path.is_symlink() or (path.exists() and path.stat().st_uid != 0) for path in paths):
        raise ValidationError("Unsafe managed HTTPS files")
    previous = {path: (path.read_bytes(), path.stat().st_mode & 0o777) if path.exists() else None for path in paths}
    added = []
    enabled = subprocess.run(["systemctl", "is-enabled", "--quiet", "ftm-caddy"], capture_output=True).returncode == 0
    try:
        _atomic(caddyfile, proposed)
        _atomic(saved_state, json.dumps({"version": 1, "mode": "probe", "host": host, "caddy_version": version}))
        _atomic(firewall_wrapper, "#!/usr/bin/python3 -I\nimport runpy,sys\nsys.path.insert(0, '/opt/ftm/current')\nrunpy.run_module('ftm.https_probe', run_name='__main__')\n", mode=0o755)
        firewall_wrapper.chmod(0o755)
        _atomic(firewall_unit, """[Unit]
Description=FreeTurn Manager scoped HTTPS firewall
After=network-online.target vps-vk-network.service
Wants=network-online.target
Before=ftm-caddy.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/ftm-https-firewall --ensure-firewall
User=root
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
CapabilityBoundingSet=CAP_NET_ADMIN
ReadWritePaths=/run
TimeoutStartSec=30
""", mode=0o644)
        _atomic(unit, f"""[Unit]
Description=FreeTurn Manager trusted HTTPS edge
After=network-online.target ftm-https-firewall.service
Wants=network-online.target
Requires=ftm-https-firewall.service

[Service]
Type=simple
User=ftm-caddy
Group=ftm-caddy
ExecStart={executable} run --config %d/Caddyfile --adapter caddyfile
LoadCredential=Caddyfile:/etc/ftm/Caddyfile
Environment=XDG_DATA_HOME=/var/lib/ftm-caddy
Environment=GOMEMLIMIT=64MiB
Environment=GOMAXPROCS=1
StateDirectory=ftm-caddy
StateDirectoryMode=0700
UMask=0077
Restart=on-failure
RestartSec=5
TimeoutStopSec=15
MemoryHigh=96M
MemoryMax=128M
TasksMax=64
LimitNOFILE=2048
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ReadWritePaths=/var/lib/ftm-caddy

[Install]
WantedBy=multi-user.target
""", mode=0o644)
        _run(["systemd-analyze", "verify", str(unit), str(firewall_unit)])
        for rule in firewall_rules(state):
            if not rule_exists(rule):
                _run(rule)
                added.append(rule)
        _run(["systemctl", "daemon-reload"])
        subprocess.run(["systemctl", "reset-failed", "ftm-caddy"], capture_output=True, timeout=15)
        _run(["systemctl", "enable", "ftm-caddy"])
        _run(["systemctl", "restart", "ftm-caddy"])
        certificate = None
        deadline = time.monotonic() + TLS_WAIT_SECONDS
        while time.monotonic() < deadline:
            try:
                certificate = trusted_certificate(host)
                break
            except (OSError, RuntimeError, ValueError):
                time.sleep(2)
        if certificate is None:
            raise RuntimeError("Trusted public certificate was not obtained; private access retained")
        return {"trusted_https_probe": True, "public_api_enabled": False, "certificate": certificate,
                "vpn_or_ssh_restarted": False, "caddy_version": version}
    except BaseException:
        subprocess.run(["systemctl", "stop", "ftm-caddy"], capture_output=True, timeout=20)
        if not enabled:
            subprocess.run(["systemctl", "disable", "ftm-caddy"], capture_output=True, timeout=20)
        for path, value in previous.items():
            if value is None:
                path.unlink(missing_ok=True)
            else:
                _atomic(path, value[0], mode=value[1])
                path.chmod(value[1])
        for rule in reversed(added):
            if rule_exists(rule):
                remove = rule.copy()
                remove[5] = "-D"
                _run(remove)
        _run(["systemctl", "daemon-reload"])
        if already_active:
            _run(["systemctl", "start", "ftm-caddy"])
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--ensure-firewall", action="store_true")
    parser.add_argument("--checkpoint", type=Path)
    parser.add_argument("--offsite-sha256")
    args = parser.parse_args()
    if os.name != "posix" or os.geteuid() != 0:
        parser.error("Requires root and --apply on the agreed test VPS")
    if args.ensure_firewall:
        if args.apply or args.checkpoint or args.offsite_sha256:
            parser.error("Fixed firewall hook accepts no installation arguments")
        ensure_firewall()
        return
    if not args.apply or not args.checkpoint or not args.offsite_sha256:
        parser.error("Requires --apply, --checkpoint and --offsite-sha256")
    print(json.dumps(install(args.checkpoint, args.offsite_sha256)))


if __name__ == "__main__":
    try:
        main()
    except (ValidationError, RuntimeError) as error:
        print("HTTPS probe failed: " + str(error), file=__import__("sys").stderr)
        raise SystemExit(1)
    except (ValueError, OSError, KeyError, tarfile.TarError):
        print("HTTPS probe failed; private data withheld", file=__import__("sys").stderr)
        raise SystemExit(1)
