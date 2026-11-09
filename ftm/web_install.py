"""Install a loopback-only rootless web service with systemd credentials."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import time
import urllib.request

from .agent import NetworkAgent, _atomic, _run
from .checkpoint import _read_encrypted, capture_live as capture, open_checkpoint
from .installer import read_private_json
from .runtime import _trusted_directory
from .store import Store, ValidationError
from .web_auth import load_config, make_config

UNIT = """[Unit]
Description=FreeTurn Manager private web panel
Requires=ftm-control.service
After=ftm-control.service
StartLimitIntervalSec=60
StartLimitBurst=4

[Service]
Type=simple
User=ftm-api
Group=ftm-api
ExecStart=/usr/local/bin/ftm-api --config %d/web.json --port 8080
LoadCredential=web.json:/etc/ftm/web.json
RuntimeDirectory=ftm-web
RuntimeDirectoryMode=0700
Environment=PYTHONDONTWRITEBYTECODE=1
UMask=0077
Restart=on-failure
RestartSec=5
TimeoutStopSec=15
MemoryHigh=112M
MemoryMax=160M
TasksMax=48
LimitNOFILE=256
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
CapabilityBoundingSet=
LockPersonality=yes
ReadWritePaths=/run/ftm-web

[Install]
WantedBy=multi-user.target
"""


def install(checkpoint, offsite_sha256):
    import fcntl
    import pwd
    if pwd.getpwnam("ftm-api").pw_uid == 0:
        raise ValidationError("Unprivileged API account required")
    runtime = Path("/opt/ftm/current").resolve()
    requirements = runtime / "requirements.lock"
    if not (runtime / "web/dist/index.html").is_file() or not requirements.is_file():
        raise ValidationError("Install the runtime with built web assets and dependency lock first")
    encrypted = _read_encrypted(checkpoint)
    if hashlib.sha256(encrypted).hexdigest() != offsite_sha256:
        raise ValidationError("Matching offsite checkpoint required")
    phrase = Path("/root/ftm-test-backup.pass")
    if phrase.is_symlink() or phrase.stat().st_uid != 0 or phrase.stat().st_mode & 0o077:
        raise ValidationError("Private recovery phrase required")
    snapshot = open_checkpoint(encrypted, phrase.read_text().strip())
    state = read_private_json("/var/lib/vps-vk/main/state.json", 1048576)
    fd = os.open("/run/lock/vps-vk.lock", os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        if snapshot != capture(Store("/var/lib/ftm/manager.sqlite3"), NetworkAgent(state, config_dir="/etc/vps-vk/main", state_dir="/var/lib/ftm-agent")):
            raise ValidationError("Take a fresh checkpoint before web deployment")
    finally:
        os.close(fd)
    venvironments = Path("/opt/ftm/venvs")
    _trusted_directory(venvironments)
    lock_digest = hashlib.sha256(requirements.read_bytes()).hexdigest()
    venv = venvironments / lock_digest[:16]
    if venv.is_symlink():
        raise ValidationError("API environment symlink rejected")
    if venv.exists():
        _trusted_directory(venv)
        for path in venv.rglob("*"):
            info = path.stat()
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ValidationError("Existing API environment must be root-owned and read-only to other users")
    marker = venv / ".ftm-requirements"
    if not marker.is_file() or marker.read_text() != lock_digest:
        mask = os.umask(0o022)
        try:
            result = subprocess.run(["/usr/bin/python3", "-m", "venv", str(venv)], capture_output=True, timeout=90)
            if result.returncode:
                raise RuntimeError("Python venv unavailable; install Ubuntu python3-venv")
            result = subprocess.run([str(venv / "bin/python"), "-m", "pip", "install", "--disable-pip-version-check",
                                     "--require-hashes", "--only-binary=:all:", "-r", str(requirements)], capture_output=True, timeout=240)
            if result.returncode:
                raise RuntimeError("Pinned API dependency installation failed")
            _atomic(marker, lock_digest, mode=0o644)
        finally:
            os.umask(mask)
    _trusted_directory(venv)
    config_dir = Path("/etc/ftm")
    if config_dir.is_symlink():
        raise ValidationError("Web configuration directory symlink rejected")
    config_dir.mkdir(mode=0o700, exist_ok=True)
    if config_dir.stat().st_uid != 0 or config_dir.stat().st_mode & 0o077:
        raise ValidationError("Manager config directory must remain root-owned 0700")
    config_path = config_dir / "web.json"
    login_note = Path("/root/ftm-web-login.json")
    if config_path.exists():
        config = load_config(config_path)
    else:
        password = secrets.token_urlsafe(24)
        config = make_config("admin", password)
        _atomic(config_path, json.dumps(config))
        _atomic(login_note, json.dumps({"username": "admin", "password": password,
                "panel_path": "/a/" + config["panel_slug"] + "/", "server_listens": "127.0.0.1:8080",
                "access": "SSH forwarding required; no public HTTP listener"}, ensure_ascii=False))
        del password
    if config["secure_cookie"]:
        raise ValidationError("This installer currently supports only private loopback HTTP")
    unit, wrapper = Path("/etc/systemd/system/ftm-api.service"), Path("/usr/local/bin/ftm-api")
    if any(path.is_symlink() or (path.exists() and path.stat().st_uid != 0) for path in (unit, wrapper)):
        raise ValidationError("Unsafe API entrypoint files")
    saved = {path: (path.read_bytes(), path.stat().st_mode & 0o777) if path.exists() else None for path in (unit, wrapper)}
    active = subprocess.run(["systemctl", "is-active", "--quiet", "ftm-api"], capture_output=True).returncode == 0
    enabled = subprocess.run(["systemctl", "is-enabled", "--quiet", "ftm-api"], capture_output=True).returncode == 0
    if not active:
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", 8080))
            except OSError:
                raise ValidationError("Loopback API port is already in use") from None
    recovery = Path("/root") / ("ftm-api-before-" + secrets.token_hex(5))
    recovery.mkdir(mode=0o700)
    for index, value in enumerate(saved.values()):
        if value:
            _atomic(recovery / f"entry-{index}.bin", value[0])
    try:
        script = f"#!{venv}/bin/python -I\nimport runpy,sys\nsys.path.insert(0,'/opt/ftm/current')\nrunpy.run_module('ftm.web',run_name='__main__')\n"
        _atomic(wrapper, script, mode=0o755)
        wrapper.chmod(0o755)
        _atomic(unit, UNIT, mode=0o644)
        _run(["systemd-analyze", "verify", str(unit)])
        _run(["systemctl", "daemon-reload"])
        subprocess.run(["systemctl", "reset-failed", "ftm-api"], capture_output=True, timeout=20)
        _run(["systemctl", "enable", "ftm-api"])
        _run(["systemctl", "restart", "ftm-api"])
        for attempt in range(30):
            try:
                with urllib.request.urlopen("http://127.0.0.1:8080/", timeout=2) as response:
                    if response.status != 200:
                        raise RuntimeError("API health check failed")
                break
            except (OSError, RuntimeError):
                if attempt == 29:
                    raise RuntimeError("API did not become ready") from None
                time.sleep(0.2)
    except BaseException:
        subprocess.run(["systemctl", "stop", "ftm-api"], capture_output=True, timeout=20)
        if not enabled:
            subprocess.run(["systemctl", "disable", "ftm-api"], capture_output=True, timeout=20)
        for path, value in saved.items():
            if value is None:
                path.unlink(missing_ok=True)
            else:
                _atomic(path, value[0], mode=value[1])
                path.chmod(value[1])
        _run(["systemctl", "daemon-reload"])
        if active:
            _run(["systemctl", "start", "ftm-api"])
        raise
    return {"private_web_service_installed": True, "listen": "127.0.0.1:8080", "uid": "ftm-api",
            "root_sqlite_exposed": False, "public_ports_opened": False, "vpn_or_ssh_restarted": False,
            "login_note": str(login_note) if login_note.is_file() else None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--offsite-sha256", required=True)
    args = parser.parse_args()
    if not args.apply or os.name != "posix" or os.geteuid() != 0:
        parser.error("Requires root and --apply on the agreed test VPS")
    print(json.dumps(install(args.checkpoint, args.offsite_sha256)))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, OSError):
        print("Private API deployment failed; sensitive details withheld", file=__import__("sys").stderr)
        raise SystemExit(1)
