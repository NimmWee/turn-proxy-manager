"""Install the limited root IPC service; no API or public listener is started."""

import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import time

from .agent import _atomic, _run
from .control import request
from .store import ValidationError

UNIT = """[Unit]
Description=FreeTurn Manager restricted control service
After=vps-vk-network.service vps-vk.service
StartLimitIntervalSec=60
StartLimitBurst=4

[Service]
Type=simple
User=root
Group=ftm-api
ExecStart=/usr/local/bin/ftm-control --serve
RuntimeDirectory=ftm
RuntimeDirectoryMode=0750
UMask=0077
Restart=on-failure
RestartSec=5
TimeoutStopSec=10
MemoryMax=96M
TasksMax=16
LimitNOFILE=128
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6
CapabilityBoundingSet=CAP_NET_ADMIN CAP_CHOWN CAP_DAC_OVERRIDE
LockPersonality=yes
ReadWritePaths=/var/lib/ftm /var/lib/ftm-agent /etc/vps-vk/main /run/ftm /run/lock

[Install]
WantedBy=multi-user.target
"""


def install():
    import pwd
    installed = Path("/opt/ftm/current/ftm/control.py")
    if not installed.is_file() or installed.stat().st_uid != 0 or installed.stat().st_mode & 0o022:
        raise ValidationError("Install the root-owned runtime with control.py first")
    try:
        account = pwd.getpwnam("ftm-api")
    except KeyError:
        _run(["/usr/sbin/useradd", "--system", "--user-group", "--home-dir", "/var/lib/ftm-api",
              "--no-create-home", "--shell", "/usr/sbin/nologin", "ftm-api"])
        account = pwd.getpwnam("ftm-api")
    if account.pw_uid == 0 or account.pw_gid == 0 or account.pw_shell not in ("/usr/sbin/nologin", "/bin/false"):
        raise ValidationError("API account must be an unprivileged service account")
    unit = Path("/etc/systemd/system/ftm-control.service")
    wrapper = Path("/usr/local/bin/ftm-control")
    if any(path.is_symlink() or (path.exists() and path.stat().st_uid != 0) for path in (unit, wrapper)):
        raise ValidationError("Unsafe control service files")
    saved = {path: (path.read_bytes(), path.stat().st_mode & 0o777) if path.exists() else None for path in (unit, wrapper)}
    active = subprocess.run(["systemctl", "is-active", "--quiet", "ftm-control"], capture_output=True).returncode == 0
    enabled = subprocess.run(["systemctl", "is-enabled", "--quiet", "ftm-control"], capture_output=True).returncode == 0
    recovery = Path("/root") / ("ftm-control-before-" + secrets.token_hex(5))
    recovery.mkdir(mode=0o700)
    for index, value in enumerate(saved.values()):
        if value:
            _atomic(recovery / f"entry-{index}.bin", value[0])
    try:
        _atomic(wrapper, "#!/usr/bin/python3 -I\nimport runpy, sys\nsys.path.insert(0, '/opt/ftm/current')\nrunpy.run_module('ftm.control', run_name='__main__')\n", mode=0o755)
        wrapper.chmod(0o755)
        _atomic(unit, UNIT, mode=0o644)
        _run(["systemd-analyze", "verify", str(unit)])
        _run(["systemctl", "daemon-reload"])
        # A newly installed, not-yet-loaded unit makes reset-failed return
        # nonzero. The subsequent enable/restart/readiness checks are strict.
        subprocess.run(["systemctl", "reset-failed", "ftm-control"], capture_output=True, timeout=20)
        _run(["systemctl", "enable", "ftm-control"])
        _run(["systemctl", "restart", "ftm-control"])
        for attempt in range(15):
            try:
                request("users.list", timeout=2)
                break
            except (ValueError, RuntimeError, OSError):
                if attempt == 14:
                    raise RuntimeError("Control service did not become ready") from None
                time.sleep(0.2)
    except BaseException:
        subprocess.run(["systemctl", "stop", "ftm-control"], capture_output=True, timeout=20)
        if not enabled:
            subprocess.run(["systemctl", "disable", "ftm-control"], capture_output=True, timeout=20)
        for path, value in saved.items():
            if value is None:
                path.unlink(missing_ok=True)
            else:
                _atomic(path, value[0], mode=value[1])
                path.chmod(value[1])
        _run(["systemctl", "daemon-reload"])
        if active:
            _run(["systemctl", "start", "ftm-control"])
        raise
    return {"control_service_installed": True, "api_account_unprivileged": True,
            "sqlite_remains_root_owned": True, "public_listener_started": False,
            "vpn_and_ssh_restarted": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if not args.apply or os.name != "posix" or os.geteuid() != 0:
        parser.error("Requires root and --apply")
    print(json.dumps(install()))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, OSError):
        print("Control service installation failed; private data withheld", file=__import__("sys").stderr)
        raise SystemExit(1)
