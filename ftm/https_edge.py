"""Enable the typed admin API behind trusted TLS; no VPN changes or public bind."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import urllib.error
import urllib.request

from .agent import NetworkAgent, _atomic, _run
from .checkpoint import _read_encrypted, capture_live, open_checkpoint
from .https_probe import config as render_caddy, trusted_certificate
from .installer import read_private_json
from .store import Store, ValidationError
from .web_auth import validate_config

DIRECTORY = Path("/etc/ftm")


def render(host, web):
    web = validate_config(web)
    public = web.get("public_origin")
    if public and public != "https://" + host:
        raise ValidationError("HTTPS origin must match the already provisioned IP certificate")
    return render_caddy(host, panel_slug=web["panel_slug"] if public else None)


def planned_config(state, web):
    saved = read_private_json(DIRECTORY / "https.json")
    if (set(saved) != {"version", "mode", "host", "caddy_version"} or saved["version"] != 1
            or saved["mode"] not in ("probe", "public") or saved["host"] != state["endpoint"]
            or not isinstance(saved["caddy_version"], str) or not re.fullmatch(r"\d+\.\d+\.\d+", saved["caddy_version"])):
        raise ValidationError("Existing HTTPS edge does not match this host")
    proposed = render(state["endpoint"], web)
    saved["mode"] = "public" if web.get("public_origin") else "probe"
    return saved, proposed


def sync_config(state):
    """Data-only recovery: regenerate edge config using trusted installed code."""
    saved, proposed = planned_config(state, read_private_json(DIRECTORY / "web.json", 16384))
    _atomic(DIRECTORY / "Caddyfile", proposed)
    _atomic(DIRECTORY / "https.json", json.dumps(saved))


def active(service):
    return subprocess.run(["systemctl", "is-active", "--quiet", service], capture_output=True, timeout=10).returncode == 0


def wait_ready(host, *, tls):
    for attempt in range(30):
        try:
            if tls:
                trusted_certificate(host)
            else:
                with urllib.request.urlopen("http://127.0.0.1:8080/", timeout=2) as response:
                    if response.status != 200:
                        raise RuntimeError("API health check failed")
            return
        except (OSError, RuntimeError, ValueError):
            if attempt == 29:
                raise RuntimeError("HTTPS panel readiness failed") from None
            time.sleep(0.2)


def enable(checkpoint, offsite_sha256):
    import fcntl
    state = read_private_json("/var/lib/vps-vk/main/state.json", 1048576)
    agent = NetworkAgent(state, config_dir="/etc/vps-vk/main", state_dir="/var/lib/ftm-agent")
    host = state["endpoint"]
    trusted_certificate(host)
    fd = os.open("/run/lock/vps-vk.lock", os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        web = validate_config(read_private_json(DIRECTORY / "web.json", 16384))
        proposed = dict(web, version=2, secure_cookie=True, public_origin="https://" + host)
        edge, caddy = planned_config(state, proposed)
        current_edge = read_private_json(DIRECTORY / "https.json")
        if (web == proposed and current_edge["mode"] == "public" and (DIRECTORY / "Caddyfile").read_text() == caddy
                and active("ftm-api") and active("ftm-caddy")):
            return {"public_api_enabled": True, "changed": False, "vpn_or_ssh_restarted": False}
        raw = _read_encrypted(checkpoint)
        if hashlib.sha256(raw).hexdigest() != offsite_sha256:
            raise ValidationError("Matching offsite checkpoint required")
        phrase = Path("/root/ftm-test-backup.pass")
        if phrase.is_symlink() or phrase.stat().st_uid != 0 or phrase.stat().st_mode & 0o077:
            raise ValidationError("Private recovery phrase required")
        snapshot = open_checkpoint(raw, phrase.read_text().strip())
        if snapshot != capture_live(Store("/var/lib/ftm/manager.sqlite3"), agent):
            raise ValidationError("Take a fresh checkpoint before enabling the public panel")
        executable = Path("/opt/ftm/caddy") / edge["caddy_version"] / "caddy"
        if executable.is_symlink() or executable.stat().st_uid != 0 or executable.stat().st_mode & 0o022:
            raise ValidationError("Root-owned pinned Caddy required")
        checked = subprocess.run(["runuser", "-u", "ftm-caddy", "--", "env", "XDG_DATA_HOME=/var/lib/ftm-caddy",
                                  str(executable), "validate", "--config", "-", "--adapter", "caddyfile"],
                                 input=caddy.encode(), capture_output=True, timeout=30)
        if checked.returncode:
            raise RuntimeError("Pinned Caddy rejected the public panel route")
        note_path = Path("/root/ftm-web-login.json")
        note = read_private_json(note_path)
        paths = [DIRECTORY / name for name in ("web.json", "Caddyfile", "https.json")] + [note_path]
        if any(path.is_symlink() or path.stat().st_uid != 0 or path.stat().st_mode & 0o077 for path in paths):
            raise ValidationError("Private root configuration required")
        previous = {path: path.read_bytes() for path in paths}
        was_active = {service: active(service) for service in ("ftm-api", "ftm-caddy")}
        if not all(was_active.values()):
            raise ValidationError("A healthy private API and HTTPS edge are required")

        def start():
            _run(["systemctl", "reset-failed", "ftm-api", "ftm-caddy"])
            _run(["systemctl", "start", "ftm-api"])
            wait_ready(host, tls=False)
            _run(["systemctl", "start", "ftm-caddy"])
            wait_ready(host, tls=True)

        try:
            _run(["systemctl", "stop", "ftm-caddy"])
            _run(["systemctl", "stop", "ftm-api"])
            _atomic(DIRECTORY / "web.json", json.dumps(proposed))
            sync_config(state)
            note.update({"public_url": "https://" + host + "/a/" + proposed["panel_slug"] + "/",
                         "access": "trusted HTTPS; loopback API only"})
            _atomic(note_path, json.dumps(note))
            start()
            # No credentials needed for the first public-boundary assertion.
            try:
                urllib.request.urlopen("https://" + host + "/a/" + proposed["panel_slug"] + "/api/status", timeout=5)
            except urllib.error.HTTPError as error:
                if error.code != 401:
                    raise RuntimeError("Public API authentication boundary failed") from None
            else:
                raise RuntimeError("Public API accepted an unauthenticated request")
        except BaseException:
            subprocess.run(["systemctl", "stop", "ftm-caddy", "ftm-api"], capture_output=True, timeout=30)
            for path, data in previous.items():
                _atomic(path, data)
            start()
            raise RuntimeError("HTTPS enable failed; previous private configuration recovered") from None
        return {"public_api_enabled": True, "changed": True, "secure_cookie": True,
                "fixed_https_origin": True, "api_loopback_only": True, "vpn_or_ssh_restarted": False}
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--checkpoint", required=True, type=Path)
    parser.add_argument("--offsite-sha256", required=True)
    args = parser.parse_args()
    if not args.apply or os.name != "posix" or os.geteuid() != 0:
        parser.error("Requires root and --apply on the agreed test VPS")
    try:
        print(json.dumps(enable(args.checkpoint, args.offsite_sha256)))
    except Exception:
        print("HTTPS enable failed; private data withheld", file=__import__("sys").stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
