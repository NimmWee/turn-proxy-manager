"""Trusted TLS and post-write rollback check on the agreed test VPS only."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request
from unittest.mock import patch

sys.path.insert(0, "/opt/ftm/current")
from ftm import https_probe
from ftm.agent import _run
from ftm.legacy import baseline_module


def verify(checkpoint, digest):
    app = baseline_module()
    conf, directory = app.paths("main")
    state = app.load_state("main")
    protected = [conf / name for name in ("wireguard.conf", "clients.json", "obf.key")]
    protected += [directory / "state.json", directory / "profiles/iphone-import.txt",
                  Path("/var/lib/ftm-agent/managed.json"), Path("/etc/ftm/web.json")]
    before = {path: path.read_bytes() for path in protected}
    pids = {name: _run(["systemctl", "show", name, "-p", "MainPID", "--value"])
            for name in ("vps-vk", "ssh", "ftm-api")}
    result = https_probe.install(checkpoint, digest)
    saved = {path: path.read_bytes() for path in (Path("/etc/ftm/Caddyfile"), Path("/etc/ftm/https.json"),
                                                 Path("/etc/systemd/system/ftm-caddy.service"))}
    # Certificate-wait timeout after writing config and starting the service.
    # The existing trusted cert remains in the isolated Caddy state directory.
    with patch.object(https_probe, "TLS_WAIT_SECONDS", 0):
        try:
            https_probe.install(checkpoint, digest)
        except RuntimeError as error:
            if "Trusted public certificate was not obtained" not in str(error):
                raise
        else:
            raise RuntimeError("Injected post-start failure was not detected")
    if any(path.read_bytes() != raw for path, raw in saved.items()):
        raise RuntimeError("HTTPS rollback did not restore its previous configuration")
    _run(["systemctl", "restart", "ftm-https-firewall"])
    _run(["systemctl", "restart", "ftm-https-firewall"])
    if _run(["systemctl", "is-active", "ftm-caddy"]).strip() != "active":
        raise RuntimeError("HTTPS did not survive its firewall hook")
    for attempt in range(20):
        try:
            https_probe.trusted_certificate(state["endpoint"])
            break
        except OSError:
            if attempt == 19:
                raise RuntimeError("Trusted HTTPS did not recover") from None
            time.sleep(0.2)
    with urllib.request.urlopen("https://" + state["endpoint"] + "/", timeout=15) as response:
        if response.status != 200 or "Сервис готовится".encode() not in response.read():
            raise RuntimeError("Neutral HTTPS page is not available")
    for path in ("/var/lib/ftm/manager.sqlite3", "/var/lib/ftm-agent/managed.json", "/etc/vps-vk/main/obf.key"):
        if subprocess.run(["runuser", "-u", "ftm-caddy", "--", "test", "-r", path], capture_output=True).returncode == 0:
            raise RuntimeError("HTTPS user can read root VPN data")
    if any(path.read_bytes() != raw for path, raw in before.items()):
        raise RuntimeError("TLS setup changed VPN or web identity")
    if any(_run(["systemctl", "show", name, "-p", "MainPID", "--value"]) != pid for name, pid in pids.items()):
        raise RuntimeError("TLS setup restarted VPN, SSH or API")
    return {"result": "PASS", "trusted_chain_and_ip_san": True, "neutral_page_only": True,
            "post_start_failure_rollback": True, "repeat_scoped_firewall_hook": True,
            "caddy_cannot_read_root_vpn_data": True, "vpn_profile_and_vpn_ssh_api_pids_unchanged": True,
            "caddy_version": result["caddy_version"], "certificate": result["certificate"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-vps-apply", action="store_true")
    parser.add_argument("--checkpoint", required=True, type=Path)
    parser.add_argument("--offsite-sha256", required=True)
    args = parser.parse_args()
    if not args.test_vps_apply or os.name != "posix" or os.geteuid() != 0:
        parser.error("Requires root and --test-vps-apply on the agreed test VPS")
    try:
        result = verify(args.checkpoint, args.offsite_sha256)
        report = Path("/root/ftm-https-probe-report.json")
        report.write_text(json.dumps(result, indent=2))
        report.chmod(0o600)
        print(json.dumps(result))
    except Exception:
        print("HTTPS verification failed; private data withheld", file=sys.stderr)
        raise SystemExit(1)
