"""Offline binary/CLI smoke. Does not configure VPN, systemd or firewall."""

import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.verify_baseline import verify_baseline


def smoke():
    verify_baseline(ROOT)
    if sys.platform != "linux" or platform.machine().lower() not in {"x86_64", "amd64", "aarch64", "arm64"}:
        raise ValueError("Smoke requires Linux amd64 or arm64; use Ubuntu 24.04/WSL")
    arch = "amd64" if platform.machine().lower() in {"x86_64", "amd64"} else "arm64"
    binary = ROOT / f"vendor/vps/artifacts/freeturn-linux-{arch}"
    # File mode is not preserved by Windows copy; chmod only the local executable, never system files.
    binary.chmod(0o755)
    with tempfile.TemporaryDirectory(prefix="ftm-smoke-") as folder:
        work = Path(folder)
        client_file = work / "clients.json"
        key_file = work / "obf.key"
        key_file.write_text("a" * 64 + "\n", encoding="ascii")  # Synthetic test key only.
        key_file.chmod(0o600)
        env = {**os.environ, "CLIENTS_FILE": str(client_file), "GOMAXPROCS": "1", "GOMEMLIMIT": "48MiB"}

        def run(*args):
            result = subprocess.run([str(binary), *args], cwd=work, env=env, capture_output=True,
                                    text=True, encoding="utf-8", timeout=10)
            if result.returncode:
                raise ValueError("Baseline command failed; captured output withheld")
            return result.stdout + result.stderr

        help_text = run("-h")
        for flag in ("-clients-file", "-obf-key-file", "-connect", "-listen"):
            if flag not in help_text:
                raise ValueError("Baseline CLI contract changed")
        cid = "0" * 32  # Synthetic smoke identifier, not a user's token.
        run("clients", "add", cid, "ftm-offline-smoke")
        if cid not in json.loads(client_file.read_text())["clients"] or cid not in run("clients", "list"):
            raise ValueError("CID add/list failed")
        run("clients", "remove", cid)
        if json.loads(client_file.read_text())["clients"]:
            raise ValueError("CID remove failed")
        # Ephemeral loopback listener: startup/version probe only, no user traffic or tunnel.
        with (work / "startup.log").open("w+b") as output:
            process = subprocess.Popen([str(binary), "-listen", "127.0.0.1:0", "-connect", "127.0.0.1:9",
                                        "-mode", "udp", "-clients-file", str(client_file),
                                        "-obf-profile", "rtpopus3", "-obf-key-file", str(key_file)],
                                       cwd=work, env=env, stdout=output, stderr=output)
            try:
                deadline = time.monotonic() + 5
                expected = "server version=4.1.2-vps1"
                while time.monotonic() < deadline:
                    output.seek(0)
                    text = output.read().decode("utf-8", errors="replace")
                    if process.poll() is not None:
                        raise ValueError("Baseline listener exited during startup")
                    if (expected in text and "Client ID authorization enabled" in text
                            and "OBF profile=rtpopus3: listener" in text):
                        break
                    time.sleep(0.05)
                else:
                    raise ValueError("Baseline startup/version not confirmed")
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
    return {"result": "PASS", "binary_version": "4.1.2-vps1", "architecture": arch, "wire_profile": "rtpopus3",
            "checks": ["sha256", "cli_help", "cid_add_list_remove", "loopback_startup_and_shutdown"],
            "vpn_traffic_tested": False, "vk_relay_tested": False, "system_configuration_changed": False}


if __name__ == "__main__":
    try:
        print(json.dumps(smoke(), ensure_ascii=False, indent=2))
    except (ValueError, OSError, subprocess.TimeoutExpired):
        print("FAIL: offline baseline smoke; VPN/E2E was not tested", file=sys.stderr)
        raise SystemExit(1)
