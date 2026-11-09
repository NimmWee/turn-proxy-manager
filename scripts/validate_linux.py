"""Run all local checks on native Linux storage, including when launched from WSL.

NTFS mounts may not enforce chmod(0600). Use an isolated copy in /tmp so permission
tests exercise real Linux file semantics. Nothing is installed on the host.
"""

import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile


def main():
    if sys.platform != "linux":
        print("Run with Linux Python 3.10+ (Ubuntu 24.04 recommended).", file=sys.stderr)
        return 2
    source = Path(__file__).resolve().parents[1]
    checks = [
        ["python3", "scripts/verify_baseline.py"],
        ["python3", "vendor/vps/scripts/verify-package.py"],
        ["python3", "-m", "unittest", "discover", "-s", "vendor/vps/tests", "-v"],
        ["python3", "-m", "unittest", "discover", "-s", "tests", "-v"],
        ["bash", "-n", "install.sh", "vendor/vps/install.sh", "vendor/vps/scripts/build-freeturn.sh"],
        ["python3", "scripts/smoke_baseline.py"],
    ]
    with tempfile.TemporaryDirectory(prefix="ftm-verify-") as folder:
        root = Path(folder) / "project"
        shutil.copytree(source, root, ignore=shutil.ignore_patterns(".git", ".references", "logs", "__pycache__"))
        config = root / "examples/install.domain.json"
        config.chmod(0o600)
        checks.append(["bash", "install.sh", "--manager", "--non-interactive", "--config", str(config), "--dry-run"])
        for command in checks:
            result = subprocess.run(command, cwd=root, timeout=120)
            if result.returncode:
                print("FAIL: " + " ".join(command[:4]), file=sys.stderr)
                return result.returncode
    print(json.dumps({"result": "PASS", "python": platform.python_version(), "kernel": platform.release(),
                      "groups": len(checks), "production_installation_tested": False,
                      "vpn_e2e_tested": False}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
