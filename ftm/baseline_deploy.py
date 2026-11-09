"""Explicit test-VPS baseline deployment; the full Manager installer stays unavailable."""

import argparse
import json
from pathlib import Path
import sys

from .legacy import baseline_module
from .ssh_protection import configure
from scripts.verify_baseline import verify_baseline


def check_baseline_only(registry_path=Path("/var/lib/ftm-agent/managed.json")):
    registry_path = Path(registry_path)
    if registry_path.is_symlink():
        raise ValueError("Unsafe agent registry")
    if registry_path.exists():
        if registry_path.stat().st_size > 2 * 1024 ** 2:
            raise ValueError("Unsafe agent registry")
        registry = json.loads(registry_path.read_text())
        if not isinstance(registry, dict) or not isinstance(registry.get("devices"), dict):
            raise ValueError("Unsafe agent registry")
        if registry["devices"]:
            raise ValueError("Baseline reinstall would overwrite managed peers; use a managed migration")


def run_baseline_install(vk_link_file, endpoint, *, qr=False):
    app = baseline_module()
    endpoint = app.validate_endpoint(endpoint)
    check_baseline_only()
    root = Path(__file__).resolve().parents[1]
    verify_baseline(root)
    original_policy, original_argv = app.configure_fail2ban, sys.argv
    original_install = app.install
    def guarded_install(*args, **kwargs):
        # legacy main has acquired vps-vk.lock before calling install.
        check_baseline_only()
        return original_install(*args, **kwargs)
    try:
        # Preserve the reviewed upstream code; replace only its obsolete 30-day policy hook.
        app.configure_fail2ban = configure
        app.install = guarded_install
        sys.argv = ["vps-vk", "install", "--bundle", str(root / "vendor/vps"),
                    "--endpoint", endpoint, "--vk-link-file", str(vk_link_file)]
        if qr:
            sys.argv.append("--qr")
        return app.main()
    finally:
        app.configure_fail2ban, sys.argv = original_policy, original_argv
        app.install = original_install


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="Explicitly allow baseline installation on the test VPS")
    parser.add_argument("--vk-link-file", type=Path, required=True)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--qr", action="store_true")
    args = parser.parse_args()
    if not args.apply:
        parser.error("Baseline deployment requires explicit --apply on the authorized test VPS")
    try:
        return run_baseline_install(args.vk_link_file, args.endpoint, qr=args.qr)
    except Exception:
        print("Baseline installation failed. Check the root-only server logs; secrets withheld.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
