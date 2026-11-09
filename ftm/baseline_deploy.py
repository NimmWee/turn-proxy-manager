"""Explicit test-VPS baseline deployment; the full Manager installer stays unavailable."""

import argparse
from pathlib import Path
import sys

from .legacy import baseline_module
from .ssh_protection import configure
from scripts.verify_baseline import verify_baseline


def run_baseline_install(vk_link_file, endpoint, *, qr=False):
    app = baseline_module()
    endpoint = app.validate_endpoint(endpoint)
    root = Path(__file__).resolve().parents[1]
    verify_baseline(root)
    original_policy, original_argv = app.configure_fail2ban, sys.argv
    try:
        # Preserve the reviewed upstream code; replace only its obsolete 30-day policy hook.
        app.configure_fail2ban = configure
        sys.argv = ["vps-vk", "install", "--bundle", str(root / "vendor/vps"),
                    "--endpoint", endpoint, "--vk-link-file", str(vk_link_file)]
        if qr:
            sys.argv.append("--qr")
        return app.main()
    finally:
        app.configure_fail2ban, sys.argv = original_policy, original_argv


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
