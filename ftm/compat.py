"""Compatibility entrypoint for status/profiles after dynamic peer adoption."""

import argparse
import json
import os
from pathlib import Path
import sys

from .agent import _run
from .installer import read_private_json
from .legacy import baseline_module
from .store import valid_key, ValidationError


def managed_status(state, registry, runner=_run):
    app = baseline_module()
    interface = app.iface(state)
    entries = list(registry["devices"].values())
    known = set()
    expected = set()
    disabled = set()
    adopted = set()
    pending = 0
    for record in entries:
        public = record["spec"]["wg_public_key"]
        if not valid_key(public):
            raise ValidationError("Invalid root ownership record")
        known.add(public)
        if record.get("legacy"):
            adopted.add(public)
        if record.get("enabled", record["phase"] != "revoked"):
            expected.add(public)
        else:
            disabled.add(public)
        pending += record["phase"] not in ("active", "revoked")
    baseline_public = {peer["public_key"] for peer in state["clients"].values()}
    expected.update(baseline_public - adopted)
    known.update(baseline_public)
    services = {}
    for name in (*app.units(state), "fail2ban"):
        try:
            services[name] = runner(["systemctl", "is-active", name]).strip()
        except RuntimeError:
            services[name] = "inactive_or_unavailable"
    try:
        actual = set(runner(["wg", "show", interface, "peers"]).split())
        interface_available = True
    except RuntimeError:
        actual, interface_available = set(), False
    missing, disabled_present = expected - actual, disabled & actual
    return {"version": app.VERSION, "managed": bool(entries), "instance": state["instance"],
            "endpoint": state["endpoint"] + ":" + str(state["port"]), "interface": interface,
            "services": services, "peers": len(actual), "expected_peers": len(expected),
            "missing_peers": len(missing), "disabled_peers_present": len(disabled_present),
            "unknown_peers": len(actual - known), "pending_root_operations": pending,
            "consistent": interface_available and not missing and not disabled_present and not pending
                          and all(value == "active" for value in services.values())}


def enabled_legacy_profiles(state, registry):
    disabled = {record["spec"]["wg_public_key"] for record in registry["devices"].values()
                if record.get("legacy") and not record.get("enabled", record["phase"] != "revoked")}
    return {name: link for name, link in baseline_module().profile_links(state).items()
            if state["clients"][name]["public_key"] not in disabled}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    app = baseline_module()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("status", "profiles", "install", "backup", "restore", "uninstall", "network-up", "network-down"))
    parser.add_argument("file", nargs="?")
    parser.add_argument("--instance", default="main")
    parser.add_argument("--endpoint")
    parser.add_argument("--port", type=int, default=56001)
    parser.add_argument("--backend-port", type=int, default=51830)
    parser.add_argument("--subnet", default="10.77.43.0/24")
    parser.add_argument("--vk-link-file")
    parser.add_argument("--bundle")
    parser.add_argument("--adopt-legacy", action="store_true")
    parser.add_argument("--qr", action="store_true")
    parser.add_argument("--show", action="store_true")
    args = parser.parse_args(argv)
    if os.name != "posix" or os.geteuid() != 0:
        raise ValidationError("Run on the VPS as root")
    registry_path = Path("/var/lib/ftm-agent/managed.json")
    registry = read_private_json(registry_path, 2 * 1024 ** 2) if registry_path.exists() and args.instance == "main" else {"devices": {}}
    if not isinstance(registry.get("devices"), dict):
        raise ValidationError("Invalid root ownership registry")
    if args.instance != "main" or args.command not in ("status", "profiles"):
        if registry["devices"]:
            raise ValidationError("Managed state requires the managed checkpoint/startup tools; legacy mutation blocked")
        original_argv = sys.argv
        try:
            sys.argv = ["vps-vk", *argv]
            return app.main()
        finally:
            sys.argv = original_argv
    state = app.load_state(args.instance)
    if args.command == "status":
        report = managed_status(state, registry)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0 if report["consistent"] else 1
    import fcntl
    with Path("/run/lock/vps-vk.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        # Reread under lock to avoid showing a profile revoked concurrently.
        registry = read_private_json(registry_path, 2 * 1024 ** 2) if registry_path.exists() else {"devices": {}}
        state = app.load_state(args.instance)
        if args.endpoint:
            state = app.migrate_state(state, args.endpoint)
            app.atomic_write(app.paths(state["instance"])[1] / "state.json", json.dumps(state, indent=2))
        output = app.paths(state["instance"])[1] / "profiles"
        app.mkdir(output)
        links = enabled_legacy_profiles(state, registry)
        for name in ("iphone", "android"):
            text, qr = output / (name + "-import.txt"), output / (name + "-qr.png")
            if name not in links:
                for path in (text, qr):
                    if path.is_symlink():
                        raise ValidationError("Unexpected profile symlink")
                    path.unlink(missing_ok=True)
                continue
            app.atomic_write(text, links[name] + "\n")
            if args.qr:
                app.run(["qrencode", "-o", qr, "-s", "7", "-l", "M"], links[name])
                qr.chmod(0o600)
        print(str(output))
        if args.show:
            for name, link in links.items():
                print(name + ":\n" + link)
        return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError, OSError, KeyError):
        print("Compatibility operation rejected or failed; private data withheld", file=sys.stderr)
        raise SystemExit(2)
