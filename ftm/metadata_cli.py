"""Local metadata administration. Network changes require the separate root agent."""

import argparse
import json
from pathlib import Path
import sqlite3
import sys

from .installer import read_private_json
from .store import Store, ValidationError


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=Path("/var/lib/ftm/manager.sqlite3"))
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init")
    legacy = commands.add_parser("import-legacy")
    legacy.add_argument("--state", type=Path, default=Path("/var/lib/vps-vk/main/state.json"))
    backup = commands.add_parser("backup")
    backup.add_argument("destination", type=Path)
    users = commands.add_parser("users").add_subparsers(dest="action", required=True)
    users.add_parser("list")
    create = users.add_parser("create")
    create.add_argument("name")
    create.add_argument("--device-limit", type=int)
    for action in ("disable", "enable"):
        users.add_parser(action).add_argument("user_id")
    devices = commands.add_parser("devices").add_subparsers(dest="action", required=True)
    listing = devices.add_parser("list")
    listing.add_argument("--user-id")
    create = devices.add_parser("add")
    create.add_argument("user_id")
    create.add_argument("name")
    create.add_argument("--platform", choices=("android", "windows", "ios", "other"), required=True)
    create.add_argument("--public-key-file", type=Path, required=True)
    create.add_argument("--request-id", required=True)
    devices.add_parser("revoke").add_argument("device_id")
    args = parser.parse_args(argv)
    try:
        store = Store(args.db)
        if args.command != "init" and not args.db.is_file():
            raise ValidationError("Database is not initialized")
        if args.command == "init":
            store.initialize()
            result = {"initialized": True, "network_changed": False}
        elif args.command == "import-legacy":
            result = store.import_legacy(read_private_json(args.state, 1048576))
            result["network_changed"] = False
        elif args.command == "backup":
            store.backup(args.destination)
            result = {"backup_created": True, "encrypted": False, "private_file": True}
        elif args.command == "users":
            if args.action == "list":
                result = store.list_users()
            elif args.action == "create":
                result = store.create_user(args.name, args.device_limit)
            else:
                store.set_user_enabled(args.user_id, args.action == "enable")
                result = {"updated": True, "network_apply_required": True}
        elif args.action == "list":
            result = store.list_devices(args.user_id)
        elif args.action == "add":
            if not args.public_key_file.is_file() or args.public_key_file.stat().st_size > 1024:
                raise ValidationError("Invalid public key file")
            public = args.public_key_file.read_text(encoding="ascii").strip()
            device = store.create_device(args.user_id, args.name, args.platform, public, args.request_id)
            result = {"id": device["id"], "ip": device["ip"], "state": device["state"], "network_apply_required": True}
        else:
            store.revoke_device(args.device_id)
            result = {"revocation_queued": True, "network_apply_required": True}
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (ValueError, OSError, sqlite3.Error):
        print("Metadata operation rejected or failed; private data withheld", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
