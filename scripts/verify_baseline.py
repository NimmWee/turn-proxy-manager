"""Verify the preserved baseline against the committed SHA256 allowlist."""

import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys


def verify_baseline(root):
    root = Path(root).resolve()
    try:
        lock = json.loads((root / "upstreams.lock.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise ValueError("Cannot read baseline lock") from None
    if not isinstance(lock, dict) or type(lock.get("schema_version")) is not int or lock["schema_version"] != 1:
        raise ValueError("Unsupported baseline lock")
    files = lock.get("baseline_files")
    if not isinstance(files, dict) or not files:
        raise ValueError("Empty or invalid baseline allowlist")
    base = root / "vendor/vps"
    if (root / "vendor").is_symlink() or base.is_symlink():
        raise ValueError("Baseline directory must not be a symlink")
    for name, digest in files.items():
        if not isinstance(name, str) or not name or "\\" in name or ":" in name:
            raise ValueError("Unsafe baseline path")
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts or name != relative.as_posix():
            raise ValueError("Unsafe baseline path")
        if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise ValueError("Invalid SHA256 in baseline lock")
        target = base
        for part in relative.parts:
            target = target / part
            if target.is_symlink():
                raise ValueError("Baseline symlink rejected")
        if not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest() != digest:
            raise ValueError(f"Missing or modified baseline file: {name}")
    return len(files)


def main():
    try:
        count = verify_baseline(Path(__file__).resolve().parents[1])
        print(f"PASS: {count} preserved baseline files match SHA256 lock")
        return 0
    except (ValueError, OSError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
