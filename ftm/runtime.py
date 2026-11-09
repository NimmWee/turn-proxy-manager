"""Install a root-owned managed runtime and startup hook without restarting VPN."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile

from .agent import _atomic, _run, NetworkAgent
from .checkpoint import capture_live as capture, open_checkpoint, _read_encrypted
from .installer import read_private_json
from .store import Store, ValidationError


def _trusted_directory(path, mode=0o755):
    if path.is_symlink():
        raise ValidationError("Runtime directory symlink rejected")
    path.mkdir(mode=mode, parents=True, exist_ok=True)
    if path.stat().st_uid != 0 or path.stat().st_mode & 0o022:
        raise ValidationError("Runtime directories must be root-owned and not writable by other users")


def install(checkpoint, offsite_sha256):
    source = Path(__file__).resolve().parents[1]
    from scripts.verify_baseline import verify_baseline
    verify_baseline(source)
    state = read_private_json("/var/lib/vps-vk/main/state.json", 1048576)
    store = Store("/var/lib/ftm/manager.sqlite3")
    agent = NetworkAgent(state, config_dir="/etc/vps-vk/main", state_dir="/var/lib/ftm-agent")
    encrypted = _read_encrypted(checkpoint)
    if hashlib.sha256(encrypted).hexdigest() != offsite_sha256:
        raise ValidationError("Matching offsite-verified checkpoint is required")
    phrase = Path("/root/ftm-test-backup.pass")
    if phrase.is_symlink() or phrase.stat().st_uid != 0 or phrase.stat().st_mode & 0o077:
        raise ValidationError("Private recovery phrase required")
    snapshot = open_checkpoint(encrypted, phrase.read_text().strip())
    if snapshot != capture(store, agent):
        raise ValidationError("Take a fresh checkpoint before changing the runtime")
    files = [p.relative_to(source) for p in (source / "ftm").glob("*.py")]
    files += [Path("ftm/migrations/001_initial.sql"), Path("scripts/verify_baseline.py"), Path("upstreams.lock.json")]
    if (source / "requirements.lock").is_file():
        files.append(Path("requirements.lock"))
    if (source / "web/dist").is_dir():
        files += [path.relative_to(source) for path in (source / "web/dist").rglob("*") if path.is_file()]
    lock = json.loads((source / "upstreams.lock.json").read_text())
    files += [Path("vendor/vps") / name for name in lock["baseline_files"]]
    manifest = {}
    for name in sorted(files):
        path = source / name
        if path.is_symlink() or not path.is_file():
            raise ValidationError("Unsafe runtime source file")
        manifest[name.as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    digest = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()[:16]
    base = Path("/opt/ftm")
    releases = base / "releases"
    for path in (Path("/opt"), base, releases):
        _trusted_directory(path)
    release = releases / digest
    if not release.exists():
        staging = Path(tempfile.mkdtemp(prefix=".release-", dir=releases))
        staging.chmod(0o755)
        try:
            for name in files:
                target = staging / name
                target.parent.mkdir(parents=True, mode=0o755, exist_ok=True)
                shutil.copyfile(source / name, target)
                target.chmod(0o644)
            _atomic(staging / "runtime-manifest.json", json.dumps(manifest), mode=0o644)
            os.replace(staging, release)
        except BaseException:
            # Keep an incomplete private release for root diagnosis. Never use it.
            staging.chmod(0o700)
            raise
    if release.is_symlink() or any((release / name).is_symlink() or hashlib.sha256((release / name).read_bytes()).hexdigest() != expected
                                   for name, expected in manifest.items()):
        raise ValidationError("Existing runtime release differs from its manifest")
    current = base / "current"
    previous_target = os.readlink(current) if current.is_symlink() else None
    if current.exists() and not current.is_symlink():
        raise ValidationError("Expected a managed current symlink")
    if previous_target and not current.resolve().is_relative_to(releases.resolve()):
        raise ValidationError("Current runtime target is outside managed releases")
    wrappers = {
        Path("/usr/local/bin/ftm"): "ftm",
        Path("/usr/local/bin/vps-vk"): "ftm.compat",
        Path("/usr/local/bin/ftm-startup"): "ftm.startup",
    }
    dropin = Path("/etc/systemd/system/vps-vk-network.service.d/20-ftm-startup.conf")
    _trusted_directory(dropin.parent)
    for path in (*wrappers, dropin):
        if path.is_symlink() or (path.exists() and (not path.is_file() or path.stat().st_uid != 0)):
            raise ValidationError("Unsafe entrypoint or service hook")
    previous = {path: (path.read_bytes(), path.stat().st_mode & 0o777) if path.exists() else None for path in (*wrappers, dropin)}
    recovery = Path("/root") / ("ftm-runtime-before-" + digest)
    recovery.mkdir(mode=0o700, exist_ok=True)
    for index, (path, value) in enumerate(previous.items()):
        if value is not None and not (recovery / f"entry-{index}.bin").exists():
            _atomic(recovery / f"entry-{index}.bin", value[0])

    def switch(target):
        temporary = base / ".current-next"
        if temporary.exists() and not temporary.is_symlink():
            raise ValidationError("Unexpected runtime switch file")
        temporary.unlink(missing_ok=True)
        temporary.symlink_to(target)
        os.replace(temporary, current)

    try:
        switch(release)
        for path, module in wrappers.items():
            script = ("#!/usr/bin/python3 -I\nimport runpy, sys\nsys.path.insert(0, '/opt/ftm/current')\n"
                      f"runpy.run_module('{module}', run_name='__main__')\n")
            _atomic(path, script, mode=0o755)
            path.chmod(0o755)
        _atomic(dropin, "[Service]\nExecStartPre=/usr/local/bin/ftm-startup --prepare\n", mode=0o644)
        _run(["systemd-analyze", "verify", "/etc/systemd/system/vps-vk-network.service", "/etc/systemd/system/vps-vk.service"])
        _run(["systemctl", "daemon-reload"])
        _run(["/usr/local/bin/vps-vk", "status"])
    except BaseException:
        if previous_target:
            switch(previous_target)
        else:
            current.unlink(missing_ok=True)
        for path, value in previous.items():
            if value is None:
                path.unlink(missing_ok=True)
            else:
                _atomic(path, value[0], mode=value[1])
                path.chmod(value[1])
        _run(["systemctl", "daemon-reload"])
        raise
    return {"runtime_installed": True, "release": digest, "startup_hook_installed": True,
            "vpn_restarted": False, "ssh_changed": False, "host_reboot_tested": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--offsite-sha256", required=True)
    args = parser.parse_args()
    if not args.apply or os.name != "posix" or os.geteuid() != 0:
        parser.error("Requires root and --apply")
    import fcntl
    fd = os.open("/run/lock/vps-vk.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        print(json.dumps(install(args.checkpoint, args.offsite_sha256)))
        return 0
    finally:
        os.close(fd)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError, OSError, KeyError):
        print("Managed runtime installation failed; private data withheld", file=__import__("sys").stderr)
        raise SystemExit(1)
