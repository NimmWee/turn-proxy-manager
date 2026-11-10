"""Fixed root-only VPN HTTPS exception. Never flushes chains or opens WG backend."""

import argparse
import hashlib
import os
from pathlib import Path
import subprocess

from .agent import NetworkAgent, _atomic, _run
from .checkpoint import _read_encrypted, capture_live, open_checkpoint
from .installer import read_private_json
from .runtime import _trusted_directory
from .store import Store, ValidationError
from .web_auth import validate_config

HOOK = Path('/etc/systemd/system/vps-vk-network.service.d/30-ftm-https.conf')
WRAPPER = Path('/usr/local/bin/ftm-internal-https')


def rule(agent):
    return ['iptables', '-w', '5', '-t', 'filter', '-I', 'INPUT', '-i', agent.interface,
            '-s', str(agent.subnet), '-d', str(agent.subnet.network_address + 1),
            '-p', 'tcp', '--dport', '443', '-m', 'comment', '--comment', 'ftm-client-internal', '-j', 'ACCEPT']


def exists(command):
    check = command.copy()
    check[5] = '-C'
    return subprocess.run(check, capture_output=True, timeout=10).returncode == 0


def set_rule(agent, enabled):
    command = rule(agent)
    # Reinsert above the baseline's interface REJECT after every network start.
    delete = command.copy()
    delete[5] = '-D'
    for _ in range(32):
        if not exists(command):
            break
        _run(delete)
    else:
        raise RuntimeError('Too many duplicate internal HTTPS rules')
    if enabled:
        _run(command)


def sync(agent, *, required=False):
    if not HOOK.exists():
        if required:
            raise ValidationError('Internal HTTPS hook is not installed')
        return False
    for path in (HOOK, WRAPPER):
        if path.is_symlink() or not path.is_file() or path.stat().st_uid != 0 or path.stat().st_mode & 0o022:
            raise ValidationError('Trusted internal HTTPS hook required')
    web = validate_config(read_private_json('/etc/ftm/web.json', 16384))
    enabled = bool(web.get('public_origin'))
    set_rule(agent, enabled)
    return True


def load_agent():
    return NetworkAgent(read_private_json('/var/lib/vps-vk/main/state.json', 1048576),
                        config_dir='/etc/vps-vk/main', state_dir='/var/lib/ftm-agent')


def ensure():
    agent = load_agent()
    try:
        sync(agent, required=True)
    except Exception:
        # A broken management configuration must not leave its own permission
        # behind. systemd ignores this hook's exit status to preserve VPN.
        set_rule(agent, False)
        raise RuntimeError('Internal HTTPS unavailable; VPN startup may continue') from None


def install(checkpoint, offsite_sha256):
    import fcntl
    agent = load_agent()
    fd = os.open('/run/lock/vps-vk.lock', os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        raw = _read_encrypted(checkpoint)
        if hashlib.sha256(raw).hexdigest() != offsite_sha256:
            raise ValidationError('Matching offsite-verified checkpoint required')
        phrase = Path('/root/ftm-test-backup.pass')
        if phrase.is_symlink() or phrase.stat().st_uid != 0 or phrase.stat().st_mode & 0o077:
            raise ValidationError('Private recovery phrase required')
        if open_checkpoint(raw, phrase.read_text().strip()) != capture_live(Store('/var/lib/ftm/manager.sqlite3'), agent):
            raise ValidationError('Take a fresh checkpoint before internal HTTPS installation')
        _trusted_directory(HOOK.parent)
        previous = {}
        for path in (HOOK, WRAPPER):
            if path.is_symlink() or (path.exists() and (not path.is_file() or path.stat().st_uid != 0 or path.stat().st_mode & 0o022)):
                raise ValidationError('Unsafe internal HTTPS entrypoint')
            previous[path] = (path.read_bytes(), path.stat().st_mode & 0o777) if path.exists() else None
        was_enabled = exists(rule(agent))
        try:
            _atomic(WRAPPER, "#!/usr/bin/python3 -I\nimport runpy,sys\nsys.path.insert(0, '/opt/ftm/current')\nrunpy.run_module('ftm.internal_https', run_name='__main__')\n", mode=0o755)
            _atomic(HOOK, '[Service]\nExecStartPost=-/usr/local/bin/ftm-internal-https --ensure\n', mode=0o644)
            _run(['systemd-analyze', 'verify', '/etc/systemd/system/vps-vk-network.service'])
            _run(['systemctl', 'daemon-reload'])
            sync(agent, required=True)
        except BaseException:
            for path, old in previous.items():
                if old is None:
                    path.unlink(missing_ok=True)
                else:
                    _atomic(path, old[0], mode=old[1])
            _run(['systemctl', 'daemon-reload'])
            set_rule(agent, was_enabled)
            raise RuntimeError('Internal HTTPS installation failed; previous access restored') from None
        return {'internal_https_installed': True, 'vpn_or_ssh_restarted': False, 'wg_backend_opened': False}
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ensure', action='store_true')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--checkpoint', type=Path)
    parser.add_argument('--offsite-sha256')
    args = parser.parse_args()
    if os.name != 'posix' or os.geteuid() != 0:
        parser.error('Requires root on the agreed test VPS')
    try:
        if args.ensure and not any((args.apply, args.checkpoint, args.offsite_sha256)):
            ensure()
        elif args.apply and not args.ensure and args.checkpoint and args.offsite_sha256:
            import json
            print(json.dumps(install(args.checkpoint, args.offsite_sha256)))
        else:
            parser.error('Use fixed --ensure or --apply with checkpoint and offsite SHA256')
    except Exception:
        print('Internal HTTPS failed; private data withheld', file=__import__('sys').stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
