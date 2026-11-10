"""Issue one private bootstrap artifact as root; no public/admin export endpoint."""

import argparse
import json
import os
from pathlib import Path
import subprocess

from .bootstrap import Bootstraps
from .internal_https import load_agent
from .store import Store, ValidationError


def generate_keys():
    private = subprocess.check_output(['wg', 'genkey'], timeout=10).strip()
    public = subprocess.check_output(['wg', 'pubkey'], input=private, timeout=10).strip()
    return private.decode(), public.decode()


def private_file(output, producer):
    output = Path(output).absolute()
    parent = output.parent
    if (any(p.is_symlink() for p in (parent, *parent.parents)) or parent.stat().st_uid != 0
            or parent.stat().st_mode & 0o077):
        raise ValidationError('A private root output directory is required')
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            def deliver(value):
                stream.write(json.dumps(value, ensure_ascii=False))
                stream.flush()
                os.fsync(stream.fileno())
                parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(parent_fd)
                finally:
                    os.close(parent_fd)
            return producer(deliver)
    except BaseException:
        output.unlink(missing_ok=True)
        raise


def issue_file(service, output, user_id, *, name, platform, ttl_seconds=3600, keypair=generate_keys):
    return private_file(output, lambda deliver: service.issue(user_id, name=name, platform=platform,
                        keypair=keypair, deliver=deliver, ttl_seconds=ttl_seconds))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--user-id', required=True)
    parser.add_argument('--name', required=True)
    parser.add_argument('--platform', required=True, choices=('android', 'windows', 'other'))
    parser.add_argument('--ttl-seconds', type=int, default=3600)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.name != 'posix' or os.geteuid() != 0:
        parser.error('Requires root on the agreed test VPS')
    path = Path('/var/lib/ftm/manager.sqlite3')
    if path.is_symlink() or path.stat().st_uid != 0 or path.stat().st_mode & 0o077:
        raise ValidationError('Private root metadata required')
    import fcntl
    fd = os.open('/run/lock/vps-vk.lock', os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        result = issue_file(Bootstraps(Store(path), load_agent()), args.output, args.user_id,
                            name=args.name, platform=args.platform, ttl_seconds=args.ttl_seconds)
        print(json.dumps(result))
    finally:
        os.close(fd)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Bootstrap issuance failed; private data withheld', file=__import__('sys').stderr)
        raise SystemExit(1)
