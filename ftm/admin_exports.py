"""Root password verification and bounded private delivery cache for admin exports."""

from collections import deque
import hashlib
import json
from pathlib import Path
import secrets
import time
import uuid

from .bootstrap import Bootstraps
from .bootstrap_cli import private_file, generate_keys
from .client_protocol import ClientFault
from .credentials import Credentials, _digest, _identifier
from .installer import read_private_json
from .runtime import _trusted_directory
from .store import ValidationError
from .web_auth import _password_hash, validate_config


class AdminExports:
    def __init__(self, store, agent, *, directory='/var/lib/ftm/exports', config_reader=None, clock=time.time, monotonic=time.monotonic, keypair=generate_keys):
        self.store, self.agent, self.directory = store, agent, Path(directory)
        self.config_reader = config_reader or (lambda: read_private_json('/etc/ftm/web.json', 16384))
        self.clock, self.monotonic, self.keypair = clock, monotonic, keypair
        self.failures = deque()
        self.next_cleanup, self.cleanup_failed = 0, False

    def tick(self):
        if self.monotonic() < self.next_cleanup:
            return
        self.next_cleanup = self.monotonic() + 30
        try:
            if self.directory.exists():
                self._prepare()
            self.cleanup_failed = False
        except (OSError, ValueError, RuntimeError):
            if not self.cleanup_failed:
                print('Private delivery cleanup needs root attention; details withheld', file=__import__('sys').stderr)
            self.cleanup_failed = True

    def authenticate(self, password):
        now = self.monotonic()
        while self.failures and now - self.failures[0] >= 600:
            self.failures.popleft()
        if len(self.failures) >= 5:
            raise ClientFault('rate_limited')
        config = validate_config(self.config_reader())
        if (not isinstance(password, str) or not 1 <= len(password) <= 1024
                or not secrets.compare_digest(_password_hash(password, config['password_salt']), config['password_hash'])):
            self.failures.append(now)
            raise ClientFault('admin_password_required')
        if config.get('public_origin') != 'https://' + self.agent.baseline['endpoint']:
            raise ClientFault('service_unavailable')
        return config

    def _prepare(self):
        _trusted_directory(self.directory, mode=0o700)
        if self.directory.stat().st_mode & 0o077:
            raise ValidationError('Private export directory required')
        paths = list(self.directory.iterdir())
        if len(paths) > 128:
            raise ClientFault('service_unavailable')
        for path in paths:
            try:
                own = path.name == str(uuid.UUID(path.stem)) + '.json'
            except ValueError:
                own = False
            if own:
                if path.is_symlink() or not path.is_file() or path.stat().st_uid != 0 or path.stat().st_mode & 0o077:
                    raise ValidationError('Unsafe private export cache')
                age = self.clock() - path.stat().st_mtime
                if age < 0 or age >= 600:
                    path.unlink()

    def export(self, kind, args):
        self.authenticate(args.get('password'))
        user_id, request_id = _identifier(args['user_id']), _identifier(args['request_id'])
        identity = {'kind': kind, 'user_id': user_id}
        if kind == 'bootstrap':
            identity.update(name=args['name'], platform=args['platform'])
        elif kind != 'subscription':
            raise ValidationError('Unsupported export')
        fingerprint = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
        self._prepare()
        output = self.directory / (request_id + '.json')
        with self.store.connect() as db:
            bootstrap = db.execute('SELECT b.*,d.user_id,d.enabled,u.enabled AS user_enabled FROM bootstraps b JOIN devices d ON d.id=b.device_id JOIN users u ON u.id=d.user_id WHERE b.id=?', (request_id,)).fetchone()
            setting = db.execute('SELECT value FROM settings WHERE key=?', ('admin_export/' + request_id,)).fetchone()
            user = db.execute('SELECT enabled FROM users WHERE id=?', (user_id,)).fetchone()
            subscription = db.execute('SELECT * FROM subscriptions WHERE user_id=?', (user_id,)).fetchone()
        if user is None or not user['enabled']:
            raise ClientFault('device_disabled')
        if bootstrap or setting:
            known = bootstrap['user_id'] if bootstrap else json.loads(setting['value'])['user_id']
            if known != user_id or (kind == 'bootstrap') != bool(bootstrap):
                raise ClientFault('export_conflict')
            if not output.exists():
                raise ClientFault('export_expired')
            cached = read_private_json(output, 65536)
            if set(cached) != {'fingerprint', 'artifact'} or cached['fingerprint'] != fingerprint:
                raise ClientFault('export_conflict')
            artifact = cached['artifact']
            if bootstrap:
                import datetime
                if (not bootstrap['enabled'] or not bootstrap['user_enabled'] or artifact['device_id'] != bootstrap['device_id']
                        or _digest(artifact['claim_nonce'], 'bootstrap') != bootstrap['nonce_hash']
                        or datetime.datetime.fromisoformat(bootstrap['expires_at']).timestamp() <= self.clock()):
                    raise ClientFault('export_expired')
            elif (subscription is None or subscription['revoked_at'] is not None
                  or _digest(artifact['user_token'], 'user') != subscription['token_hash']):
                raise ClientFault('export_expired')
            return artifact
        if output.exists():
            # File from an aborted transaction/older restored DB is never trusted.
            raise ClientFault('export_expired')
        if len(list(self.directory.iterdir())) >= 64:
            raise ClientFault('service_unavailable')
        artifact = None
        def producer(deliver):
            def save(value):
                nonlocal artifact
                artifact = value if kind == 'bootstrap' else {'version': 1, 'format': 'ftm-enrollment',
                            'origin': 'https://' + self.agent.baseline['endpoint'], 'user_token': value['token']}
                deliver({'fingerprint': fingerprint, 'artifact': artifact})
            if kind == 'bootstrap':
                Bootstraps(self.store, self.agent).issue(user_id, name=args['name'], platform=args['platform'],
                                keypair=self.keypair, deliver=save, request_id=request_id)
            else:
                Credentials(self.store).issue_subscription(user_id, deliver=save, request_id=request_id)
        private_file(output, producer)
        return artifact
