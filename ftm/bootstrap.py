"""Root bootstrap issuance and one-time VPN-bound claim. No private key in DB."""

import datetime
import re
import secrets
import uuid

from .client_protocol import ClientFault
from .client_service import ClientService
from .credentials import _digest, _identifier
from .managed_profile import to_share
from .store import ValidationError, Conflict, _now, valid_key


class Bootstraps:
    def __init__(self, store, agent, *, clock=None):
        self.store, self.agent = store, agent
        self.clock = clock or (lambda: datetime.datetime.now(datetime.timezone.utc))

    def issue(self, user_id, *, name, platform, keypair, deliver, ttl_seconds=3600):
        user_id = _identifier(user_id)
        if platform not in ('android', 'windows', 'other') or type(ttl_seconds) is not int or not 60 <= ttl_seconds <= 86400:
            raise ValidationError('Invalid bootstrap platform or TTL')
        private, public = keypair()
        if not valid_key(private) or not valid_key(public):
            raise ValidationError('WireGuard key generation failed')
        nonce = 'ftmb1_' + secrets.token_urlsafe(32)
        expires = (self.clock() + datetime.timedelta(seconds=ttl_seconds)).isoformat()
        with self.store.transaction() as db:
            subscription = db.execute('SELECT id FROM subscriptions WHERE user_id=? AND revoked_at IS NULL', (user_id,)).fetchone()
            if subscription is None:
                raise ValidationError('Enabled subscription required before bootstrap issuance')
            # New random request identity: retry by issuing another artifact is
            # explicit, never silent reuse of an undelivered private key.
            device = self.store._create_device(db, user_id, name, platform, public, str(uuid.uuid4()))
            identifier = str(uuid.uuid4())
            db.execute('INSERT INTO bootstraps VALUES(?,?,?,?,NULL)', (identifier, device['id'], _digest(nonce, 'bootstrap'), expires))
            service = ClientService(self.store, self.agent)
            manifest = service.manifest(device, self.agent._validate(device))
            artifact = {'version': 1, 'format': 'ftm-bootstrap', 'device_id': device['id'], 'public_key': public,
                        'origin': manifest['management']['origin'], 'internal_api_ip': manifest['management']['internal_api_ip'],
                        'claim_nonce': nonce, 'expires_at': expires,
                        'share': to_share(manifest, private, expected_public_key=public, expected_origin=manifest['management']['origin'])}
            self.store._audit(db, 'bootstrap.issue', 'device', device['id'])
            # CLI fsyncs private file and parent before the transaction commits.
            deliver(artifact)
        return {'device_id': device['id'], 'state': 'pending', 'expires_at': expires}

    def claim(self, nonce, device_id, credential_hash, source_ip):
        digest = _digest(nonce, 'bootstrap')
        try:
            device_id = _identifier(device_id)
        except ValidationError:
            raise ClientFault('invalid_request') from None
        if not isinstance(credential_hash, str) or not re.fullmatch(r'[a-f0-9]{64}', credential_hash):
            raise ClientFault('invalid_request')
        if digest is None:
            raise ClientFault('credential_invalid')
        try:
            with self.store.transaction() as db:
                row = db.execute('SELECT * FROM bootstraps WHERE nonce_hash=? AND device_id=?', (digest, device_id)).fetchone()
                if row is None:
                    raise ClientFault('bootstrap_unavailable')
                device = db.execute('SELECT d.*,u.enabled AS user_enabled FROM devices d JOIN users u ON u.id=d.user_id WHERE d.id=?',
                                    (device_id,)).fetchone()
                if not device['enabled'] or not device['user_enabled'] or device['platform'] == 'ios':
                    raise ClientFault('device_disabled')
                if not isinstance(source_ip, str) or source_ip != device['ip']:
                    raise ClientFault('bootstrap_source_denied')
                try:
                    expired = datetime.datetime.fromisoformat(row['expires_at']) <= self.clock()
                except (ValueError, TypeError):
                    raise ClientFault('bootstrap_unavailable') from None
                if expired:
                    raise ClientFault('bootstrap_unavailable')
                if device['state'] != 'active':
                    raise ClientFault('service_unavailable')
                ClientService(self.store, self.agent)._spec(dict(device))
                subscription = db.execute('SELECT id,version FROM subscriptions WHERE user_id=? AND revoked_at IS NULL', (device['user_id'],)).fetchone()
                if subscription is None:
                    raise ClientFault('credential_invalid')
                known = db.execute('SELECT token_hash,revoked_at FROM device_tokens WHERE device_id=?', (device_id,)).fetchall()
                if row['consumed_at'] is not None:
                    if not any(t['token_hash'] == credential_hash and t['revoked_at'] is None for t in known):
                        raise ClientFault('bootstrap_unavailable')
                else:
                    if known:
                        raise ClientFault('bootstrap_unavailable')
                    db.execute('INSERT INTO device_tokens VALUES(?,?,?,?,NULL)', (str(uuid.uuid4()), device_id, credential_hash, _now()))
                    db.execute('UPDATE bootstraps SET consumed_at=? WHERE id=?', (_now(), row['id']))
                    self.store._audit(db, 'bootstrap.claim', 'device', device_id)
                return {'device_id': device_id, 'subscription_id': subscription['id'], 'subscription_version': subscription['version'],
                        'revision': device['revision'], 'state': 'active', 'ready': True}
        except Conflict:
            raise ClientFault('bootstrap_unavailable') from None
