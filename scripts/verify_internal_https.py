"""Agreed test VPS only: real kernel WG namespace and HTTPS, not TURN/native E2E."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import uuid
import urllib.error
import urllib.request

sys.path.insert(0, '/opt/ftm/current')
from ftm.agent import _atomic, _run, reconcile
from ftm.credentials import Credentials
from ftm.installer import read_private_json
from ftm.internal_https import load_agent, set_rule, sync, rule, exists
from ftm.reference_client import ReferenceClient, _InternalHTTPS, _NoRedirect
from ftm.store import Store
from verify_credentials import lifecycle


def reject_wrong_identity(target):
    wrong_origin = 'https://203.0.113.254'
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect(), _InternalHTTPS(wrong_origin, target))
    try:
        opener.open(wrong_origin + '/api/client/v1/status', timeout=5)
    except urllib.error.URLError as error:
        if not isinstance(error.reason, ssl.SSLCertVerificationError):
            raise RuntimeError('Expected TLS certificate verification rejection') from None
    else:
        raise RuntimeError('Internal transport accepted another TLS identity')


def inside(path):
    value = read_private_json(path)
    client = ReferenceClient(**value)
    if not client.refresh() or client.refresh():
        raise RuntimeError('Internal configuration/304 failed')
    for port in (22, 8080):
        try:
            with socket.create_connection((value['internal_address'], port), timeout=3):
                raise RuntimeError('Unrelated server port reachable from VPN')
        except OSError:
            pass
    reject_wrong_identity(value['internal_address'])
    return {'kernel_wg_https_config_and_304': True, 'other_server_ports_blocked': True, 'wrong_tls_identity_rejected': True}


def verify():
    agent = load_agent()
    store = Store('/var/lib/ftm/manager.sqlite3')
    creds = Credentials(store)
    paths = [Path('/var/lib/vps-vk/main/state.json'), agent.config / 'wireguard.conf', agent.config / 'clients.json',
             agent.config / 'obf.key', agent.registry, Path('/var/lib/vps-vk/main/profiles/iphone-import.txt')]
    before = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    pids = {s: _run(['systemctl', 'show', s, '-p', 'MainPID', '--value']) for s in ('vps-vk', 'ssh')}
    peers = set(_run(['wg', 'show', agent.interface, 'peers']).split())
    ns = 'ftm-tls-' + secrets.token_hex(3)
    wg = 'ftmt' + secrets.token_hex(3)
    user = None
    made_ns = made_interface = False
    result = None
    try:
        with lifecycle():
            user = store.create_user('Internal HTTPS verification', 1)
            link = creds.issue_subscription(user['id'])['token']
        private = subprocess.check_output(['wg', 'genkey']).decode().strip()
        public = subprocess.check_output(['wg', 'pubkey'], input=private.encode()).decode().strip()
        data = dict(origin='https://' + agent.baseline['endpoint'], private_key=private, public_key=public,
                    device_token='ftmd1_' + secrets.token_urlsafe(32), client_id=secrets.token_hex(16))
        client = ReferenceClient(**data)
        client.enroll(link, name='Internal HTTPS temporary WG peer', platform='android', request_id=str(uuid.uuid4()))
        with lifecycle():
            if reconcile(store, agent)['errors']:
                raise RuntimeError('Temporary peer apply failed')
        if not client.refresh():
            raise RuntimeError('Initial public config failed')
        target = client.last_good['management']['internal_api_ip']
        data['internal_address'] = target
        with tempfile.TemporaryDirectory(prefix='ftm-internal-', dir='/root') as directory:
            root = Path(directory)
            settings, config = root / 'caller.json', root / 'wg.conf'
            _atomic(settings, json.dumps(data))
            _atomic(config, '[Interface]\nPrivateKey = ' + private + '\n[Peer]\nPublicKey = ' + agent.baseline['server_public'] +
                    '\nPresharedKey = ' + client.last_good['wireguard']['preshared_key'] + '\nAllowedIPs = ' + target + '/32' +
                    '\nEndpoint = 127.0.0.1:' + str(agent.baseline['backend_port']) + '\nPersistentKeepalive = 5\n')
            _run(['ip', 'netns', 'add', ns])
            made_ns = True
            # Birthplace UDP socket remains in the host; encrypted underlay is
            # loopback, without any exception to the public WG backend DROP.
            _run(['ip', 'link', 'add', wg, 'type', 'wireguard'])
            made_interface = True
            _run(['ip', 'link', 'set', wg, 'netns', ns])
            made_interface = False
            _run(['ip', 'netns', 'exec', ns, 'wg', 'setconf', wg, str(config)])
            _run(['ip', '-n', ns, 'address', 'add', client.last_good['wireguard']['addresses'][0], 'dev', wg])
            _run(['ip', '-n', ns, 'link', 'set', wg, 'mtu', '1280', 'up'])
            _run(['ip', '-n', ns, 'route', 'add', target + '/32', 'dev', wg])
            command = ['ip', 'netns', 'exec', ns, 'python3', str(Path(__file__).resolve()), '--inside', str(settings)]
            result = json.loads(_run(command))
            # Private-mode recovery must close the exception. Test the same
            # fixed primitive without changing the admin identity/web config.
            set_rule(agent, False)
            blocked = subprocess.run(['ip', 'netns', 'exec', ns, 'python3', '-c',
                                      'import socket;socket.create_connection((' + repr(target) + ',443),3)'],
                                     capture_output=True, timeout=8)
            if blocked.returncode == 0:
                raise RuntimeError('Internal HTTPS exception did not close')
            sync(agent, required=True)
            if json.loads(_run(command)) != result:
                raise RuntimeError('Internal HTTPS exception did not recover')
        handshake = dict(line.split() for line in _run(['wg', 'show', agent.interface, 'latest-handshakes']).splitlines())
        if int(handshake.get(public, '0')) < int(time.time()) - 120:
            raise RuntimeError('No real kernel WireGuard handshake')
    finally:
        sync(agent, required=True)
        if made_ns:
            _run(['ip', 'netns', 'delete', ns])
        if made_interface:
            _run(['ip', 'link', 'delete', wg])
        if user:
            with lifecycle():
                store.set_user_enabled(user['id'], False)
                creds.revoke_subscription(user['id'])
                if reconcile(store, agent)['errors']:
                    raise RuntimeError('Temporary peer cleanup failed')
    if {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths} != before:
        raise RuntimeError('Original configuration or iPhone profile changed')
    if set(_run(['wg', 'show', agent.interface, 'peers']).split()) != peers:
        raise RuntimeError('Original kernel peers changed')
    if {s: _run(['systemctl', 'show', s, '-p', 'MainPID', '--value']) for s in pids} != pids:
        raise RuntimeError('VPN/SSH restarted')
    result.update({'internal_close_and_recover': True, 'original_peers_keys_profile_and_pids_preserved': True,
                   'wg_backend_opened': False, 'turn_or_native_client_e2e': False})
    _atomic(Path('/root/ftm-internal-https-report.json'), json.dumps(result))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--test-vps-apply', action='store_true')
    parser.add_argument('--inside', type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0 or not (args.test_vps_apply or args.inside):
        parser.error('Requires explicit root test operation')
    try:
        print(json.dumps(inside(args.inside) if args.inside else verify()))
    except Exception:
        print('Internal HTTPS verification failed; private data withheld', file=sys.stderr)
        raise SystemExit(1)
