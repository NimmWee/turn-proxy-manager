"""Real offline issuance -> kernel WG -> internal TLS claim. Not TURN/native E2E."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

sys.path.insert(0, '/opt/ftm/current')
from ftm.agent import _run, _atomic, reconcile
from ftm.bootstrap import Bootstraps
from ftm.bootstrap_cli import issue_file
from ftm.credentials import Credentials, _digest
from ftm.installer import read_private_json
from ftm.internal_https import load_agent
from ftm.profile_codec import decode
from ftm.reference_client import ReferenceClient, ClientSyncError
from ftm.store import Store
from verify_credentials import lifecycle


def inside(path, revoked=False):
    data = read_private_json(path)
    nonce, device_id = data.pop('nonce'), data.pop('device_id')
    client = ReferenceClient(**data)
    if revoked:
        try:
            client.claim_bootstrap(nonce, device_id)
        except ClientSyncError as error:
            if error.status != 410:
                raise RuntimeError('Consumed nonce revoke did not return410') from None
        else:
            raise RuntimeError('Consumed nonce revived a revoked credential')
        return {'revoked_credential_not_reissued': True}
    first = client.claim_bootstrap(nonce, device_id)
    if first != client.claim_bootstrap(nonce, device_id) or not first['ready']:
        raise RuntimeError('Lost-response retry changed bootstrap identity')
    if not client.refresh() or client.refresh() or client.last_good['device_id'] != device_id:
        raise RuntimeError('Bootstrap did not transition to managed config/304')
    return {'internal_claim_retry_managed_and304': True}


def verify():
    agent, store = load_agent(), Store('/var/lib/ftm/manager.sqlite3')
    credentials = Credentials(store)
    paths = [Path('/var/lib/vps-vk/main/state.json'), agent.config/'wireguard.conf', agent.config/'clients.json',
             agent.config/'obf.key', agent.registry, Path('/var/lib/vps-vk/main/profiles/iphone-import.txt')]
    original = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    pids = {s: _run(['systemctl','show',s,'-p','MainPID','--value']) for s in ('vps-vk','ssh')}
    peers = set(_run(['wg','show',agent.interface,'peers']).split())
    ns, wg = 'ftm-b-' + secrets.token_hex(3), 'ftmb' + secrets.token_hex(3)
    user = None
    made_ns = made_interface = False
    try:
        with tempfile.TemporaryDirectory(prefix='ftm-bootstrap-', dir='/root') as directory:
            root = Path(directory)
            with lifecycle():
                user = store.create_user('Bootstrap verification', 1)
                credentials.issue_subscription(user['id'])
                issued = issue_file(Bootstraps(store, agent), root/'bootstrap.json', user['id'], name='Offline test profile', platform='android')
                if reconcile(store,agent)['errors']:
                    raise RuntimeError('Bootstrap peer did not apply')
            artifact = read_private_json(root/'bootstrap.json', 65536)
            device = store.get_device(issued['device_id'])
            share = decode(artifact['share'])
            private = next(line.split('=',1)[1].strip() for line in share['wg'].splitlines() if line.startswith('PrivateKey'))
            token = 'ftmd1_' + secrets.token_urlsafe(32)
            body = {'device_id':device['id'], 'device_token_hash':_digest(token,'device')}
            public = urllib.request.Request(artifact['origin']+'/api/client/v1/bootstrap/claim', data=json.dumps(body).encode(),
                    headers={'Content-Type':'application/json','Authorization':'Bearer '+artifact['claim_nonce'],'X-Forwarded-For':device['ip']})
            try:
                urllib.request.urlopen(public, timeout=10)
            except urllib.error.HTTPError as error:
                if error.code != 403:
                    raise RuntimeError('Public spoofed claim did not return403') from None
            else:
                raise RuntimeError('Public forwarded-header spoof claimed bootstrap')
            target = artifact['internal_api_ip']
            data = dict(origin=artifact['origin'], private_key=private, public_key=artifact['public_key'], device_token=token,
                        client_id=share['cid'], internal_address=target, nonce=artifact['claim_nonce'], device_id=device['id'])
            caller, config = root/'caller.json', root/'wg.conf'
            _atomic(caller,json.dumps(data))
            _atomic(config, '[Interface]\nPrivateKey = '+private+'\n[Peer]\nPublicKey = '+agent.baseline['server_public']+
                    '\nPresharedKey = '+device['preshared_key']+'\nAllowedIPs = '+target+'/32\nEndpoint = 127.0.0.1:'+str(agent.baseline['backend_port'])+'\nPersistentKeepalive = 5\n')
            _run(['ip','netns','add',ns]); made_ns=True
            _run(['ip','link','add',wg,'type','wireguard']); made_interface=True
            _run(['ip','link','set',wg,'netns',ns]); made_interface=False
            _run(['ip','netns','exec',ns,'wg','setconf',wg,str(config)])
            _run(['ip','-n',ns,'address','add',device['ip']+'/32','dev',wg])
            _run(['ip','-n',ns,'link','set',wg,'mtu','1280','up'])
            # Only the internal API route exists: the namespace cannot use public443.
            _run(['ip','-n',ns,'route','add',target+'/32','dev',wg])
            after_apply = {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
            command=['ip','netns','exec',ns,'python3',str(Path(__file__).resolve()),'--inside',str(caller)]
            result=json.loads(_run(command))
            if {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths} != after_apply:
                raise RuntimeError('Claim changed WireGuard keys or transport identity')
            with lifecycle(): credentials.revoke_device_credential(device['id'])
            result.update(json.loads(_run(command+['--revoked'])))
            logs=_run(['journalctl','-u','ftm-api','-u','ftm-control','-u','ftm-caddy','--since','5 minutes ago','--no-pager','-o','cat'])
            if any(secret in logs for secret in (private, token, artifact['claim_nonce'], share['cid'], agent.baseline['vk_link'],agent.baseline['obf_key'])):
                raise RuntimeError('Service journal disclosed private bootstrap values')
    finally:
        if made_ns: _run(['ip','netns','delete',ns])
        if made_interface: _run(['ip','link','delete',wg])
        if user:
            with lifecycle():
                store.set_user_enabled(user['id'],False)
                credentials.revoke_subscription(user['id'])
                if reconcile(store,agent)['errors']: raise RuntimeError('Bootstrap peer cleanup failed')
    if {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths} != original or set(_run(['wg','show',agent.interface,'peers']).split()) != peers:
        raise RuntimeError('Original configuration/profile/peers changed')
    if {s:_run(['systemctl','show',s,'-p','MainPID','--value']) for s in pids} != pids:
        raise RuntimeError('VPN or SSH restarted')
    result.update({'offline_private_issue':True,'public_spoofed_forwarded_header_denied':True,'original_keys_profile_peers_and_pids_preserved':True,
                   'no_private_values_in_journal':True,'turn_or_native_client_e2e':False})
    _atomic(Path('/root/ftm-bootstrap-report.json'),json.dumps(result))
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--test-vps-apply',action='store_true')
    parser.add_argument('--inside',type=Path)
    parser.add_argument('--revoked',action='store_true')
    args=parser.parse_args()
    if os.geteuid()!=0 or not(args.test_vps_apply or args.inside): parser.error('Explicit root test operation required')
    try: print(json.dumps(inside(args.inside,args.revoked) if args.inside else verify()))
    except Exception:
        print('Bootstrap verification failed; private data withheld',file=sys.stderr)
        raise SystemExit(1)
