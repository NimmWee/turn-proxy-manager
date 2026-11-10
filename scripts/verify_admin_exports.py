"""Real test VPS re-auth/export/retry check. Never prints downloaded secrets."""

import argparse
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

sys.path.insert(0, '/opt/ftm/current')
from ftm.agent import _atomic, _run, reconcile
from ftm.credentials import Credentials
from ftm.installer import read_private_json
from ftm.internal_https import load_agent
from ftm.https_edge import wait_ready
from ftm.profile_codec import decode
from ftm.store import Store
from verify_credentials import lifecycle

last_operation, last_status = None, None


def verify():
    agent, store = load_agent(), Store('/var/lib/ftm/manager.sqlite3')
    wait_ready(agent.baseline['endpoint'], tls=False)
    note = read_private_json('/root/ftm-web-login.json')
    origin = 'https://' + agent.baseline['endpoint']
    base = origin + note['panel_path'] + 'api'
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    csrf = None
    def post(path, body, *, authorized=True):
        global last_operation, last_status
        last_operation = path.rsplit('/',1)[-1]
        headers = {'Content-Type':'application/json', 'Origin':origin}
        if authorized and csrf:
            headers['X-CSRF-Token'] = csrf
        try:
            with opener.open(urllib.request.Request(base+path, data=json.dumps(body).encode(), headers=headers), timeout=20) as response:
                last_status = response.status
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            last_status = error.code
            return error.code, json.loads(error.read())
    paths=[Path('/var/lib/vps-vk/main/state.json'),agent.registry,agent.config/'wireguard.conf',agent.config/'clients.json',agent.config/'obf.key',Path('/var/lib/vps-vk/main/profiles/iphone-import.txt')]
    before={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    pids={s:_run(['systemctl','show',s,'-p','MainPID','--value']) for s in ('vps-vk','ssh')}
    user=None
    ids=[str(uuid.uuid4()) for _ in range(3)]
    try:
        with lifecycle(): user=store.create_user('Admin export verification',2)
        path='/users/'+user['id']+'/subscription-export'
        payload={'password':note['password'],'request_id':ids[0]}
        assert post(path,payload)[0]==401
        status,login=post('/auth/login',{'username':note['username'],'password':note['password']})
        assert status==200
        csrf=login['csrf']
        assert post(path,payload,authorized=False)[0]==403
        assert post(path,dict(payload,password='synthetic incorrect confirmation'))[0]==403
        status,subscription=post(path,payload)
        assert status==200
        assert post(path,payload)==(status,subscription)
        assert Credentials(store).subscription(subscription['user_token'])['user_id']==user['id']
        bpath='/users/'+user['id']+'/bootstrap-export'
        bpayload=dict(payload,request_id=ids[1],name='Panel-issued temporary device',platform='android')
        status,artifact=post(bpath,bpayload)
        assert status==200
        assert post(bpath,bpayload)==(status,artifact)
        assert len(store.list_devices(user['id']))==1
        deadline=time.monotonic()+50
        while store.get_device(artifact['device_id'])['state']!='active':
            if time.monotonic()>deadline: raise RuntimeError('Panel peer apply timed out')
            time.sleep(3)
        output=Path('/var/lib/ftm/exports')/(ids[1]+'.json')
        assert output.stat().st_mode & 0o777==0o600
        assert output.parent.stat().st_mode & 0o777==0o700
        assert subprocess.run(['runuser','-u','ftm-api','--','test','-r',str(output)],capture_output=True).returncode!=0
        output.unlink()
        assert post(bpath,bpayload)[0]==410
        assert len(store.list_devices(user['id']))==1
        status,new_subscription=post(path,dict(payload,request_id=ids[2]))
        assert status==200 and new_subscription['user_token']!=subscription['user_token']
        assert post(path,payload)[0]==410
        share=decode(artifact['share'])
        private=next(line.split('=',1)[1].strip() for line in share['wg'].splitlines() if line.startswith('PrivateKey'))
        logs=_run(['journalctl','-u','ftm-api','-u','ftm-control','-u','ftm-caddy','--since','5 minutes ago','--no-pager','-o','cat'])
        assert not any(secret in logs for secret in (private,artifact['claim_nonce'],subscription['user_token'],new_subscription['user_token'],note['password']))
        assert post('/auth/logout',{})[0]==200
    finally:
        if user:
            with lifecycle():
                store.set_user_enabled(user['id'],False)
                if reconcile(store,agent)['errors']: raise RuntimeError('Export verification cleanup failed')
        for identifier in ids:
            (Path('/var/lib/ftm/exports')/(identifier+'.json')).unlink(missing_ok=True)
    assert {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}==before
    assert {s:_run(['systemctl','show',s,'-p','MainPID','--value']) for s in pids}==pids
    result={'session_csrf_and_root_password_required':True,'subscription_and_bootstrap_retry_identical':True,
            'lost_delivery_never_creates_second_peer':True,'old_subscription_cache_cannot_restore_rotated_token':True,
            'api_uid_cannot_read_root_cache':True,'private_values_absent_from_journal':True,
            'original_keys_profile_config_and_vpn_ssh_pids_preserved':True,'native_client_e2e':False}
    _atomic(Path('/root/ftm-admin-export-report.json'),json.dumps(result))
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--test-vps-apply',action='store_true')
    args=parser.parse_args()
    if not args.test_vps_apply or os.geteuid()!=0: parser.error('Explicit root test operation required')
    try: print(json.dumps(verify()))
    except Exception as error:
        print('Admin export verification failed: '+type(error).__name__+'; operation='+str(last_operation)+'; status='+str(last_status)+'; private data withheld',file=sys.stderr)
        raise SystemExit(1)
