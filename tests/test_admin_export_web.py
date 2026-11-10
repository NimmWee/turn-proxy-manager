import unittest
import uuid

from ftm.client_protocol import ClientFault
from ftm.web_auth import make_config
try:
    from fastapi.testclient import TestClient
    from ftm.web import create_app
except ImportError:
    TestClient=None


@unittest.skipUnless(TestClient,'Install web development dependencies')
class ExportHttpBoundaryTests(unittest.TestCase):
    def test_session_origin_csrf_and_root_reauth_are_all_required(self):
        config=dict(make_config('admin','Synthetic export web phrase'),version=2,public_origin='https://8.8.8.8',secure_cookie=True)
        calls=[]
        def rpc(operation,args):
            calls.append((operation,args))
            raise ClientFault('admin_password_required')
        base='/a/'+config['panel_slug']+'/api'
        path=base+'/users/'+str(uuid.uuid4())+'/subscription-export'
        body={'password':'not the root password','request_id':str(uuid.uuid4())}
        with TestClient(create_app(config,rpc=rpc),base_url='https://8.8.8.8') as client:
            self.assertEqual(client.post(path,json=body).status_code,401)
            login=client.post(base+'/auth/login',json={'username':'admin','password':'Synthetic export web phrase'},headers={'Origin':'https://8.8.8.8'})
            self.assertEqual(client.post(path,json=body,headers={'Origin':'https://8.8.8.8'}).status_code,403)
            csrf=login.json()['csrf']
            self.assertEqual(client.post(path,json=body,headers={'Origin':'https://other.example','X-CSRF-Token':csrf}).status_code,403)
            self.assertFalse(calls)
            rejected=client.post(path,json=body,headers={'Origin':'https://8.8.8.8','X-CSRF-Token':csrf})
            self.assertEqual(rejected.status_code,403)
            self.assertEqual(calls[0][0],'admin.subscription_export')
            self.assertNotIn(body['password'],rejected.text)
            self.assertEqual(rejected.headers['cache-control'],'no-store')
