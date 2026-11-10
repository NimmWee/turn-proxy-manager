import os
from pathlib import Path
import time
import unittest
import uuid

from ftm.admin_exports import AdminExports
from ftm.client_protocol import ClientFault
from ftm.control import execute
from ftm.web_auth import make_config
from tests import test_client_service
from tests.test_store import key


class AdminReauthenticationTests(unittest.TestCase):
    def setUp(self):
        test_client_service.ClientDisclosureTests.setUp(self)
        self.password = 'Synthetic export admin phrase'
        self.config = dict(make_config('admin', self.password), version=2, public_origin='https://'+self.state['endpoint'], secure_cookie=True)
        self.now = 1000
        self.exports = AdminExports(self.store, self.agent, directory=Path(self.folder.name)/'exports',
                    config_reader=lambda:self.config, monotonic=lambda:self.now, keypair=lambda:(key(96),key(97)))

    def test_api_uid_cannot_export_without_root_password_and_failure_budget_survives_requests(self):
        args = {'user_id':self.user['id'], 'request_id':str(uuid.uuid4()), 'password':'wrong'}
        for _ in range(5):
            with self.assertRaises(ClientFault) as error:
                execute({'v':1,'op':'admin.subscription_export','args':args}, uid=456,api_uid=456,
                        store=self.store,agent=self.agent,exports=self.exports)
            self.assertEqual(error.exception.code,'admin_password_required')
        with self.assertRaises(ClientFault) as error:
            self.exports.authenticate(self.password)
        self.assertEqual(error.exception.status,429)
        self.now+=601
        self.exports.authenticate(self.password)
        self.assertFalse(self.exports.directory.exists())

    @unittest.skipUnless(os.name=='posix' and os.geteuid()==0, 'Private root file delivery requires Linux root; real VPS check')
    def test_private_retry_is_identical_and_missing_cache_cannot_create_another_peer(self):
        args={'user_id':self.user['id'],'request_id':str(uuid.uuid4()),'password':self.password,'name':'One profile','platform':'android'}
        artifact=self.exports.export('bootstrap',args)
        self.assertEqual(self.exports.export('bootstrap',args),artifact)
        output=self.exports.directory/(args['request_id']+'.json')
        self.assertEqual(output.stat().st_mode & 0o777,0o600)
        self.assertEqual(self.exports.directory.stat().st_mode & 0o777,0o700)
        before=self.store.list_devices(self.user['id'])
        os.utime(output,(time.time()-601,time.time()-601))
        self.exports.tick()
        self.assertFalse(output.exists())
        with self.assertRaises(ClientFault) as error:
            self.exports.export('bootstrap',args)
        self.assertEqual(error.exception.status,410)
        self.assertEqual(self.store.list_devices(self.user['id']),before)

    @unittest.skipUnless(os.name=='posix' and os.geteuid()==0, 'Private root file delivery requires Linux root; real VPS check')
    def test_subscription_retry_rotates_once_and_old_cached_export_never_recovers_old_token(self):
        args={'user_id':self.user['id'],'request_id':str(uuid.uuid4()),'password':self.password}
        artifact=self.exports.export('subscription',args)
        self.assertEqual(self.exports.export('subscription',args),artifact)
        self.exports.export('subscription',dict(args,request_id=str(uuid.uuid4())))
        with self.assertRaises(ClientFault) as error:
            self.exports.export('subscription',args)
        self.assertEqual(error.exception.status,410)
