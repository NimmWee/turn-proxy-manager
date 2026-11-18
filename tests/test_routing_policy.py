import copy
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from ftm.control import execute
from ftm.routing_policy import RoutingPublication, validate_policy, import_catalog
from ftm.store import Store, Conflict, ValidationError
from ftm.client_protocol import ClientFault
from tests.test_client_service import ClientDisclosureTests
from ftm.agent import reconcile

class RoutingStoreTests(unittest.TestCase):
 def setUp(self):
  self.folder=tempfile.TemporaryDirectory();self.addCleanup(self.folder.cleanup)
  self.store=Store(Path(self.folder.name)/"private/db.sqlite3");self.store.initialize();self.publication=RoutingPublication(self.store)
 def test_compare_and_swap_and_invalid_policy_preserve_last_publication(self):
  initial=self.publication.read();policy=initial["policy"];policy["rules"]=[{"domain":"example.com","action":"direct","subdomains":True}]
  self.assertEqual(self.publication.publish(0,policy),{"revision":1})
  with self.assertRaises(Conflict):self.publication.publish(0,policy)
  for rule in ({"domain":"1.1.1.1","action":"direct","subdomains":True},{"domain":"bad/path.ru","action":"direct","subdomains":True},{"domain":"example.com","action":"direct","subdomains":"yes"}):
   bad=copy.deepcopy(policy);bad["rules"]=[rule]
   with self.assertRaises(ValidationError):self.publication.publish(1,bad)
  self.assertEqual(self.publication.read()["revision"],1)
  if os.name=="posix":self.assertEqual(self.store.path.stat().st_mode&0o777,0o600)
 def test_catalog_pin_and_preservation_across_rule_publish(self):
  root=Path(__file__).resolve().parents[1];path=root/"clients/windows/engine/routingdata/catalog.json"
  if not path.exists():self.skipTest("catalogue not copied into Linux fixture")
  raw=path.read_bytes()
  with self.assertRaises(ValidationError):import_catalog(self.store,path,"0"*64)
  self.assertEqual(self.publication.read()["revision"],0)
  import_catalog(self.store,path,hashlib.sha256(raw).hexdigest());first=self.publication.read()
  self.publication.publish(1,first["policy"]);self.assertEqual(self.publication.read()["catalog"],first["catalog"])
 def test_ipc_does_not_accept_catalogue_or_other_uid(self):
  args={"expected_revision":0,"policy":self.publication.read()["policy"],"catalog":"untrusted"}
  with self.assertRaises(ValidationError):execute({"v":1,"op":"routing.publish","args":args},uid=10,api_uid=10,store=self.store,agent=None)
  with self.assertRaises(PermissionError):execute({"v":1,"op":"routing.get","args":{}},uid=11,api_uid=10,store=self.store,agent=None)

class RoutingAuthorizationTests(ClientDisclosureTests):
 def test_device_auth_active_registry_and_revoke_precede_routing_delivery(self):
  result=self.service.enroll(self.link,self.args)
  def get(token):return execute({"v":1,"op":"client.routing","args":{"token":token,"capability":"routing-bundle-v1"}},uid=10,api_uid=10,store=self.store,agent=self.agent)
  with self.assertRaises(ClientFault):get(self.token)
  reconcile(self.store,self.agent)
  with self.assertRaises(ClientFault):get(self.link)
  self.assertEqual(get(self.token)["v"],1)
  self.store.revoke_device(result["device_id"])
  with self.assertRaises(ClientFault):get(self.token)
