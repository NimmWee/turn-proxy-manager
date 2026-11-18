import unittest
from unittest.mock import patch

from tests import test_managed
from ftm.control import execute
from ftm.admin_exports import AdminExports
from ftm.client_protocol import ClientFault
from ftm.credentials import Credentials


class ControlBoundaryTests(unittest.TestCase):
    setUp = test_managed.ManagedAdoptionTests.setUp

    def test_other_uid_cannot_issue_even_a_valid_command(self):
        with self.assertRaises(PermissionError):
            execute({"v": 1, "op": "users.list", "args": {}}, uid=123, api_uid=456,
                    store=self.store, agent=self.agent)

    def test_unknown_operation_and_extra_shell_fields_are_rejected(self):
        for request in ({"v": 1, "op": "shell", "args": {"command": "id"}},
                        {"v": 1, "op": "users.create", "args": {"name": "Family", "shell": "id"}}):
            with self.assertRaises(ValueError):
                execute(request, uid=456, api_uid=456, store=self.store, agent=self.agent)
        self.assertFalse(self.runner.commands)

    def test_lists_from_api_uid_do_not_disclose_device_credentials(self):
        result = execute({"v": 1, "op": "devices.list", "args": {}}, uid=456, api_uid=456,
                         store=self.store, agent=self.agent)
        for device in result:
            self.assertFalse(set(device) & {"preshared_key", "cid", "wg_public_key", "private_key"})

    def test_subscription_metadata_and_version_bound_revoke(self):
        credentials = Credentials(self.store)
        user = self.store.create_user("Тестовая семья")
        first = credentials.issue_subscription(user["id"])
        second = credentials.issue_subscription(user["id"])

        def require_password(password):
            if password != "verified":
                raise ClientFault("admin_password_required")

        exports = AdminExports(self.store, self.agent)
        exports.authenticate = require_password

        def call(op, args):
            return execute({"v": 1, "op": op, "args": args}, uid=456, api_uid=456,
                           store=self.store, agent=self.agent, exports=exports)

        result = call("subscriptions.list", {"page": 1, "search": "СЕМЬЯ"})
        self.assertFalse(result["has_next"])
        self.assertEqual(result["items"], [{"user_id": user["id"], "name": user["name"],
                                           "enabled": 1, "version": 2, "revoked_at": None}])
        args = {"user_id": user["id"], "expected_version": first["version"], "password": "verified"}
        with self.assertRaises(ClientFault) as stale:
            call("admin.subscription_revoke", args)
        self.assertEqual(stale.exception.code, "subscription_conflict")
        with self.assertRaises(ClientFault) as denied:
            call("admin.subscription_revoke", {**args, "expected_version": 2, "password": "incorrect"})
        self.assertEqual(denied.exception.code, "admin_password_required")
        self.assertIsNotNone(credentials.subscription(second["token"]))
        devices = self.store.list_devices()
        call("admin.subscription_revoke", {**args, "expected_version": 2})
        self.assertIsNone(credentials.subscription(second["token"]))
        self.assertEqual(self.store.list_devices(), devices)
        self.assertFalse(self.runner.commands)

    def test_live_device_counters_join_without_disclosing_wireguard_identity(self):
        phone = self.state["clients"]["iphone"]["public_key"]
        with patch("ftm.metrics.wireguard_counters", return_value={phone: (123, 456, 1_700_000_000)}):
            result = execute({"v": 1, "op": "devices.list", "args": {"telemetry": True}}, uid=456, api_uid=456,
                             store=self.store, agent=self.agent)
        ios = next(device for device in result if device["platform"] == "ios")
        android = next(device for device in result if device["platform"] == "android")
        self.assertEqual((ios["rx_bytes"], ios["tx_bytes"]), (123, 456))
        self.assertEqual(ios["last_handshake_at"], "2023-11-14T22:13:20+00:00")
        self.assertIsNone(android["rx_bytes"])
        self.assertIsNone(android["last_handshake_at"])
        self.assertNotIn(phone, str(result))
        self.assertFalse(set(ios) & {"preshared_key", "cid", "wg_public_key", "private_key"})
