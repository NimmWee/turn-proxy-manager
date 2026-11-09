import unittest

from tests import test_managed
from ftm.control import execute


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
