import sys
import unittest
from unittest.mock import patch

from ftm.baseline_deploy import run_baseline_install
from ftm.legacy import baseline_module


class BaselineDeployTests(unittest.TestCase):
    def test_install_uses_yearly_policy_and_restores_module_and_argv(self):
        app = baseline_module()
        original_policy = app.configure_fail2ban
        original_argv = sys.argv
        observed = []

        def main():
            observed.append(sys.argv[1:])
            app.configure_fail2ban()
            return 0

        with patch.object(app, "main", side_effect=main), patch("ftm.baseline_deploy.configure") as policy:
            self.assertEqual(run_baseline_install("/root/private-vk", "93.184.216.34", qr=True), 0)
            policy.assert_called_once_with()
        self.assertEqual(observed[0][0], "install")
        self.assertIn("--qr", observed[0])
        self.assertIn("--vk-link-file", observed[0])
        self.assertIn("--bundle", observed[0])
        self.assertIs(app.configure_fail2ban, original_policy)
        self.assertIs(sys.argv, original_argv)

    def test_failed_install_restores_hook_without_printing_secrets(self):
        app = baseline_module()
        original_policy = app.configure_fail2ban
        original_argv = sys.argv
        with patch.object(app, "main", side_effect=RuntimeError("install failed")):
            with self.assertRaises(RuntimeError):
                run_baseline_install("/root/private-vk", "93.184.216.34")
        self.assertIs(app.configure_fail2ban, original_policy)
        self.assertIs(sys.argv, original_argv)

    def test_unsafe_endpoint_is_rejected_before_install(self):
        with patch.object(baseline_module(), "main") as main:
            with self.assertRaises(ValueError):
                run_baseline_install("/root/private-vk", "x;reboot")
            main.assert_not_called()
