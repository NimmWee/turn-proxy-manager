import unittest
from unittest.mock import patch

from ftm.reconcile_loop import ReconcileLoop


class RetrySafetyTests(unittest.TestCase):
    def setUp(self):
        self.now = 0
        self.loop = ReconcileLoop(object(), object(), clock=lambda: self.now)

    @patch("ftm.reconcile_loop._apply_pending")
    def test_maintenance_lock_defers_without_calling_network_again(self, apply):
        self.loop.tick()
        apply.assert_not_called()
        self.now = 30
        apply.side_effect = BlockingIOError()
        self.assertIsNone(self.loop.tick())
        self.assertEqual(self.loop.next_due, 35)
        self.now = 34
        self.loop.tick()
        self.assertEqual(apply.call_count, 1)

    @patch("ftm.reconcile_loop._apply_pending")
    def test_persistent_errors_back_off_then_success_returns_to_normal(self, apply):
        apply.return_value = {"processed": 0, "errors": 1, "cancelled": 0}
        for expected in (60, 120, 240, 300, 300):
            self.now = self.loop.next_due
            self.loop.tick()
            self.assertEqual(self.loop.delay, expected)
        apply.return_value = {"processed": 1, "errors": 0, "cancelled": 1}
        self.now = self.loop.next_due
        self.loop.tick()
        self.assertEqual(self.loop.delay, 30)

    @patch("ftm.reconcile_loop._apply_pending", side_effect=RuntimeError("credential-marker"))
    @patch("builtins.print")
    def test_exception_does_not_escape_or_disclose_data(self, output, apply):
        self.now = 30
        self.assertEqual(self.loop.tick()["errors"], 1)
        self.assertNotIn("credential-marker", str(output.call_args))
