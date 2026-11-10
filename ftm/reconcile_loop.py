"""Bounded retry of durable operations inside the existing root control service."""

import os
import time

from .agent import reconcile


def _apply_pending(store, agent):
    import fcntl
    fd = os.open("/run/lock/vps-vk.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return reconcile(store, agent)
    finally:
        os.close(fd)


class ReconcileLoop:
    """Single-threaded: never overlaps RPC writes, backup, startup or restore."""

    def __init__(self, store, agent, *, clock=time.monotonic):
        self.store, self.agent, self.clock = store, agent, clock
        self.delay = 30
        self.next_due = clock() + self.delay

    def tick(self):
        if self.clock() < self.next_due:
            return None
        try:
            report = _apply_pending(self.store, self.agent)
        except BlockingIOError:
            # An explicit maintenance operation owns the lifecycle lock.
            self.next_due = self.clock() + 5
            return None
        except Exception:
            # Never log DB rows, operation IDs, request data or exception text.
            report = {"processed": 0, "errors": 1, "cancelled": 0}
        self.delay = min(300, self.delay * 2) if report["errors"] else 30
        self.next_due = self.clock() + self.delay
        if any(report[key] for key in ("processed", "errors", "cancelled")):
            print("Reconcile: applied=%d errors=%d obsolete=%d" %
                  (report["processed"], report["errors"], report["cancelled"]), flush=True)
        return report
