"""Bounded host telemetry stored outside configuration checkpoints."""

import sqlite3
import time

from .metrics import collect
from .store import Store, ValidationError


RESOLUTION_MINUTES = {1: 1, 6: 3, 24: 10, 168: 60}
HISTORY_DAYS = max(RESOLUTION_MINUTES) // 24
RETENTION_MINUTES = HISTORY_DAYS * 24 * 60


class MetricsHistory:
    def __init__(self, path, state, *, collector=collect, wall=time.time, clock=time.monotonic):
        self.store = Store(path)
        self.state, self.collector = state, collector
        self.wall, self.clock = wall, clock
        self.next_due = 0
        self.sampling_failed = False

    def tick(self):
        if self.clock() < self.next_due:
            return
        self.next_due = self.clock() + 60
        try:
            minute = int(self.wall() // 60)
            sample = self.collector(self.state)
            total = sample["memory_total_bytes"]
            memory_pct = 100 * max(0, min(1, sample["memory_used_bytes"] / total)) if total > 0 else None
            with self.store.transaction() as db:
                db.execute("""CREATE TABLE IF NOT EXISTS samples(
                              minute INTEGER PRIMARY KEY, cpu_pct REAL, memory_pct REAL,
                              peers_active INTEGER) STRICT""")
                # A wall clock correction invalidates samples in the new future.
                db.execute("DELETE FROM samples WHERE minute <= ? OR minute > ?",
                           (minute - RETENTION_MINUTES, minute))
                db.execute("INSERT OR IGNORE INTO samples VALUES(?,?,?,?)",
                           (minute, sample["cpu_pct"], memory_pct, sample["recent_handshakes_estimate"]))
        except (sqlite3.Error, OSError, RuntimeError, ValueError, KeyError):
            self.sampling_failed = True
        else:
            self.sampling_failed = False

    def read(self, hours):
        if type(hours) is not int or hours not in RESOLUTION_MINUTES:
            raise ValidationError("Unsupported monitoring period")
        step = RESOLUTION_MINUTES[hours]
        result = {"step_minutes": step, "sampling_failed": self.sampling_failed, "samples": []}
        if not self.store.path.exists() and not self.store.path.is_symlink():
            return result
        minute = int(self.wall() // 60)
        with self.store.connect() as db:
            rows = db.execute("""SELECT min(minute) * 60 AS timestamp,
                           round(avg(cpu_pct),1) AS cpu_pct, round(avg(memory_pct),1) AS memory_pct,
                           max(peers_active) AS recent_handshakes_estimate
                           FROM samples WHERE minute > ? AND minute <= ?
                           GROUP BY minute / ? ORDER BY min(minute)""",
                           (minute - hours * 60, minute, step))
            result["samples"] = [dict(row) for row in rows]
        return result
