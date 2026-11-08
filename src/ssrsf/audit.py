"""Acknowledged local audit records. The collector/SQLite owner is trusted.

FULL synchronous commits acknowledge SQLite persistence, not cloud object lock.
The appender has no read/update/delete interface; filesystem-owner tampering and
tail truncation require an independently retained receipt to detect.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .controls import Rejected, canonical, inventory


class AuditUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class Receipt:
    sequence: int
    digest: str


class AuditCollector:
    def __init__(self, path: Path, key: bytes):
        self.path, self.key = path, key
        self.available = True
        self.lock = threading.RLock()
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS audit (sequence INTEGER PRIMARY KEY, "
                       "event_id TEXT UNIQUE NOT NULL, payload TEXT NOT NULL, digest TEXT NOT NULL)")

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        try:
            db.execute("PRAGMA synchronous=FULL")
            with db:
                yield db
        finally:
            db.close()

    def append(self, event_id: str, event: dict) -> Receipt:
        if not self.available:
            raise AuditUnavailable("Audit acknowledgement unavailable")
        if not isinstance(event_id, str) or not event_id or not isinstance(event, dict):
            raise Rejected("Invalid audit event or idempotency key")
        payload = canonical(event).decode()
        event = json.loads(payload)  # Stable snapshot, detached from caller mutation.
        with self.lock, self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT sequence,payload,digest FROM audit WHERE event_id=?", (event_id,)).fetchone()
            if old:
                if old[1] != payload:
                    raise Rejected("Conflicting idempotency key")
                return Receipt(old[0], old[2])
            last = db.execute("SELECT sequence,digest FROM audit ORDER BY sequence DESC LIMIT 1").fetchone()
            sequence, previous = (last[0] + 1, last[1]) if last else (1, "0" * 64)
            message = canonical({"sequence": sequence, "previous": previous,
                                 "event_id": event_id, "event": event})
            digest = hmac.new(self.key, message, hashlib.sha256).hexdigest()
            db.execute("INSERT INTO audit VALUES (?,?,?,?)", (sequence, event_id, payload, digest))
            db.commit()  # Receipt is returned only after commit succeeds.
            return Receipt(sequence, digest)

    def records(self, role: str):
        if role != "investigator":
            raise Rejected("Audit read requires investigator role")
        with self.connect() as db:
            return [{"sequence": n, "event_id": eid, "event": json.loads(payload), "digest": digest}
                    for n, eid, payload, digest in db.execute("SELECT * FROM audit ORDER BY sequence")]

    def verify(self, anchor: Receipt | None = None) -> bool:
        previous = "0" * 64
        try:
            records = self.records("investigator")
        except (json.JSONDecodeError, sqlite3.DatabaseError):
            return False
        for expected, row in enumerate(records, 1):
            message = canonical({"sequence": row["sequence"], "previous": previous,
                                 "event_id": row["event_id"], "event": row["event"]})
            if row["sequence"] != expected or not hmac.compare_digest(
                    row["digest"], hmac.new(self.key, message, hashlib.sha256).hexdigest()):
                return False
            previous = row["digest"]
        return anchor is None or any(r["sequence"] == anchor.sequence and r["digest"] == anchor.digest for r in records)


class InvocationEvidence:
    """Serial environment entry/exit capture; recovers baselines from the collector."""
    def __init__(self, collector: AuditCollector, environment: str, root: Path):
        self.collector, self.environment, self.root = collector, environment, root
        self.lock = threading.RLock()

    def invoke(self, invocation: str, operation):
        with self.lock:
            history = [r["event"] for r in self.collector.records("investigator")
                       if r["event"].get("environment") == self.environment
                       and r["event"].get("phase") in ("entry", "exit")]
            if any(e["invocation"] == invocation for e in history):
                raise Rejected("Invocation already admitted; reconcile instead of repeating side effects")
            state = inventory(self.root)
            last = history[-1] if history else None
            status = ("evidence-gap" if last and last["phase"] != "exit" else
                      "mismatch" if last and last["manifest"] != state else
                      "bootstrap" if last is None else "matched")
            event = {"environment": self.environment, "invocation": invocation,
                     "phase": "entry", "manifest": state, "status": status}
            entry = self.collector.append(invocation + ":entry", event)
            # Inventory mismatch is a triage signal, not a malware verdict.
            try:
                result = operation()
            except Exception as exc:
                self.collector.append(invocation + ":exit", {**event, "phase": "exit",
                    "manifest": inventory(self.root), "status": "failed", "error": type(exc).__name__})
                raise
            try:
                exit_receipt = self.collector.append(invocation + ":exit", {**event, "phase": "exit",
                    "manifest": inventory(self.root), "status": "completed"})
            except AuditUnavailable as exc:
                raise AuditUnavailable("Exit evidence gap; application side effects may have committed") from exc
            return {"result": result, "entry": entry, "exit": exit_receipt, "entry_status": status}
