"""Trusted controller state. Transitions, outcomes and audit commit together."""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from ssrsf.controls import canonical

from .contracts import Denied, STAGES, exact, identifier
from .reference import ReferenceOperations


class WorkflowStore(ReferenceOperations):
    def __init__(self, path: Path, audit_key: bytes, clock=time.time, lease_seconds=30, cap=20):
        self.path, self.audit_key, self.clock = path, audit_key, clock
        self.lease_seconds, self.cap = lease_seconds, cap
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS workflows (
                    id TEXT PRIMARY KEY, owner TEXT NOT NULL, raw TEXT NOT NULL,
                    version TEXT NOT NULL, stage INTEGER NOT NULL DEFAULT 0,
                    value TEXT NOT NULL, label TEXT, token TEXT, expires REAL,
                    input_hash TEXT, created REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS outcomes (
                    token TEXT PRIMARY KEY, workflow TEXT NOT NULL, stage TEXT NOT NULL,
                    body TEXT NOT NULL, response TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS audit (
                    sequence INTEGER PRIMARY KEY, payload TEXT NOT NULL, digest TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS quota (
                    owner TEXT NOT NULL, bucket INTEGER NOT NULL, used INTEGER NOT NULL,
                    PRIMARY KEY(owner,bucket));
            """)
            self.initialize_reference(db)
        if not self.verify_audit():
            raise Denied("Audit integrity failure")

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA synchronous=FULL")
            with db:
                yield db
        finally:
            db.close()

    def audit(self, db, event):
        previous = db.execute("SELECT sequence,digest FROM audit ORDER BY sequence DESC LIMIT 1").fetchone()
        sequence, digest = (previous[0] + 1, previous[1]) if previous else (1, "0" * 64)
        payload = canonical({"sequence": sequence, "previous": digest, "event": event}).decode()
        tag = hmac.new(self.audit_key, payload.encode(), hashlib.sha256).hexdigest()
        db.execute("INSERT INTO audit VALUES (?,?,?)", (sequence, payload, tag))

    def verify_audit(self):
        previous = "0" * 64
        try:
            with self.connect() as db:
                for sequence, row in enumerate(db.execute("SELECT * FROM audit ORDER BY sequence"), 1):
                    payload = json.loads(row["payload"])
                    expected = hmac.new(self.audit_key, row["payload"].encode(), hashlib.sha256).hexdigest()
                    if (row["sequence"] != sequence or payload["sequence"] != sequence
                            or payload["previous"] != previous
                            or not hmac.compare_digest(expected, row["digest"])):
                        return False
                    previous = row["digest"]
        except (ValueError, KeyError, TypeError, sqlite3.DatabaseError):
            return False
        return True

    def submit(self, owner, body):
        exact(body, ("id", "text"))
        workflow = identifier(body["id"])
        text = body["text"]
        if not isinstance(text, str) or not 1 <= len(text) <= 128:
            raise Denied("Text must contain 1 to 128 characters")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM deleted_workflows WHERE id=?", (workflow,)).fetchone():
                raise Denied("Deleted workflow IDs cannot be reused")
            old = db.execute("SELECT * FROM workflows WHERE id=?", (workflow,)).fetchone()
            if old:
                if old["owner"] != owner or old["raw"] != text:
                    raise Denied("Conflicting workflow id")
                return {"id": workflow, "version": old["version"]}
            now = self.clock()
            bucket = int(now // 60)
            used = db.execute("SELECT used FROM quota WHERE owner=? AND bucket=?", (owner, bucket)).fetchone()
            if used and used[0] >= self.cap:
                raise Denied("Submission quota exhausted")
            db.execute("INSERT INTO quota VALUES (?,?,1) ON CONFLICT(owner,bucket) DO UPDATE SET used=used+1",
                       (owner, bucket))
            version = secrets.token_hex(16)
            db.execute("INSERT INTO workflows(id,owner,raw,version,value,created) VALUES (?,?,?,?,?,?)",
                       (workflow, owner, text, version, text, now))
            self.audit(db, {"kind": "submitted", "id": workflow, "version": version, "owner": owner})
        return {"id": workflow, "version": version}

    def status(self, owner, body):
        exact(body, ("id",))
        workflow = identifier(body["id"])
        with self.connect() as db:
            row = db.execute("SELECT * FROM workflows WHERE id=? AND (owner=? OR ?='admin')", (workflow, owner, owner)).fetchone()
        if row is None:
            raise Denied("Unknown workflow")
        return {"id": workflow, "version": row["version"],
                "state": STAGES[row["stage"]] if row["stage"] < len(STAGES) else "complete",
                "text": row["value"] if row["stage"] == len(STAGES) else None, "label": row["label"],
                "raw": row["raw"], "owner": row["owner"]}

    def claim(self, stage, body):
        exact(body, ("scratch",) if "scratch" in body else ())
        snapshot = scratch_snapshot(body.get("scratch", {}))
        if stage not in STAGES:
            raise Denied("Unknown stage")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self.enforce_policy(db, stage)
            now = self.clock()
            row = db.execute("SELECT * FROM workflows WHERE stage=? AND (token IS NULL OR expires<=?) "
                             "ORDER BY created,id LIMIT 1", (STAGES.index(stage), now)).fetchone()
            if row is None:
                return {"task": None}
            token = secrets.token_hex(32)
            digest = hashlib.sha256(row["value"].encode()).hexdigest()
            expires = now + self.lease_seconds
            db.execute("UPDATE workflows SET token=?,expires=?,input_hash=? WHERE id=?",
                       (token, expires, digest, row["id"]))
            previous = db.execute("SELECT snapshot FROM scratch WHERE stage=?", (stage,)).fetchone()
            entry_status = "first" if previous is None else ("matched" if previous[0] == canonical(snapshot).decode() else "mismatch")
            self.audit(db, {"kind": "claimed", "id": row["id"], "stage": stage,
                            "version": row["version"], "input_hash": digest, "expires": expires,
                            "scratch_entry": snapshot, "entry_status": entry_status})
            return {"task": {"id": row["id"], "version": row["version"], "stage": stage,
                             "value": row["value"], "input_hash": digest, "token": token, "expires": expires}}

    def complete(self, stage, body):
        exact(body, ("id", "version", "input_hash", "token", "output", *(["scratch"] if "scratch" in body else [])))
        snapshot = scratch_snapshot(body.get("scratch", {}))
        if stage not in STAGES:
            raise Denied("Unknown stage")
        workflow = identifier(body["id"])
        if any(not isinstance(body[k], str) for k in ("version", "input_hash", "token", "output")):
            raise Denied("Invalid completion")
        output = body["output"]
        if len(output) > 128 or (stage == "classify" and output not in ("short", "long")):
            raise Denied("Invalid stage output")
        encoded = canonical(body).decode()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self.enforce_policy(db, stage)
            old = db.execute("SELECT * FROM outcomes WHERE token=?", (body["token"],)).fetchone()
            if old:
                if old["stage"] != stage or old["body"] != encoded:
                    raise Denied("Conflicting completion replay")
                return json.loads(old["response"])
            row = db.execute("SELECT * FROM workflows WHERE id=?", (workflow,)).fetchone()
            if (row is None or row["stage"] != STAGES.index(stage) or row["token"] is None
                    or not hmac.compare_digest(row["token"], body["token"])
                    or row["version"] != body["version"] or row["input_hash"] != body["input_hash"]
                    or row["expires"] <= self.clock()):
                raise Denied("Invalid, expired or out-of-order completion")
            next_stage = row["stage"] + 1
            response = {"id": workflow, "state": STAGES[next_stage] if next_stage < len(STAGES) else "complete"}
            db.execute("UPDATE workflows SET stage=?,value=?,label=?,token=NULL,expires=NULL,input_hash=NULL WHERE id=?",
                       (next_stage, row["value"] if stage == "classify" else output,
                        output if stage == "classify" else None, workflow))
            db.execute("INSERT INTO outcomes VALUES (?,?,?,?,?)",
                       (body["token"], workflow, stage, encoded, canonical(response).decode()))
            db.execute("INSERT INTO scratch VALUES (?,?) ON CONFLICT(stage) DO UPDATE SET snapshot=excluded.snapshot",
                       (stage, canonical(snapshot).decode()))
            self.audit(db, {"kind": "completed", "id": workflow, "stage": stage,
                            "version": row["version"], "input_hash": row["input_hash"],
                            "output_hash": hashlib.sha256(output.encode()).hexdigest(), "scratch_exit": snapshot})
        return response


def scratch_snapshot(snapshot):
    if (not isinstance(snapshot, dict) or len(snapshot) > 16
            or any(not isinstance(k, str) or not 1 <= len(k) <= 128
                   or not isinstance(v, str) or not re.fullmatch(r"[0-9a-f]{64}", v) for k,v in snapshot.items())):
        raise Denied("Invalid bounded scratch inventory")
    return snapshot
