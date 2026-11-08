"""Independent exact-version purge grants and transactional local deletion.

Approval authority and broker are trusted local services. Python object boundaries
are not process isolation. One SQLite transaction consumes the nonce and deletes
all targets; this atomicity does not generalize to cloud multi-service deletion.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from .audit import AuditCollector
from .controls import Rejected, canonical


class DocumentStore:
    def __init__(self, path: Path):
        self.path = path
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS documents (id TEXT PRIMARY KEY, owner TEXT NOT NULL, "
                       "version TEXT NOT NULL, raw TEXT NOT NULL, extracted TEXT NOT NULL, label TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS consumed (nonce TEXT PRIMARY KEY, operation TEXT UNIQUE NOT NULL)")

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        try:
            db.execute("PRAGMA synchronous=FULL")
            with db:
                yield db
        finally:
            db.close()

    def put(self, doc_id, owner, text):
        version = secrets.token_hex(16)
        extracted = " ".join(text.split())
        label = "long" if len(extracted.split()) >= 10 else "short"
        with self.connect() as db:
            db.execute("INSERT INTO documents VALUES (?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
                       "owner=excluded.owner, version=excluded.version, raw=excluded.raw, "
                       "extracted=excluded.extracted,label=excluded.label",
                       (doc_id, owner, version, text, extracted, label))
        return {"id": doc_id, "version": version, "label": label}

    def get(self, doc_id):
        with self.connect() as db:
            row = db.execute("SELECT id,owner,version,raw,extracted,label FROM documents WHERE id=?", (doc_id,)).fetchone()
        if row is None:
            raise Rejected("Unknown document")
        return dict(zip(("id", "owner", "version", "raw", "extracted", "label"), row))


class ApprovalAuthority:
    def __init__(self, key: bytes, credentials: dict, clock=time.time):
        self.key, self.credentials, self.clock = key, dict(credentials), clock
        self.available = True

    def identity(self, credential):
        if not self.available:
            raise Rejected("Independent authorization unavailable")
        identity = self.credentials.get(credential)
        if identity is None:
            raise Rejected("Invalid requester credential")
        return identity

    def issue(self, credential, targets, operation, ttl=30):
        identity = self.identity(credential)
        if (identity[1] != "administrator" or isinstance(ttl, bool) or not isinstance(ttl, (int, float))
                or not math.isfinite(ttl) or not 0 < ttl <= 300):
            raise Rejected("Approval denied")
        if (not isinstance(targets, (list, tuple)) or not targets or len(targets) > 20
                or any(not isinstance(t, (list, tuple)) or len(t) != 2
                       or any(not isinstance(v, str) or not 1 <= len(v) <= 128 for v in t) for t in targets)
                or len({t[0] for t in targets}) != len(targets)
                or not isinstance(operation, str) or not 1 <= len(operation) <= 128):
            raise Rejected("Invalid target scope")
        grant = {"requester": identity[0], "action": "purge", "targets": [list(t) for t in targets],
                 "operation": operation, "nonce": secrets.token_hex(24), "expires": self.clock() + ttl}
        return {"grant": grant, "signature": hmac.new(self.key, canonical(grant), hashlib.sha256).hexdigest()}

    def verify(self, envelope, credential):
        identity = self.identity(credential)
        try:
            grant = json.loads(canonical(envelope["grant"]))
            signature = envelope["signature"]
            expected = hmac.new(self.key, canonical(grant), hashlib.sha256).hexdigest()
            if (set(grant) != {"requester", "action", "targets", "operation", "nonce", "expires"}
                    or not hmac.compare_digest(signature, expected)
                    or grant["requester"] != identity[0] or identity[1] != "administrator"
                    or grant["action"] != "purge" or grant["expires"] <= self.clock()):
                raise Rejected("Invalid, expired or substituted grant")
        except Rejected:
            raise
        except (KeyError, TypeError, ValueError):
            raise Rejected("Malformed purge envelope") from None
        return grant


class PurgeBroker:
    def __init__(self, store: DocumentStore, authority: ApprovalAuthority, audit: AuditCollector):
        self.store, self.authority, self.audit = store, authority, audit

    def purge(self, envelope, credential):
        grant = self.authority.verify(envelope, credential)
        envelope = {"grant": grant, "signature": envelope["signature"]}
        # Audit admission is acknowledged before any destructive side effect.
        self.audit.append("purge:" + grant["operation"] + ":entry", {"kind": "purge-entry", "grant": grant})
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            # Recheck after waiting for the database write lock.
            self.authority.verify(envelope, credential)
            if db.execute("SELECT 1 FROM consumed WHERE nonce=? OR operation=?",
                          (grant["nonce"], grant["operation"])).fetchone():
                raise Rejected("Purge replay")
            for doc_id, version in grant["targets"]:
                row = db.execute("SELECT version FROM documents WHERE id=?", (doc_id,)).fetchone()
                if row is None or row[0] != version:
                    raise Rejected("Missing or replaced target; no targets deleted")
            db.execute("INSERT INTO consumed VALUES (?,?)", (grant["nonce"], grant["operation"]))
            for doc_id, version in grant["targets"]:
                db.execute("DELETE FROM documents WHERE id=? AND version=?", (doc_id, version))
            db.commit()
        self.audit.append("purge:" + grant["operation"] + ":exit",
                          {"kind": "purge-exit", "operation": grant["operation"], "deleted": len(grant["targets"])})
        return {"operation": grant["operation"], "deleted": len(grant["targets"])}

    def reconcile(self, envelope, credential):
        """Read durable outcome without reusing a destructive capability."""
        grant = self.authority.verify(envelope, credential)
        with self.store.connect() as db:
            row = db.execute("SELECT operation FROM consumed WHERE nonce=?", (grant["nonce"],)).fetchone()
        if row is None:
            return {"status": "not-committed"}
        return {"status": "committed", "operation": row[0]}
