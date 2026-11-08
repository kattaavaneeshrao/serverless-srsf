"""Executable local ReferenceApp, with independently configurable controls.

All roles are enforced by a trusted Python reference monitor; object references
and SQLite databases are not a boundary against hostile code in this process.
The bounded parser accepts UTF-8 text, not arbitrary PDFs or downloaded code.
"""
from __future__ import annotations

import secrets
import threading
import time
from pathlib import Path

from .audit import AuditCollector, InvocationEvidence
from .broker import ApprovalAuthority, DocumentStore, PurgeBroker
from .controls import Rejected, accept_event, sign_event, verify_inventory
from .policy import PolicyDeployment, Request, normalize
from .state import bootstrap

CONTROLS = frozenset({"audit", "broker", "gate", "integrity", "telemetry"})


def rule(principal, action, resource, effect="allow"):
    return {"principal": principal, "action": action, "resource": resource, "effect": effect}


class InvocationBudget:
    """Fixed ingest quota per explicitly closed local bucket; resets on restart."""
    def __init__(self, cap=20):
        if isinstance(cap, bool) or not isinstance(cap, int) or cap < 1:
            raise ValueError("Positive integer quota required")
        self.cap = cap
        self.offered, self.accepted = 0, 0
        self.lock = threading.RLock()

    def admit(self):
        with self.lock:
            self.offered += 1
            if self.accepted >= self.cap:
                raise Rejected("Invocation quota exhausted")
            self.accepted += 1

    def close_bucket(self):
        with self.lock:
            result = {"offered": self.offered, "accepted": self.accepted,
                      "rejected": self.offered - self.accepted, "quota": self.cap}
            self.offered = self.accepted = 0
            return result


class ReferenceApp:
    def __init__(self, root: Path, controls=CONTROLS, clock=time.time):
        self.root, self.controls = root, frozenset(controls)
        if not self.controls <= CONTROLS:
            raise ValueError("Unknown control")
        root.mkdir(parents=True, exist_ok=True)
        keys, self.trusted_inventory = bootstrap(root)
        self.credentials = {"user-token": ("alice", "user"), "admin-token": ("operator", "administrator"),
                            "investigator-token": ("auditor", "investigator")}
        self.audit = AuditCollector(root / "audit.sqlite", keys["audit"])
        if not self.audit.verify():
            raise Rejected("Audit integrity failure at startup")
        self.documents = DocumentStore(root / "documents.sqlite")
        self.authority = ApprovalAuthority(keys["approval"], self.credentials, clock)
        self.broker = PurgeBroker(self.documents, self.authority, self.audit)
        self.workspace = root / "scratch"
        self.workspace.mkdir(exist_ok=True)
        self.evidence = InvocationEvidence(self.audit, "extract-worker-1", self.workspace)
        self.artifacts = root / "artifacts"
        self.event_key = keys["events"]
        catalogue = [Request(p, a, "public/item") for p in ("extract", "retired") for a in ("read", "delete")]
        self.policy = PolicyDeployment([rule("extract", "read", "public/item")], catalogue, self.audit)
        self.budget = InvocationBudget()
        self.trace = []
        self.receipts = []

    def identity(self, credential):
        identity = self.credentials.get(credential)
        if identity is None:
            raise Rejected("Invalid gateway credential")
        return identity

    def envelope(self, text):
        event = {"action": "read", "resource": "public/item", "value": text}
        return event, sign_event(event, self.event_key)

    def ingest(self, credential, text, *, event=None, signature=None, exit_outage=False):
        identity = self.identity(credential)
        self.budget.admit()
        if event is None:
            event, signature = self.envelope(text)
        if "integrity" in self.controls:
            event = accept_event(event, signature, self.event_key)
            if event["resource"] != "public/item":
                raise Rejected("Resource outside reference workflow scope")
            if not verify_inventory(self.artifacts, self.trusted_inventory):
                raise Rejected("Untrusted parser artifact")
        invocation = secrets.token_hex(16)
        def process():
            try:
                current = self.documents.get("public/item")
            except Rejected:
                current = None
            if current and current["owner"] != identity[0] and identity[1] != "administrator":
                raise Rejected("Only the owner or administrator may replace a document")
            self.trace.extend(["ingest", "extract", "classify"])
            # No shell, eval, pickle, external parser or model is involved.
            (self.workspace / "cache.txt").write_text("bounded application cache")
            result = self.documents.put("public/item", identity[0], event["value"])
            if exit_outage:
                self.audit.available = False
            return result
        def capture():
            if "audit" in self.controls:
                outcome = self.evidence.invoke(invocation, process)
                self.receipts.append(outcome["exit"])
                return outcome["result"]
            return process()
        return self.policy.invoke(Request("extract", "read", "public/item"), capture)

    def read(self, credential, doc_id="public/item"):
        identity = self.identity(credential)
        result = self.documents.get(doc_id)
        if result["owner"] != identity[0] and identity[1] != "administrator":
            raise Rejected("Document owner mismatch")
        return result

    def report(self, credential):
        if self.identity(credential)[1] != "administrator":
            raise Rejected("Reporting requires administrator")
        with self.documents.connect() as db:
            return dict(db.execute("SELECT label,count(*) FROM documents GROUP BY label"))

    def approve(self, credential, targets, operation=None, ttl=30):
        return self.authority.issue(credential, targets, operation or secrets.token_hex(16), ttl)

    def purge(self, credential, targets, envelope=None):
        self.identity(credential)
        if "broker" in self.controls:
            if envelope is None or envelope.get("grant", {}).get("targets") != [list(t) for t in targets]:
                raise Rejected("Independent exact-scope approval required")
            return self.broker.purge(envelope, credential)
        # Ablation: authenticated caller reaches an overprivileged deletion function.
        with self.documents.connect() as db:
            for doc_id, version in targets:
                db.execute("DELETE FROM documents WHERE id=? AND version=?", (doc_id, version))
        return {"deleted": len(targets)}

    def deploy(self, candidate):
        if "gate" in self.controls:
            return self.policy.deploy(candidate, secrets.token_hex(16))
        with self.policy.lock:
            self.policy.rules = normalize(candidate)
            self.policy.version += 1
        return {"status": "accepted", "version": self.policy.version}

    def telemetry(self, credential, detailed=False):
        identity = self.identity(credential)
        if detailed and "telemetry" in self.controls:
            if identity[1] not in ("administrator", "investigator"):
                raise Rejected("Detailed telemetry restricted to investigator")
        if detailed:
            return {"trace": list(self.trace), "audit": self.audit.records("investigator")}
        return {"service": "reference-app", "status": "available"}
