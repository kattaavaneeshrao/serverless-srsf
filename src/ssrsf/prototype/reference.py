"""Authenticated management operations for the Docker reference application.

All changes use the controller's SQLite transactions and authenticated audit chain.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import secrets

from ssrsf.controls import canonical
from .contracts import Denied, STAGES, exact, identifier

CLIENTS = ("client", "client2", "admin", "investigator")
DOCUMENT_CLIENTS = ("client", "client2", "admin")
POLICY_CATALOGUE = frozenset((p, a, "documents") for p in (*STAGES, "retired") for a in ("read", "delete"))


def require(actor, roles):
    if actor not in roles:
        raise Denied("Operation not permitted for this identity")


def normalize_policy(candidate):
    if not isinstance(candidate, list) or len(candidate) > 20:
        raise Denied("Policy must contain at most 20 exact rules")
    rules = set()
    for rule in candidate:
        exact(rule, ("principal", "action", "resource", "effect"))
        values = tuple(rule[k] for k in ("principal", "action", "resource", "effect"))
        if any(not isinstance(v, str) for v in values) or values[:3] not in POLICY_CATALOGUE or values[3] not in ("allow", "deny"):
            raise Denied("Rule outside declared exact policy catalogue")
        rules.add(values)
    return sorted(rules)


def allowed(rules, scope):
    effects = {r[3] for r in rules if tuple(r[:3]) == scope}
    return "allow" in effects and "deny" not in effects


class ReferenceOperations:
    def initialize_reference(self, db):
        db.executescript("""
            CREATE TABLE IF NOT EXISTS approvals (
                operation TEXT PRIMARY KEY, request TEXT NOT NULL, grant TEXT NOT NULL,
                signature TEXT NOT NULL, consumed INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS deletions (
                operation TEXT PRIMARY KEY, outcome TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS deleted_workflows (
                id TEXT PRIMARY KEY, version TEXT NOT NULL, owner TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS active_policy (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1), rules TEXT NOT NULL, version INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS deployments (
                id TEXT PRIMARY KEY, candidate TEXT NOT NULL, outcome TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS scratch (
                stage TEXT PRIMARY KEY, snapshot TEXT NOT NULL);
        """)
        rules = [(stage, "read", "documents", "allow") for stage in STAGES]
        db.execute("INSERT OR IGNORE INTO active_policy VALUES (1,?,1)", (canonical(rules).decode(),))

    def enforce_policy(self, db, stage):
        rules = json.loads(db.execute("SELECT rules FROM active_policy WHERE singleton=1").fetchone()[0])
        if not allowed(rules, (stage, "read", "documents")):
            raise Denied("Denied by active policy")

    def approve(self, actor, body):
        require(actor, ("admin",))
        exact(body, ("targets", "operation", "ttl"))
        operation = identifier(body["operation"])
        ttl, targets = body["ttl"], body["targets"]
        if isinstance(ttl, bool) or not isinstance(ttl, (int, float)) or not math.isfinite(ttl) or not 0 < ttl <= 300:
            raise Denied("Approval lifetime must be 1 to 300 seconds")
        if not isinstance(targets, list) or not 1 <= len(targets) <= 20:
            raise Denied("Approve 1 to 20 exact document versions")
        for target in targets:
            if not isinstance(target, list) or len(target) != 2 or not all(isinstance(v, str) for v in target):
                raise Denied("Targets require document ID and exact version")
            identifier(target[0])
        if len({t[0] for t in targets}) != len(targets):
            raise Denied("Duplicate approval target")
        encoded = canonical(body).decode()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT * FROM approvals WHERE operation=?", (operation,)).fetchone()
            if old:
                if old["request"] != encoded:
                    raise Denied("Conflicting approval operation")
                return {"grant": json.loads(old["grant"]), "signature": old["signature"]}
            for workflow, version in targets:
                row = db.execute("SELECT version FROM workflows WHERE id=?", (workflow,)).fetchone()
                if row is None or row[0] != version:
                    raise Denied("Missing or replaced target")
            grant = {"requester": actor, "action": "purge", "targets": targets,
                     "operation": operation, "nonce": secrets.token_hex(24), "expires": self.clock() + ttl}
            tag = self.grant_signature(grant)
            db.execute("INSERT INTO approvals VALUES (?,?,?,?,0)", (operation, encoded, canonical(grant).decode(), tag))
            self.audit(db, {"kind": "approval", "actor": actor, "grant": grant})
        return {"grant": grant, "signature": tag}

    def grant_signature(self, grant):
        key = hmac.new(self.audit_key, b"srsf:purge-approval:v1", hashlib.sha256).digest()
        return hmac.new(key, canonical(grant), hashlib.sha256).hexdigest()

    def purge(self, actor, body):
        require(actor, ("admin",))
        exact(body, ("grant", "signature"))
        grant, signature = body["grant"], body["signature"]
        exact(grant, ("requester", "action", "targets", "operation", "nonce", "expires"))
        operation = identifier(grant["operation"])
        if not isinstance(signature, str) or not hmac.compare_digest(signature, self.grant_signature(grant)) or grant["requester"] != actor:
            raise Denied("Invalid or substituted approval")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            approval = db.execute("SELECT * FROM approvals WHERE operation=?", (operation,)).fetchone()
            if (approval is None or approval["grant"] != canonical(grant).decode() or approval["consumed"]
                    or grant["action"] != "purge" or grant["expires"] <= self.clock()):
                raise Denied("Invalid, expired or already consumed approval")
            for workflow, version in grant["targets"]:
                row = db.execute("SELECT version,owner FROM workflows WHERE id=?", (workflow,)).fetchone()
                if row is None or row["version"] != version:
                    raise Denied("Missing or replaced target; no documents deleted")
                db.execute("INSERT INTO deleted_workflows VALUES (?,?,?)", (workflow, version, row["owner"]))
                db.execute("DELETE FROM workflows WHERE id=? AND version=?", (workflow, version))
                db.execute("DELETE FROM outcomes WHERE workflow=?", (workflow,))
            outcome = {"operation": operation, "requester": actor, "deleted": len(grant["targets"]),
                       "targets": grant["targets"], "grant_digest": hashlib.sha256(canonical(grant)).hexdigest()}
            db.execute("UPDATE approvals SET consumed=1 WHERE operation=?", (operation,))
            db.execute("INSERT INTO deletions VALUES (?,?)", (operation, canonical(outcome).decode()))
            self.audit(db, {"kind": "purge", **outcome})
        return outcome

    def investigate(self, actor, body):
        require(actor, ("admin", "investigator"))
        exact(body, ("operation",))
        operation = identifier(body["operation"])
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT outcome FROM deletions WHERE operation=?", (operation,)).fetchone()
            outcome = {"status": "committed", **json.loads(row[0])} if row else {"status": "not-committed", "operation": operation}
            self.audit(db, {"kind": "reconciliation", "actor": actor, "outcome": outcome})
        return outcome

    def report(self, actor, body):
        require(actor, ("admin",))
        exact(body, ())
        with self.connect() as db:
            return {"classifications": dict(db.execute("SELECT label,count(*) FROM workflows WHERE stage=3 GROUP BY label")),
                    "pending": db.execute("SELECT count(*) FROM workflows WHERE stage<3").fetchone()[0]}

    def budget(self, actor, body):
        require(actor, DOCUMENT_CLIENTS)
        exact(body, ("owner", "reset"))
        owner = body["owner"]
        if owner not in DOCUMENT_CLIENTS or not isinstance(body["reset"], bool):
            raise Denied("Invalid budget request")
        if owner != actor or body["reset"]:
            require(actor, ("admin",))
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            bucket = int(self.clock() // 60)
            row = db.execute("SELECT used FROM quota WHERE owner=? AND bucket=?", (owner, bucket)).fetchone()
            used = row[0] if row else 0
            if body["reset"]:
                db.execute("DELETE FROM quota WHERE owner=? AND bucket=?", (owner, bucket))
                self.audit(db, {"kind": "budget-reset", "actor": actor, "owner": owner, "previous": used, "bucket": bucket})
                used = 0
            return {"owner": owner, "bucket": bucket, "accepted": used, "cap": self.cap, "remaining": max(0, self.cap-used)}

    def telemetry(self, actor, body):
        require(actor, CLIENTS)
        exact(body, ("detailed", "after", "limit"))
        if (not isinstance(body["detailed"], bool) or type(body["after"]) is not int or body["after"] < 0
                or type(body["limit"]) is not int or not 1 <= body["limit"] <= 100):
            raise Denied("Invalid telemetry page")
        if not body["detailed"]:
            return {"service": "reference-app", "status": "available"}
        require(actor, ("admin", "investigator"))
        with self.connect() as db:
            rows = db.execute("SELECT * FROM audit WHERE sequence>? ORDER BY sequence LIMIT ?", (body["after"], body["limit"])).fetchall()
            records = [{"sequence": r["sequence"], "digest": r["digest"], **json.loads(r["payload"])} for r in rows]
            return {"audit": records, "trace": [r["event"] for r in records if r["event"].get("kind") in ("claimed", "completed")],
                    "next": rows[-1]["sequence"] if rows else body["after"]}

    def audit_status(self, actor, body):
        require(actor, CLIENTS)
        exact(body, ("receipt",))
        receipt = body["receipt"]
        if receipt is not None:
            exact(receipt, ("sequence", "digest"))
            if type(receipt["sequence"]) is not int or not isinstance(receipt["digest"], str):
                raise Denied("Invalid audit receipt")
        verified = self.verify_audit()
        with self.connect() as db:
            last = db.execute("SELECT sequence,digest FROM audit ORDER BY sequence DESC LIMIT 1").fetchone()
            if receipt is not None:
                anchor = db.execute("SELECT digest FROM audit WHERE sequence=?", (receipt["sequence"],)).fetchone()
                verified = verified and anchor is not None and hmac.compare_digest(anchor[0], receipt["digest"])
        return {"verified": bool(verified), "receipt": dict(last) if last else None}

    def deploy(self, actor, body):
        require(actor, ("admin",))
        exact(body, ("rules", "change_id"))
        change_id = identifier(body["change_id"])
        encoded = canonical(body["rules"]).decode()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT candidate,outcome FROM deployments WHERE id=?", (change_id,)).fetchone()
            if old:
                if old["candidate"] != encoded:
                    raise Denied("Conflicting deployment ID")
                return json.loads(old["outcome"])
            current = db.execute("SELECT rules,version FROM active_policy WHERE singleton=1").fetchone()
            rules = json.loads(current["rules"])
            status, reason, matrix = "accepted", "", []
            try:
                candidate = normalize_policy(body["rules"])
                matrix = [{"request": list(scope), "before": allowed(rules, scope), "after": allowed(candidate, scope)} for scope in sorted(POLICY_CATALOGUE)]
                if any(not r["before"] and r["after"] for r in matrix):
                    status, reason = "review-required", "Authorization expansion"
            except Denied as exc:
                status, reason = "unresolved", str(exc)
            version = current["version"]
            if status == "accepted":
                version += 1
                db.execute("UPDATE active_policy SET rules=?,version=? WHERE singleton=1", (canonical(candidate).decode(), version))
            outcome = {"status": status, "reason": reason, "matrix": matrix, "version": version}
            db.execute("INSERT INTO deployments VALUES (?,?,?)", (change_id, encoded, canonical(outcome).decode()))
            self.audit(db, {"kind": "deployment", "actor": actor, "change_id": change_id, **outcome})
        return outcome

    def replace(self, actor, body):
        require(actor, DOCUMENT_CLIENTS)
        exact(body, ("id", "version", "text"))
        workflow = identifier(body["id"])
        if not isinstance(body["text"], str) or not 1 <= len(body["text"]) <= 128 or not isinstance(body["version"], str):
            raise Denied("Invalid replacement document")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM workflows WHERE id=?", (workflow,)).fetchone()
            if row is None or row["version"] != body["version"] or (row["owner"] != actor and actor != "admin"):
                raise Denied("Missing document, owner mismatch or replaced version")
            bucket = int(self.clock() // 60)
            used = db.execute("SELECT used FROM quota WHERE owner=? AND bucket=?", (actor, bucket)).fetchone()
            if used and used[0] >= self.cap:
                raise Denied("Submission quota exhausted")
            db.execute("INSERT INTO quota VALUES (?,?,1) ON CONFLICT(owner,bucket) DO UPDATE SET used=used+1", (actor, bucket))
            version = secrets.token_hex(16)
            db.execute("UPDATE workflows SET version=?,raw=?,value=?,stage=0,label=NULL,token=NULL,expires=NULL,input_hash=NULL WHERE id=?", (version, body["text"], body["text"], workflow))
            db.execute("DELETE FROM outcomes WHERE workflow=?", (workflow,))
            self.audit(db, {"kind": "replaced", "id": workflow, "previous_version": row["version"], "version": version, "actor": actor})
        return {"id": workflow, "version": version}
