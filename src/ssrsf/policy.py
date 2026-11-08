"""Bounded policy-as-code: exact rules, explicit deny, no IAM interpretation."""
from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass

from .audit import AuditCollector
from .controls import Rejected, canonical


@dataclass(frozen=True, order=True)
class Request:
    principal: str
    action: str
    resource: str


def normalize(policy):
    if not isinstance(policy, (list, tuple)):
        raise Rejected("Policy must be a list of exact rules")
    rules = []
    for rule in policy:
        if not isinstance(rule, dict) or set(rule) != {"principal", "action", "resource", "effect"}:
            raise Rejected("Unsupported policy fields or conditions")
        if rule["effect"] not in ("allow", "deny"):
            raise Rejected("Unsupported effect")
        if any(not isinstance(rule[k], str) or not rule[k] or any(c in rule[k] for c in "*?")
               for k in ("principal", "action", "resource")):
            raise Rejected("Only exact nonempty rule values are supported")
        rules.append(tuple(rule[k] for k in ("principal", "action", "resource", "effect")))
    return tuple(sorted(set(rules)))


def decision(rules, request):
    effects = {r[3] for r in rules if r[:3] == (request.principal, request.action, request.resource)}
    return "allow" if "allow" in effects and "deny" not in effects else "deny"


class PolicyDeployment:
    def __init__(self, policy, catalogue, collector: AuditCollector):
        self.rules = normalize(policy)
        self.catalogue = frozenset(catalogue)
        if not self.catalogue or any(not isinstance(r, Request) for r in self.catalogue):
            raise ValueError("A nonempty exact request catalogue is required")
        self.collector, self.version = collector, 1
        self.lock = threading.RLock()
        # Accepted records are the local durable policy commit point. A restart
        # must not silently resurrect permissions removed by a previous cutover.
        for row in collector.records("investigator"):
            event = row["event"]
            if event.get("kind") == "deployment" and event.get("status") == "accepted":
                if "rules" not in event or event["version_before"] != self.version:
                    raise Rejected("Incomplete policy recovery history")
                rules = tuple(tuple(r) for r in event["rules"])
                if any(Request(*r[:3]) not in self.catalogue for r in rules):
                    raise Rejected("Recovered policy exceeds catalogue")
                self.rules, self.version = rules, self.version + 1

    def deploy(self, candidate, change_id):
        # Detach input before normalization and hashing so audit and installation agree.
        try:
            candidate = json.loads(canonical({"policy": candidate}))["policy"]
        except (TypeError, ValueError):
            raise Rejected("Policy input must be finite JSON") from None
        with self.lock:
            status, reason, matrix = "accepted", "", []
            try:
                rules = normalize(candidate)
                if any(Request(*r[:3]) not in self.catalogue for r in (*self.rules, *rules)):
                    raise Rejected("Rule outside declared catalogue")
                matrix = [{"request": vars(r), "before": decision(self.rules, r), "after": decision(rules, r)}
                          for r in sorted(self.catalogue)]
                if any(r["before"] == "deny" and r["after"] == "allow" for r in matrix):
                    status, reason = "review-required", "Authorization expansion"
            except Rejected as exc:
                rules = self.rules
                status, reason = "unresolved", str(exc)
            self.collector.append("deploy:" + change_id, {"kind": "deployment", "status": status,
                "reason": reason, "matrix": matrix,
                "candidate_sha256": hashlib.sha256(canonical({"policy": candidate})).hexdigest(),
                "rules": rules,
                "version_before": self.version})
            if status == "accepted":
                self.rules = rules
                self.version += 1
            return {"status": status, "reason": reason, "matrix": matrix, "version": self.version}

    def invoke(self, request, operation):
        # Lock spans admitted work and policy replacement; local draining semantics.
        with self.lock:
            if decision(self.rules, request) != "allow":
                raise Rejected("Denied by active policy")
            return operation()
