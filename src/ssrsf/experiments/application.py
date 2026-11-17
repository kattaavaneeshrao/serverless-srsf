"""Application-level experiments (article section 6, pp. 8–9)."""
from __future__ import annotations

import os
import random
import tempfile
import time
from pathlib import Path

from ..controls import (AccessControl, Identity, Rejected, accept_event, inventory,
                       sign_event, verify_inventory)


def observation(trial, variant, case, attack, operation):
    start = time.perf_counter_ns()
    try:
        operation()
        accepted = True
    except Rejected:
        accepted = False
    return {"trial": trial, "variant": variant, "case": case, "attack": attack,
            "accepted": accepted, "attack_succeeded": attack and accepted,
            "legitimate_succeeded": not attack and accepted,
            "latency_ms": (time.perf_counter_ns() - start) / 1e6}


def events(trials, seed):
    key = b"local-experiment-key; never a production credential"
    valid = {"action": "read", "resource": "public/item", "value": "hello"}
    cases = [
        ("ordinary", False, valid, sign_event(valid, key)),
        ("metacharacters-as-data", False, {**valid, "value": "'; $(echo data) <script>"}, None),
        ("internal-queue-delete", True, {**valid, "action": "delete"}, None),
        ("resource-traversal", True, {**valid, "resource": "public/../private/secret"}, None),
        ("oversized-value", True, {**valid, "value": "x" * 129}, None),
        ("extra-privilege-field", True, {**valid, "role": "admin"}, None),
        ("tampered-in-transit", True, {**valid, "value": "modified"}, sign_event(valid, key)),
    ]
    rows, rng = [], random.Random(seed)
    for trial in range(trials):
        order = list(cases)
        rng.shuffle(order)
        for case, attack, event, signature in order:
            signature = sign_event(event, key) if signature is None else signature
            variants = ["unchecked", "validated-signed"]
            rng.shuffle(variants)
            for variant in variants:
                def execute():
                    accepted = accept_event(event, signature, key) if variant == "validated-signed" else event
                    # A real in-memory event consumer; no command strings are executed.
                    store = {"public/item": "hello", "private/secret": "private"}
                    if accepted["action"] == "delete":
                        store.pop("public/item")
                    elif accepted["action"] == "read":
                        store.get(accepted["resource"])
                rows.append(observation(trial, variant, case, attack, execute))
    return {"paper_pages": "8–9", "kind": "executed local event consumer",
            "hypothesis": "Validate internal and external event schemas; verify integrity before use.",
            "limits": ["Constructed event corpus, not an injection vulnerability scanner.",
                       "Acceptance measures schema/integrity violations; payload strings are never executed.",
                       "HMAC is a local integrity mechanism, not a public-key signature or replay defense."],
            "observations": rows}


def authorization(trials, seed):
    guard = AccessControl({"reader-token": Identity("reader", "reader"),
                           "admin-token": Identity("admin", "admin")},
                          {"reader": {("read", "public/item")},
                           "admin": {("read", "public/item"), ("delete", "public/item")}})
    cases = [
        ("reader", False, "gateway", "reader-token", "read", "public/item"),
        ("admin", False, "gateway", "admin-token", "delete", "public/item"),
        ("internal-legitimate", False, "queue", "reader-token", "read", "public/item"),
        ("direct-invocation-bypass", True, "queue", "", "delete", "public/item"),
        ("forged-credential", True, "queue", "forged", "delete", "public/item"),
        ("excess-function-privilege", True, "queue", "reader-token", "delete", "public/item"),
        ("wrong-resource", True, "queue", "reader-token", "read", "private/secret"),
    ]
    rows, rng = [], random.Random(seed)
    for trial in range(trials):
        order = list(cases)
        rng.shuffle(order)
        for case, attack, source, token, action, resource in order:
            variants = ["gateway-only-broad-role", "per-function-least-privilege"]
            rng.shuffle(variants)
            for variant in variants:
                def execute():
                    if variant == "per-function-least-privilege":
                        guard.authorize(token, action, resource)
                    elif source == "gateway" and token not in guard.credentials:
                        raise Rejected("Gateway rejected")
                    store = {"public/item": "public", "private/secret": "private"}
                    if action == "delete":
                        store.pop(resource)
                    else:
                        store[resource]
                rows.append(observation(trial, variant, case, attack, execute))
    return {"paper_pages": "8–9", "kind": "executed local function/service access checks",
            "hypothesis": "Gateway authentication alone leaves internal entry points exposed; enforce exact capabilities.",
            "limits": ["Python reference monitor, not OS isolation, IAM, tenant identity or cloud enforcement."],
            "observations": rows}


def dependencies(trials, seed):
    rows, rng = [], random.Random(seed)
    with tempfile.TemporaryDirectory(prefix="serverless-dependencies-") as directory:
        root = Path(directory)
        for trial in range(trials):
            cases = ["unchanged", "same-size-mtime-tamper", "unlisted-dependency"]
            rng.shuffle(cases)
            for case in cases:
                for existing in root.iterdir():
                    existing.unlink()
                module = root / "library.txt"
                module.write_bytes(b"trusted artifact")
                lock = inventory(root)
                original_stat = module.stat()
                if case == "same-size-mtime-tamper":
                    module.write_bytes(b"changed artifact")
                    os.utime(module, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
                elif case == "unlisted-dependency":
                    (root / "unexpected.txt").write_bytes(b"unapproved dependency")
                variants = ["untracked", "hash-locked-inventory"]
                rng.shuffle(variants)
                for variant in variants:
                    def execute():
                        if variant == "hash-locked-inventory" and not verify_inventory(root, lock):
                            raise Rejected("Dependency inventory changed")
                        module.read_bytes()
                    rows.append(observation(trial, variant, case, case != "unchanged", execute))
    return {"paper_pages": "9", "kind": "executed file integrity experiment",
            "hypothesis": "Track third-party artifacts; reject changed or unlisted components before use.",
            "limits": ["Hash pinning detects changes, not known vulnerabilities or malicious trusted artifacts.",
                       "Trusted inventory storage is assumed; no exploit code is imported."],
            "observations": rows}
