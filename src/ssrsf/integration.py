"""Paired end-to-end scenarios, single-control ablations and dependency faults."""
from __future__ import annotations

import random
import tempfile
import time
from pathlib import Path

from .audit import AuditUnavailable
from .controls import Rejected
from .policy import Request
from .workflow import CONTROLS, ReferenceApp, rule

CASES = {"unsigned-event": "integrity", "artifact-change": "integrity",
         "unapproved-purge": "broker", "replayed-grant": "broker", "replaced-target": "broker",
         "policy-expansion": "gate", "private-telemetry": "telemetry",
         "audit-entry-outage": "audit", "audit-exit-outage": "audit", "legitimate-workflow": None}


def scenario(app, case):
    """Returns observed completion and state, never a predefined success value."""
    result = {"completed": False, "side_effect": False, "gap_observed": False}
    if case == "audit-entry-outage":
        app.audit.available = False
    if case == "artifact-change":
        (app.artifacts / "parser.rules").write_text("modified parser")
    try:
        if case == "unsigned-event":
            event, _ = app.envelope("bounded text")
            app.ingest("user-token", "bounded text", event=event, signature="forged")
            result["completed"] = True
        elif case == "private-telemetry":
            app.ingest("user-token", "bounded text")
            result["completed"] = "trace" in app.telemetry("user-token", detailed=True)
        elif case == "policy-expansion":
            candidate = [rule("extract", "read", "public/item"), rule("retired", "read", "public/item")]
            app.deploy(candidate)
            result["completed"] = app.policy.invoke(Request("retired", "read", "public/item"), lambda: True)
        else:
            doc = app.ingest("user-token", "bounded text", exit_outage=case == "audit-exit-outage")
            targets = [(doc["id"], doc["version"])]
            if case in ("unapproved-purge", "replayed-grant", "replaced-target", "legitimate-workflow"):
                grant = app.approve("admin-token", targets)
                if case == "replayed-grant":
                    app.purge("admin-token", targets, grant)
                if case == "replaced-target":
                    replacement = app.ingest("user-token", "new version")
                    # Same key, newly created version; old grant must not delete it.
                    targets = [(replacement["id"], replacement["version"])]
                app.purge("user-token" if case == "unapproved-purge" else "admin-token", targets,
                          None if case == "unapproved-purge" else grant)
            result["completed"] = True
    except (Rejected, AuditUnavailable) as exc:
        result["error"] = type(exc).__name__
    try:
        app.documents.get("public/item")
        result["side_effect"] = True
    except Rejected:
        pass
    if case == "audit-exit-outage":
        app.audit.available = True
        app.ingest("user-token", "recovery")
        entries = [r["event"] for r in app.audit.records("investigator") if r["event"].get("phase") == "entry"]
        result["gap_observed"] = bool(entries and entries[-1]["status"] == "evidence-gap")
    return result


def framework(trials, seed):
    rng, rows = random.Random(seed), []
    with tempfile.TemporaryDirectory(prefix="ssrsf-framework-") as directory:
        root = Path(directory)
        for trial in range(trials):
            cases = list(CASES)
            rng.shuffle(cases)
            for case in cases:
                removed = CASES[case]
                variants = [("unprotected", frozenset()), ("full", CONTROLS)]
                if removed:
                    variants.append(("without-" + removed, CONTROLS - {removed}))
                rng.shuffle(variants)
                for variant, controls in variants:
                    start = time.perf_counter_ns()
                    app = ReferenceApp(root / f"{trial}-{case}-{variant}", controls)
                    initialized = time.perf_counter_ns()
                    outcome = scenario(app, case)
                    row = {"trial": trial, "case": case, "variant": variant,
                           "controls": sorted(controls), **outcome,
                           "latency_ms": (time.perf_counter_ns() - start) / 1e6,
                           "initialization_ms": (initialized - start) / 1e6}
                    if case == "legitimate-workflow":
                        row["legitimate_succeeded"] = outcome["completed"]
                    elif not case.startswith("audit-"):
                        row.update(attack=True, attack_succeeded=outcome["completed"])
                    rows.append(row)
    return {"paper_pages": "8–11", "kind": "integrated local text-document workflow and component ablations",
            "hypothesis": "Independent audit, approval, policy and telemetry controls change admission and failure behavior.",
            "cases": CASES, "observations": rows,
            "limits": ["SQLite and trusted Python objects model service boundaries; they are not IAM or process isolation.",
                       "Audit ACK is a FULL synchronous SQLite commit; it is not provider retention or proof against the filesystem owner.",
                       "Replaced-target success measures acceptance of a mismatched grant, not deletion of the replacement in every ablation.",
                       "Fault outcomes report side effects separately; exit audit failure cannot undo committed work.",
                       "Initialization, local storage setup and scenario work are included in total trial timing."]}
