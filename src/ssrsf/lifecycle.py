"""Real interpreter exit/restart and post-expiry operation recovery."""
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def lifecycle(trials, seed):
    rows = []
    worker = Path(__file__).with_name("recovery_worker.py")
    with tempfile.TemporaryDirectory(prefix="ssrsf-restart-") as directory:
        for trial in range(trials):
            root = str(Path(directory) / str(trial))
            def invoke(payload):
                result = subprocess.run([sys.executable, "-I", str(worker)], input=json.dumps(payload),
                    text=True, capture_output=True, timeout=20, check=True, env={})
                return json.loads(result.stdout)
            start = time.perf_counter_ns()
            prepared = invoke({"root": root, "phase": "prepare"})
            outcome = invoke({"root": root, "phase": "recover", "prepared": prepared})
            rows.append({"trial": trial, "variant": "durable-restart", "case": "post-expiry-recovery",
                         "legitimate_succeeded": all(outcome.values()) and prepared["exit_failed"],
                         "exit_audit_failure_observed": prepared["exit_failed"], **outcome,
                         "latency_ms": (time.perf_counter_ns() - start) / 1e6})
    return {"paper_pages": "10–11", "kind": "two isolated Python interpreters per trial sharing durable local state",
            "seed": seed, "observations": rows,
            "hypothesis": "Key continuity and audited policy history preserve revocation and permit independently authorized recovery after a grant expires.",
            "limits": ["Normal interpreter exit/restart, not host power loss, filesystem corruption or distributed failover.",
                       "The fixed clock advances from 1000 to 1040 seconds without waiting; this tests expiry semantics.",
                       "Keys remain in an owner-readable mode-0600 file; no external key manager or key rotation is claimed.",
                       "Invocation budgets are process-local and reset on restart; their restart continuity is not evaluated.",
                       "A complete local owner can replace state and keys; independently retained anchors remain necessary."]}
