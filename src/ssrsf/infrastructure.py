"""Locally executable analogues of infrastructure threats (article pp. 9–11)."""
from __future__ import annotations

import random
import statistics
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .controls import LocalRollout
from .metrics import latency, proportion
from .runtime import FunctionProcess


def persistence(trials, seed):
    rng, rows = random.Random(seed), []
    with tempfile.TemporaryDirectory(prefix="serverless-persistence-") as directory:
        for trial in range(trials):
            variants = ["warm-unchecked", "warm-monitored", "fresh-workspace"]
            rng.shuffle(variants)
            for variant in variants:
                root = Path(directory) / f"{trial}-{variant}"
                start = time.perf_counter_ns()
                with FunctionProcess(root, monitored=variant == "warm-monitored") as worker:
                    worker.invoke("compromise")
                    if variant == "fresh-workspace":
                        with FunctionProcess(root.with_name(root.name + "-next")) as fresh:
                            outcome = fresh.invoke("legitimate")
                            fresh.invoke("legitimate")
                            cache_ok = (fresh.root / "cache.txt").exists()
                        detections = 0
                    else:
                        outcome = worker.invoke("legitimate")
                        detections = len(worker.quarantined)
                        # The known application cache must survive legitimate warm invocations.
                        worker.invoke("legitimate")
                    if variant != "fresh-workspace":
                        cache_ok = (root / "cache.txt").exists()
                rows.append({"trial": trial, "variant": variant, "attack": True,
                             "case": "marker-across-invocations", "detected": detections > 0,
                             "attack_succeeded": outcome["persistent_marker_observed"],
                             "legitimate_succeeded": cache_ok,
                             "latency_ms": (time.perf_counter_ns() - start) / 1e6})
    return {"paper_pages": "10–11", "kind": "real subprocesses and temporary filesystem",
            "hypothesis": "Reuse retains attacker state; a fresh workspace or declared-content monitoring removes it.",
            "limits": ["The implant is an inert marker, not arbitrary malware or a container escape.",
                       "A fixed cache allowlist operationalizes the paper's legitimate/malicious distinction.",
                       "No host isolation guarantee; timing covers process startup, calls, cleanup and shutdown.",
                       "All modes run one compromise and two legitimate calls; fresh mode starts a second process."],
            "observations": rows}


def _workflow(role: str):
    start = time.perf_counter_ns()
    trace = ["authenticate"]
    if role == "admin":
        trace.extend(["F2", "F3"])
        time.sleep(.003)
    else:
        trace.extend(["F4", "F5"])
        time.sleep(.001)
    return {"role": role, "trace": trace,
            "latency_ms": (time.perf_counter_ns() - start) / 1e6}


def timing_attack(train: list[dict], test: list[dict]) -> dict:
    # Fit direction and threshold on training data only, then freeze them.
    medians = {role: statistics.median(r["latency_ms"] for r in train if r["role"] == role)
               for role in ("user", "admin")}
    threshold = statistics.mean(medians.values())
    admin_slower = medians["admin"] >= medians["user"]
    predictions = ["admin" if (r["latency_ms"] >= threshold) == admin_slower else "user" for r in test]
    correct = sum(p == r["role"] for p, r in zip(predictions, test))
    return {"threshold_ms": threshold, "admin_slower": admin_slower,
            "held_out_accuracy": proportion(correct, len(test)), "predictions": predictions}


def side_channels(trials, seed):
    rng, rows = random.Random(seed), []
    for split in ("train", "test"):
        schedule = [(trial, role) for trial in range(trials) for role in ("user", "admin")]
        rng.shuffle(schedule)
        for trial, role in schedule:
            rows.append({"trial": trial, "split": split, "variant": "exposed", **_workflow(role)})
    train = [r for r in rows if r["split"] == "train"]
    test = [r for r in rows if r["split"] == "test"]
    mapping = {}
    for trace in {tuple(r["trace"]) for r in train}:
        subset = [r for r in train if tuple(r["trace"]) == trace]
        mapping[trace] = "admin" if sum(r["role"] == "admin" for r in subset) > len(subset) / 2 else "user"
    correct = sum(mapping.get(tuple(r["trace"]), "user") == r["role"] for r in test)
    metrics = {"exposed": {"timing_attacker": timing_attack(train, test),
                           "trace_attacker_accuracy": proportion(correct, len(test)),
                           "latency": latency([r["latency_ms"] for r in test])}}
    return {"paper_pages": "9–10, Figure 2", "kind": "local workflow information-exposure demonstration",
            "hypothesis": "Branch-specific traces and response timing can reveal the caller's role.",
            "observer": "Observer is assumed to see function trace names and total response time.",
            "metrics": metrics,
            "limits": ["Threat demonstration only; the review specifies no workflow side-channel defense.",
                       "Service delays (user 1 ms, admin 3 ms) are constructed; wall-clock times are measured.",
                       "Training and test calls are disjoint, balanced and randomized.",
                       "Inference accuracy depends on this host and the limited tested attacker.",
                       "No shared-host CPU/cache channel or real cloud trace access is evaluated."],
            "observations": rows}


def rollouts(trials, seed):
    rng, rows = random.Random(seed), []
    for trial in range(trials):
        deployment = LocalRollout()
        start = time.perf_counter_ns()
        deployment.update(first_replica_only=True)
        replica_order = list(range(4))
        rng.shuffle(replica_order)
        with ThreadPoolExecutor(max_workers=4) as executor:
            calls = list(executor.map(lambda replica: deployment.invoke(replica, "retired"), replica_order))
            legitimate = list(executor.map(lambda replica: deployment.invoke(replica, "active"), replica_order))
        rows.append({"trial": trial, "variant": "rolling-stale-replicas", "attack": True,
                     "case": "revocation-with-stale-replicas", "calls": calls,
                     "attack_succeeded": any(c["allowed"] for c in calls),
                     "stale_allows": sum(c["allowed"] for c in calls),
                     "legitimate_succeeded": all(c["allowed"] for c in legitimate),
                     "latency_ms": (time.perf_counter_ns() - start) / 1e6})
    return {"paper_pages": "10", "kind": "concurrent calls to a partially updated local replica pool",
            "hypothesis": "Partial updates leave revoked access reachable through stale replicas.",
            "limits": ["Threat demonstration only; the review does not specify a rollout defense.",
                       "Four replica objects share one process; they are not distributed nodes.",
                       "The stale-version window is intentionally forced, not measured in production.",
                       "No provider convergence or cloud availability claim."],
            "observations": rows}
