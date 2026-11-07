"""Locally executable analogues of infrastructure threats (article pp. 9–11)."""
from __future__ import annotations

import random
import statistics
import tempfile
import threading
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


def _workflow(role: str, variant: str, floor_ms: float):
    start = time.perf_counter_ns()
    cpu_start = time.process_time_ns()
    trace = ["authenticate"]
    if role == "admin":
        trace.extend(["F2", "F3"])
        time.sleep(.003)
    else:
        trace.extend(["F4", "F5"])
        time.sleep(.001)
    if variant != "exposed":
        deadline = start + int(floor_ms * 1e6)
        remaining = (deadline - time.perf_counter_ns()) / 1e9
        # Separate experimental mitigation: sleep coarsely, then wait on an
        # absolute monotonic deadline to reduce role-dependent sleep overshoot.
        # This costs CPU and still has no constant-time/security guarantee.
        if variant == "facade-deadline":
            remaining -= .002
        if remaining > 0:
            time.sleep(remaining)
        if variant == "facade-deadline":
            while time.perf_counter_ns() < deadline:
                pass
    elapsed = (time.perf_counter_ns() - start) / 1e6
    return {"role": role, "trace": trace if variant == "exposed" else ["facade"],
            "latency_ms": elapsed, "cpu_ms": (time.process_time_ns() - cpu_start) / 1e6}


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


def side_channels(trials, seed, floor_ms):
    rng, rows = random.Random(seed), []
    # Roles, variants, and collection order are balanced and randomized in both splits.
    for split in ("train", "test"):
        schedule = [(trial, role, variant) for trial in range(trials)
                    for role in ("user", "admin") for variant in ("exposed", "facade-floor", "facade-deadline")]
        rng.shuffle(schedule)
        for trial, role, variant in schedule:
            rows.append({"trial": trial, "split": split, "variant": variant,
                         **_workflow(role, variant, floor_ms)})
    metrics = {}
    for variant in ("exposed", "facade-floor", "facade-deadline"):
        train = [r for r in rows if r["variant"] == variant and r["split"] == "train"]
        test = [r for r in rows if r["variant"] == variant and r["split"] == "test"]
        # Learn trace -> majority role on training data; ties choose user.
        mapping = {}
        for trace in {tuple(r["trace"]) for r in train}:
            subset = [r for r in train if tuple(r["trace"]) == trace]
            mapping[trace] = "admin" if sum(r["role"] == "admin" for r in subset) > len(subset) / 2 else "user"
        correct = sum(mapping.get(tuple(r["trace"]), "user") == r["role"] for r in test)
        metrics[variant] = {"timing_attacker": timing_attack(train, test),
                            "trace_attacker_accuracy": proportion(correct, len(test)),
                            "latency": latency([r["latency_ms"] for r in test]),
                            "mean_cpu_ms": statistics.mean(r["cpu_ms"] for r in test),
                            "over_floor": sum(r["latency_ms"] > floor_ms for r in test)}
    return {"paper_pages": "9–10, Figure 2", "kind": "measured local workflows with controlled service delays",
            "hypothesis": "Branch-specific traces/timing reveal roles; a facade restricts trace visibility and padding reduces timing signal.",
            "observer": "External observer sees exported trace names and total response time, not internal traces.",
            "floor_ms": floor_ms, "metrics": metrics,
            "limits": ["Service delays (user 1 ms, admin 3 ms) are constructed; wall-clock times are measured.",
                       "Training and test calls are disjoint, balanced and randomized; no attacker uses test labels to fit.",
                       "Wilson intervals describe sample proportions, not proof of independence or zero leakage.",
                       "The facade deliberately hides internal names from this observer; privileged telemetry observers still see them.",
                       "Simple sleep padding can itself retain role-dependent timing on some hosts.",
                       "Deadline padding spins for up to the final 2 ms, increasing CPU cost; no constant-time guarantee.",
                       "Padding may leak under contention or slow handlers; accuracy need not equal chance."],
            "observations": rows}


def rollouts(trials, seed):
    rng, rows = random.Random(seed), []
    for trial in range(trials):
        variants = ["rolling-stale-replicas", "atomic-cutover"]
        rng.shuffle(variants)
        for variant in variants:
            deployment = LocalRollout(atomic=variant == "atomic-cutover")
            start = time.perf_counter_ns()
            deployment.update(first_replica_only=True)
            # Requests execute concurrently after the local cutover/first-replica update.
            with ThreadPoolExecutor(max_workers=4) as executor:
                calls = list(executor.map(lambda replica: deployment.invoke(replica, "retired"), range(4)))
                legitimate = list(executor.map(lambda replica: deployment.invoke(replica, "active"), range(4)))
            rows.append({"trial": trial, "variant": variant, "attack": True,
                         "case": "revocation-with-stale-replicas", "calls": calls,
                         "attack_succeeded": any(c["allowed"] for c in calls),
                         "stale_allows": sum(c["allowed"] for c in calls),
                         "legitimate_succeeded": all(c["allowed"] for c in legitimate),
                         "latency_ms": (time.perf_counter_ns() - start) / 1e6})
            # Hold a previously authorized request while a revocation tries to cut over.
            deployment = LocalRollout(atomic=variant == "atomic-cutover")
            admitted, release, updating, updated = (threading.Event() for _ in range(4))
            def hold():
                admitted.set()
                if not release.wait(5):
                    raise RuntimeError("Timed out waiting for in-flight release")
            def cutover():
                updating.set()
                deployment.update()
                updated.set()
            start = time.perf_counter_ns()
            with ThreadPoolExecutor(max_workers=2) as executor:
                request = executor.submit(deployment.invoke, 0, "retired", hold)
                try:
                    if not admitted.wait(5):
                        raise RuntimeError("Request did not reach admission barrier")
                    update = executor.submit(cutover)
                    if not updating.wait(5):
                        raise RuntimeError("Update did not start")
                    if deployment.atomic:
                        cutover_before_release = updated.wait(.005)
                    else:
                        if not updated.wait(5):
                            raise RuntimeError("Unprotected update did not complete")
                        cutover_before_release = True
                finally:
                    release.set()
                result = request.result(timeout=5)
                update.result(timeout=5)
            rows.append({"trial": trial, "variant": variant, "attack": True,
                         "case": "inflight-revocation", "calls": [result],
                         "cutover_before_release": cutover_before_release,
                         "attack_succeeded": result["allowed"] and cutover_before_release,
                         "legitimate_succeeded": deployment.invoke(0, "active")["allowed"],
                         "latency_ms": (time.perf_counter_ns() - start) / 1e6})
    return {"paper_pages": "10", "kind": "concurrent requests to a local in-process replica pool",
            "hypothesis": "Partial updates leave revoked access reachable; atomic code/policy cutover prevents post-cutover stale access.",
            "limits": ["Four replica objects share one host and synchronization lock, not distributed nodes.",
                       "The stale-version window is intentionally forced; its production frequency is not estimated.",
                       "In-flight requests admitted before revocation may finish; protected cutover waits for them.",
                       "No packet loss, provider convergence or cloud availability claim."],
            "observations": rows}
