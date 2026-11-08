"""Prespecified paired threshold/quota sweep; no selection of best test setting."""
from __future__ import annotations

import random
import time

from .billing import simulate, workload


def sensitivity(trials, seed, unit_price):
    rows = []
    for trial in range(trials):
        workload_seed = seed + trial * 1009
        for case in ("steady", "legitimate-burst", "sustained-attack", "low-rate-attack", "slow-ramp"):
            trace = workload(case, random.Random(workload_seed))
            settings = [(d, q) for d in (2., 4., 6.) for q in (10, 20, 40)]
            random.Random(workload_seed + 1).shuffle(settings)
            for deviations, quota in settings:
                start = time.perf_counter_ns()
                outcome = simulate(trace, "adaptive-quota", unit_price, quota, deviations=deviations)
                # Per-trial aggregates and seeds retained; full bucket records live in the main billing experiment.
                outcome.pop("buckets")
                rows.append({"trial": trial, "case": case, "variant": f"d{deviations:g}-q{quota}",
                             "workload_seed": workload_seed, "deviations": deviations, "quota": quota,
                             "latency_ms": (time.perf_counter_ns() - start) / 1e6, **outcome})
    return {"paper_pages": "11", "kind": "paired 3-by-3 detector threshold and invocation quota sweep",
            "hypothesis": "Detector sensitivity and admission budgets trade missed attacks against legitimate rejection.",
            "observations": rows,
            "limits": ["Prespecified settings are reported together; no best configuration is selected on these workloads.",
                       "Independent workload seeds vary traffic within the same five constructed workload families.",
                       "Synthetic buckets and modeled costs do not measure cloud scalability or bills."]}
