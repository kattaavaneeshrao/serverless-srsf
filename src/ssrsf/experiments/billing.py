"""Denial-of-Wallet experiments with synthetic demand and real local dispatch counts."""
from __future__ import annotations

import random
import time

from ..metrics import confusion


def workload(case, rng):
    if case not in ("steady", "legitimate-burst", "sustained-attack", "low-rate-attack", "slow-ramp"):
        raise ValueError("Unknown workload")
    buckets = []
    for minute in range(70):
        legitimate, malicious = rng.randint(8, 12), 0
        if case == "legitimate-burst" and 30 <= minute < 36:
            legitimate += 80
        if 30 <= minute < 55:
            if case == "sustained-attack":
                malicious = 80
            elif case == "low-rate-attack":
                malicious = 2
            elif case == "slow-ramp":
                malicious = (minute - 30) // 3 + 1
        arrivals = [False] * legitimate + [True] * malicious
        rng.shuffle(arrivals)
        buckets.append(arrivals)
    return buckets


def simulate(buckets, variant, unit_price, quota=20):
    if variant not in ("uncontrolled", "alert-only", "fixed-quota"):
        raise ValueError("Unknown control")
    spending_limit = quota * unit_price
    records, ledger = [], []
    for minute, arrivals in enumerate(buckets):
        cap = quota if variant == "fixed-quota" else len(arrivals)
        accepted_legitimate = accepted_attack = 0
        for position, malicious in enumerate(arrivals):
            if position < cap:
                # Every accepted invocation performs the same small local function.
                # Ground-truth labels are used only for outcome accounting.
                ledger.append((minute, (position * 17 + minute) % 257))
                accepted_attack += int(malicious)
                accepted_legitimate += int(not malicious)
        # Closed-bucket spending alert: notification only, with no automatic enforcement.
        alert = variant == "alert-only" and (accepted_legitimate + accepted_attack) * unit_price > spending_limit
        records.append({"minute": minute, "warmup": minute < 20,
                        "offered_legitimate": arrivals.count(False), "offered_attack": arrivals.count(True),
                        "accepted_legitimate": accepted_legitimate, "accepted_attack": accepted_attack,
                        "rejected_legitimate": arrivals.count(False) - accepted_legitimate,
                        "rejected_attack": arrivals.count(True) - accepted_attack,
                        "alert": alert, "quota_applied": cap < len(arrivals)})
    evaluated = [r for r in records if not r["warmup"]]
    first_attack = next((r["minute"] for r in records if r["offered_attack"]), None)
    first_alert = next((r["minute"] for r in records if r["alert"] and first_attack is not None and r["minute"] >= first_attack), None)
    first_enforcement = next((r["minute"] for r in records if r["quota_applied"] and first_attack is not None and r["minute"] >= first_attack), None)
    accepted_attack = sum(r["accepted_attack"] for r in records)
    rejected_legitimate = sum(r["rejected_legitimate"] for r in records)
    return {"buckets": records, "dispatch_count": len(ledger), "dispatch_checksum": sum(v for _, v in ledger),
            "offered_invocations": sum(len(a) for a in buckets),
            "accepted_attack": accepted_attack, "rejected_legitimate": rejected_legitimate,
            "offered_legitimate": sum(a.count(False) for a in buckets),
            "modeled_spend": len(ledger) * unit_price, "modeled_attack_spend": accepted_attack * unit_price,
            "detection": confusion([r["offered_attack"] > 0 for r in evaluated], [r["alert"] for r in evaluated]),
            "alert_delay_minutes": first_alert - first_attack + 1 if first_alert is not None else None,
            "enforcement_delay_minutes": first_enforcement - first_attack if first_enforcement is not None else None,
            "attack_invocations_before_alert": sum(r["accepted_attack"] for r in records
                if first_alert is None or r["minute"] <= first_alert)}


def billing(trials, seed, unit_price):
    rows, rng = [], random.Random(seed)
    for trial in range(trials):
        for case in ("steady", "legitimate-burst", "sustained-attack", "low-rate-attack", "slow-ramp"):
            buckets = workload(case, rng)
            variants = ["uncontrolled", "alert-only", "fixed-quota"]
            rng.shuffle(variants)
            for variant in variants:
                start = time.perf_counter_ns()
                measured = simulate(buckets, variant, unit_price)
                rows.append({"trial": trial, "case": case, "variant": variant,
                             "latency_ms": (time.perf_counter_ns() - start) / 1e6, **measured})
    return {"paper_pages": "11", "kind": "synthetic labeled demand; actual local function dispatch ledger",
            "hypothesis": "Spending alerts notify without limiting work; fixed invocation quotas limit cost and may reject legitimate calls.",
            "configuration": {"bucket_seconds": 60, "buckets": 70, "warmup_buckets": 20,
                              "baseline": "uniform integers 8..12", "quota_per_minute": 20,
                              "unit_price": unit_price, "price_units": "arbitrary cost units per accepted invocation",
                              "alert_limit_per_bucket": 20 * unit_price},
            "limits": ["Simulated minutes advance immediately, not a wall-clock load or scalability benchmark.",
                       "No cloud bill, real concurrency quota, network overhead, retries or downstream costs.",
                       "Spending alerts use a fixed per-bucket limit, not an anomaly detector or request classifier.",
                       "Labels are hidden from enforcement; legitimate bursts can trigger alerts or lose legitimate requests.",
                       "The local per-bucket cap approximates the quota idea; it is not a provider concurrency limit.",
                       "Bucket labels and repeated fixture trials are correlated; do not treat them as a real-world attack population.",
                       "Demand for all control variants is paired exactly; alert-only never rejects an invocation."],
            "observations": rows}
