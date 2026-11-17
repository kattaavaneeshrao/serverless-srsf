"""Small-sample summaries. Keep raw observations alongside every aggregate."""
from __future__ import annotations

import math
import statistics


def proportion(successes: int, total: int) -> dict:
    if total < 0 or not 0 <= successes <= total:
        raise ValueError("Invalid binomial counts")
    if not total:
        return {"count": successes, "total": total, "rate": None, "wilson95": None}
    p, z = successes / total, 1.959963984540054
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return {"count": successes, "total": total, "rate": p,
            "wilson95": [max(0., center - half), min(1., center + half)]}


def percentile(values: list[float], q: float) -> float | None:
    if not 0 <= q <= 1:
        raise ValueError("Quantile must be in [0, 1]")
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * q
    lower, upper = math.floor(position), math.ceil(position)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def latency(values: list[float]) -> dict:
    return {"samples": len(values), "p50_ms": percentile(values, .5),
            "p95_ms": percentile(values, .95), "p99_ms": percentile(values, .99),
            "mean_ms": statistics.mean(values) if values else None}


def confusion(labels: list[bool], predictions: list[bool]) -> dict:
    if len(labels) != len(predictions):
        raise ValueError("Labels and predictions must align")
    tp = sum(y and p for y, p in zip(labels, predictions))
    fp = sum(not y and p for y, p in zip(labels, predictions))
    fn = sum(y and not p for y, p in zip(labels, predictions))
    tn = sum(not y and not p for y, p in zip(labels, predictions))
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "recall": proportion(tp, tp + fn), "false_positive_rate": proportion(fp, fp + tn),
            "precision": proportion(tp, tp + fp)}
