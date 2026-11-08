"""Out-of-primary-family billing probes with a fixed-training comparator."""
import math
import random
import statistics
import time

from .billing import simulate


class TrainingReference:
    """Project comparator: fixed mean/std from 20 unlabeled initial buckets.

    Same four-deviation threshold floor and three-candidate confirmation as the
    primary controller; unlike EWMA, the learned reference never adapts later.
    This is an inspectable engineering baseline, not a published SOTA method.
    """
    def __init__(self):
        self.training, self.mean, self.streak, self.threshold = [], None, 0, None

    def observe(self, count):
        if len(self.training) < 20:
            self.training.append(count)
            if len(self.training) == 20:
                self.mean = statistics.mean(self.training)
                self.threshold = self.mean + 4 * max(1., statistics.pstdev(self.training))
            return False
        self.streak = self.streak + 1 if count > self.threshold else 0
        return self.streak >= 3


CASES = ("stationary", "seasonal-legitimate", "growing-legitimate", "flash-crowd", "pulsed-attack", "ramp-attack")
FIELDS = ("minute", "offered_legitimate", "offered_attack", "accepted_legitimate", "accepted_attack", "alert", "quota_applied")


def trace(case, seed):
    if case not in CASES:
        raise ValueError("Unknown robustness workload")
    rng, buckets = random.Random(seed), []
    for minute in range(100):
        legitimate, attack = rng.randint(8, 12), 0
        if case == "seasonal-legitimate":
            legitimate = max(0, legitimate + round(6 * math.sin(2 * math.pi * minute / 40)))
        if case == "growing-legitimate" and minute >= 40:
            legitimate += (minute - 40) // 4
        if case == "flash-crowd" and (40 <= minute < 45 or 65 <= minute < 70):
            legitimate += 40
        if 40 <= minute < 80:
            if case == "pulsed-attack" and (minute - 40) % 3 == 0:
                attack = 60
            if case == "ramp-attack":
                attack = 1 + (minute - 40) // 4
        arrivals = [False] * legitimate + [True] * attack
        rng.shuffle(arrivals)
        buckets.append(arrivals)
    return buckets


def robustness(trials, seed, unit_price):
    rows = []
    for trial in range(trials):
        workload_seed = seed + 1009 * trial
        for case in CASES:
            buckets = trace(case, workload_seed)
            variants = ["uncontrolled", "alert-only", "adaptive-quota", "fixed-quota", "training-quota"]
            random.Random(workload_seed + 7).shuffle(variants)
            for variant in variants:
                start = time.perf_counter_ns()
                result = simulate(buckets, variant, unit_price,
                                  detector=TrainingReference() if variant == "training-quota" else None)
                records = result.pop("buckets")
                rows.append({"trial": trial, "case": case, "variant": variant, "workload_seed": workload_seed,
                             "latency_ms": (time.perf_counter_ns() - start) / 1e6,
                             "bucket_counts": [[r[k] for k in FIELDS] for r in records], **result})
    return {"paper_pages": "11", "kind": "paired nonstationary and intermittent demand with a fixed-training comparator",
            "hypothesis": "A frozen training reference and adapting EWMA differ under legitimate drift and intermittent abuse.",
            "bucket_count_fields": FIELDS, "observations": rows,
            "limits": ["Six new synthetic workload families, not production traces or an unseen real-world attack sample.",
                       "Added after the initial study; these are disclosed follow-up probes, not a preregistered validation set.",
                       "Training-reference parameters are fixed and all comparator outcomes retained; no best setting selected.",
                       "Detection labels remain hidden; legitimate growth can be flagged and confirmation can miss pulses.",
                       "Only local dispatch and arbitrary cost units; no cloud billing or distributed enforcement."]}
