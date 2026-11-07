import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from ssrsf.application import authorization, dependencies, events
from ssrsf.billing import simulate, workload
from ssrsf.cli import main
from ssrsf.controls import Rejected
from ssrsf.evaluation import evaluate, summarize, write_bundle
from ssrsf.infrastructure import persistence, rollouts, side_channels, timing_attack
from ssrsf.runtime import FunctionProcess


class ApplicationExperiments(unittest.TestCase):
    def test_paired_adversarial_and_legitimate_cases(self):
        for runner in (events, authorization, dependencies):
            with self.subTest(runner=runner.__name__):
                result = runner(2, 42)
                summary = summarize(result)
                rates = sorted(s["attack_success"]["rate"] for s in summary.values())
                self.assertEqual(rates, [0, 1])
                self.assertTrue(all(s["legitimate_success"]["rate"] == 1 for s in summary.values()))
                self.assertEqual(len(result["observations"]) % 4, 0)


class PersistenceExperiments(unittest.TestCase):
    def test_real_workers_and_filesystem_reuse(self):
        result = summarize(persistence(2, 42))
        self.assertEqual(result["warm-unchecked"]["attack_success"]["rate"], 1)
        for variant in ("warm-monitored", "fresh-workspace"):
            self.assertEqual(result[variant]["attack_success"]["rate"], 0)
            self.assertEqual(result[variant]["legitimate_success"]["rate"], 1)

    def test_monitor_cleans_between_calls_and_preserves_declared_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            with FunctionProcess(Path(directory), monitored=True) as process:
                process.invoke("legitimate")
                (process.root / "outside-write").write_text("undeclared")
                result = process.invoke("legitimate")
                self.assertFalse(result["persistent_marker_observed"])
                self.assertFalse((process.root / "outside-write").exists())
                self.assertTrue((process.root / "cache.txt").exists())
                self.assertEqual(len(process.quarantined), 1)

    def test_monitor_rejects_symlinks_without_following(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with FunctionProcess(root / "work", monitored=True) as process:
                outside = root / "outside"
                outside.write_text("keep")
                (process.root / "link").symlink_to(outside)
                with self.assertRaises(Rejected):
                    process.invoke("legitimate")
                self.assertEqual(outside.read_text(), "keep")


class InfrastructureExperiments(unittest.TestCase):
    def test_trace_attacker_has_disjoint_balanced_splits(self):
        result = side_channels(3, 42, 4)
        self.assertEqual(result["metrics"]["exposed"]["trace_attacker_accuracy"]["rate"], 1)
        self.assertEqual(result["metrics"]["facade-floor"]["trace_attacker_accuracy"]["rate"], .5)
        self.assertEqual(result["metrics"]["facade-deadline"]["trace_attacker_accuracy"]["rate"], .5)
        for variant in result["metrics"]:
            train = [r for r in result["observations"] if r["variant"] == variant and r["split"] == "train"]
            test = [r for r in result["observations"] if r["variant"] == variant and r["split"] == "test"]
            self.assertEqual(len(train), len(test))
            self.assertEqual(sum(r["role"] == "admin" for r in test), 3)

    def test_timing_fit_does_not_use_test_labels(self):
        train = [{"role": "user", "latency_ms": 1}, {"role": "admin", "latency_ms": 3}]
        test = [{"role": "admin", "latency_ms": 2.5}, {"role": "user", "latency_ms": 1.5}]
        first = timing_attack(train, test)
        changed = [{**r, "role": "user" if r["role"] == "admin" else "admin"} for r in test]
        second = timing_attack(train, changed)
        self.assertEqual(first["predictions"], second["predictions"])
        self.assertEqual(first["held_out_accuracy"]["rate"], 1)
        self.assertEqual(second["held_out_accuracy"]["rate"], 0)

    def test_stale_replicas_and_actual_inflight_revocation(self):
        result = rollouts(3, 42)
        summary = summarize(result)
        self.assertEqual(summary["rolling-stale-replicas"]["attack_success"]["rate"], 1)
        self.assertEqual(summary["atomic-cutover"]["attack_success"]["rate"], 0)
        self.assertTrue(all(r["legitimate_succeeded"] for r in result["observations"]))
        protected = [r for r in result["observations"] if r["variant"] == "atomic-cutover" and r["case"] == "inflight-revocation"]
        self.assertTrue(all(not r["cutover_before_release"] for r in protected))


class BillingExperiments(unittest.TestCase):
    def run_trace(self, case):
        import random
        trace = workload(case, random.Random(42))
        return {name: simulate(trace, name, .001) for name in ("uncontrolled", "alert-only", "adaptive-quota", "fixed-quota")}

    def test_paired_dispatch_counts_and_costs(self):
        results = self.run_trace("sustained-attack")
        baseline, alert, limited = (results[k] for k in ("uncontrolled", "alert-only", "adaptive-quota"))
        self.assertEqual(baseline["dispatch_count"], alert["dispatch_count"])
        self.assertEqual(baseline["modeled_spend"], alert["modeled_spend"])
        self.assertLess(limited["accepted_attack"], baseline["accepted_attack"])
        self.assertLess(limited["modeled_spend"], baseline["modeled_spend"])
        self.assertEqual(limited["modeled_spend"], limited["dispatch_count"] * .001)

    def test_enforcement_waits_for_closed_bucket_confirmation(self):
        import random
        result = simulate(workload("sustained-attack", random.Random(42)), "adaptive-quota", .001)
        self.assertEqual(result["alert_delay_minutes"], 3)
        self.assertEqual(result["enforcement_delay_minutes"], 3)
        self.assertGreater(result["attack_invocations_before_alert"], 0)

    def test_legitimate_bursts_false_page_and_drop(self):
        result = self.run_trace("legitimate-burst")["adaptive-quota"]
        self.assertGreater(result["detection"]["fp"], 0)
        self.assertGreater(result["rejected_legitimate"], 0)
        self.assertIsNone(result["detection"]["recall"]["rate"])

    def test_low_rate_miss_remains_in_results(self):
        result = self.run_trace("low-rate-attack")["adaptive-quota"]
        self.assertGreater(result["detection"]["fn"], 0)
        self.assertGreater(result["accepted_attack"], 0)

    def test_fixed_quota_does_not_claim_to_detect_attacks(self):
        result = self.run_trace("sustained-attack")["fixed-quota"]
        self.assertFalse(any(r["alert"] for r in result["buckets"]))
        self.assertIsNone(result["alert_delay_minutes"])
        self.assertLess(result["accepted_attack"], 2000)


class EvidenceTests(unittest.TestCase):
    def test_full_bundle_roundtrip_and_integrity(self):
        bundle = evaluate(trials=2, floor_ms=4)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_bundle(bundle, root)
            loaded = json.loads((root / "results.json").read_text())
            self.assertEqual(len(loaded["experiments"]), 7)
            self.assertIsNone(loaded["paper"]["numerical_reference_results"])
            self.assertTrue(loaded["source_sha256"])
            for line in (root / "SHA256SUMS").read_text().splitlines():
                digest, name = line.split("  ")
                self.assertEqual(hashlib.sha256((root / name).read_bytes()).hexdigest(), digest)
            self.assertIn("low-rate-attack", (root / "report.md").read_text())
            self.assertIn("timing_accuracy", (root / "metrics.csv").read_text())

    def test_invalid_run_configuration(self):
        for kwargs in ({"trials": 0}, {"trials": True}, {"seed": -1}, {"floor_ms": float("nan")},
                       {"unit_price": -1}, {"selected": []}, {"selected": ["events", "events"]}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                evaluate(**kwargs)

    def test_subset_seed_is_stable(self):
        bundle = evaluate(2, seed=42, selected=["authorization"])
        self.assertEqual(bundle["experiments"]["authorization"]["seed"], 43)

    def test_cli_writes_report_and_rejects_bad_parameters(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(main(["evaluate", "--trials", "2", "--experiment", "events", "--output", directory]), 0)
            self.assertTrue((Path(directory) / "report.md").exists())
            self.assertEqual(main(["evaluate", "--trials", "0", "--output", directory]), 1)
