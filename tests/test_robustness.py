import unittest

from ssrsf.billing import simulate
from ssrsf.robustness import CASES, TrainingReference, robustness, trace


class RobustnessTests(unittest.TestCase):
    def test_training_reference_is_fixed_and_labels_not_inputs(self):
        detector = TrainingReference()
        for _ in range(20):
            self.assertFalse(detector.observe(10))
        for count in [90] * 3:
            alert = detector.observe(count)
        self.assertTrue(alert)
        self.assertEqual(detector.mean, 10)
        self.assertFalse(detector.observe(10))

    def test_intermittent_attack_evades_consecutive_confirmation(self):
        result = simulate(trace("pulsed-attack", 42), "training-quota", .001, detector=TrainingReference())
        self.assertEqual(result["accepted_attack"], 14 * 60)
        self.assertEqual(result["detection"]["tp"], 0)
        self.assertEqual(result["detection"]["fn"], 14)

    def test_growth_is_legitimate_even_when_flagged(self):
        result = simulate(trace("growing-legitimate", 42), "training-quota", .001, detector=TrainingReference())
        self.assertEqual(result["accepted_attack"], 0)
        self.assertGreater(result["detection"]["fp"], 0)
        self.assertGreater(result["rejected_legitimate"], 0)

    def test_paired_workload_conservation_and_raw_bucket_schema(self):
        result = robustness(2, 42, .001)
        self.assertEqual(len(result["observations"]), 2 * len(CASES) * 5)
        for trial in range(2):
            for case in CASES:
                rows = [r for r in result["observations"] if r["trial"] == trial and r["case"] == case]
                self.assertEqual(len({r["offered_invocations"] for r in rows}), 1)
                for row in rows:
                    self.assertEqual(len(row["bucket_counts"]), 100)
                    self.assertTrue(all(len(r) == len(result["bucket_count_fields"]) for r in row["bucket_counts"]))
                    self.assertEqual(row["dispatch_count"], sum(r[3] + r[4] for r in row["bucket_counts"]))
                    self.assertAlmostEqual(row["modeled_spend"], row["dispatch_count"] * .001)
