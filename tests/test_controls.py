import os
import tempfile
import unittest
from pathlib import Path

from ssrsf.controls import (AccessControl, Identity, Rejected,
                           accept_event, inventory, sign_event, verify_inventory)
from ssrsf.metrics import confusion, percentile, proportion


class EventTests(unittest.TestCase):
    def setUp(self):
        self.key = b"test-key"
        self.event = {"action": "read", "resource": "public/item", "value": "text"}

    def test_intact_signed_event(self):
        self.assertEqual(accept_event(self.event, sign_event(self.event, self.key), self.key), self.event)

    def test_tampered_signed_payload(self):
        with self.assertRaises(Rejected):
            accept_event({**self.event, "value": "changed"}, sign_event(self.event, self.key), self.key)

    def test_internal_events_still_require_valid_schema(self):
        for event in ({**self.event, "action": "delete"}, {**self.event, "resource": "public/../secret"},
                      {**self.event, "role": "admin"}, {**self.event, "value": "x" * 129},
                      {**self.event, "resource": 3}, {**self.event, "value": {"$ne": None}}):
            with self.subTest(event=event), self.assertRaises(Rejected):
                accept_event(event, sign_event(event, self.key), self.key)

    def test_untrusted_envelope_types_and_nan_rejected(self):
        for event, signature in ((None, "x"), ([], "x"), (self.event, None), ({"x": float("nan")}, "x")):
            with self.subTest(event=event), self.assertRaises(Rejected):
                accept_event(event, signature, self.key)

    def test_foreign_key_rejected(self):
        with self.assertRaises(Rejected):
            accept_event(self.event, sign_event(self.event, b"wrong"), self.key)

    def test_metacharacters_are_data(self):
        event = {**self.event, "value": "$(touch /never-executed); ' OR 1=1"}
        self.assertEqual(accept_event(event, sign_event(event, self.key), self.key), event)


class AuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.guard = AccessControl({"token": Identity("alice", "reader")}, {"reader": {("read", "public/item")}})

    def test_exact_capability(self):
        self.assertEqual(self.guard.authorize("token", "read", "public/item").subject, "alice")

    def test_missing_forged_excess_and_wrong_resource(self):
        for token, action, resource in (("", "read", "public/item"), ("forged", "read", "public/item"),
                                        ("token", "delete", "public/item"), ("token", "read", "private/item")):
            with self.subTest(token=token, action=action, resource=resource), self.assertRaises(Rejected):
                self.guard.authorize(token, action, resource)

    def test_caller_cannot_mutate_original_grants(self):
        grants = {"reader": {("read", "public/item")}}
        guard = AccessControl({"token": Identity("alice", "reader")}, grants)
        grants["reader"].add(("delete", "public/item"))
        with self.assertRaises(Rejected):
            guard.authorize("token", "delete", "public/item")


class InventoryTests(unittest.TestCase):
    def test_hash_detects_preserved_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "library.txt"
            path.write_bytes(b"original")
            stat = path.stat()
            lock = inventory(root)
            path.write_bytes(b"tampered")
            os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns))
            self.assertFalse(verify_inventory(root, lock))

    def test_additions_removals_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "library.txt"
            path.write_text("original")
            lock = inventory(root)
            self.assertTrue(verify_inventory(root, lock))
            extra = root / "extra"
            extra.write_text("unexpected")
            self.assertFalse(verify_inventory(root, lock))
            extra.unlink()
            extra.symlink_to(path)
            self.assertFalse(verify_inventory(root, lock))
            extra.unlink()
            path.unlink()
            self.assertFalse(verify_inventory(root, lock))


class MetricTests(unittest.TestCase):
    def test_zero_denominators_are_unknown(self):
        self.assertIsNone(proportion(0, 0)["rate"])
        self.assertIsNone(confusion([False], [False])["recall"]["rate"])

    def test_confusion_and_interval(self):
        result = confusion([True, True, False, False], [True, False, True, False])
        self.assertEqual([result[k] for k in ("tp", "fp", "fn", "tn")], [1, 1, 1, 1])
        self.assertLess(proportion(10, 10)["wilson95"][0], 1)
        self.assertGreater(proportion(0, 10)["wilson95"][1], 0)

    def test_percentile_interpolates(self):
        self.assertEqual(percentile([0, 10], .95), 9.5)
        self.assertIsNone(percentile([], .5))
        with self.assertRaises(ValueError):
            confusion([True], [])
