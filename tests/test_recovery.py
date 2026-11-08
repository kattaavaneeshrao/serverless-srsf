import json
import os
import tempfile
import unittest
from pathlib import Path

from ssrsf.audit import AuditUnavailable
from ssrsf.controls import Rejected
from ssrsf.workflow import ReferenceApp


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.now = 1000.
        self.app = ReferenceApp(self.root, clock=lambda: self.now)

    def tearDown(self):
        self.temp.cleanup()

    def test_restart_preserves_document_keys_and_restrictive_policy(self):
        doc = self.app.ingest("user-token", "retained document")
        event, signature = self.app.envelope("signed before restart")
        self.app.deploy([])
        restarted = ReferenceApp(self.root, clock=lambda: self.now)
        self.assertEqual(restarted.read("user-token")["version"], doc["version"])
        self.assertEqual(restarted.event_key, self.app.event_key)
        self.assertEqual(restarted.policy.version, self.app.policy.version)
        with self.assertRaises(Rejected):
            restarted.ingest("user-token", "attempt", event=event, signature=signature)
        self.assertTrue(restarted.audit.verify())
        self.assertEqual(os.stat(self.root / "trusted-state.json").st_mode & 0o777, 0o600)

    def test_missing_or_changed_keys_do_not_silently_reset_trust(self):
        self.app.ingest("user-token", "retained")
        path = self.root / "trusted-state.json"
        data = path.read_text()
        path.unlink()
        with self.assertRaises(Rejected):
            ReferenceApp(self.root)
        state = json.loads(data)
        state["keys"]["audit"] = "ab" * 32
        path.write_text(json.dumps(state))
        with self.assertRaisesRegex(Rejected, "integrity"):
            ReferenceApp(self.root)

    def test_restart_does_not_trust_modified_artifact(self):
        (self.app.artifacts / "parser.rules").write_text("changed after bootstrap")
        restarted = ReferenceApp(self.root)
        with self.assertRaises(Rejected):
            restarted.ingest("user-token", "text")

    def test_independent_investigator_recovers_after_expiry_and_restart(self):
        doc = self.app.ingest("user-token", "delete fixture")
        targets = [(doc["id"], doc["version"])]
        grant = self.app.approve("admin-token", targets, "recover-me", ttl=1)
        original = self.app.audit.append
        def fail_exit(event_id, event):
            if event.get("kind") == "purge-exit":
                raise AuditUnavailable("injected failure")
            return original(event_id, event)
        self.app.audit.append = fail_exit
        with self.assertRaises(AuditUnavailable):
            self.app.purge("admin-token", targets, grant)
        self.now += 2
        restarted = ReferenceApp(self.root, clock=lambda: self.now)
        with self.assertRaises(Rejected):
            restarted.broker.reconcile(grant, "admin-token")
        for credential in ("user-token", "admin-token", "forged"):
            with self.assertRaises(Rejected):
                restarted.broker.investigate("recover-me", credential)
        result = restarted.broker.investigate("recover-me", "investigator-token")
        self.assertEqual((result["status"], result["deleted"]), ("committed", 1))
        self.assertEqual(restarted.broker.investigate("absent", "investigator-token")["status"], "not-committed")
        restarted.authority.available = False
        with self.assertRaises(Rejected):
            restarted.broker.investigate("recover-me", "investigator-token")
        restarted.authority.available = True
        restarted.audit.available = False
        with self.assertRaises(AuditUnavailable):
            restarted.broker.investigate("recover-me", "investigator-token")

