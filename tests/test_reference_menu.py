"""Interactive 6-choice menu and reference-app boundary tests."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import call, patch

import test_prototype as fixtures
from test_prototype import completion
from ssrsf.prototype import client as cli, menu
from ssrsf.prototype.store import STAGES
from ssrsf.reference import ReferenceApp


class ReferenceMenuHTTPTests(unittest.TestCase):
    setUp = fixtures.HTTPTests.setUp
    tearDown = fixtures.HTTPTests.tearDown
    call = fixtures.HTTPTests.call

    def finish(self, workflow):
        for stage in STAGES:
            task = self.call(stage, "/claim", {})["task"]
            if task:
                self.call(stage, "/complete", completion(task))
        return self.call("admin", "/status", {"id": workflow})

    def run_menu(self, answers, identity="client"):
        output = io.StringIO()
        inputs = iter(answers)
        with contextlib.redirect_stdout(output), \
                patch.object(cli, "credential", side_effect=lambda name: self.credentials[name]), \
                patch.object(cli, "wait_complete", side_effect=lambda url, workflow, **kw: self.finish(workflow)), \
                patch.object(ReferenceApp, "wait", side_effect=lambda self_app, workflow, **kw: self.finish(workflow)), \
                patch.object(cli, "check") as mock_check:
            cli.interactive(self.url, lambda prompt: next(inputs), identity=identity)
        return output.getvalue()

    def test_six_choice_menu_workflow(self):
        output = self.run_menu([
            "1", "hello serverless security",          # 1: Submit document text
            "3", "",                                    # 3: Check status (last submission)
            "4", "2",                                   # 4: Switch identity to admin
            "5",                                        # 5: Verify audit log
            "6",                                        # 6: Check quota and security
            "0",                                        # 0: Exit
        ])
        self.assertIn("State: complete", output)
        self.assertIn("Using identity: admin", output)
        self.assertIn('"verified": true', output)
        self.assertIn("Security checks passed", output)
        self.assertTrue(self.store.verify_audit())

    def test_file_input_in_menu(self):
        with tempfile.TemporaryDirectory() as directory:
            doc_file = Path(directory) / "doc.txt"
            doc_file.write_text("file content for test", encoding="utf-8")
            output = self.run_menu([
                "2", str(doc_file),                     # 2: Process UTF-8 text file
                "3", "",                                # 3: Check status
                "0",
            ])
        self.assertIn("State: complete", output)
        self.assertIn("Processed text: file content for test", output)

    def test_unlisted_choice_rejected(self):
        output = self.run_menu(["9", "0"])
        self.assertIn("Choose a listed option (0–6)", output)

    def test_reference_app_advanced_operations(self):
        """Advanced administrative operations remain fully functional via ReferenceApp API."""
        apps = {actor: ReferenceApp(self.url, identity=actor, token=self.credentials[actor]) for actor in ("client", "admin", "investigator")}
        self.call("client", "/submit", {"id": "adv-1", "text": "advanced test doc"})
        for stage in STAGES:
            self.call(stage, "/complete", completion(self.call(stage, "/claim", {})["task"]))
        # Read and report
        doc = apps["admin"].read("adv-1")
        self.assertEqual(doc["raw"], "advanced test doc")
        report = apps["admin"].report()
        self.assertEqual(report["classifications"], {"short": 1})
        # Two-step approved deletion
        targets = [("adv-1", doc["version"])]
        grant = apps["admin"].approve(targets, operation="op-test", ttl=30)
        self.assertIn("grant", grant)
        purge_res = apps["admin"].purge(grant)
        self.assertEqual(purge_res["deleted"], 1)
        # Reconciliation
        inv = apps["investigator"].investigate("op-test")
        self.assertEqual(inv["status"], "committed")
        # Audit verification
        audit = apps["client"].audit()
        self.assertTrue(audit["verified"])
