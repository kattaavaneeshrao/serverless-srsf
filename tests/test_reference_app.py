"""Parity and adversarial tests for the Docker reference application's controls."""
import concurrent.futures
import copy
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import test_prototype as fixtures
from test_prototype import completion
from ssrsf.controls import inventory, sign_event
from ssrsf.prototype.integrity import verify_image
from ssrsf.prototype.reference import CLIENTS
from ssrsf.prototype.store import Denied, STAGES, WorkflowStore
from ssrsf.prototype.transport import RemoteError, request
from ssrsf.reference import ReferenceApp


class ReferenceStoreTests(unittest.TestCase):
    setUp = fixtures.StoreTests.setUp
    tearDown = fixtures.StoreTests.tearDown
    submit = fixtures.StoreTests.submit

    def approved(self, ids=("one",), operation="delete-one", ttl=30):
        targets = [[i, self.store.status("admin", {"id": i})["version"]] for i in ids]
        return self.store.approve("admin", {"targets": targets, "operation": operation, "ttl": ttl})

    def finish(self):
        for stage in STAGES:
            task = self.store.claim(stage, {})["task"]
            self.store.complete(stage, completion(task))

    def test_owner_admin_and_second_user_reads_and_replacements(self):
        version = self.submit()["version"]
        with self.assertRaises(Denied):
            self.store.status("client2", {"id": "one"})
        with self.assertRaises(Denied):
            self.store.replace("client2", {"id": "one", "version": version, "text": "stolen"})
        replacement = self.store.replace("admin", {"id": "one", "version": version, "text": "updated"})
        self.assertNotEqual(replacement["version"], version)
        self.assertEqual(self.store.status("client", {"id": "one"})["raw"], "updated")
        with self.assertRaises(Denied):
            self.store.replace("client", {"id": "one", "version": version, "text": "stale"})

    def test_replacement_invalidates_inflight_tasks_and_old_approval(self):
        version = self.submit()["version"]
        task = self.store.claim("ingest", {})["task"]
        grant = self.approved()
        self.store.replace("client", {"id": "one", "version": version, "text": "new version"})
        with self.assertRaises(Denied):
            self.store.complete("ingest", completion(task))
        with self.assertRaises(Denied):
            self.store.purge("admin", grant)
        self.assertEqual(self.store.status("client", {"id": "one"})["raw"], "new version")

    def test_approval_role_ttl_scope_and_substitution(self):
        self.submit()
        grant = self.approved()
        body = {"targets": grant["grant"]["targets"], "operation": "other", "ttl": 30}
        for role in ("client", "client2", "investigator", "ingest"):
            with self.assertRaises(Denied):
                self.store.approve(role, body)
            with self.assertRaises(Denied):
                self.store.purge(role, grant)
        for ttl in (0, -1, 301, True, float('nan'), float('inf')):
            with self.assertRaises(Denied):
                self.store.approve("admin", {**body, "ttl": ttl})
        for key, value in (("requester", "client"), ("targets", [["other", "version"]]), ("expires", 9999999)):
            altered = copy.deepcopy(grant)
            altered["grant"][key] = value
            with self.assertRaises(Denied):
                self.store.purge("admin", altered)
        self.assertEqual(self.store.status("client", {"id": "one"})["state"], "ingest")

    def test_expired_or_replayed_grant_cannot_delete(self):
        self.submit()
        expired = self.approved(ttl=1)
        self.now += 2
        with self.assertRaises(Denied):
            self.store.purge("admin", expired)
        grant = self.approved(operation="valid")
        self.assertEqual(self.store.purge("admin", grant)["deleted"], 1)
        with self.assertRaises(Denied):
            self.store.purge("admin", grant)
        with self.assertRaises(Denied):
            self.submit()

    def test_concurrent_purge_commits_once_and_reconciliation_survives_expiry_restart(self):
        self.submit()
        grant = self.approved()
        def run(_):
            try:
                self.store.purge("admin", grant)
                return True
            except Denied:
                return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            self.assertEqual(sum(pool.map(run, range(4))), 1)
        self.now += 300
        reopened = WorkflowStore(self.path, b"audit-key", clock=lambda: self.now)
        result = reopened.investigate("investigator", {"operation": "delete-one"})
        self.assertEqual((result["status"], result["deleted"]), ("committed", 1))
        with self.assertRaises(Denied):
            reopened.investigate("client", {"operation": "delete-one"})
        self.assertEqual(reopened.investigate("investigator", {"operation": "missing"})["status"], "not-committed")

    def test_purge_audit_failure_rolls_back_grant_consumption_and_all_deletions(self):
        self.submit("one")
        self.submit("two")
        grant = self.approved(("one", "two"))
        audit = self.store.audit
        with patch.object(self.store, "audit", side_effect=sqlite3.OperationalError("audit unavailable")):
            with self.assertRaises(sqlite3.OperationalError):
                self.store.purge("admin", grant)
        for workflow in ("one", "two"):
            self.store.status("client", {"id": workflow})
        self.assertEqual(self.store.purge("admin", grant)["deleted"], 2)
        self.assertTrue(self.store.verify_audit())

    def test_approval_idempotency_conflicts_and_all_or_nothing_target_versions(self):
        self.submit("one")
        self.submit("two")
        grant = self.approved(("one", "two"))
        self.assertEqual(self.approved(("one", "two")), grant)
        with self.assertRaises(Denied):
            self.approved(("one",))
        old = self.store.status("client", {"id": "two"})
        self.store.replace("client", {"id": "two", "version": old["version"], "text": "new"})
        with self.assertRaises(Denied):
            self.store.purge("admin", grant)
        for workflow in ("one", "two"):
            self.store.status("client", {"id": workflow})

    def test_report_telemetry_and_receipts_are_role_scoped(self):
        self.submit()
        self.finish()
        self.assertEqual(self.store.report("admin", {})["classifications"], {"short": 1})
        body = {"detailed": True, "after": 0, "limit": 2}
        with self.assertRaises(Denied):
            self.store.report("client", {})
        with self.assertRaises(Denied):
            self.store.telemetry("client", body)
        page = self.store.telemetry("investigator", body)
        self.assertEqual(len(page["audit"]), 2)
        self.assertGreater(self.store.telemetry("admin", {**body, "after": page["next"]})["next"], page["next"])
        receipt = self.store.audit_status("client", {"receipt": None})["receipt"]
        self.assertTrue(self.store.audit_status("client", {"receipt": receipt})["verified"])
        with self.store.connect() as db:
            db.execute("DELETE FROM audit WHERE sequence=?", (receipt["sequence"],))
        self.assertTrue(self.store.verify_audit())
        self.assertFalse(self.store.audit_status("client", {"receipt": receipt})["verified"])

    def test_policy_cutover_expansion_review_explicit_deny_and_restart(self):
        self.submit()
        rules = [{"principal": s, "action": "read", "resource": "documents", "effect": "allow"} for s in STAGES]
        deny = {"principal": "ingest", "action": "read", "resource": "documents", "effect": "deny"}
        body = {"rules": rules + [deny], "change_id": "cutover"}
        result = self.store.deploy("admin", body)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(self.store.deploy("admin", body), result)
        reopened = WorkflowStore(self.path, b"audit-key", clock=lambda: self.now)
        with self.assertRaises(Denied):
            reopened.claim("ingest", {})
        restored = reopened.deploy("admin", {"rules": rules, "change_id": "expand"})
        self.assertEqual(restored["status"], "review-required")
        with self.assertRaises(Denied):
            reopened.claim("ingest", {})
        malformed = reopened.deploy("admin", {"rules": [{**deny, "principal": "*"}], "change_id": "wildcard"})
        self.assertEqual(malformed["status"], "unresolved")
        with self.assertRaises(Denied):
            reopened.deploy("client", body)

    def test_policy_cutover_blocks_inflight_completion(self):
        self.submit()
        task = self.store.claim("ingest", {})["task"]
        self.store.deploy("admin", {"rules": [], "change_id": "revoke"})
        with self.assertRaises(Denied):
            self.store.complete("ingest", completion(task))
        self.assertEqual(self.store.status("client", {"id": "one"})["state"], "ingest")

    def test_budget_reporting_owner_scope_admin_reset_and_replacement_accounting(self):
        first = self.submit()
        body = {"owner": "client", "reset": False}
        self.assertEqual(self.store.budget("client", body)["accepted"], 1)
        with self.assertRaises(Denied):
            self.store.budget("client2", body)
        with self.assertRaises(Denied):
            self.store.budget("client", {**body, "reset": True})
        self.store.replace("client", {"id": "one", "version": first["version"], "text": "new"})
        self.assertEqual(self.store.budget("client", body)["accepted"], 2)
        self.assertEqual(self.store.budget("admin", {**body, "reset": True})["accepted"], 0)
        reopened = WorkflowStore(self.path, b"audit-key", clock=lambda: self.now)
        self.assertEqual(reopened.budget("client", body)["accepted"], 0)

    def test_scratch_entry_exit_and_between_invocation_mismatch(self):
        self.submit()
        task = self.store.claim("ingest", {"scratch": {}})["task"]
        snapshot = {"cache.txt": "a" * 64}
        self.store.complete("ingest", {**completion(task), "scratch": snapshot})
        self.submit("two")
        self.store.claim("ingest", {"scratch": {"cache.txt": "b" * 64}})
        records = self.store.telemetry("investigator", {"detailed": True, "after": 0, "limit": 100})["audit"]
        self.assertEqual(records[-1]["event"]["entry_status"], "mismatch")
        with self.assertRaises(Denied):
            self.store.claim("ingest", {"scratch": {"x": "not-a-digest"}})

    def test_image_manifest_rejects_changed_unlisted_and_symlink_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)/"src"
            root.mkdir()
            module = root/"parser.py"
            module.write_text("trusted")
            manifest = Path(directory)/"manifest.json"
            manifest.write_text(json.dumps(inventory(root)))
            verify_image(root, manifest)
            module.write_text("changed")
            with self.assertRaises(RuntimeError):
                verify_image(root, manifest)
            module.write_text("trusted")
            (root/"unexpected.py").write_text("unlisted")
            with self.assertRaises(RuntimeError):
                verify_image(root, manifest)
            (root/"unexpected.py").unlink()
            (root/"linked.py").symlink_to(module)
            with self.assertRaises(RuntimeError):
                verify_image(root, manifest)


class ReferenceHTTPTests(unittest.TestCase):
    setUp = fixtures.HTTPTests.setUp
    tearDown = fixtures.HTTPTests.tearDown
    call = fixtures.HTTPTests.call

    def test_signed_body_and_path_integrity_reject_tampering(self):
        body = {"id": "one", "text": "original"}
        signature = sign_event({"path": "/submit", "body": body}, self.credentials["client"].encode())
        with self.assertRaises(RemoteError) as raised:
            request(self.url+"/submit", self.credentials["client"], {**body, "text": "tampered"}, signature=signature)
        self.assertEqual(raised.exception.status, 403)
        with self.assertRaises(RemoteError):
            request(self.url+"/status", self.credentials["client"], body, signature=signature)
        with self.store.connect() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM workflows").fetchone()[0], 0)

    def test_python_client_controls_through_guard_and_controller(self):
        apps = {actor: ReferenceApp(self.url, identity=actor, token=self.credentials[actor]) for actor in CLIENTS}
        self.call("client", "/submit", {"id": "one", "text": "one   two"})
        for stage in STAGES:
            self.call(stage, "/complete", completion(self.call(stage, "/claim", {})["task"]))
        self.assertEqual(apps["client"].read("one")["text"], "one two")
        with self.assertRaises(RemoteError):
            apps["client2"].read("one")
        with self.assertRaises(RemoteError):
            apps["investigator"].read("one")
        self.assertTrue(apps["client"].audit()["verified"])
        self.assertEqual(apps["admin"].report()["classifications"], {"short": 1})
        grant = apps["admin"].approve([("one", apps["admin"].read("one")["version"])], operation="delete")
        with self.assertRaises(RemoteError):
            apps["client"].purge(grant)
        self.assertEqual(apps["admin"].purge(grant)["deleted"], 1)
        self.assertEqual(apps["investigator"].investigate("delete")["status"], "committed")
        for stage in STAGES:
            for path, body in (("/report", {}), ("/audit", {"receipt": None}), ("/telemetry", {"detailed": True, "after": 0, "limit": 10})):
                with self.assertRaises(RemoteError):
                    self.call(stage, path, body)
