import concurrent.futures
import copy
import sqlite3
import tempfile
import unittest
from pathlib import Path

from ssrsf.audit import AuditCollector, AuditUnavailable, InvocationEvidence
from ssrsf.controls import Rejected
from ssrsf.policy import Request
from ssrsf.workflow import CONTROLS, InvocationBudget, ReferenceApp, rule
from ssrsf.integration import framework
from ssrsf.sensitivity import sensitivity


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.collector = AuditCollector(self.root / "audit.sqlite", b"test-only-key")

    def tearDown(self):
        self.temp.cleanup()

    def test_receipt_survives_reopening_and_duplicate_delivery(self):
        first = self.collector.append("one", {"kind": "test"})
        reopened = AuditCollector(self.collector.path, b"test-only-key")
        self.assertEqual(first, reopened.append("one", {"kind": "test"}))
        self.assertEqual(len(reopened.records("investigator")), 1)
        self.assertTrue(reopened.verify(first))
        with self.assertRaises(Rejected):
            reopened.append("one", {"kind": "conflict"})

    def test_modified_record_and_anchored_tail_removal_are_detected(self):
        self.collector.append("one", {"kind": "test"})
        receipt = self.collector.append("two", {"kind": "second"})
        with sqlite3.connect(self.collector.path) as db:
            db.execute("DELETE FROM audit WHERE sequence=2")
        self.assertTrue(self.collector.verify())  # Valid prefix alone cannot prove completeness.
        self.assertFalse(self.collector.verify(receipt))
        with sqlite3.connect(self.collector.path) as db:
            db.execute("UPDATE audit SET payload='{}' WHERE sequence=1")
        self.assertFalse(self.collector.verify())
        with sqlite3.connect(self.collector.path) as db:
            db.execute("UPDATE audit SET payload='not-json' WHERE sequence=1")
        self.assertFalse(self.collector.verify())

    def test_audit_reader_role_and_concurrent_append_chain(self):
        with self.assertRaises(Rejected):
            self.collector.records("application")
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            receipts = list(pool.map(lambda i: self.collector.append(str(i), {"i": i}), range(20)))
        self.assertEqual(len({r.sequence for r in receipts}), 20)
        self.assertTrue(self.collector.verify())

    def test_entry_failure_prevents_work_exit_failure_retains_gap(self):
        scratch = self.root / "scratch"
        scratch.mkdir()
        evidence = InvocationEvidence(self.collector, "env", scratch)
        touched = []
        self.collector.available = False
        with self.assertRaises(AuditUnavailable):
            evidence.invoke("entry-outage", lambda: touched.append(1))
        self.assertEqual(touched, [])
        self.collector.available = True
        def work():
            touched.append(2)
            self.collector.available = False
        with self.assertRaisesRegex(AuditUnavailable, "side effects"):
            evidence.invoke("exit-outage", work)
        self.assertEqual(touched, [2])
        self.collector.available = True
        recovered = InvocationEvidence(self.collector, "env", scratch).invoke("next", lambda: 3)
        self.assertEqual(recovered["entry_status"], "evidence-gap")

    def test_previous_exit_not_entry_is_baseline_and_reexecution_denied(self):
        scratch = self.root / "scratch"
        scratch.mkdir()
        evidence = InvocationEvidence(self.collector, "env", scratch)
        evidence.invoke("one", lambda: (scratch / "legitimate").write_text("cache"))
        self.assertEqual(evidence.invoke("two", lambda: None)["entry_status"], "matched")
        (scratch / "legitimate").write_text("changed")
        self.assertEqual(evidence.invoke("three", lambda: None)["entry_status"], "mismatch")
        with self.assertRaises(Rejected):
            evidence.invoke("three", lambda: self.fail("Repeated invocation ran"))


class ReferenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.now = 1000.
        self.app = ReferenceApp(self.root, clock=lambda: self.now)

    def tearDown(self):
        self.temp.cleanup()

    def targets(self):
        doc = self.app.ingest("user-token", "A bounded text document")
        return [(doc["id"], doc["version"])]

    def test_document_pipeline_owner_read_and_independent_purge(self):
        targets = self.targets()
        doc = self.app.read("user-token")
        self.assertEqual(doc["extracted"], "A bounded text document")
        self.assertEqual(doc["label"], "short")
        self.assertEqual(self.app.report("admin-token"), {"short": 1})
        with self.assertRaises(Rejected):
            self.app.report("user-token")
        grant = self.app.approve("admin-token", targets)
        self.assertEqual(self.app.purge("admin-token", targets, grant)["deleted"], 1)
        with self.assertRaises(Rejected):
            self.app.read("user-token")
        self.assertTrue(self.app.audit.verify())

    def test_gateway_and_internal_envelope_cannot_bypass(self):
        event, signature = self.app.envelope("original")
        with self.assertRaises(Rejected):
            self.app.ingest("missing", "text")
        with self.assertRaises(Rejected):
            self.app.ingest("user-token", "text", event={**event, "value": "changed"}, signature=signature)
        with self.assertRaises(Rejected):
            self.app.read("user-token")

    def test_second_user_cannot_read_or_replace_document(self):
        targets = self.targets()
        self.app.credentials["bob-token"] = ("bob", "user")
        with self.assertRaises(Rejected):
            self.app.read("bob-token")
        with self.assertRaises(Rejected):
            self.app.ingest("bob-token", "replacement")
        self.assertEqual(self.app.read("user-token")["version"], targets[0][1])

    def test_artifact_tamper_blocks_processing(self):
        (self.app.artifacts / "parser.rules").write_text("tampered")
        with self.assertRaises(Rejected):
            self.app.ingest("user-token", "text")
        with self.assertRaises(Rejected):
            self.app.read("user-token")

    def test_no_self_approval_or_direct_unapproved_delete(self):
        targets = self.targets()
        with self.assertRaises(Rejected):
            self.app.approve("user-token", targets)
        with self.assertRaises(Rejected):
            self.app.purge("user-token", targets)
        self.assertEqual(self.app.read("user-token")["version"], targets[0][1])

    def test_forgery_expiry_substitution_and_scope(self):
        targets = self.targets()
        grant = self.app.approve("admin-token", targets)
        forged = copy.deepcopy(grant)
        forged["grant"]["requester"] = "alice"
        for envelope, credential, scope in ((forged, "admin-token", targets),
                (grant, "user-token", targets), (grant, "admin-token", [("other", "v1")])):
            with self.subTest(credential=credential, scope=scope), self.assertRaises(Rejected):
                self.app.purge(credential, scope, envelope)
        self.now += 31
        with self.assertRaises(Rejected):
            self.app.purge("admin-token", targets, grant)
        self.assertEqual(self.app.read("user-token")["version"], targets[0][1])

    def test_malformed_grant_requests_are_rejected(self):
        for targets in (None, [], ["bad"], [("x",)], [("x", 1)], [("x", "1"), ("x", "2")]):
            with self.subTest(targets=targets), self.assertRaises(Rejected):
                self.app.approve("admin-token", targets)
        for ttl in (float("nan"), float("inf"), True, -1):
            with self.subTest(ttl=ttl), self.assertRaises(Rejected):
                self.app.approve("admin-token", [("x", "v1")], ttl=ttl)

    def test_replaced_version_does_not_delete_or_consume_valid_targets(self):
        targets = self.targets()
        second = self.app.documents.put("other", "alice", "other")
        targets += [(second["id"], second["version"])]
        grant = self.app.approve("admin-token", targets)
        self.app.documents.put("other", "alice", "replacement")
        with self.assertRaises(Rejected):
            self.app.purge("admin-token", targets, grant)
        self.assertEqual(self.app.read("user-token")["version"], targets[0][1])
        self.assertEqual(self.app.broker.reconcile(grant, "admin-token")["status"], "not-committed")

    def test_concurrent_replay_consumes_once_and_reconciles(self):
        targets = self.targets()
        grant = self.app.approve("admin-token", targets)
        def attempt(_):
            try:
                self.app.purge("admin-token", targets, grant)
                return True
            except Rejected:
                return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            self.assertEqual(sum(pool.map(attempt, range(8))), 1)
        self.assertEqual(self.app.broker.reconcile(grant, "admin-token")["status"], "committed")

    def test_audit_and_authority_outages_preserve_documents(self):
        targets = self.targets()
        grant = self.app.approve("admin-token", targets)
        self.app.authority.available = False
        with self.assertRaises(Rejected):
            self.app.purge("admin-token", targets, grant)
        self.app.authority.available = True
        self.app.audit.available = False
        with self.assertRaises(AuditUnavailable):
            self.app.purge("admin-token", targets, grant)
        self.assertEqual(self.app.read("user-token")["version"], targets[0][1])

    def test_purge_exit_failure_reconciles_committed_deletion(self):
        targets = self.targets()
        grant = self.app.approve("admin-token", targets)
        original = self.app.audit.append
        def fail_exit(event_id, event):
            if event["kind"] == "purge-exit":
                raise AuditUnavailable("injected exit failure")
            return original(event_id, event)
        self.app.audit.append = fail_exit
        with self.assertRaises(AuditUnavailable):
            self.app.purge("admin-token", targets, grant)
        self.assertEqual(self.app.broker.reconcile(grant, "admin-token")["status"], "committed")
        with self.assertRaises(Rejected):
            self.app.purge("admin-token", targets, grant)

    def test_policy_expansion_unknown_cases_and_fail_closed_audit(self):
        expansion = [rule("extract", "read", "public/item"), rule("retired", "read", "public/item")]
        self.assertEqual(self.app.deploy(expansion)["status"], "review-required")
        with self.assertRaises(Rejected):
            self.app.policy.invoke(Request("retired", "read", "public/item"), lambda: None)
        for candidate in ([rule("extract", "read", "*")], [rule("new", "read", "outside")],
                          [{**rule("extract", "read", "public/item"), "condition": {}}]):
            self.assertEqual(self.app.deploy(candidate)["status"], "unresolved")
        self.app.audit.available = False
        with self.assertRaises(AuditUnavailable):
            self.app.deploy([])
        self.app.audit.available = True
        self.assertEqual(self.app.deploy([])["status"], "accepted")
        with self.assertRaises(Rejected):
            self.app.ingest("user-token", "denied after revocation")

    def test_explicit_deny_overrides_allow(self):
        candidate = [rule("extract", "read", "public/item"), rule("extract", "read", "public/item", "deny")]
        self.assertEqual(self.app.deploy(candidate)["status"], "accepted")
        with self.assertRaises(Rejected):
            self.app.ingest("user-token", "denied")

    def test_telemetry_separates_public_and_investigator(self):
        self.targets()
        self.assertNotIn("trace", self.app.telemetry("user-token"))
        with self.assertRaises(Rejected):
            self.app.telemetry("user-token", detailed=True)
        self.assertEqual(self.app.telemetry("admin-token", detailed=True)["trace"], ["ingest", "extract", "classify"])

    def test_integrated_entry_and_exit_audit_outage_outcomes(self):
        self.app.audit.available = False
        with self.assertRaises(AuditUnavailable):
            self.app.ingest("user-token", "entry outage")
        with self.assertRaises(Rejected):
            self.app.read("user-token")
        self.app.audit.available = True
        with self.assertRaises(AuditUnavailable):
            self.app.ingest("user-token", "committed", exit_outage=True)
        self.assertEqual(self.app.read("user-token")["raw"], "committed")
        self.app.audit.available = True
        self.app.ingest("user-token", "next")
        entries = [r["event"] for r in self.app.audit.records("investigator") if r["event"].get("phase") == "entry"]
        self.assertEqual(entries[-1]["status"], "evidence-gap")

    def test_ablation_removes_only_selected_control(self):
        app = ReferenceApp(self.root / "ablation", CONTROLS - {"broker"})
        doc = app.ingest("user-token", "text")
        self.assertEqual(app.purge("user-token", [(doc["id"], doc["version"])])["deleted"], 1)
        with self.assertRaises(Rejected):
            app.telemetry("user-token", detailed=True)


class BudgetTests(unittest.TestCase):
    def test_offered_demand_remains_visible_during_enforcement(self):
        budget = InvocationBudget(20)
        for count in [10] * 20 + [90] * 3:
            for _ in range(count):
                budget.admit()
            bucket = budget.close_bucket()
        self.assertTrue(bucket["next_alert"])
        accepted = 0
        for _ in range(90):
            try:
                budget.admit()
                accepted += 1
            except Rejected:
                pass
        self.assertEqual(accepted, 20)
        self.assertEqual(budget.close_bucket(), {"offered": 90, "accepted": 20, "rejected": 70, "next_alert": True})


class IntegratedEvidenceTests(unittest.TestCase):
    def test_ablations_expose_admission_and_fault_tradeoffs(self):
        rows = framework(2, 42)["observations"]
        for row in rows:
            if row["variant"] == "full":
                if row["case"] == "legitimate-workflow":
                    self.assertTrue(row["completed"])
                else:
                    self.assertFalse(row["completed"])
                if row["case"] == "audit-entry-outage":
                    self.assertFalse(row["side_effect"])
                if row["case"] == "audit-exit-outage":
                    self.assertTrue(row["side_effect"])
                    self.assertTrue(row["gap_observed"])
            elif row["variant"].startswith("without-"):
                self.assertTrue(row["completed"])

    def test_sensitivity_pairs_demand_and_records_all_settings(self):
        rows = sensitivity(2, 50, .001)["observations"]
        self.assertEqual(len(rows), 2 * 5 * 9)
        for trial in range(2):
            for case in {r["case"] for r in rows}:
                selected = [r for r in rows if r["trial"] == trial and r["case"] == case]
                self.assertEqual(len({r["offered_invocations"] for r in selected}), 1)
                self.assertEqual(len({r["workload_seed"] for r in selected}), 1)
                for row in selected:
                    self.assertAlmostEqual(row["modeled_spend"], row["dispatch_count"] * .001)
