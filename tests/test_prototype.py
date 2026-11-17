"""Real HTTP boundaries and transactional controller failure/concurrency tests."""
import concurrent.futures
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from ssrsf.prototype.service import controller_dispatch, guard_dispatch, transform
from ssrsf.prototype.store import Denied, STAGES, WorkflowStore
from ssrsf.prototype.reference import CLIENTS
from ssrsf.prototype.transport import RemoteError, request, server


def completion(task, output=None):
    body = {k: task[k] for k in ("id", "version", "token", "input_hash")}
    body["output"] = transform(task["stage"], task["value"]) if output is None else output
    return body


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "state.sqlite"
        self.now = 1000.
        self.store = WorkflowStore(self.path, b"audit-key", clock=lambda: self.now)

    def tearDown(self):
        self.directory.cleanup()

    def submit(self, workflow="one", text="A   bounded document"):
        return self.store.submit("client", {"id": workflow, "text": text})

    def test_order_scope_and_duplicate_outcome_survive_restart(self):
        self.submit()
        self.assertIsNone(self.store.claim("classify", {})["task"])
        for stage in STAGES:
            task = self.store.claim(stage, {})["task"]
            body = completion(task)
            for replacement in ({"id": "other"}, {"version": "other"}, {"input_hash": "other"}, {"token": "other"}):
                with self.assertRaises(Denied):
                    self.store.complete(stage, {**body, **replacement})
            with self.assertRaises(Denied):
                self.store.complete(STAGES[(STAGES.index(stage) + 1) % 3], body)
            result = self.store.complete(stage, body)
            reopened = WorkflowStore(self.path, b"audit-key", clock=lambda: self.now)
            self.assertEqual(reopened.complete(stage, body), result)
            with self.assertRaises(Denied):
                reopened.complete(stage, {**body, "output": "long" if stage == "classify" else "different"})
        status = self.store.status("client", {"id": "one"})
        self.assertEqual((status["state"], status["text"], status["label"]),
                         ("complete", "A bounded document", "short"))
        self.assertTrue(self.store.verify_audit())

    def test_expired_lease_recovered_after_restart(self):
        self.submit()
        old = self.store.claim("ingest", {})["task"]
        self.now += 31
        reopened = WorkflowStore(self.path, b"audit-key", clock=lambda: self.now)
        new = reopened.claim("ingest", {})["task"]
        self.assertNotEqual(new["token"], old["token"])
        with self.assertRaises(Denied):
            reopened.complete("ingest", completion(old))
        reopened.complete("ingest", completion(new))

    def test_concurrent_claims_and_completion_do_not_repeat_transition(self):
        self.submit()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            tasks = list(pool.map(lambda _: self.store.claim("ingest", {})["task"], range(8)))
        self.assertEqual(sum(t is not None for t in tasks), 1)
        body = completion(next(t for t in tasks if t))
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(lambda _: self.store.complete("ingest", body), range(8)))
        self.assertTrue(all(r == outcomes[0] for r in outcomes))
        with self.store.connect() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM outcomes").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT count(*) FROM audit").fetchone()[0], 3)

    def test_audit_failure_rolls_back_mutation_then_retry_commits(self):
        self.submit()
        body = completion(self.store.claim("ingest", {})["task"])
        audit = self.store.audit
        def failure(db, event):
            raise sqlite3.OperationalError("injected audit write failure")
        self.store.audit = failure
        with self.assertRaises(sqlite3.OperationalError):
            self.store.complete("ingest", body)
        self.assertEqual(self.store.status("client", {"id": "one"})["state"], "ingest")
        with self.store.connect() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM outcomes").fetchone()[0], 0)
        self.store.audit = audit
        self.assertEqual(self.store.complete("ingest", body)["state"], "extract")

    def test_shared_quota_idempotent_submission_and_owner_scope(self):
        self.store.cap = 2
        body = {"id": "one", "text": "text"}
        first = self.store.submit("client", body)
        self.assertEqual(self.store.submit("client", body), first)
        with self.assertRaises(Denied):
            self.store.submit("client", {**body, "text": "changed"})
        with self.assertRaises(Denied):
            self.store.status("other", {"id": "one"})
        self.submit("two")
        reopened = WorkflowStore(self.path, b"audit-key", clock=lambda: self.now, cap=2)
        with self.assertRaises(Denied):
            reopened.submit("client", {"id": "three", "text": "text"})
        self.now += 60
        reopened.submit("client", {"id": "three", "text": "text"})

    def test_multiple_workflows_cannot_exchange_grants(self):
        self.submit("one")
        self.submit("two")
        one, two = [self.store.claim("ingest", {})["task"] for _ in range(2)]
        with self.assertRaises(Denied):
            self.store.complete("ingest", {**completion(one), "id": two["id"], "version": two["version"]})
        self.store.complete("ingest", completion(two))
        self.assertEqual(self.store.status("client", {"id": one["id"]})["state"], "ingest")

    def test_tampered_audit_rejected_on_restart(self):
        self.submit()
        with self.store.connect() as db:
            db.execute("UPDATE audit SET payload='{}'")
        with self.assertRaises(Denied):
            WorkflowStore(self.path, b"audit-key")


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = WorkflowStore(Path(self.directory.name) / "state.sqlite", b"audit-key")
        self.credentials = {name: name + "-credential" * 4 for name in (*CLIENTS, *STAGES)}
        self.internal = server(("127.0.0.1", 0), controller_dispatch(self.store), {"guard": "private-controller"})
        self.internal_url = "http://127.0.0.1:" + str(self.internal.server_port)
        self.guard = server(("127.0.0.1", 0), guard_dispatch(self.internal_url, "private-controller"), self.credentials)
        self.url = "http://127.0.0.1:" + str(self.guard.server_port)
        self.threads = []
        for listener in (self.internal, self.guard):
            thread = threading.Thread(target=listener.serve_forever, daemon=True)
            thread.start()
            self.threads.append(thread)

    def tearDown(self):
        for listener in (self.guard, self.internal):
            listener.shutdown()
            listener.server_close()
        for thread in self.threads:
            thread.join()
        self.directory.cleanup()

    def call(self, actor, path, body):
        return request(self.url + path, self.credentials[actor], body)

    def test_real_http_pipeline_and_role_denials(self):
        self.call("client", "/submit", {"id": "http-one", "text": "one   two"})
        for stage in STAGES:
            task = self.call(stage, "/claim", {})["task"]
            self.call(stage, "/complete", completion(task))
        self.assertEqual(self.call("client", "/status", {"id": "http-one"})["text"], "one two")
        for actor, path, body in (("client", "/claim", {}), ("extract", "/submit", {}),
                                  ("ingest", "/claim", {"actor": "classify"})):
            with self.assertRaises(RemoteError) as raised:
                self.call(actor, path, body)
            self.assertEqual(raised.exception.status, 403)
        with self.assertRaises(RemoteError) as raised:
            request(self.internal_url + "/claim", self.credentials["extract"], {"actor": "extract", "request": {}})
        self.assertEqual(raised.exception.status, 401)

    def test_controller_outage_fails_closed_without_advancing(self):
        self.call("client", "/submit", {"id": "outage", "text": "text"})
        task = self.call("ingest", "/claim", {})["task"]
        self.internal.shutdown()
        self.internal.server_close()
        with self.assertRaises(RemoteError) as raised:
            self.call("ingest", "/complete", completion(task))
        self.assertEqual(raised.exception.status, 503)
        self.assertEqual(self.store.status("client", {"id": "outage"})["state"], "ingest")

    def test_invalid_credentials_schemas_and_oversized_http_body_do_not_create_work(self):
        with self.assertRaises(RemoteError) as raised:
            request(self.url + "/submit", "forged", {"id": "forged", "text": "text"})
        self.assertEqual(raised.exception.status, 401)
        for body in ({"id": "bad", "text": "text", "actor": "classify"},
                     {"id": "oversized", "text": "x" * 9000},
                     {"id": "../traversal", "text": "text"}):
            with self.assertRaises(RemoteError) as raised:
                self.call("client", "/submit", body)
            self.assertEqual(raised.exception.status, 403)
        with self.store.connect() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM workflows").fetchone()[0], 0)
