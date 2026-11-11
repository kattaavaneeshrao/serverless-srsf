"""Controller, mandatory guard and stage workers for the Compose prototype."""
from __future__ import annotations

import argparse
import hashlib
import os
import time
from pathlib import Path

from .store import Denied, STAGES, WorkflowStore, exact
from .transport import RemoteError, request, server


def secret(name):
    value = (Path(os.environ.get("SRSF_SECRETS", "/run/secrets")) / name).read_text().strip()
    if len(value) < 32:
        raise RuntimeError("Missing or short service credential")
    return value


def controller_dispatch(store):
    def dispatch(identity, path, body):
        if identity != "guard":
            raise Denied("Guard required")
        exact(body, ("actor", "request"))
        actor, payload = body["actor"], body["request"]
        if actor == "client":
            if path == "/submit":
                return store.submit(actor, payload)
            if path == "/status":
                return store.status(actor, payload)
        if actor in STAGES:
            if path == "/claim":
                return store.claim(actor, payload)
            if path == "/complete":
                return store.complete(actor, payload)
        raise Denied("Operation not permitted")
    return dispatch


def guard_dispatch(controller_url, controller_token):
    def dispatch(identity, path, body):
        if identity == "client" and path in ("/submit", "/status"):
            pass
        elif identity in STAGES and path in ("/claim", "/complete"):
            pass
        else:
            raise Denied("Operation not permitted for this service")
        # Caller identity comes exclusively from the authenticated connection.
        return request(controller_url + path, controller_token, {"actor": identity, "request": body})
    return dispatch


def transform(stage, value):
    if stage == "ingest":
        return value
    if stage == "extract":
        return " ".join(value.split())
    if stage == "classify":
        return "long" if len(value.split()) >= 10 else "short"
    raise ValueError("Unknown worker stage")


def run_worker(stage):
    url = os.environ.get("SRSF_GUARD", "http://guard:8080")
    token = secret(stage)
    while True:
        try:
            task = request(url + "/claim", token, {})["task"]
            if task is None:
                time.sleep(0.25)
                continue
            if task["stage"] != stage or hashlib.sha256(task["value"].encode()).hexdigest() != task["input_hash"]:
                raise RuntimeError("Task scope or input digest mismatch")
            completion = {k: task[k] for k in ("id", "version", "input_hash", "token")}
            completion["output"] = transform(stage, task["value"])
            # Retry identical completion after a lost response; the controller returns
            # the durable outcome. A worker crash is recovered through lease expiry.
            while True:
                try:
                    request(url + "/complete", token, completion)
                    break
                except RemoteError as exc:
                    if exc.status < 500:
                        break  # Expired/replaced lease: never advance it locally.
                    time.sleep(0.5)
        except RemoteError:
            time.sleep(0.5)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("role", choices=("controller", "guard", *STAGES))
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    if args.role in STAGES:
        run_worker(args.role)
        return
    if args.role == "controller":
        path = Path(os.environ.get("SRSF_STATE", "/state")) / "workflow.sqlite"
        store = WorkflowStore(path, secret("audit").encode())
        dispatch = controller_dispatch(store)
        credentials = {"guard": secret("controller")}
    else:
        dispatch = guard_dispatch(os.environ.get("SRSF_CONTROLLER", "http://controller:8080"), secret("controller"))
        credentials = {name: secret(name) for name in ("client", *STAGES)}
    server(("0.0.0.0", args.port), dispatch, credentials).serve_forever()


if __name__ == "__main__":
    main()
