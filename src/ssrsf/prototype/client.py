#!/usr/bin/env python3
"""Host client for the Docker reference app and Compose checks."""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import secrets
import statistics
import subprocess
import time
from pathlib import Path

from ssrsf.prototype.store import STAGES
from ssrsf.prototype.reference import CLIENTS
from ssrsf.controls import sign_event
from ssrsf.prototype.transport import RemoteError, request

_SOURCE_ROOT = Path(__file__).resolve().parents[3]
ROOT = next((path for path in (_SOURCE_ROOT, Path.cwd(), *Path.cwd().parents)
             if (path / "compose.yaml").is_file() and (path / "src/ssrsf").is_dir()), _SOURCE_ROOT)
SECRETS = ROOT / ".prototype" / "secrets"


def start_services(*, reuse=False):
    if not (ROOT / "compose.yaml").is_file():
        raise RuntimeError("Run ssrsf from the project checkout containing compose.yaml.")
    initialize()
    try:
        if reuse:
            status = subprocess.run(["docker", "compose", "ps", "--format", "json"],
                                    cwd=ROOT, check=True, capture_output=True, text=True)
            try:
                services = []
                for line in status.stdout.splitlines():
                    value = json.loads(line)
                    services.extend(value if isinstance(value, list) else [value])
                running = {item["Service"]: item for item in services if isinstance(item, dict)}
                required = ("controller", "guard", *STAGES)
                if (all(name in running and running[name].get("State") == "running" for name in required)
                        and all(running[name].get("Health") == "healthy" for name in ("controller", "guard"))):
                    print("Document services are already running.")
                    return
            except (ValueError, KeyError, TypeError):
                pass  # Older/unrecognized Compose output: ensure services with up.
        subprocess.run(["docker", "compose", "up", "--build", "-d", "--wait"], cwd=ROOT, check=True)
    except FileNotFoundError:
        raise RuntimeError("Docker was not found. Install/start Docker Desktop and try again.") from None
    except subprocess.CalledProcessError:
        raise RuntimeError("Could not start services. Check Docker Desktop and the Compose output.") from None


def initialize():
    for directory in (SECRETS.parent, SECRETS):
        directory.mkdir(exist_ok=True, mode=0o700)
        if directory.is_symlink():
            raise RuntimeError("Refusing symlink secret directory")
        directory.chmod(0o700)
    for name in ("controller", "audit", *CLIENTS, *STAGES):
        path = SECRETS / name
        if path.is_symlink():
            raise RuntimeError("Refusing symlink credential")
        if path.exists():
            if len(path.read_text().strip()) < 32:
                raise RuntimeError("Invalid existing credential; refusing replacement")
            path.chmod(0o444)
            continue
        # Compose bind-mounts individual files into non-root containers. The host
        # directory is private; mounted credential files must be container-readable.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
        with os.fdopen(fd, "w") as handle:
            os.fchmod(handle.fileno(), 0o444)
            handle.write(secrets.token_hex(32) + "\n")
    print("Private service credentials ready; existing credentials preserved.")


def credential(name):
    return (SECRETS / name).read_text().strip()


def wait_complete(url, workflow, timeout=30, *, identity="client"):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = request(url + "/status", credential(identity), {"id": workflow})
        if result["state"] == "complete":
            return result
        time.sleep(0.1)
    raise RuntimeError("Workflow did not complete before timeout")


def rejected(url, name, path, body):
    try:
        request(url + path, credential(name) if name != "forged" else "invalid", body)
    except RemoteError as exc:
        if exc.status in (401, 403):
            return
        raise
    raise RuntimeError("Forbidden operation was accepted")


def check(url):
    workflow = "check-" + secrets.token_hex(8)
    body = {"id": workflow, "text": "A   bounded document"}
    first = request(url + "/submit", credential("client"), body)
    assert request(url + "/submit", credential("client"), body) == first
    result = wait_complete(url, workflow)
    assert result["text"] == "A bounded document" and result["label"] == "short"
    rejected(url, "forged", "/submit", body)
    rejected(url, "client", "/claim", {})
    rejected(url, "extract", "/submit", body)
    rejected(url, "client", "/submit", {**body, "text": "conflict"})
    rejected(url, "classify", "/complete", {"id": workflow, "version": first["version"],
             "token": "forged", "input_hash": "forged", "output": "long"})
    rejected(url, "ingest", "/claim", {"actor": "classify"})
    # Verify from *inside each worker* that controller access, sibling access,
    # direct database access and direct external egress are unavailable.
    controller_ip = subprocess.run(
        ["docker", "compose", "exec", "-T", "controller", "python", "-c",
         "import socket; print(socket.gethostbyname(socket.gethostname()))"],
        cwd=ROOT, check=True, capture_output=True, text=True).stdout.strip()
    probe = """
import socket
from pathlib import Path
assert not Path('/state/workflow.sqlite').exists()
assert sorted(p.name for p in Path('/run/secrets').iterdir()) == [STAGE]
for host,port in [('controller',8080), (CONTROLLER_IP,8080), ('SIBLING',8080), ('1.1.1.1',443)]:
    try:
        connection=socket.create_connection((host,port),timeout=2)
    except OSError:
        continue
    connection.close()
    raise SystemExit('Forbidden direct connection succeeded')
print('Worker boundary verified')
"""
    for stage in STAGES:
        sibling = STAGES[(STAGES.index(stage) + 1) % len(STAGES)]
        code = ("STAGE=" + repr(stage) + "\nCONTROLLER_IP=" + repr(controller_ip)
                + "\n" + probe.replace("SIBLING", sibling))
        subprocess.run(["docker", "compose", "exec", "-T", stage, "python", "-c", code],
                       cwd=ROOT, check=True)
    print("Workflow, idempotency, authorization and worker boundaries passed.")


def load(url, count, *, identity="client"):
    def trial(i):
        workflow = "load-" + secrets.token_hex(8)
        start = time.monotonic()
        try:
            request(url + "/submit", credential(identity), {"id": workflow, "text": "load test document"})
            wait_complete(url, workflow) if identity == "client" else wait_complete(url, workflow, identity=identity)
            return {"completed": True, "seconds": time.monotonic() - start}
        except RemoteError as exc:
            return {"completed": False, "status": exc.status}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(trial, range(count)))
    durations = [r["seconds"] for r in results if r["completed"]]
    print(json.dumps({"submitted": count, "completed": len(durations),
                      "median_seconds": statistics.median(durations) if durations else None,
                      "observations": results}, indent=2))
    if len(durations) != count:
        raise RuntimeError("Some requests failed; the shared 20/minute quota also applies to load tests.")


def send_submission(url, body, *, identity="client"):
    print("Workflow ID:", body["id"], flush=True)
    request(url + "/submit", credential(identity), body)
    return wait_complete(url, body["id"]) if identity == "client" else wait_complete(url, body["id"], identity=identity)


def show_workflow(result):
    print("Workflow:", result["id"])
    print("State:", result["state"])
    if result["state"] == "complete":
        print("Classification:", result["label"])
        print("Processed text:", result["text"])


def document_text(value):
    if not 1 <= len(value) <= 128:
        raise ValueError("Enter 1 to 128 characters. Your document was not submitted.")
    return value


def interactive(url, input_fn=None, *, return_to_main=False, identity="client"):
    from .menu import run
    return run(url, input_fn, return_to_main=return_to_main, identity=identity)


def tamper(url, identity, text):
    body = {"id": secrets.token_hex(16), "text": text}
    token = credential(identity)
    signature = sign_event({"path": "/submit", "body": body}, token.encode())
    try:
        request(url.rstrip("/") + "/submit", token, {**body, "text": text + " altered"}, signature=signature)
    except RemoteError as exc:
        if exc.status != 403:
            raise
        return {"tampering_rejected": True}
    raise RuntimeError("Altered event was accepted")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    parser.add_argument("--identity", choices=CLIENTS, default="client", help="Authenticate as a provisioned role")
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("interactive", help="Open the document menu (default)")
    commands.add_parser("init")
    submit = commands.add_parser("submit")
    submit.add_argument("text")
    submit.add_argument("--id", default=None, help="Reuse this id for a safe retry")
    status = commands.add_parser("status")
    status.add_argument("id")
    read = commands.add_parser("read", help="Read an owned document (administrator can read all)")
    read.add_argument("id")
    replacement = commands.add_parser("replace")
    replacement.add_argument("id")
    replacement.add_argument("version")
    replacement.add_argument("text")
    approval = commands.add_parser("approve")
    approval.add_argument("ids", nargs="+")
    approval.add_argument("--operation", default=None)
    approval.add_argument("--ttl", type=int, default=30)
    approval.add_argument("--output", type=Path, required=True, help="Save the exact deletion grant")
    purge = commands.add_parser("purge")
    purge.add_argument("grant", type=Path)
    investigation = commands.add_parser("investigate")
    investigation.add_argument("operation")
    commands.add_parser("report")
    telemetry = commands.add_parser("telemetry")
    telemetry.add_argument("--detailed", action="store_true")
    telemetry.add_argument("--after", type=int, default=0)
    telemetry.add_argument("--limit", type=int, default=50)
    audit = commands.add_parser("audit")
    audit.add_argument("--receipt", type=Path)
    budget = commands.add_parser("budget")
    budget.add_argument("--owner")
    budget.add_argument("--reset", action="store_true")
    deployment = commands.add_parser("deploy")
    deployment.add_argument("rules", type=Path)
    deployment.add_argument("--change-id")
    tamper = commands.add_parser("tamper")
    tamper.add_argument("text")
    commands.add_parser("check")
    stress = commands.add_parser("load")
    stress.add_argument("--requests", type=int, default=5, choices=range(1, 21))
    args = parser.parse_args(argv)
    if args.command in (None, "interactive"):
        start_services(reuse=True)
        interactive(args.url) if args.identity == "client" else interactive(args.url, identity=args.identity)
    elif args.command == "init":
        initialize()
    elif args.command == "submit":
        workflow = args.id or secrets.token_hex(16)
        print(json.dumps(send_submission(args.url, {"id": workflow, "text": args.text}, identity=args.identity), indent=2))
    elif args.command in ("status", "read"):
        print(json.dumps(request(args.url + "/status", credential(args.identity), {"id": args.id}), indent=2))
    elif args.command == "check":
        check(args.url)
    elif args.command == "load":
        load(args.url, args.requests) if args.identity == "client" else load(args.url, args.requests, identity=args.identity)
    else:
        from ssrsf.reference import ReferenceApp
        app = ReferenceApp(args.url, identity=args.identity)
        if args.command == "replace":
            result = app.replace(args.id, args.version, args.text)
        elif args.command == "approve":
            targets = [(workflow, app.read(workflow)["version"]) for workflow in args.ids]
            # Open exclusively before issuing a grant; never overwrite a saved capability.
            with args.output.open("x", encoding="utf-8") as output:
                try:
                    os.fchmod(output.fileno(), 0o600)
                    result = app.approve(targets, operation=args.operation, ttl=args.ttl)
                    json.dump(result, output, indent=2)
                except Exception:
                    args.output.unlink()
                    raise
        elif args.command == "purge":
            result = app.purge(json.loads(args.grant.read_text()))
        elif args.command == "investigate":
            result = app.investigate(args.operation)
        elif args.command == "report":
            result = app.report()
        elif args.command == "telemetry":
            result = app.telemetry(detailed=args.detailed, after=args.after, limit=args.limit)
        elif args.command == "audit":
            result = app.audit(json.loads(args.receipt.read_text()) if args.receipt else None)
        elif args.command == "budget":
            result = app.budget(owner=args.owner, reset=args.reset)
        elif args.command == "deploy":
            result = app.deploy(json.loads(args.rules.read_text()), change_id=args.change_id)
        elif args.command == "tamper":
            result = tamper(args.url, args.identity, args.text)
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except FileNotFoundError:
        raise SystemExit("prototype: Missing credentials; run python3 scripts/prototype.py init first.")
    except (RemoteError, RuntimeError) as exc:
        raise SystemExit(f"prototype: {exc}")
