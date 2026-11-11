#!/usr/bin/env python3
"""Host client for the isolated document workflow and Compose checks."""
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
    for name in ("controller", "audit", "client", *STAGES):
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


def wait_complete(url, workflow, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = request(url + "/status", credential("client"), {"id": workflow})
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


def load(url, count):
    def trial(i):
        workflow = "load-" + secrets.token_hex(8)
        start = time.monotonic()
        try:
            request(url + "/submit", credential("client"), {"id": workflow, "text": "load test document"})
            wait_complete(url, workflow)
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


def send_submission(url, body):
    print("Workflow ID:", body["id"], flush=True)
    request(url + "/submit", credential("client"), body)
    return wait_complete(url, body["id"])


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


def interactive(url, input_fn=None, *, return_to_main=False):
    ask = input_fn or input
    last = None
    print("Serverless SRSF — container workflow")
    print("Documents accept 1–128 characters. The shared limit is 20 new workflows per minute.")
    while True:
        print("\n1. Enter document text\n2. Process a UTF-8 text file\n3. Check workflow status")
        print("0. Back to main menu" if return_to_main else "0. Quit")
        try:
            choice = ask("Choose [1]: ").strip() or "1"
            if choice in ("0", "q", "quit"):
                print("Returning to the main menu. Services keep running." if return_to_main else
                      "Goodbye. Services keep running.")
                return
            if choice in ("1", "2"):
                if choice == "1":
                    text = document_text(ask("Document text: "))
                else:
                    path = ask("UTF-8 text file path: ").strip()
                    if not path:
                        raise ValueError("Enter a file path.")
                    with Path(path).expanduser().open(encoding="utf-8") as handle:
                        text = document_text(handle.read(129))
                # Preserve the ID and exact input before dispatch, including when
                # a response is lost or the user cancels the wait.
                last = {"id": secrets.token_hex(16), "text": text}
                show_workflow(send_submission(url, last))
            elif choice == "3":
                suffix = " [last submission]" if last else ""
                workflow = ask("Workflow ID" + suffix + ": ").strip()
                workflow = workflow or (last["id"] if last else "")
                if not workflow:
                    raise ValueError("Enter a workflow ID or submit a document first.")
                show_workflow(request(url + "/status", credential("client"), {"id": workflow}))
            else:
                print("Choose a listed option (0–3).")
        except EOFError:
            print("\nGoodbye. Services keep running.")
            return
        except KeyboardInterrupt:
            print("\nAction cancelled. Submitted workflows may still finish; check workflow status.")
        except RemoteError as exc:
            if exc.status >= 500:
                print("Service unavailable or still processing. Return to the main menu and reopen Document workflow, then check status.")
            else:
                print("Request rejected:", exc)
        except FileNotFoundError as exc:
            if exc.filename and str(SECRETS) in str(exc.filename):
                print("Credentials are missing. Return to the main menu and reopen Document workflow.")
            elif exc.filename == "docker":
                print("Docker was not found. Install/start Docker Desktop and try again.")
            else:
                print("File not found:", exc.filename or "check the supplied path")
        except subprocess.CalledProcessError:
            print("Docker operation failed. Check Docker Desktop and the service output, then try again.")
        except (OSError, UnicodeError, ValueError, RuntimeError) as exc:
            print("Could not complete this action:", exc)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("interactive", help="Open the document menu (default)")
    commands.add_parser("init")
    submit = commands.add_parser("submit")
    submit.add_argument("text")
    submit.add_argument("--id", default=None, help="Reuse this id for a safe retry")
    status = commands.add_parser("status")
    status.add_argument("id")
    commands.add_parser("check")
    stress = commands.add_parser("load")
    stress.add_argument("--requests", type=int, default=5, choices=range(1, 21))
    args = parser.parse_args(argv)
    if args.command in (None, "interactive"):
        start_services(reuse=True)
        interactive(args.url)
    elif args.command == "init":
        initialize()
    elif args.command == "submit":
        workflow = args.id or secrets.token_hex(16)
        print(json.dumps(send_submission(args.url, {"id": workflow, "text": args.text}), indent=2))
    elif args.command == "status":
        print(json.dumps(request(args.url + "/status", credential("client"), {"id": args.id}), indent=2))
    elif args.command == "check":
        check(args.url)
    elif args.command == "load":
        load(args.url, args.requests)


if __name__ == "__main__":
    try:
        main()
    except FileNotFoundError:
        raise SystemExit("prototype: Missing credentials; run python3 scripts/prototype.py init first.")
    except (RemoteError, RuntimeError) as exc:
        raise SystemExit(f"prototype: {exc}")
