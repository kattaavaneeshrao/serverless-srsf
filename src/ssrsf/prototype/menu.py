"""Interactive access to every Docker reference-app operation."""
from __future__ import annotations

import json
import os
import secrets
from pathlib import Path

from ssrsf.reference import ReferenceApp
from .reference import CLIENTS, DOCUMENT_CLIENTS
from .store import STAGES
from .transport import RemoteError


def show(value):
    print(json.dumps(value, indent=2, ensure_ascii=False))


def number(ask, prompt, default, low, high):
    raw = ask(f"{prompt} [{default}]: ").strip() or str(default)
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"Enter a whole number from {low} to {high}.") from None
    if not low <= value <= high:
        raise ValueError(f"Enter a whole number from {low} to {high}.")
    return value


def yes(ask, prompt, default=False):
    raw = ask(prompt + (" [Y/n]: " if default else " [y/N]: ")).strip().lower()
    if not raw:
        return default
    if raw not in ("y", "yes", "n", "no"):
        raise ValueError("Enter yes or no.")
    return raw in ("y", "yes")


def save_json(path, value):
    path = Path(path).expanduser()
    with path.open("x", encoding="utf-8") as output:
        try:
            os.fchmod(output.fileno(), 0o600)
            json.dump(value, output, indent=2, ensure_ascii=False)
            output.write("\n")
        except BaseException:
            path.unlink()
            raise
    print("Saved:", path)


def policy_input(ask):
    print("1. Build rules interactively\n2. Paste a JSON rule list\n3. Read a JSON file")
    source = number(ask, "Policy input", 1, 1, 3)
    if source == 2:
        rules = json.loads(ask("JSON rule list: "))
    elif source == 3:
        rules = json.loads(Path(ask("Policy JSON file: ").strip()).expanduser().read_text(encoding="utf-8"))
    else:
        rules = []
        print("Add exact rules. An empty policy denies every stage; omitted permissions deny.")
        print("Principals: ingest, extract, classify, retired. Resource: documents.")
        while len(rules) < 20:
            principal = ask("Principal (Enter to finish): ").strip()
            if not principal:
                break
            if principal not in (*STAGES, "retired"):
                raise ValueError("Choose ingest, extract, classify or retired.")
            action = ask("Action [read]: ").strip() or "read"
            effect = ask("Effect [allow]: ").strip() or "allow"
            if action not in ("read", "delete") or effect not in ("allow", "deny"):
                raise ValueError("Actions: read/delete. Effects: allow/deny.")
            rules.append({"principal": principal, "action": action, "resource": "documents", "effect": effect})
    if not isinstance(rules, list):
        raise ValueError("Policy must be a JSON list of rules.")
    show(rules)
    return rules


def run(url, input_fn=None, *, return_to_main=False, identity="client"):
    from . import client as cli
    ask = input_fn or input
    last_ids, submissions = {}, {}
    grant = None
    approval_request = None
    operation = None
    receipt = None
    print("Serverless SRSF — reference app")
    print("Documents accept 1–128 characters; the limit is 20 submissions/replacements per client per minute.")
    while True:
        print(f"\nCurrent identity: {identity}")
        print("  1. Enter document text\n  2. Process a UTF-8 text file\n  3. Read document / check status")
        print("  4. Switch identity\n  5. Verify audit log\n  6. Check quota and security")
        print("  0. Back to main menu" if return_to_main else "  0. Quit")
        try:
            choice = ask("Choose [1]: ").strip() or "1"
            if choice in ("0", "q", "quit"):
                print("Returning to the main menu. Services keep running if started." if return_to_main else "Goodbye.")
                return
            if choice == "4":
                print("1. client\n2. admin\n3. client2\n4. investigator")
                idx = number(ask, "Identity", 1, 1, len(CLIENTS))
                # Map 1 -> client, 2 -> admin, 3 -> client2, 4 -> investigator
                role_order = ["client", "admin", "client2", "investigator"]
                selected = role_order[idx - 1] if idx <= len(role_order) else CLIENTS[idx - 1]
                cli.credential(selected)  # Verify provisioned credentials before changing session identity.
                identity = selected
                print("Using identity:", identity)
                continue
            if choice in ("1", "2"):
                if choice == "1":
                    text = cli.document_text(ask("Document text: "))
                else:
                    path = ask("UTF-8 text file path: ").strip()
                    if not path:
                        raise ValueError("Enter a file path.")
                    with Path(path).expanduser().open(encoding="utf-8") as handle:
                        text = cli.document_text(handle.read(129))
                last_ids[identity] = secrets.token_hex(16)
                body = {"id": last_ids[identity], "text": text}
                submissions[identity] = body
                cli.show_workflow(cli.send_submission(url, body) if identity == "client" else cli.send_submission(url, body, identity=identity))
                continue
            if choice == "3":
                last = last_ids.get(identity)
                workflow = ask("Workflow ID" + (" [last submission]" if last else "") + ": ").strip() or last
                if not workflow:
                    raise ValueError("Enter a workflow ID or submit a document first.")
                result = cli.request(url + "/status", cli.credential(identity), {"id": workflow})
                cli.show_workflow(result)
                if "owner" in result:
                    print("Owner:", result["owner"], "\nVersion:", result["version"], "\nOriginal text:", result["raw"])
                last_ids[identity] = workflow
                continue
            app = ReferenceApp(url, identity=identity)
            if choice == "5":
                result = app.audit()
                show(result)
                continue
            if choice == "6":
                print("Quota budget for current identity:")
                show(app.budget(owner=identity))
                print("\nRunning worker boundary and isolation checks...")
                cli.check(url)
                print("Security checks passed: worker isolation and tamper rejection verified.")
                continue
            print("Choose a listed option (0–6).")
            continue
        except EOFError:
            print("\nSession ended. Services keep running if started.")
            return
        except KeyboardInterrupt:
            print("\nAction cancelled. Admitted work may still finish; use status or reconciliation.")
        except RemoteError as exc:
            if exc.status >= 500:
                print("Service unavailable or still processing. Use option 18, then check status or reconcile the operation.")
            else:
                print("Request rejected:", exc)
        except FileNotFoundError as exc:
            print("File not found:", exc.filename or "check the supplied path", "— use option 18 if credentials are missing.")
        except (OSError, UnicodeError, ValueError, RuntimeError, cli.subprocess.CalledProcessError) as exc:
            print("Could not complete this action:", exc)
