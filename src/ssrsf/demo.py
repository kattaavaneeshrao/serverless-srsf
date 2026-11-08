"""Hands-on terminal interface to the real ReferenceApp workflow."""
from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from .workflow import ReferenceApp


HELP = """Commands:
  ingest TEXT         Process your text (up to 128 characters)
  file PATH           Process a UTF-8 text file (up to 128 characters)
  read                Show the current document and extracted text
  auth TOKEN          Use user-token, admin-token, investigator-token, or try an invalid token
  approve             Request a purge grant for the current document version
  purge               Delete using the last grant; try before approval or twice
  tamper TEXT         Modify a signed event before delivery; observe rejection
  telemetry           Request detailed traces and audit records with the current role
  audit               Verify the audit chain
  budget              Close the invocation bucket and show accounting
  help / quit

One document slot is available: public/item. Each ingest replaces its version.
Classification is based on word count: 10 or more words = long, otherwise short.
Roles use local fixture credentials. Approval grants expire after 30 seconds.
"""


def show(value):
    print(json.dumps(value, indent=2, ensure_ascii=False))


def read_text(path):
    # The workflow accepts at most 128 characters; bound file reads accordingly.
    with Path(path).expanduser().open(encoding="utf-8") as stream:
        text = stream.read(129)
    if len(text) > 128:
        raise ValueError("Text files must contain at most 128 characters")
    return text


def session(app, args):
    credential = "user-token"
    if args.text is not None or args.file is not None:
        text = args.text if args.text is not None else read_text(args.file)
        app.ingest(credential, text)
        show(app.read(credential))
        show({"audit_verified": app.audit.verify()})
        return 0

    print("SRSF document workflow — enter your own text and commands.")
    print(HELP)
    grant = None
    targets = []
    while True:
        try:
            line = input(f"ssrsf [{credential}]> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nSession ended.")
            return 0
        if not line:
            continue
        command, _, argument = line.partition(" ")
        argument = argument.strip()
        try:
            if command in {"quit", "exit"}:
                return 0
            if command == "help":
                print(HELP)
            elif command == "auth":
                app.identity(argument)
                credential = argument
                print(f"Using {credential}")
            elif command in {"ingest", "file", "tamper"}:
                if not argument:
                    raise ValueError(f"Usage: {command} {'PATH' if command == 'file' else 'TEXT'}")
                text = read_text(argument) if command == "file" else argument
                if command == "tamper":
                    event, signature = app.envelope(text)
                    event["value"] += " (changed in transit)"
                    show(app.ingest(credential, text, event=event, signature=signature))
                else:
                    app.ingest(credential, text)
                    show(app.read(credential))
                    print("Processed: ingest → extract → classify; audit entry and exit recorded.")
            elif command == "read":
                show(app.read(credential))
            elif command == "approve":
                document = app.read(credential)
                candidate = [(document["id"], document["version"])]
                issued = app.approve(credential, candidate)
                targets, grant = candidate, issued
                show(grant)
            elif command == "purge":
                if grant is None:
                    document = app.read(credential)
                    targets = [(document["id"], document["version"])]
                show(app.purge(credential, targets, grant))
            elif command == "telemetry":
                show(app.telemetry(credential, detailed=True))
            elif command == "audit":
                show({"audit_verified": app.audit.verify()})
            elif command == "budget":
                show(app.budget.close_bucket())
            else:
                print("Unknown command. Enter help for commands.")
        except (ValueError, OSError, RuntimeError) as exc:
            print(f"Rejected: {exc}")


def run(args):
    if args.state is not None:
        print(f"Demo state: {args.state.resolve()}")
        return session(ReferenceApp(args.state), args)
    with TemporaryDirectory(prefix="ssrsf-demo-") as directory:
        print("Using temporary demo state; it is removed when this session ends.")
        return session(ReferenceApp(Path(directory)), args)
