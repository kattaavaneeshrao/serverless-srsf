"""Fixed trusted lifecycle fixture launched in isolated-mode Python."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ssrsf.audit import AuditUnavailable, Receipt
from ssrsf.controls import Rejected
from ssrsf.policy import Request
from ssrsf.workflow import ReferenceApp


def run(request):
    app = ReferenceApp(Path(request["root"]), clock=lambda: 1000. if request["phase"] == "prepare" else 1040.)
    if request["phase"] == "prepare":
        doc = app.ingest("user-token", "lifecycle fixture")
        retained = app.documents.put("public/retained", "alice", "must survive restart")
        grant = app.approve("admin-token", [(doc["id"], doc["version"])], "recovery-operation", ttl=30)
        append = app.audit.append
        def fail_exit(event_id, event):
            if event.get("kind") == "purge-exit":
                raise AuditUnavailable("injected exit acknowledgement loss")
            return append(event_id, event)
        app.audit.append = fail_exit
        exit_failed = False
        try:
            app.purge("admin-token", [(doc["id"], doc["version"])], grant)
        except AuditUnavailable:
            exit_failed = True
        app.audit.append = append
        app.deploy([])  # Revocation must survive the interpreter exit.
        last = app.audit.records("investigator")[-1]
        return {"grant": grant, "retained": retained, "exit_failed": exit_failed,
                "anchor": {"sequence": last["sequence"], "digest": last["digest"]}}
    before = request["prepared"]
    expired_rejected = False
    try:
        app.authority.verify(before["grant"], "admin-token")
    except Rejected:
        expired_rejected = True
    recovery = app.broker.investigate("recovery-operation", "investigator-token")
    revoked = False
    try:
        app.policy.invoke(Request("extract", "read", "public/item"), lambda: None)
    except Rejected:
        revoked = True
    retained = app.documents.get("public/retained")
    with app.documents.connect() as db:
        consumed = db.execute("SELECT count(*) FROM consumed").fetchone()[0]
        deleted_absent = db.execute("SELECT count(*) FROM documents WHERE id='public/item'").fetchone()[0] == 0
    return {"expired_grant_rejected": expired_rejected,
            "operation_recovered": recovery["status"] == "committed" and recovery["deleted"] == 1,
            "revocation_retained": revoked, "retained_version_matches": retained["version"] == before["retained"]["version"],
            "anchored_chain_valid": app.audit.verify(Receipt(**before["anchor"])),
            "single_nonce_consumption": consumed == 1, "deleted_document_absent": deleted_absent}


if __name__ == "__main__":
    print(json.dumps(run(json.load(sys.stdin))))
