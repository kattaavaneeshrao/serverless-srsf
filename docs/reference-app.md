# Docker reference app

The Docker application is the project's reference implementation. The host menu, command line and Python client all call the same guard and controller. There is no separate in-process application or local document database.

## Start or upgrade

Run from the repository root with Python 3.11+ and Docker Desktop/Engine running Linux containers:

```bash
PYTHONPATH=src python3 -m ssrsf
```

Choose **1 — Document workflow**. The document menu accepts text or UTF-8 files and retrieves status. Documents contain 1–128 characters; ten or more words yields `long`, otherwise `short`.

After updating source or adding identities, rebuild the services once:

```bash
python3 scripts/prototype.py init
docker compose up --build -d --wait
```

Initialization preserves existing credentials. Never regenerate the audit key while retaining its database. Database changes are additive; existing workflows and audit records remain valid. `docker compose down` stops services and preserves their volume and credentials.

## Identities and ownership

Commands below use `PYTHONPATH=src python3 -m ssrsf reference`; after installation, use `ssrsf reference` instead. `scripts/prototype.py` is a compatibility entry point for the same client.

| Identity | Authority |
|---|---|
| `client` (default) | Submit, read and replace its own documents; see its budget, public telemetry and audit verification |
| `client2` | A second document owner with the same restrictions |
| `admin` | Read/replace any document; aggregate reporting, deletion approval/purge, policy deployment, budget reset and detailed telemetry |
| `investigator` | Detailed telemetry, audit verification and read-only deletion reconciliation; no document reads or deletion |

`--identity` selects a provisioned credential from `.prototype/secrets/`. The guard derives identity from that credential, never from a role supplied in the request body. The trusted host operator can access these fixture credentials; this is not an account-management service. Workers have separate credentials and cannot invoke management operations.

## Document operations

```bash
PYTHONPATH=src python3 -m ssrsf reference submit "My document"
PYTHONPATH=src python3 -m ssrsf reference read WORKFLOW_ID
PYTHONPATH=src python3 -m ssrsf reference replace WORKFLOW_ID CURRENT_VERSION "Updated document"
PYTHONPATH=src python3 -m ssrsf reference --identity client2 submit "Another user's document"
PYTHONPATH=src python3 -m ssrsf reference --identity admin report
```

Submission prints the workflow ID before dispatch. Retry uncertain submissions with `submit --id WORKFLOW_ID "same text"`. Reusing an ID with different text fails. Replacement requires the current version, retains ownership, invalidates old stage grants and consumes a quota slot. Retrieve status to wait for replacement processing. Deleted IDs cannot be reused.

## Approved deletion and reconciliation

An administrator issues a signed grant for exact workflow versions. Default expiry is 30 seconds, maximum 300 seconds. The administrator can both approve and execute; independent human approval is not provided.

```bash
PYTHONPATH=src python3 -m ssrsf reference --identity admin approve WORKFLOW_ID --operation deletion-demo --output grant.json
PYTHONPATH=src python3 -m ssrsf reference --identity admin purge grant.json
PYTHONPATH=src python3 -m ssrsf reference --identity investigator investigate deletion-demo
```

Approval supports up to 20 workflow IDs. It saves a private grant file and refuses to overwrite an existing file. Keep the operation ID to reconcile a lost response. The same approval request and operation ID return the original grant; changing its scope fails. Purge validates requester, signature, expiry and every version under a database write lock. Grant consumption, all deletions, the retained outcome and audit record commit together. Expired, forged, replayed or stale-version grants cannot delete documents. Purging an in-progress workflow invalidates its outstanding tasks. Reconciliation is read-only and remains available after grant expiry or controller restart.

## Audit, telemetry and tampering

```bash
PYTHONPATH=src python3 -m ssrsf reference audit
PYTHONPATH=src python3 -m ssrsf reference telemetry
PYTHONPATH=src python3 -m ssrsf reference --identity investigator telemetry --detailed --after 0 --limit 50
PYTHONPATH=src python3 -m ssrsf reference tamper "Original document"
```

Every HTTP request includes a path-bound HMAC over its canonical JSON body, in addition to bearer authentication. `tamper` changes a signed submission and verifies rejection. HMAC does not provide confidentiality or general replay prevention; workflow IDs and task grants provide operation-specific retry controls.

Audit verification returns a `receipt` containing sequence and digest. Save that object separately as JSON and pass `audit --receipt receipt.json` to detect removal of that previously observed audit tail. A valid prefix without an external receipt cannot prove completeness. Startup verifies the audit chain; audit-write failures roll back workflow and management mutations.

Detailed telemetry is paginated and restricted to administrators/investigators. Use the returned `next` sequence as `--after` to continue. Worker stage-entry/exit events contain scratch inventories; changes between a prior exit and next entry appear as `entry_status: mismatch`. Each worker has a bounded writable scratch tmpfs. Scratch evidence is reported by the worker and is not independent attestation of a compromised process.

The image build creates a SHA-256 source inventory. Services verify it at startup and before dispatch; workers also verify it before processing and completing tasks. Changed, missing or unlisted source files fail verification. Rebuilding from trusted source intentionally establishes a new inventory. This detects byte changes, not dependency vulnerabilities or malicious trusted source.

## Policy and quota

```bash
PYTHONPATH=src python3 -m ssrsf reference budget
PYTHONPATH=src python3 -m ssrsf reference --identity admin budget --owner client --reset
PYTHONPATH=src python3 -m ssrsf reference --identity admin deploy policy.json --change-id policy-demo
```

The default quota admits 20 submissions/replacements per client per fixed minute. Identical submission retries do not consume another slot. Counters survive restart. Ordinary users can only read their own budget; administrator resets are audited.

`policy.json` is a JSON list of exact rules, for example:

```json
[
  {"principal": "ingest", "action": "read", "resource": "documents", "effect": "allow"},
  {"principal": "extract", "action": "read", "resource": "documents", "effect": "allow"},
  {"principal": "classify", "action": "read", "resource": "documents", "effect": "allow"}
]
```

Supported principals are the three stages and the disabled fixture `retired`; supported actions are `read` and `delete`, with resource `documents`. These are a bounded policy catalogue, not cloud IAM rules. Stage claims and completions require `read`; the catalogue's `delete` entries model permission expansion and do not give workers a deletion API. Explicit deny wins; omitted permissions deny. Wildcards/unknown fields return `unresolved`. Any newly allowed permission returns `review-required` and leaves the current policy unchanged; there is no bypass command to force acceptance. Accepted restrictive changes persist across restart and gate claims/completions in the same transaction as stage changes. Revoked in-flight tasks cannot advance. Use stable change IDs for retry; conflicting reuse fails.

## Python interface

```python
from ssrsf.reference import ReferenceApp

app = ReferenceApp()  # Calls the running Docker stack as client.
document = app.ingest("A bounded document")
print(app.read(document["id"]))
print(app.audit())

admin = ReferenceApp(identity="admin")
print(admin.report())
```

The client also exposes `replace`, `approve`, `purge`, `investigate`, `deploy`, `telemetry` and `budget`. An explicit `url` and `token` can select another configured endpoint. The controller remains the sole owner of documents, policy, approvals, audit records and quota state. Local host directories are not document state.
