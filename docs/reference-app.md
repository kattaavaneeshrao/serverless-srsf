# Docker reference app

The Docker application is the project's reference implementation. The host menu, command line and Python client all call the same guard and controller. There is no separate in-process application or local document database.

## Start or upgrade

Run from the repository root with Python 3.11+ and Docker Desktop/Engine running Linux containers:

```bash
PYTHONPATH=src python3 -m ssrsf
```

Choose **1 — Document workflow**. The reference-app menu provides document work and every management/security action through prompts. Documents contain 1–128 characters; ten or more words yields `long`, otherwise `short`.

After updating source or adding identities, rebuild the services once:

```bash
python3 scripts/prototype.py init
docker compose up --build -d --wait
```

Initialization preserves existing credentials. Never regenerate the audit key while retaining its database. Database changes are additive; existing workflows and audit records remain valid. `docker compose down` stops services and preserves their volume and credentials.

## Complete interactive walkthrough

No additional terminal commands are required after opening the app and selecting activity **1**. The menu prints the current identity; permissions are enforced by the Docker controller as well as the menu. Use **4** to switch between `client` and `admin`.

| Menu choice | Action | What to enter / expect |
|---|---|---|
| **1** | Enter document text | Enter 1–128 characters of UTF-8 document text; prints workflow ID, state, classification and processed text |
| **2** | Process text file | Enter the path to a UTF-8 text file; oversized files (>128 chars) are rejected locally before submission |
| **3** | Read document / status | Enter a workflow ID, or press Enter for this identity's last document; displays state, owner, version, classification, and text |
| **4** | Switch identity | Toggle between `client` (standard user) and `admin` (privileged operator); checks credentials locally and enforces RBAC |
| **5** | Verify audit log | Cryptographically verifies the SHA-256 HMAC hash chain of audit records to detect log alteration or tail truncation |
| **6** | Quota & security | Displays current 20-req/min token-bucket budget, then runs automated worker boundary isolation and tamper probes |
| **0** | Back to main menu | Returns to the Document / Control benchmarks activity menu |

## Identities and ownership

Commands below use `PYTHONPATH=src python3 -m ssrsf reference`; after installation, use `ssrsf reference` instead. `scripts/prototype.py` is a compatibility entry point for the same client.

| Identity | Authority |
|---|---|
| `client` (default) | Submit and read its own documents; check its budget and verify audit records |
| `admin` | Read all documents, verify audit records, and manage quota budgets |

`--identity` selects a provisioned credential from `.prototype/secrets/`. The guard derives identity from that credential, never from a role supplied in the request body. The trusted host operator can access these fixture credentials; this is not an account-management service. Workers have separate credentials and cannot invoke management operations.

## Document operations

```bash
PYTHONPATH=src python3 -m ssrsf reference submit "My document"
PYTHONPATH=src python3 -m ssrsf reference read WORKFLOW_ID
```

Submission prints the workflow ID before dispatch. Retry uncertain submissions with `submit --id WORKFLOW_ID "same text"`. Reusing an ID with different text fails. Retrieve status to wait for processing.

## Audit and tampering

```bash
PYTHONPATH=src python3 -m ssrsf reference audit
PYTHONPATH=src python3 -m ssrsf reference tamper "Original document"
```

Every HTTP request includes a path-bound HMAC over its canonical JSON body, in addition to bearer authentication. `tamper` changes a signed submission and verifies rejection. HMAC does not provide confidentiality or general replay prevention; workflow IDs and task grants provide operation-specific retry controls.

Audit verification returns a `receipt` containing sequence and digest. Save that object separately as JSON and pass `audit --receipt receipt.json` to detect removal of that previously observed audit tail. A valid prefix without an external receipt cannot prove completeness. Startup verifies the audit chain; audit-write failures roll back workflow mutations.

The image build creates a SHA-256 source inventory. Services verify it at startup and before dispatch; workers also verify it before processing and completing tasks. Changed, missing or unlisted source files fail verification. Rebuilding from trusted source intentionally establishes a new inventory. This detects byte changes, not dependency vulnerabilities or malicious trusted source.

## Rate limiting and quota

```bash
PYTHONPATH=src python3 -m ssrsf reference budget
PYTHONPATH=src python3 -m ssrsf reference --identity admin budget --owner client --reset
```

The default quota admits 20 submissions per client per fixed minute. Identical submission retries do not consume another slot. Counters survive restart. Ordinary users can only read their own budget; administrator resets are audited.

## Python interface

```python
from ssrsf.reference import ReferenceApp

app = ReferenceApp()  # Calls the running Docker stack as client.
document = app.ingest("A bounded document")
print(app.read(document["id"]))
print(app.audit())
```

The controller remains the sole owner of documents, audit records and quota state. Local host directories are not document state.
