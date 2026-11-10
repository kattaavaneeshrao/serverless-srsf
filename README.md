# Serverless SRSF: A Site Reliability and Security Framework

Serverless SRSF is a local Python framework for applying security controls to a serverless-style document workflow. It implements selected recommendations from [Marin, Perino and Di Pietro’s “Serverless computing: a security perspective” (2022)](https://doi.org/10.1186/s13677-022-00347-w).

The project has two parts:

- **A reusable application:** ingest → extract → classify, guarded by event validation, ownership checks, artifact integrity, audit logging, approved deletion, policy enforcement and invocation quotas.
- **Seven supporting experiments:** controlled comparisons and threat demonstrations covering events, authorization, dependencies, persistence, side channels, rollouts and billing.

Everything runs locally with Python 3.11+ and the standard library. Cloud deployment paths are described [below](#implementing-on-serverless-platforms); cloud adapters and infrastructure are not included. The experiments measure individual behaviors, not the integrated framework’s end-to-end effectiveness.

## Quick start

Run from the repository root:

```bash
# Open the interactive menu for documents or experiments
PYTHONPATH=src python3 -m ssrsf

# Process text directly
PYTHONPATH=src python3 -m ssrsf --text "My document about serverless security"

# Open guided experiments directly
PYTHONPATH=src python3 -m ssrsf evaluate
```

The startup menu offers **1. Document workflow**, **2. Guided experiments** and **3. Quit**. Press Enter to open the document workflow. Both the installed `ssrsf` command and `python3 -m ssrsf` use this menu.

To install the shorter `ssrsf` command:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
ssrsf
```

On Windows, activate with `.venv\Scripts\Activate.ps1`.

## Try the document workflow

Choose **1. Document workflow** from the startup menu, then enter this session in the console:

```text
ingest This is my document about serverless security.
read
tamper Changed input
purge
auth admin-token
approve
purge
audit
quit
```

`tamper` demonstrates integrity rejection. The first `purge` fails without approval; the administrator can then approve and delete the current version. Approval expires after 30 seconds and cannot be reused or applied to a replacement version.

| Command | Purpose |
|---|---|
| `ingest TEXT` / `file PATH` | Process text or a UTF-8 file, replacing the current version |
| `read` | Show the document, normalized text, version and classification |
| `auth TOKEN` | Select a local fixture identity |
| `approve` / `purge` | Issue an administrator grant / delete its exact target version |
| `tamper TEXT` | Demonstrate rejection of an altered signed event |
| `telemetry` | Read detailed traces and audit records as administrator or investigator |
| `audit` | Verify the audit chain |
| `budget` | Show ingest accounting and reset the quota bucket |
| `help` / `quit` | Show commands / exit |

The workflow stores one document (`public/item`), accepts at most 128 characters and normalizes whitespace. At least 10 words produces the label `long`; otherwise it is `short`. Sessions start as `user-token`; `admin-token` and `investigator-token` select the other fixture roles. Each bucket admits at most 20 ingest attempts; quotas reset with `budget` or restart.

State is temporary unless `--state` is supplied:

```bash
# Keep state while using the interactive document workflow (choose 1)
PYTHONPATH=src python3 -m ssrsf --state /tmp/my-srsf

# Process a file directly using the same persistent state
PYTHONPATH=src python3 -m ssrsf --file /path/to/input.txt --state /tmp/my-srsf
```

## Use it from Python

Install the package or run with `PYTHONPATH=src`:

```python
from pathlib import Path
from ssrsf.workflow import ReferenceApp

app = ReferenceApp(Path("/tmp/my-srsf-app"))
document = app.ingest("user-token", "A bounded local text document")
targets = [(document["id"], document["version"])]
grant = app.approve("admin-token", targets)
app.purge("admin-token", targets, grant)
assert app.audit.verify()
```

| Component | Responsibility |
|---|---|
| [workflow.py](src/ssrsf/workflow.py) | Compose the pipeline, ownership checks, telemetry and quota |
| [controls.py](src/ssrsf/controls.py) | Validate schemas and HMAC integrity; verify artifact hashes |
| [audit.py](src/ssrsf/audit.py) | Commit audit records and capture invocation/scratch-state evidence |
| [broker.py](src/ssrsf/broker.py) | Store versioned documents and enforce single-use purge grants |
| [policy.py](src/ssrsf/policy.py) | Enforce exact rules and hold permission expansions for review |
| [state.py](src/ssrsf/state.py) | Persist trusted keys and artifact inventory |

Keys, documents and accepted policy history persist in the state directory. Startup verifies audit integrity and refuses existing databases with missing keys. An exit-audit failure can leave a committed operation with an evidence gap; the broker supports read-only reconciliation.

The application controls live directly in `src/ssrsf/`; controlled threat fixtures and worker processes live in [`experiments/`](src/ssrsf/experiments/). [`evaluation.py`](src/ssrsf/evaluation.py) runs them, [`evidence.py`](src/ssrsf/evidence.py) defines the source inventory, and `scripts/` validates retained results.

## Experiments and results

Choose **2. Guided experiments** in the startup menu, or open the prompts directly. Options supplied to `evaluate` become defaults that you can accept or change:

```bash
PYTHONPATH=src python3 -m ssrsf evaluate
PYTHONPATH=src python3 -m ssrsf evaluate --experiment persistence --trials 20 --output results-persistence
```

Press Enter to accept each default. Invalid answers are retried; Ctrl+C or end of input cancels before evaluation starts. `ssrsf interactive` also opens guided experiments.

For scripts and CI, add `--non-interactive` to run all seven experiments or a selected subset without prompts:

```bash
PYTHONPATH=src python3 -m ssrsf evaluate --non-interactive --trials 30 --seed 42 --output results
PYTHONPATH=src python3 -m ssrsf evaluate --non-interactive --experiment persistence --trials 20 --output results-persistence
```

Guided evaluation prompts for experiments, trials (2–200), seed, modeled invocation price and output folder. Defaults are all experiments, 30 trials, seed 42, price `0.000001` and `results/`. Existing report files in the chosen folder are replaced after the final prompt. Use `evaluate --help` for options. Explicit `--text` and `--file` commands process a document directly.

| Experiment | What it examines | Article reference |
|---|---|---|
| Events | Validated, authenticated events versus unchecked input | Section 6, pp. 8–9 |
| Authorization | Per-function capabilities versus gateway-only checks | Section 6, pp. 8–9 |
| Dependencies | Hash inventories rejecting changed or unlisted files | Section 6, p. 9 |
| Persistence | Scratch marker survival with reuse, monitoring or fresh workspaces | Section 6, pp. 10–11; reuse p. 8 |
| Side channels | Role inference with exposed versus uniform traces and work schedules | Section 6, pp. 9–10, Figure 2 |
| Rollouts | Revoked access through stale replicas, with and without a current-policy gate | Section 6, p. 10 |
| Billing | Uncontrolled dispatch, alerts, quotas and authorization before dispatch | Section 6, p. 11 |

Read the [measured report](results/report.md) for findings and limitations. [results.json](results/results.json) contains observations, configuration, host details and source hashes; [metrics.csv](results/metrics.csv) contains aggregates. The [methodology](research/methodology.md) includes protocols and the [workflow-to-paper mapping](research/methodology.md#document-workflow-mapped-to-the-paper); [article.json](research/article.json) records the source PDF’s identity.

The paper is a review; the event schema, HMAC, artifact inventory, audit chain, approval protocol and quota settings are this project’s engineering choices. HMAC provides shared-key integrity, not replay protection. Artifact hashes detect changes, not dependency vulnerabilities.

Every experiment includes a protected variant alongside its vulnerable comparison. Side channels use uniform public traces and the same work schedule for both roles; timing inference is measured, not assumed eliminated. Rollouts check the current reader policy on every invocation, including calls to stale replicas. Billing's `authenticated-quota` variant verifies credentials and exact invoke permission before metered dispatch, then applies the 20-call bucket cap. Forged, revoked and read-only fixture credentials are rejected even at low rates; valid invoke credentials can still be abused.

Rates and descriptive 95% Wilson intervals apply to constructed fixtures. Side-channel delays and stale replicas are deliberately configured. Billing uses synthetic time buckets and arbitrary cost units: alerts do not reject work, quotas can reject legitimate bursts, and low-rate attacks can pass both without the authorization gate. Rejection does not eliminate authentication or infrastructure costs. These results do not establish real-world attack prevalence, provider behavior or cloud costs.

## Implementing on serverless platforms

AWS is optional. A cloud port needs authenticated Python execution, durable transactional storage, protected keys and restricted audit access. The following are proposed implementation paths, not tested deployments.

Start with one function for ingest → extract → classify. Expose ingest, read, approve, purge and telemetry through authenticated endpoints. Separate approval issuance and purge into distinct identities when independent enforcement is needed. The local administrator currently both obtains approval and executes deletion; a second human approver would require an additional workflow.

| Responsibility | AWS | Google Cloud | Azure |
|---|---|---|---|
| Python execution | Lambda | Cloud Run functions | Azure Functions |
| API and identity | API Gateway + Cognito | Optional API Gateway; IAM/ID tokens for service calls, verified user JWTs for users | HTTP triggers / API Management + Entra ID |
| Durable state | DynamoDB | Firestore | Cosmos DB for NoSQL |
| Keys and secrets | Secrets Manager / KMS | Secret Manager / Cloud KMS | Key Vault |
| Operational telemetry | CloudWatch | Cloud Logging / Monitoring | Application Insights / Azure Monitor |
| Deployment definition | SAM / CloudFormation | Terraform + function deployment pipeline | Bicep / Terraform |

### Changes required on every platform

`ReferenceApp` constructs local SQLite stores, fixture credentials and filesystem state directly. Introduce injectable adapters for identity, storage, audit, policy, quota and key access before adding cloud handlers.

- **Identity:** map verified subjects to owners and roles; authorize internal and direct invocations as well as API requests. Give processor, approval and purge identities only their required permissions. A shared HMAC key lets every holder sign grants; separate signing and verification authority where independence is required.
- **Transactions and retries:** atomically check the document version and unused grant, consume the nonce/operation, delete the target and record the outcome. Check expiry during execution. Use stable operation IDs and durable reconciliation so retries do not repeat deletion.
- **Audit:** acknowledge a durable entry before protected work. Commit an outcome and pending audit event with the mutation where possible, then deliver through a retryable outbox. Operational logs alone do not reproduce the authenticated audit chain; distributed integrity needs concurrency control and protected checkpoints.
- **Shared state:** persist policy versions and transactional quota counters across instances. Define quota windows, restricted resets and revocation behavior. Local locks and counters cannot coordinate a deployment.
- **Artifacts and scratch:** provision trusted keys/manifests outside temporary storage, verify deployed artifacts and clean per-invocation scratch. Keep the initial text-only scope while validating the port.

### AWS Lambda implementation path

1. Define routes and Lambda handlers using [AWS SAM](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/). Validate user JWTs, enforce ownership/roles in handlers and restrict direct invocation through IAM.
2. Replace SQLite with DynamoDB adapters. Use [DynamoDB transactions](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transactions.html) to condition deletion on the expected version and atomically create replay markers, outcome and audit-outbox records.
3. Provision secrets/key permissions, separate execution roles, shared counters and durable policy. Deploy a test stack and verify concurrent requests and recovery.

[Lambda environments can be reused](https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtime-environment.html), so `/tmp` cannot hold authoritative state. [Budget notifications can be delayed](https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-managing-costs.html); enforce admission quotas in the request path.

### Google Cloud Run functions implementation path

1. Add Python HTTP handlers and [authenticated backend invocation](https://docs.cloud.google.com/functions/docs/securing/authenticating). Use dedicated service accounts and explicitly validate end-user identity, including when a gateway calls the backend.
2. Replace SQLite with Firestore adapters. In one purge transaction, read versions/replay state and write grant consumption, deletion, outcome and the audit outbox. [Firestore may rerun transaction callbacks](https://firebase.google.com/docs/firestore/manage-data/transactions), so keep external side effects outside them.
3. Configure [Secret Manager access](https://docs.cloud.google.com/run/docs/configuring/services/secrets), restricted telemetry, shared quotas and policy; deploy and verify. Enforce ownership in backend code rather than assuming client-facing Firestore Security Rules protect server SDK access.

### Azure Functions implementation path

1. Add HTTP-triggered handlers with [Entra authentication and application authorization](https://learn.microsoft.com/en-us/azure/azure-functions/security-concepts). Use [managed identities](https://learn.microsoft.com/en-us/azure/azure-functions/manage-connections) and separate Function Apps where identity isolation is needed; function keys alone do not identify document owners.
2. Replace SQLite with Cosmos DB adapters. For the [transactional-batch path](https://learn.microsoft.com/en-us/azure/cosmos-db/transactional-batch), put documents, replay markers, outcomes and audit-outbox records in one logical partition. Use conditional version/ETag checks and create-only replay markers. Restrict grants to that partition or redesign storage before supporting cross-partition purge.
3. Provision Key Vault permissions, shared counters, durable policy and audit delivery. Deploy with Bicep or Terraform and verify transaction/recovery behavior using SDK-based adapters.

### Verify the cloud port

Test wrong owners, invalid credentials, tampered events, expired/replaced grants and concurrent replay. Inject audit failures, retry committed operations, scale across instances and confirm shared quotas and policy revocation. Ordinary users must not access detailed telemetry or reset limits.

Record cloud observations separately from `results/`. Port the experiments to actual invocation paths, identities, artifacts and rollouts; observe rather than assume instance reuse. Measure timing under a declared observer model and distinguish synthetic billing from actual charges. Local results do not transfer automatically to a cloud deployment.

For another platform, use the same adapter boundaries and verify its runtime, transaction and identity semantics. A runtime without Python support needs a compatible container service or a rewrite. Budget alerts and concurrency controls do not guarantee a hard cap on all cloud charges.

## Tests and evidence verification

Run the existing tests:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

The retained evidence hashes source, tests and documentation. After changing tracked evidence inputs, regenerate the bundle, record tests and verify it:

```bash
PYTHONPATH=src python3 -m ssrsf evaluate --non-interactive --trials 30 --seed 42 --output results
python3 scripts/validate.py --python python3
python3 scripts/check_evidence.py
```

Repeat `--python` to validate additional installed interpreters. `results/validation.json` binds test logs to source/results; `results/SHA256SUMS` binds the evidence files. Same-host checks are not independent replication.

## Limits

This is an offline reference implementation. Python roles, SQLite and the filesystem owner share a local trust boundary. Subprocess workspaces are not hostile-code sandboxes, replica objects are not distributed nodes, and markers/artifacts are inert. Existing ignored `.ssrsf/` data is preserved and unused.

Cloud IAM enforcement, container escapes, adversarial co-location, CPU/cache channels, provider scheduling, real billing and distributed rollout safety remain outside the local evidence. Reliability measurements cover fixture completion and timing; production availability SLOs, error budgets and incident recovery are not evaluated.
