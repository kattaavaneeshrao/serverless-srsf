# Serverless SRSF: A Site Reliability and Security Framework

Serverless SRSF provides one interactive menu for an isolated document workflow and seven local security experiments. It implements selected recommendations from [Marin, Perino and Di Pietro’s “Serverless computing: a security perspective” (2022)](https://doi.org/10.1186/s13677-022-00347-w).

The implementation includes:

- **A reusable application:** ingest → extract → classify, guarded by event validation, ownership checks, artifact integrity, audit logging, approved deletion, policy enforcement and invocation quotas.
- **Seven supporting experiments:** controlled comparisons and threat demonstrations covering events, authorization, dependencies, persistence, side channels, rollouts and billing.
- **A container workflow prototype:** separate stage workers, an authenticated guard and a transactional workflow controller in Docker Compose.

The original application and experiments run locally with Python 3.11+ and the standard library. A separate [container workflow prototype](#container-workflow-prototype) adds isolated workers, a mandatory guard and a durable controller using Docker Compose. The delivered deployment uses Docker Compose on one host; cloud adapters and infrastructure are not included. The seven experiments measure individual behaviors, not the integrated framework’s end-to-end effectiveness or the container prototype.

## Quick start

From the repository root:

```bash
PYTHONPATH=src python3 -m ssrsf
```

After `python3 -m pip install -e .`, `ssrsf` opens the same menu:

```text
1. Document workflow
2. Experiments
3. Quit
```

- **1 — Document workflow:** automatically initializes missing credentials and starts or reuses the Docker Compose services, then opens the document controls. Have Docker Desktop/Engine running first.
- **2 — Experiments:** prompts for which of the seven experiments to run, trials, seed, modeled price and output folder. This mode needs Python only and does not start Docker.
- **3 — Quit:** exits the application. Already running containers remain available until stopped from the document controls.

Both activities return to this main menu when finished. Press Enter to select Document workflow. A Docker startup failure returns to the menu so Experiments remains available. Ctrl+C cancels the current activity; end of input exits. Use `results-demo` as the experiment output folder to preserve the retained `results/` bundle.

## Container workflow prototype

Requirements: Python 3.11+, Docker Engine/Desktop running Linux containers, and Docker Compose v2+. No Python packages beyond the standard library are needed. Run from the repository root:

```bash
PYTHONPATH=src python3 -m ssrsf
```

Start Docker Desktop and choose **1 — Document workflow** from the main menu. The application prepares services automatically; then choose **2** or press Enter in the document controls to type your text. The document submenu also provides a Start services action for restarting after an explicit stop. The client runs on your host and sends requests through the guard; entering text does not require rebuilding containers.

| Choice | Action | Input or result |
|---|---|---|
| **1** | Start services | Creates missing credentials and runs Compose; preserves existing credentials/state |
| **2** or **Enter** | Enter document text | Type 1–128 characters; see workflow ID, state, classification and processed text |
| **3** | Process a UTF-8 text file | Enter its path; reads at most 129 characters to detect oversized input |
| **4** | Check workflow status | Enter an ID, or press Enter to use your last submission |
| **5** | Retry last submission | Reuses its exact workflow ID and text |
| **6** | Run security checks | Executes the existing API and worker-boundary checks |
| **7** | Run a load test | Enter 1–20 workflows; Enter selects 5 |
| **8** | Stop services | Stops containers while preserving stored workflows and credentials |
| **0** | Back to main menu | Returns to the Document / Experiments menu; leaves services running |

For example, choose **2** and type `My   document about interactive serverless security`. A completed result shows:

```text
Workflow: <generated workflow ID>
State: complete
Classification: short
Processed text: My document about interactive serverless security
```

Whitespace is normalized. At least ten words produces `long`; fewer produces `short`. Inputs are bounded UTF-8 text, not PDF, Word or arbitrary file uploads. File newlines count toward the input limit. Empty or oversized input is rejected before submission.

Ctrl+C cancels the current action and returns to the menu; it does not roll back an already submitted workflow. Check status or retry to resolve its result. End of input exits the session. The last-submission shortcut lasts only for the current console session, so retain the printed ID to check a workflow after reopening. When services are unavailable, the menu reports the failure and remains available for startup or retry. Starting services still requires a running Docker engine and access to the image registry on the first build.

`python3 scripts/prototype.py` and its `interactive` alias also open the unified main menu for compatibility. Existing scripted commands remain available:

```bash
python3 scripts/prototype.py init
docker compose up --build -d --wait
python3 scripts/prototype.py submit "My document about serverless security"
python3 scripts/prototype.py status WORKFLOW_ID
python3 scripts/prototype.py check
python3 scripts/prototype.py load --requests 5
```

`submit` prints a workflow ID before dispatch. Use `submit --id ID "same text"` to retry a submission, or `status ID` to retrieve its state. The guard listens only on `127.0.0.1:8080`; the controller and workers expose no host ports. Stop the stack with `docker compose down`; its named state volume and credentials are preserved.

| Service | Authority and storage |
|---|---|
| Ingest worker | Claim and complete the ingest stage; only its own credential |
| Extract worker | Normalize whitespace; claim and complete only extraction |
| Classify worker | Label text `short`/`long` using the original ten-word threshold |
| Guard | Authenticate client/worker identities and forward permitted operations |
| Controller | Own SQLite state, enforce transitions and atomically record audit/outcomes |

The three workers each occupy a separate internal network shared only with the guard. The controller occupies another internal network shared only with the guard. Only the guard also joins an edge network for the loopback-published client endpoint. Workers have no database volume, controller credential, audit key, Docker socket or elevated capabilities. Containers run as an unprivileged user with read-only root filesystems and memory/CPU/process limits. Storage lives in SQLite behind the single controller, rather than a separate database server.

Each workflow has an immutable document version and follows `ingest → extract → classify → complete`. The controller issues opaque, 30-second task grants bound to workflow, version, stage and input hash. Claim and completion are transactional. Conflicting, expired, cross-workflow and out-of-order completions are rejected; identical completed requests return their retained outcome, even after restart. An unfinished task becomes claimable after lease expiry. Workers retry completion after a lost response. Multiple workflow IDs have independent state.

Submission IDs are idempotent: reusing an ID with different text fails. A persistent quota admits 20 new workflows per client per fixed 60-second window; retries of the same submission do not consume additional quota. Tests and load commands share this limit. If exhausted, wait until the next minute boundary. This is admission control, not a cap on every resource cost.

Transitions, completion outcomes and authenticated audit records commit in the same SQLite transaction. Audit failure rolls back the transition; startup verifies the chain. The chain has no external checkpoint, so privileged removal of its valid tail remains outside the guarantee. Credentials are generated once in ignored `.prototype/secrets/`; host directories are mode `0700`, individual mounted files are readable by non-root containers. Do not delete or regenerate credentials while retaining state. Compose secrets here are local file mounts, not encrypted secret storage.

`check` runs a real document, duplicate submission and forbidden API requests. It probes each running worker for absent storage/other credentials and denied direct TCP connections to the controller (by name and IP), a sibling and an external IP. `load` runs up to four concurrent clients and reports completion counts and observed latency. Transactional replay, grant substitution, concurrent completion, quota persistence, audit failure and lease recovery are also covered by `tests/test_prototype.py` using temporary databases and real loopback HTTP servers. These tests need permission to open local sockets.

This is a single-host workflow-security prototype with one fixture client identity and one identity per worker stage. A compromised worker can submit incorrect but schema-valid output for its assigned stage, consume tasks for that stage, or withhold completion; workflow order does not establish semantic correctness or availability. The guard, controller, Docker daemon, host and provisioned identities are trusted. HTTP credentials travel in plaintext on the private testbed networks. Direct TCP egress probes do not establish protection against every DNS/covert channel. The prototype does not provide syscall interception, TLS interception, distributed consensus or cloud/runtime isolation results. The original document approval/purge commands remain in the local application and are not container API endpoints.

Implementation: [`client.py`](src/ssrsf/prototype/client.py) supplies the host interface; [`src/ssrsf/prototype/`](src/ssrsf/prototype/), [`compose.yaml`](compose.yaml), [`scripts/prototype.py`](scripts/prototype.py). The existing seven-experiment reports remain scoped to their original fixtures; Compose verification is separate.

## Reference implementation for tests and comparison

The original in-process `ReferenceApp` remains available for tests and comparison. It is not a third main-menu mode and does not use the container store. These explicit reference commands bypass the main menu:

```bash
# Open the original local reference console
PYTHONPATH=src python3 -m ssrsf --local

# Process text with the local reference implementation
PYTHONPATH=src python3 -m ssrsf --text "My document about serverless security"

# Keep local reference state across runs
PYTHONPATH=src python3 -m ssrsf --local --state /tmp/my-srsf
```

The reference console retains ownership, tampering, audit, approval and purge demonstrations. These operations are not automatically added to the Docker document API.

## Reference control demonstration

Open the reference console with `PYTHONPATH=src python3 -m ssrsf --local`, then enter:

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
# Keep state while using the local reference console
PYTHONPATH=src python3 -m ssrsf --local --state /tmp/my-srsf

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

Choose **2. Experiments** in the startup menu, or open the prompts directly. Options supplied to `evaluate` become defaults that you can accept or change:

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

Guided evaluation prompts for experiments, trials (2–200), seed, modeled invocation price and output folder. Defaults are all experiments, 30 trials, seed 42, price `0.000001` and `results/`. Existing report files in the chosen folder are replaced after the final prompt. Use `evaluate --help` for options. Explicit `--text` and `--file` commands process a document through the local reference implementation.

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

<a id="implementing-on-serverless-platforms"></a>

## Architecture and deployment scope

The container prototype follows Kalium's separation of application code from enforcement: workers request operations through a trusted guard and controller. [Kalium](https://www.usenix.org/conference/usenixsecurity23/presentation/jegan) additionally enforces local/global communication graphs inside a modified gVisor runtime. Our prototype implements a fixed service-level stage graph and durable task grants. It does not reproduce Kalium's syscall or TLS interception, and we have no comparative performance result.

| Property | Local `ReferenceApp` | Container prototype |
|---|---|---|
| Execution | One Python processing boundary | Three workers, guard and controller |
| State | One document slot; optional local state directory | Multiple workflow IDs; controller-only SQLite volume |
| Input integrity | Schema and shared-key event HMAC | Authenticated service calls and controller-bound input hashes |
| Retry protection | Single-use version-bound purge grants | Idempotent submission/completion and expiring stage grants |
| Audit | Entry/exit records; exit failure can follow committed effects | Transition, outcome and audit commit in one transaction |
| Quota | 20 ingest attempts; manual/restart reset | 20 new workflows per client per fixed minute; persisted |
| Approval/purge | Implemented local operations | No approval/purge API |

The required stack is Python, Docker with Linux containers and Compose. SQLite is part of Python, and HTTP uses the standard library. No AWS account, Kubernetes cluster, gVisor installation or separate database server is required. Host and Docker administration remain trusted. The container prototype is not a cloud deployment or a replacement for every local application feature.

## Verified prototype behavior

The recorded Python validation contains **95 passing tests**, including ten controller/HTTP tests and ten interactive-client tests. Main-menu tests also cover automatic startup, return navigation, Docker failures and switching between document processing and experiments. Separate live Compose checks confirmed:

- A complete ingest/extract/classify workflow and idempotent submission.
- Interactive typed input, normalized output, status lookup and retry with the same workflow ID.
- Rejection of forged credentials, forbidden roles and conflicting submissions.
- All three workers lacked database access and other services' mounted credentials.
- Worker TCP probes to the controller by name and IP, a sibling and a selected external IP failed.
- Five submitted workflows completed under a smoke load of up to four concurrent clients. The observed median was approximately **1.176 seconds** for that run.
- A completed workflow kept its version, text and classification after a controller restart.

These single-host observations are separate from the seven-experiment bundle. They are not a scalability study, a general egress guarantee or a comparison with Kalium. Run `check` and `load` to repeat the live checks; quota usage and host scheduling can affect results. CI includes a separate `container-prototype` job for these commands.

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

The original application is an offline reference implementation: its Python roles, SQLite and filesystem owner share a local trust boundary. The separate container prototype places workers behind a guard/controller boundary under a trusted Docker host. Subprocess workspaces are not hostile-code sandboxes, replica objects are not distributed nodes, and markers/artifacts are inert. Existing ignored `.ssrsf/` data is preserved and unused.

Cloud IAM enforcement, container escapes, adversarial co-location, CPU/cache channels, provider scheduling, real billing and distributed rollout safety remain outside the local evidence. The seven experiments measure fixture completion and timing; prototype tests additionally exercise lease recovery, transaction rollback and restart persistence. Production availability SLOs, error budgets and multi-host incident recovery are not evaluated.
