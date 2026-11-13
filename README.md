# Serverless SRSF: A Site Reliability and Security Framework

Serverless SRSF provides one interactive menu for an isolated document workflow and seven local control benchmarks. It implements selected recommendations from [Marin, Perino and Di Pietro’s “Serverless computing: a security perspective” (2022)](https://doi.org/10.1186/s13677-022-00347-w).

The implementation includes:

- **Seven supporting control benchmarks:** controlled comparisons and threat demonstrations covering events, authorization, dependencies, persistence, side channels, rollouts and billing.
- **The Docker reference app:** separate stage workers, an authenticated guard and a transactional workflow controller in Docker Compose.

The control benchmarks run locally with Python 3.11+ and the standard library. The [document workflow](#docker-reference-app) uses isolated workers, a mandatory guard and a durable controller in Docker Compose. The delivered deployment uses Docker Compose on one host; cloud adapters and infrastructure are not included. The seven control benchmarks measure individual behaviors, not the integrated framework’s end-to-end effectiveness or the reference app.

## Quick start

From the repository root:

```bash
PYTHONPATH=src python3 -m ssrsf
```

After `python3 -m pip install -e .`, `ssrsf` opens the same menu:

```text
1. Document workflow
2. Control benchmarks
3. Quit
```

- **1 — Document workflow:** automatically initializes missing credentials and starts or reuses the Docker Compose services, then opens the document controls. Have Docker Desktop/Engine running first.
- **2 — Control benchmarks:** prompts for which of the seven control benchmarks to run, trials, seed, modeled price and output folder. This mode needs Python only and does not start Docker.
- **3 — Quit:** exits the application. Already running containers remain available until stopped with `docker compose down`.

Both activities return to this main menu when finished. Press Enter to select Document workflow. A Docker startup failure returns to the menu so Control benchmarks remains available. Ctrl+C cancels the current activity; end of input exits. Use `results-demo` as the control benchmark output folder to preserve the retained `results/` bundle.

## Docker workflow: step by step

### Step 1: start the application

With Python 3.11+ installed and Docker Desktop running, run from the repository root:

```bash
PYTHONPATH=src python3 -m ssrsf
```

Choose **1 — Document workflow** at the main menu. Services start automatically; healthy services are reused.

### Step 2: submit a document and see the result

At the document menu, choose **1** or press Enter:

```text
Choose [1]: 1
Document text: My   document about serverless security
```

The workflow runs ingest → extract → classify and displays:

```text
Workflow: <generated workflow ID>
State: complete
Classification: short
Processed text: My document about serverless security
```

Input accepts 1–128 characters. Whitespace is normalized; ten or more words produces `long`, otherwise `short`.

To process a file instead, choose **2** and enter the path to a UTF-8 text file containing 1–128 characters.

### Step 3: check a previous result

Choose **3**, then press Enter for the most recent submission or paste a saved workflow ID:

```text
Choose [1]: 3
Workflow ID [last submission]:
```

### Step 4: return to the main menu

Choose **0**. From the main menu, choose **2** for control benchmarks or **3** to quit. Services keep running. To stop them, run `docker compose down` in a terminal; stored workflows and credentials are preserved.

## Docker reference app

Requirements: Python 3.11+, Docker Engine/Desktop running Linux containers, and Docker Compose v2+. No Python packages beyond the standard library are needed. Run from the repository root:

```bash
PYTHONPATH=src python3 -m ssrsf
```

Start Docker Desktop and choose **1 — Document workflow** from the main menu. The application prepares services automatically. The host client sends documents through the guard; entering text does not require rebuilding containers.

| Choice | Action | Input or result |
|---|---|---|
| **1** or **Enter** | Enter document text | Type 1–128 characters; see the workflow ID, state, classification and processed text |
| **2** | Process a UTF-8 text file | Enter its path; oversized files (>128 chars) are rejected before submission |
| **3** | Check workflow status | Enter an ID, or press Enter to use your last submission |
| **4** | Switch identity | Switch between `client`, `admin`, `client2`, and `investigator` |
| **5** | Verify audit log | Cryptographically verify the SHA-256 HMAC audit log hash chain |
| **6** | Check quota and security | Inspect remaining quota budget (20 req/min) and run container isolation checks |
| **0** | Back to main menu | Returns to the Document / Control benchmarks menu |

Inputs are UTF-8 text, including newlines, with a 128-character limit. Empty or oversized input is rejected before submission. PDF and Word files are not accepted.

Ctrl+C cancels the current action; admitted workflows can still finish. Check status using the printed workflow ID to resolve an uncertain outcome. The last-submission shortcut lasts for the current document session, so save the ID to retrieve it later. End of input exits the session. Starting services requires a running Docker engine and access to the image registry on the first build.

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

Submission IDs are idempotent: reusing an ID with different text fails. A persistent quota admits 20 submissions/replacements per client per fixed 60-second window; retries of the same submission do not consume additional quota. Tests and load commands share this limit. If exhausted, wait until the next minute boundary. This is admission control, not a cap on every resource cost.

Transitions, completion outcomes and authenticated audit records commit in the same SQLite transaction. Audit failure rolls back the transition; startup verifies the chain. To detect removal of a previously observed valid audit tail, retain the receipt returned by `reference audit` independently and verify it with `--receipt`. Credentials are generated once in ignored `.prototype/secrets/`; host directories are mode `0700`, individual mounted files are readable by non-root containers. Do not delete or regenerate credentials while retaining state. Compose secrets here are local file mounts, not encrypted secret storage.

`check` runs a real document, duplicate submission and forbidden API requests. It probes each running worker for absent storage/other credentials and denied direct TCP connections to the controller (by name and IP), a sibling and an external IP. `load` runs up to four concurrent clients and reports completion counts and observed latency. Transactional replay, grant substitution, concurrent completion, quota persistence, audit failure and lease recovery are also covered by `tests/test_prototype.py` using temporary databases and real loopback HTTP servers. These tests need permission to open local sockets.

This is a single-host reference application with client and administrator roles and one identity per worker stage. A compromised worker can submit incorrect but schema-valid output for its assigned stage, consume tasks for that stage, or withhold completion; workflow order does not establish semantic correctness or availability. The guard, controller, Docker daemon, host and provisioned identities are trusted. Private-network HTTP is authenticated and signed but unencrypted. Direct TCP egress probes do not establish protection against every DNS/covert channel. The reference app does not provide syscall interception, TLS interception, distributed consensus or cloud/runtime isolation results. The reference app also enforces ownership, signed requests, rate-limiting quotas and cryptographic audit verification; see the [reference-app guide](docs/reference-app.md).

Implementation: [`client.py`](src/ssrsf/prototype/client.py) supplies the host interface; [`src/ssrsf/prototype/`](src/ssrsf/prototype/), [`compose.yaml`](compose.yaml), [`scripts/prototype.py`](scripts/prototype.py). The existing seven-benchmark reports remain scoped to their original fixtures; Compose verification is separate.

Python callers can also import `ReferenceApp` from `ssrsf.reference` to interact programmatically with the running Docker stack:

```python
from ssrsf.reference import ReferenceApp

app = ReferenceApp()
result = app.ingest("My document about serverless security")
status = app.read(result["id"])
audit = app.audit()
```

See the [reference-app guide](docs/reference-app.md) for identities, quota controls, and the Python API. After updating the source, run `python3 scripts/prototype.py init` and `docker compose up --build -d --wait` once to rebuild services and provision missing role credentials; existing state and credentials are preserved.

## Control benchmarks: step by step

After document step 4, continue from the same main menu. Control benchmarks use their own constructed fixtures and can run with Docker stopped. This sequence runs all seven groups into `results-demo`, preserving the retained `results/` bundle.

### Step 1: activity selection

**From the main menu after the Docker demonstration**

```text
Choose an activity [1]: 2
```

**Selected output**

```text
Serverless SRSF - guided evaluation
```

- This activity runs the seven built-in Python control benchmarks. Docker may be stopped for this part.

- Each control benchmark supplies its own paired fixtures. Your document from the Docker demonstration is not its input.

- If starting a fresh terminal, run `PYTHONPATH=src python3 -m ssrsf`, then choose 2.

### Step 2: group selection

| Number | Group |
| --- | --- |
| 1 / 2 / 3 | Events / authorization / dependencies |
| 4 / 5 | Persistence / side channels |
| 6 / 7 | Rollouts / billing |

- At the benchmark-selection prompt, enter `all` for the complete seven-group demonstration.

- A subset such as `1,4,7` or `events,persistence,billing` runs only those groups.

- The runner rejects unknown or duplicate selections and prompts again.

### Step 3: trials and seed

**Inputs after selecting `all`**

```text
Trials per case (2-200) [30]: 30
Random seed (0-4294967295) [42]: 42
```

- Trials control repetitions per fixture case. Valid values are 2–200; 30 matches the retained evaluation configuration.

- The seed fixes generated inputs and ordering. It does not fix execution time or timing-inference accuracy.

- Enter accepts each displayed default. Invalid numbers produce another prompt.

### Step 4: modeled price and output

| Prompt | Example input | Effect |
| --- | --- | --- |
| Modeled invocation cost | `0.000001` | Sets arbitrary cost units per accepted billing-fixture invocation |
| Output folder | `results-demo` | Stores this demonstration's reports separately from retained evidence |

- At the cost prompt, press Enter to accept its equivalent default, `1e-06`, or type the example value.

- Type `results-demo` at the output prompt. Existing report files in the selected folder are replaced.

- The run begins after the final output-folder answer. Ctrl+C or end of input during configuration cancels before it begins.

### Step 5: execution and completion

**Selected output for the complete demonstration**

```text
Running 7 control benchmarks with 30 trials per case...
Completed 7 local control benchmarks. Report: results-demo/report.md
```

- The runner executes the selected vulnerable and protected variants against controlled fixtures.

- It measures attack-fixture outcomes and legitimate completion separately. Billing uses synthetic time and modeled cost.

- Completion writes the report bundle and returns to the main menu. These outcomes do not establish cloud-wide protection.

### Step 6: result inspection

**In a second terminal, from the same repository root**

```bash
cat results-demo/report.md
```

| File | What it contains |
| --- | --- |
| `report.md` | Findings, comparison tables and control benchmark limits |
| `metrics.csv` | Aggregate rates, latency and descriptive intervals |
| `results.json` | Observations, configuration, host details and source hashes |
| `SHA256SUMS` | Checksums for the generated report files |

This demonstration does not automatically create a new `validation.json`; the canonical validation script separately records the Python test suite.

### Step 7: interpretation and next action

- Compare attack acceptance and legitimate completion for events, permissions and artifacts. For persistence, compare marker survival and lifecycle time.

- For side channels, inspect held-out inference accuracy. For rollouts, inspect revoked-reader admission.

- For billing, compare accepted attack work, legitimate drops and modeled spend. Alerts and admission controls have different effects.

- Back in the application, choose 2 to configure another run, 1 for document work or 3 to quit.

**Document processing, live Docker checks and the seven controlled benchmarks have distinct inputs and evidence.**

## Control benchmarks and results

Choose **2. Control benchmarks** in the startup menu, or open the prompts directly. Options supplied to `evaluate` become defaults that you can accept or change:

```bash
PYTHONPATH=src python3 -m ssrsf evaluate
PYTHONPATH=src python3 -m ssrsf evaluate --benchmark persistence --trials 20 --output results-persistence
```

Press Enter to accept each default. Invalid answers are retried; Ctrl+C or end of input cancels before evaluation starts. `ssrsf interactive` also opens guided control benchmarks.

For scripts and CI, add `--non-interactive` to run all seven control benchmarks or a selected subset without prompts:

```bash
PYTHONPATH=src python3 -m ssrsf evaluate --non-interactive --trials 30 --seed 42 --output results
PYTHONPATH=src python3 -m ssrsf evaluate --non-interactive --benchmark persistence --trials 20 --output results-persistence
```

Guided evaluation prompts for control benchmarks, trials (2–200), seed, modeled invocation price and output folder. Defaults are all control benchmarks, 30 trials, seed 42, price `0.000001` and `results/`. Existing report files in the chosen folder are replaced after the final prompt. Use `evaluate --help` for options.

| Control benchmark | What it examines | Article reference |
|---|---|---|
| Events | Validated, authenticated events versus unchecked input | Section 6, pp. 8–9 |
| Authorization | Per-function capabilities versus gateway-only checks | Section 6, pp. 8–9 |
| Dependencies | Hash inventories rejecting changed or unlisted files | Section 6, p. 9 |
| Persistence | Scratch marker survival with reuse, monitoring or fresh workspaces | Section 6, pp. 10–11; reuse p. 8 |
| Side channels | Role inference with exposed versus uniform traces and work schedules | Section 6, pp. 9–10, Figure 2 |
| Rollouts | Revoked access through stale replicas, with and without a current-policy gate | Section 6, p. 10 |
| Billing | Uncontrolled dispatch, alerts, quotas and authorization before dispatch | Section 6, p. 11 |

Read the [measured report](results/report.md) for findings and limitations. [results.json](results/results.json) contains observations, configuration, host details and source hashes; [metrics.csv](results/metrics.csv) contains aggregates. The [methodology](research/methodology.md) includes protocols and the [workflow-to-paper mapping](research/methodology.md#document-workflow-mapped-to-the-paper); [article.json](research/article.json) records the source PDF’s identity.

The paper is a review; the event schema, HMAC, artifact inventory, audit chain and quota settings are this project’s engineering choices. HMAC provides shared-key integrity, not replay protection. Artifact hashes detect changes, not dependency vulnerabilities.

Every control benchmark includes a protected variant alongside its vulnerable comparison. Side channels use uniform public traces and the same work schedule for both roles; timing inference is measured, not assumed eliminated. Rollouts check the current reader policy on every invocation, including calls to stale replicas. Billing's `authenticated-quota` variant verifies credentials and exact invoke permission before metered dispatch, then applies the 20-call bucket cap. Forged, revoked and read-only fixture credentials are rejected even at low rates; valid invoke credentials can still be abused.

Rates and descriptive 95% Wilson intervals apply to constructed fixtures. Side-channel delays and stale replicas are deliberately configured. Billing uses synthetic time buckets and arbitrary cost units: alerts do not reject work, quotas can reject legitimate bursts, and low-rate attacks can pass both without the authorization gate. Rejection does not eliminate authentication or infrastructure costs. These results do not establish real-world attack prevalence, provider behavior or cloud costs.

<a id="implementing-on-serverless-platforms"></a>

## Architecture and deployment scope

The reference app separates processing from enforcement: workers request operations through a trusted guard and controller. The controller enforces a fixed document-stage graph, issues durable task grants and records transitions with their outcomes and audit evidence. The implemented boundary is service-level workflow enforcement; syscall and TLS interception are outside the evaluated scope.

| Property | Container workflow |
|---|---|
| Execution | Three workers, guard and controller |
| State | Multiple workflow IDs; controller-only SQLite volume |
| Input integrity | Path-bound request HMAC, source inventory and controller-bound input hashes |
| Retry protection | Idempotent submission/completion and expiring stage grants |
| Audit | Transition, outcome and audit commit in one transaction |
| Quota | 20 submissions/replacements per client per fixed minute; persisted |
| Management | Six-choice interactive menu, identity switching (RBAC) and quota controls |

The required stack is Python, Docker with Linux containers and Compose. SQLite is part of Python, and HTTP uses the standard library. No AWS account, Kubernetes cluster, gVisor installation or separate database server is required. Host and Docker administration remain trusted. The reference app is a single-host deployment; cloud deployment is outside its scope.

## Verified reference-app behavior

The recorded Python validation contains **87 passing tests**, covering controller/HTTP behavior, the complete reference-app menu and restored reference-app controls. Main-menu tests also cover automatic startup, return navigation, Docker failures and switching between document processing and control benchmarks. Separate live Compose checks confirmed:

- A complete ingest/extract/classify workflow and idempotent submission.
- Typed input, normalized output and status lookup; scripted retry with the same workflow ID.
- Rejection of forged credentials, altered signed requests, forbidden roles and conflicting submissions.
- Ownership checks, identity-based access control, cryptographic audit logging and persistent quota enforcement.
- Scratch entry/exit evidence, including a mismatch after an inert marker was added between invocations.
- All three workers lacked database access and other services' mounted credentials.
- Worker TCP probes to the controller by name and IP, a sibling and a selected external IP failed.
- Five submitted workflows completed under a smoke load of up to four concurrent clients. The observed median was approximately **1.482 seconds** for that run.
- A completed workflow and valid audit chain survived a controller restart.

These single-host observations are separate from the seven-benchmark bundle. They are not a scalability study, a general egress guarantee or a comparative performance study. Run `check` and `load` to repeat the live checks; quota usage and host scheduling can affect results. CI includes a separate `container-prototype` job for these commands.

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

The reference app places workers behind a guard/controller boundary under a trusted Docker host. Subprocess workspaces are not hostile-code sandboxes, replica objects are not distributed nodes, and markers/artifacts are inert.

Cloud IAM enforcement, container escapes, adversarial co-location, CPU/cache channels, provider scheduling, real billing and distributed rollout safety remain outside the local evidence. The seven control benchmarks measure fixture completion and timing; reference-app tests additionally exercise lease recovery, transaction rollback and restart persistence. Production availability SLOs, error budgets and multi-host incident recovery are not evaluated.
