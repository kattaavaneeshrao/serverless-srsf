# Serverless SRSF: A Site Reliability and Security Framework

Serverless SRSF is a single-host, containerized reference application for studying workflow enforcement, retries and audit consistency in event-driven applications. It implements selected recommendations from [Marin, Perino and Di Pietro’s security review (2022)](https://doi.org/10.1186/s13677-022-00347-w).

The implementation has two distinct parts:

- **Core workflow:** three document-processing workers call a mandatory guard and durable controller. Task grants bind workflow, document version, stage and input hash. State advancement, retained completion outcomes and authenticated audit records commit together.
- **Supporting control benchmarks:** seven separate fixture-based comparisons cover events, authorization, artifact integrity, persistence, information exposure, stale replicas and modeled billing. Their observations do not measure the integrated application's end-to-end security.

The deployment uses Docker Compose on one trusted host. The benchmarks run independently using Python 3.11+ and the standard library. Managed serverless deployment, distributed failover and production availability are outside the evaluation.

This README covers the protocol, retained results, limitations, operation and reproduction.

The study provides a service-level workflow protocol, a reference implementation with tests for ordering, grant binding, retries, concurrency and recovery, and seven supporting control benchmarks. Its focus is workflow enforcement and evidence consistency. The motivating review supplies threat categories rather than executable benchmarks or numerical reference outcomes; the measurements here come from this project's fixtures.

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
| Classify worker | Label text `long` at ten or more words, otherwise `short` |
| Guard | Authenticate client/worker identities and forward permitted operations |
| Controller | Own SQLite state, enforce transitions and atomically record audit/outcomes |

The three workers each occupy a separate internal network shared only with the guard. The controller occupies another internal network shared only with the guard. Only the guard also joins an edge network for the loopback-published client endpoint. Workers have no database volume, controller credential, audit key, Docker socket or elevated capabilities. Containers run as an unprivileged user with read-only root filesystems and memory/CPU/process limits. Storage lives in SQLite behind the single controller, rather than a separate database server.

Each workflow has an immutable document version and follows `ingest → extract → classify → complete`. The controller issues opaque, 30-second task grants bound to workflow, version, stage and input hash. Claim and completion are transactional. Completion rechecks these bindings, expiry and current stage policy. New completions with conflicting, expired, cross-workflow or out-of-order grants are rejected; identical already-committed requests return their retained outcome, even after restart. An unfinished task becomes claimable after lease expiry. Workers retry completion after a lost response. Multiple workflow IDs have independent state. Replacing a document requires the current version, creates a new version and invalidates its old in-flight grants. Retrying a committed completion does not advance state again; worker computation may still execute more than once after a timeout or lost response.

Stage claims and completions require exact policy permissions: explicit deny wins and omitted permissions deny. Restrictive changes persist and can block an in-flight completion; permission expansions and unknown rules are not installed automatically. These are local consistency contracts under a trusted controller.

Submission IDs are idempotent: reusing an ID with different text fails. A persistent quota admits 20 submissions/replacements per client per fixed 60-second window; retries of the same submission do not consume additional quota. Tests and load commands share this limit. If exhausted, wait until the next minute boundary. This is admission control, not a cap on every resource cost.

Application POST requests verify provisioned credentials and a path-bound HMAC over the canonical JSON body. Exact schemas and input bounds reject malformed requests. The image build establishes a SHA-256 source inventory, checked at service startup and before dispatch; workers also check it before processing and completion. A trusted rebuild establishes a new inventory. These checks detect byte changes; they do not detect dependency vulnerabilities, malicious approved content or changes between verification and use.

Transitions, completion outcomes and authenticated audit records commit in the same SQLite transaction. Audit failure rolls back the transition; startup verifies the chain. To detect removal of a previously observed valid audit tail, retain the receipt returned by `reference audit` independently and verify it with `--receipt`. Credentials are generated once in ignored `.prototype/secrets/`; host directories are mode `0700`, individual mounted files are readable by non-root containers. Do not delete or regenerate credentials while retaining state. Compose secrets here are local file mounts, not encrypted secret storage.

Workers report entry/exit inventories of bounded writable scratch tmpfs mounts. A changed next-entry inventory records mismatch evidence. This is worker-reported evidence, not independent attestation or automatic malware cleanup. The separate persistence benchmark uses an allowlist monitor that removes unknown files while preserving a declared bounded cache; that monitor can also remove unrecognized legitimate files.

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

## Control benchmarks and results

Choose **2. Control benchmarks** in the startup menu, or open the prompts directly. Options supplied to `evaluate` become defaults that you can accept or change:

```bash
PYTHONPATH=src python3 -m ssrsf evaluate
PYTHONPATH=src python3 -m ssrsf evaluate --benchmark persistence --trials 20 --output results-persistence
```

Press Enter to accept each default. Invalid answers are retried; Ctrl+C or end of input cancels before evaluation starts. `ssrsf interactive` also opens guided control benchmarks.

For scripts and CI, add `--non-interactive` to run all seven control benchmarks or a selected subset without prompts:

```bash
PYTHONPATH=src python3 -m ssrsf evaluate --non-interactive --trials 30 --seed 42 --output results-repeat
PYTHONPATH=src python3 -m ssrsf evaluate --non-interactive --benchmark persistence --trials 20 --output results-persistence
```

Guided evaluation prompts for groups (`all`, numbers such as `1,4,7`, or names such as `events,persistence,billing`), trials (2–200), seed, modeled invocation price and output folder. Defaults are all seven groups, 30 trials, seed 42, price `0.000001` and `results/`. Choose `results-repeat` or `results-demo` to preserve retained evidence; existing report files in the chosen folder are replaced. Use `evaluate --help` for options. A benchmark run does not record a new `validation.json`; the validation script does that separately.

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

### Retained benchmark outcomes

The following values summarize the retained benchmark run: 30 trials per case, seed 42, recorded on **2026-11-13 09:19:07 UTC**. Counts represent attack-fixture acceptance or marker survival, with legitimate completion reported separately. The two persistence controls share the same unchecked baseline.

| Control | Baseline attack / marker outcomes | Protected attack / marker outcomes | Protected rate, 95% Wilson CI | Protected legitimate completion |
|---|---|---|---|---|
| Event validation | 150/150 | 0/150 | 0.0–2.5% | 60/60 |
| Per-function authorization | 120/120 | 0/120 | 0.0–3.1% | 90/90 |
| Artifact inventory | 60/60 | 0/60 | 0.0–6.0% | 30/30 |
| Warm workspace monitoring | 30/30 | 0/30 | 0.0–11.4% | 30/30 |
| Fresh workspace | 30/30 | 0/30 | 0.0–11.4% | 30/30 |
| Current-policy gate | 30/30 | 0/30 | 0.0–11.4% | 30/30 |

All tested legitimate calls also complete in the corresponding baselines. Persistence lifecycle timing includes startup, calls, monitoring and shutdown; fresh mode starts another process, so its duration does not isolate monitoring overhead.

On separate balanced held-out role-inference calls, exposed traces identify **60/60** roles and exposed timing identifies **59/60**. Uniform traces identify **30/60** and uniform-workflow timing identifies **28/60 (46.7%; 95% CI 34.6–59.1%)**. The timing interval includes chance accuracy (50%) for this run; it does not establish absence of timing leakage. The current-policy gate rejects revoked-reader access even through stale replicas, using a trusted local policy rather than distributed consensus.

Billing trials use 70 synthetic minute buckets, paired arrivals across controls and a 20-call quota. Modeled cost is accepted handler dispatches multiplied by `0.000001` arbitrary units; it excludes authentication, rejected-request infrastructure and downstream costs. Selected results are means over 30 paired traces:

| Workload | Control | Accepted attack calls | Rejected legitimate calls | Modeled cost units |
|---|---|---|---|---|
| Sustained attack | Uncontrolled / alert-only | 2000.0 | 0.0 | 0.002702 |
| Sustained attack | Fixed quota | 441.1 | 192.0 | 0.000951 |
| Sustained attack | Authenticated quota | 0.0 | 0.0 | 0.000702 |
| Low-rate attack | Uncontrolled / alert-only / fixed quota | 50.0 | 0.0 | 0.000750 |
| Low-rate attack | Authenticated quota | 0.0 | 0.0 | 0.000700 |
| Legitimate burst | Fixed / authenticated quota | 0.0 | 420.3 | 0.000759 |

Alert-only dispatch accepts the same work as uncontrolled dispatch. Its recall is 100% for sustained attacks, 0% for low-rate attacks and 0.7% for the slow ramp; legitimate bursts produce a 12% false-positive rate. Authenticated quota rejects the tested forged, revoked and read-only attack credentials, including low-rate and ramp requests, but still drops legitimate bursts at the cap. These are admission decisions on declared fixtures; valid invoke credentials can still cause metered work. The [measured report](results/report.md) contains all workloads and metrics.

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

| Implementation area | Source under `src/ssrsf/` |
|---|---|
| Workflow transactions and role-scoped management | `prototype/store.py`, `prototype/reference.py` |
| Signed transport and source inventory | `prototype/transport.py`, `prototype/integrity.py` |
| Guard, controller and workers | `prototype/service.py` |
| Menu, startup, scripted commands and Python HTTP client | `prototype/menu.py`, `prototype/client.py`, `reference.py` |
| Supporting controls, experiments, reports and evidence binding | `controls.py`, `experiments/`, `evaluation.py`, `evidence.py` |

## Recorded workflow evidence

The retained [validation log](results/validation.json) records **87 passing tests under Python 3.14.8**. These are recorded correctness assertions, not 87 independent security trials or a fresh validation of the current checkout. The core tests in [test_prototype.py](tests/test_prototype.py) and [test_reference_app.py](tests/test_reference_app.py) cover:

| Contract | Tested condition and assertion |
|---|---|
| Grant and version binding | Cross-workflow substitution and document replacement reject mismatched or obsolete completions |
| Single committed advancement | Concurrent claims/completions commit one transition; identical retries return retained outcomes after restart |
| Lease recovery | Expired unfinished work becomes claimable after restart |
| Audit consistency | Audit-write failure rolls back mutation; startup rejects a tampered audit chain |
| Current policy | A restrictive policy change blocks an in-flight completion |
| Fail-closed boundary | Controller outage does not advance the workflow |

Menu and HTTP tests also cover identity-scoped operations, signed requests, quotas and navigation. The project documentation separately reports live Compose smoke observations:

- A complete ingest/extract/classify workflow and idempotent submission.
- Typed input, normalized output and status lookup; scripted retry with the same workflow ID.
- Rejection of forged credentials, altered signed requests, forbidden roles and conflicting submissions.
- Ownership checks, identity-based access control, cryptographic audit logging and persistent quota enforcement.
- Scratch entry/exit evidence, including a mismatch after an inert marker was added between invocations.
- All three workers lacked database access and other services' mounted credentials.
- Worker TCP probes to the controller by name and IP, a sibling and a selected external IP failed.
- Five submitted workflows completed under a smoke load of up to four concurrent clients. The observed median was approximately **1.482 seconds** for that run.
- A completed workflow and valid audit chain survived a controller restart.
- A rebuilt image started against the existing test database.

These single-host observations are separate from the seven-benchmark bundle. They are not a scalability study, a general egress guarantee or a comparative performance study. Run `check` and `load` to repeat the live checks; quota usage and host scheduling can affect results. CI includes a separate `container-prototype` job for these commands.

## Tests and evidence verification

The retained benchmark run contains 2,010 observations combining different units, including inference calls and complete billing traces; they are not one independent sample of attacks. A fixed seed preserves generated inputs and ordering, not elapsed times.

**Current evidence status:** the retained evidence-file checksums match, but the source inventory differs in `README.md`. The bundle therefore describes its recorded revision and does not certify the current checkout. Editing documentation is not a new experimental run. This README is included in the implementation-source inventory. Hashes detect changes rather than independent provenance or owner-controlled rewriting.

Run the existing tests:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

For a new canonical bundle, freeze the implementation and documentation, then regenerate the evaluation, record tests and verify it. The following commands replace retained results; use them when intentionally establishing a new evidence revision:

```bash
PYTHONPATH=src python3 -m ssrsf evaluate --non-interactive --trials 30 --seed 42 --output results
python3 scripts/validate.py --python python3
python3 scripts/check_evidence.py
```

Repeat `--python` to validate additional installed interpreters. `results/validation.json` binds test logs to source/results; `results/SHA256SUMS` binds the evidence files. Same-host checks are not independent replication.

## Related research

The review motivates the threat coverage. The systems below provide context for the workflow and admission mechanisms; they have not been evaluated as head-to-head baselines in this repository.

| Paper | Relationship to this project |
|---|---|
| [Kalium — USENIX Security 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/jegan) | Uses local function and global application state for serverless control-flow integrity; closest context for stage-order enforcement |
| [WILL.IAM — ACSAC 2020](https://sts.cs.illinois.edu/papers/paper/WorkflowIntegrationA20201207.html) | Workflow-aware authorization and proactive rejection of requests lacking downstream permissions |
| [Valve — WWW 2020](https://doi.org/10.1145/3366423.3380173) | Network-layer information-flow enforcement and container-reuse defenses; broader interception than this application's explicit service endpoints |
| [Trapeze — OOPSLA 2018](https://doi.org/10.1145/3276488) | Dynamic information-flow control with termination-sensitive noninterference; a stronger confidentiality property than these local checks establish |
| [Growlithe — IEEE S&P 2025](https://spg.cs.ubc.ca/publication/2025-sp/) | Static analysis and runtime enforcement of declarative access/dataflow policies; this project uses provisioned policies |
| [Denial of Wallet — JISA 2021](https://doi.org/10.1016/j.jisa.2021.102843) | Billing-abuse threat definition and simulated attack patterns |
| [DoWNet — Journal of Cybersecurity 2024](https://doi.org/10.1093/cybsec/tyae004) | Learned classification of suspicious traffic; credential rejection and fixed quotas here are admission controls |

The project contributes an inspectable implementation and local evidence for version-bound transitions, retained retry outcomes and atomic audit records. It does not claim that workflow authorization, information-flow control or quotas are new, or that it outperforms these systems.

## Limits

The reference app places workers behind a guard/controller boundary under a trusted Docker host. Subprocess workspaces are not hostile-code sandboxes, replica objects are not distributed nodes, and markers/artifacts are inert.

Cloud IAM enforcement, container escapes, adversarial co-location, CPU/cache channels, provider scheduling, real billing and distributed rollout safety remain outside the local evidence. There is one worker identity per stage, with no tenant-isolated worker scheduling. The fixed stage graph does not model arbitrary per-function network operations. The seven control benchmarks measure fixture completion and timing; reference-app tests additionally exercise lease recovery, transaction rollback and restart persistence. Production availability SLOs, error budgets and multi-host incident recovery are not evaluated. Production identity, encrypted transport, external audit checkpoints and recovery across hosts require further implementation and evaluation.

A stronger evaluation would add matched authorization/workflow baselines, ablations of grant binding and atomic commit, process crashes at commit/response boundaries, sustained load across multiple workloads, and independent runs. Measure recovery time, duplicate committed effects, latency, throughput and resource use. Existing rollback and lease-recovery tests are distinct from these unperformed experiments; a FaaS deployment is needed to extend the deployment claims.
