# Serverless SRSF: Site Reliability and Security Framework

**Serverless SRSF** is a local experimental framework that implements and evaluates selected countermeasures discussed in **Marin, Perino and Di Pietro, “Serverless computing: a security perspective,” Journal of Cloud Computing 11, 69 (2022)**. [Article](https://doi.org/10.1186/s13677-022-00347-w).

The article is a security review. It does not propose the SRSF implementation or provide numerical experimental results to reproduce. This repository turns its recommendations and research questions into executable local experiments, compares vulnerable baselines with mitigations, and reports newly measured results. The article's qualitative Tables 1 and 2 are contextual comparisons, not benchmark targets.

The project includes an integrated local text-document workflow with acknowledged SQLite audit, exact-policy deployment checks, independent purge approval/replay protection, controlled telemetry access and an invocation budget. The reliability scope is legitimate-request completion under controls, local rollout consistency, audit dependency failures and execution-lifecycle latency. Production uptime SLOs, error budgets and incident recovery have not been evaluated.

## Run a hands-on demo

Requires Python 3.11 or newer. Start the terminal interface from this directory:

```bash
PYTHONPATH=src python3 -m ssrsf demo
```

Type your own commands at the prompt. For example:

```text
ingest This is my document about serverless security.
read
tamper Change this signed input
purge
telemetry
auth admin-token
approve
purge
purge
audit
quit
```

`ingest` processes your actual text, stores it in SQLite and prints the extracted text, version and classification. The tampered event is rejected. Purging before approval is rejected, and detailed telemetry requires an administrator or investigator. After switching to the administrator fixture, `approve` grants deletion of the current version for 30 seconds. The first approved purge succeeds; repeating it is rejected as replay. `audit` verifies the audit chain. You can also approve, ingest replacement text, then try purging: the old grant cannot delete the new version.

The workflow has one document slot, `public/item`, and accepts at most 128 characters per document. Each ingest replaces the slot with a new version. Classification uses a word-count rule: at least 10 words is `long`, otherwise `short`. Enter `help` for all commands, including `file PATH`, `telemetry` and `budget`.

To process input directly without the interactive prompt:

```bash
PYTHONPATH=src python3 -m ssrsf demo --text "A document I supplied myself"
PYTHONPATH=src python3 -m ssrsf demo --file /path/to/input.txt
```

Demo state is temporary by default. Add `--state /tmp/my-srsf-demo` to retain documents, keys and audit records across runs. Each interactive session starts as `user-token`; use `auth admin-token` or `auth investigator-token` to explore role restrictions. These are local demonstration credentials. Installed packages also support `ssrsf demo`.

## Run the evaluation and tests

Requires Python 3.11 or newer. The runtime and tests use only the standard library. No cloud account, credentials, Docker, network access or external services are used.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
ssrsf evaluate --trials 30 --seed 42 --output results
python -m unittest discover -s tests -v
```

Without installing the package, from this directory:

```bash
PYTHONPATH=src python3 -m ssrsf evaluate --trials 30 --seed 42 --output results
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

On Windows, activate with `.venv\Scripts\Activate.ps1` and use the installed `ssrsf` command. `python -m ssrsf` also works after installation.

Read [the measured report](results/report.md). Raw observations are in [results.json](results/results.json), aggregates in [metrics.csv](results/metrics.csv), and artifact checksums in [SHA256SUMS](results/SHA256SUMS). These results are retained in the repository; rerunning replaces files in the chosen output directory. Use a new directory to keep another run.

## Experiments

| Article topic | Local implementation | Evaluation |
|---|---|---|
| Injection and untrusted events, pp. 8–9 | Strict event schema at the consumer; canonical HMAC envelope; data-only handling | Ordinary and metacharacter values, internal delete commands, traversal, excess fields, oversized values, transit tampering |
| Authentication bypass and privilege misconfiguration, pp. 8–9 | Authentication and exact action/resource capability checks at every function boundary | Gateway-only broad role vs per-function least privilege; missing/forged credentials, direct queue entry, forbidden operation and resource |
| Third-party dependencies, p. 9 | Trusted SHA-256 artifact inventory checked before use | Unchanged, same-size/mtime-preserving modification and unlisted artifact |
| Long-lasting attacks in warm scratch storage, pp. 10–11 | Real Python subprocesses with reused or fresh workspaces; declared-content inspection before/after invocation | Inert persistence marker survival, removal/detection, declared cache preservation, total lifecycle overhead |
| Workflow side channels, pp. 9–10 / Figure 2 | Role-dependent function traces; external facade, response floor and absolute deadline padding | Train a trace classifier and timing threshold on one split; measure role accuracy on separate balanced test calls |
| Code/configuration rollout races, p. 10 | Concurrent local replica pool; version and policy replaced together under a dispatch lock | Forced stale-replica window and in-flight request across revocation; compare partial rolling update with drained atomic cutover |
| Denial-of-Wallet, p. 11 | Actual local dispatch accounting; frozen EWMA; alert-only, adaptive invocation quota and fixed quota | Paired steady, legitimate-burst, sustained, low-rate and slow-ramp traces; recall, false pages, legitimate drops, alert/enforcement delay, pre-alert attack calls and modeled spend |

The specific EWMA parameters, HMAC envelope, allowlists, quota and synchronization mechanism are this project's engineering choices. They are not algorithms specified by the article. The source and method mapping is in [research/methodology.md](research/methodology.md); the supplied PDF's bibliographic metadata and fingerprint are in [research/article.json](research/article.json).

Run a subset or change the timing/cost assumptions:

```bash
ssrsf evaluate --experiment persistence --experiment rollouts --trials 20 --output results-lifecycle
ssrsf evaluate --experiment side-channels --floor-ms 8 --trials 50 --output results-timing
ssrsf evaluate --experiment billing --unit-price 0.000001 --seed 7 --output results-billing
```

## Reading the evidence

Attack acceptance/success is a proportion over the explicitly labeled fixtures, with descriptive 95% Wilson intervals. Legitimate completion is measured separately. Latencies include initialization and are host-dependent; raw samples, p50/p95/p99 and measurement boundaries are retained. Randomized order and paired inputs reduce ordering bias. Repeated deterministic fixtures do not estimate prevalence or effectiveness on a real attack population.

The side-channel experiment measures response times with constructed 1 ms and 3 ms service delays. It uses separate training/test calls and never fits on test labels. The separate `facade-deadline` variant sleeps coarsely and spins up to the final 2 ms toward an absolute deadline. CPU time is measured alongside latency to expose its cost. It also carries no constant-time guarantee. The facade hides names only from the declared external observer; privileged internal observers retain more information. A floor is not a constant-time guarantee.

Billing uses synthetic minute buckets, advanced without waiting. Every accepted invocation runs a tiny local function and enters an accounting ledger. Prices are **arbitrary cost units**, not AWS pricing or actual bills. Detection uses only offered counts; malicious/legitimate labels are hidden from the controller and used only to score outcomes. Detection happens after a closed bucket and adaptive enforcement begins in the next bucket. Legitimate bursts can be throttled and low-rate attacks can be missed; the report includes both.

## Scope

This is a local research testbed. Workspace/process separation is not a hostile-code sandbox; Python capability checks are not IAM; a single-process rollout lock is not a distributed update protocol. Markers and dependency artifacts are inert, and all experiment storage is temporary. No uploaded or previously stored documents are accessed.

Cloud schedulers, co-location, hypervisor/container escape, CPU/cache covert channels, provider billing and the article's platform isolation comparisons require infrastructure outside this local testbed. They are explicitly outside the evidence, rather than assigned synthetic success numbers.

The previous cloud document-processing application, browser console, AWS resources and old operational runbooks are not used. The new `workflow.ReferenceApp` is an offline text-document reference implementation, separate from that application. Existing ignored `.ssrsf/` data is left untouched and is not used by this version.

## Repository

- `src/ssrsf/`: controls, process runtime, eleven experiment groups, metrics, evidence writer and CLI.
- `tests/`: adversarial control, concurrency, lifecycle, accounting and evidence-integrity tests.
- `research/`: article identity and methodology/coverage mapping.
- `results/`: retained measured run, raw observations, CSV, report and checksums.


## Integrated workflow and ablations

```bash
PYTHONPATH=src python3 -m ssrsf evaluate --experiment framework --trials 30 --seed 42 --output results-framework
PYTHONPATH=src python3 -m ssrsf evaluate --experiment sensitivity --trials 30 --seed 42 --output results-sweep
```

The framework study compares all controls, no controls, and a single removed control per relevant scenario. It tests signed input, artifact integrity, independent purge approval, replay, replaced versions, policy expansion, private telemetry and audit entry/exit failures. Audit exit failures can leave committed side effects; recovery records an evidence gap. The sensitivity study reports all nine threshold/quota settings over paired workload seeds.

`ReferenceApp` is also usable directly:

```python
from pathlib import Path
from tempfile import TemporaryDirectory
from ssrsf.workflow import ReferenceApp

with TemporaryDirectory() as directory:
    app = ReferenceApp(Path(directory))
    document = app.ingest("user-token", "A bounded local text document")
    targets = [(document["id"], document["version"])]
    grant = app.approve("admin-token", targets)
    app.purge("admin-token", targets, grant)
    assert app.audit.verify()
```

Tokens above are fixture credentials. SQLite FULL commits, HMAC chains and trusted Python roles implement local semantics; they do not provide cloud retention, independent OS identities or isolation from the filesystem owner. The policy language accepts exact rules only and rejects unsupported scope. Text classification is a deterministic word-count rule, not an inference service. See `research/methodology.md` for failure and recovery semantics.

## Restart recovery and robustness probes

```bash
PYTHONPATH=src python3 -m ssrsf evaluate --experiment lifecycle --trials 30 --output results-recovery
PYTHONPATH=src python3 -m ssrsf evaluate --experiment robustness --trials 30 --output results-robustness
```

Bootstrap keys and the trusted artifact inventory persist in a mode-0600 owner-trusted file. Reopening a workflow verifies the audit chain and restores accepted policy history. Existing database state without keys is never silently reinitialized. This supports normal local restart, not owner-resistant storage, key rotation or power-loss recovery. Invocation quotas reset on restart.

After a purge grant expires, the independent investigator fixture can query an operation without executing deletion again:

```python
outcome = app.broker.investigate(operation_id, "investigator-token")
```

The lifecycle evaluation uses two fresh interpreters and an injected exit-audit failure. The robustness evaluation compares EWMA with a fixed-training reference and fixed quota under seasonal/growing demand, legitimate crowds, intermittent attacks and ramps. All outcomes are retained, including misses and legitimate rejection.

After regenerating the retained evaluation, retain compatibility checks and validate evidence:

```bash
python3 scripts/validate.py --python .venv/bin/python --python python3
python3 scripts/paper_evidence.py --check --evidence-only
```

`results/validation.json` binds test logs and interpreter versions to the exact retained source/evidence. The installed versions are detected rather than assumed. Same-host compatibility checks do not establish independent-host replication.
