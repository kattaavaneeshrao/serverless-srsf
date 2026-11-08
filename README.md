# Serverless SRSF: A Site Reliability and Security Framework

**A reusable serverless security framework implemented through an interactive document workflow, with seven supporting security experiments.**

The interactive document workflow is the core implementation of Serverless SRSF. It processes your own text through ingest → extract → classify and enforces the framework's security controls around real local document state. Use the terminal interface to explore the workflow, or import `ReferenceApp` to reuse it from Python.

The accompanying experiments implement and evaluate selected recommendations from **Marin, Perino and Di Pietro, “Serverless computing: a security perspective,” Journal of Cloud Computing 11, 69 (2022)**. [Article DOI](https://doi.org/10.1186/s13677-022-00347-w). The article is a review with no runnable implementation or numerical benchmarks; the framework and measured results are this project's local implementation choices.

## Quick start

Requires Python 3.11 or newer. Runtime and tests use only the standard library. Run these commands from the repository root; no cloud account, Docker or external services are required.

```bash
PYTHONPATH=src python3 -m ssrsf demo
```

| Command | What it opens |
|---|---|
| `PYTHONPATH=src python3 -m ssrsf demo` | Interactive document workflow using your text |
| `PYTHONPATH=src python3 -m ssrsf` | Guided configuration for the seven paper experiments |
| `PYTHONPATH=src python3 -m ssrsf evaluate` | Evaluation with default settings and output in `results/` |

To install the `ssrsf` command in a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
ssrsf demo
```

On Windows, activate with `.venv\Scripts\Activate.ps1` and use `ssrsf demo` after installation.

## Interactive document workflow

The reusable local framework processes your own text through ingest → extract → classify, with signed event validation, parser artifact integrity, owner checks, acknowledged audit records, version-bound purge approval, restricted telemetry and a fixed invocation quota. This workflow integrates the framework's controls; the seven supporting experiments below evaluate individual security topics.

Try these commands at the document prompt:

```text
ingest This is my document about serverless security.
read
tamper Changed input
purge
telemetry
auth admin-token
approve
purge
purge
audit
quit
```

The first `purge` and `telemetry` requests are rejected under the user role. After switching to the administrator, approval permits one deletion; the second deletion is rejected as replay. `audit` verifies the audit chain.

| Command | Behavior |
|---|---|
| `ingest TEXT` / `file PATH` | Process text or a UTF-8 file and replace the current document version |
| `read` | Show the stored document, normalized text, version and classification |
| `auth TOKEN` | Select a local fixture identity |
| `approve` | Request an administrator purge grant for the current version |
| `purge` | Delete with the last grant; reject missing approval, replaced versions and replay |
| `tamper TEXT` | Alter a signed event before delivery to demonstrate integrity rejection |
| `telemetry` | Request detailed traces and audit records; requires administrator or investigator |
| `audit` | Verify the audit chain |
| `budget` | Show ingest accounting and start a new quota bucket |
| `help` / `quit` | Show commands or end the session |

Tampered input is rejected. Approval lasts 30 seconds and names an exact document version; replacing a document invalidates the old approval for deletion.

To process text or a UTF-8 file directly, and optionally keep state across sessions:

```bash
PYTHONPATH=src python3 -m ssrsf demo --text "My own document"
PYTHONPATH=src python3 -m ssrsf demo --file /path/to/input.txt --state /tmp/my-srsf-demo
```

State is temporary unless `--state` is supplied. The workflow has one document slot (`public/item`), accepts up to 128 characters and normalizes whitespace. Classification is a word-count rule: at least 10 words is `long`, otherwise `short`. Sessions begin as `user-token`; `auth admin-token` and `auth investigator-token` select local fixture roles. Enter `help` for commands. Each bucket admits at most 20 ingest attempts; `budget` prints accounting and resets the bucket. Quotas also reset on restart.

## How the workflow applies the paper

Our security framework uses the document workflow to make selected concerns from Section 6 of [Marin et al. (2022)](https://link.springer.com/article/10.1186/s13677-022-00347-w) executable in one local workflow. Its event validation, identity/ownership checks, authenticated input, artifact inventory, scratch evidence and ingest quota connect to the article's security topics.

See the [workflow-to-paper mapping](research/methodology.md#document-workflow-mapped-to-the-paper) for subsection/page references, implementing code, tests and limitations. The framework combines extract/classify steps inside one guarded Python processing boundary; it does not deploy a separate serverless function for each step.

The audit-chain format, purge grants, policy expansion gate and persistent bootstrap state are project-specific mechanisms. The paper supplies the security motivation rather than these protocols. Restricted telemetry does not establish side-channel resistance, and local policy locking/version checks do not establish distributed rollout safety. The seven experiment groups evaluate their own fixtures; their reported rates are not end-to-end security measurements of the integrated framework.

## Reuse the framework from Python

Run with `PYTHONPATH=src` or install the package first. `ReferenceApp` exposes document processing, approval, deletion, policy deployment and telemetry through the same components used by the CLI:

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
| [`workflow.py`](src/ssrsf/workflow.py) | Compose the document pipeline, ownership checks, telemetry access and fixed ingest quota |
| [`controls.py`](src/ssrsf/controls.py) | Validate event schemas and HMAC integrity; verify artifact inventories |
| [`audit.py`](src/ssrsf/audit.py) | Acknowledge SQLite audit commits and capture invocation entry/exit evidence |
| [`broker.py`](src/ssrsf/broker.py) | Store versioned documents and enforce expiring, single-use purge grants |
| [`policy.py`](src/ssrsf/policy.py) | Enforce exact rules and hold authorization expansions for review |
| [`state.py`](src/ssrsf/state.py) | Persist trusted bootstrap keys and artifact inventory |

Trusted keys, document versions and accepted policy history persist with the selected state directory. Startup verifies the audit chain and refuses existing databases with missing keys. Audit exit failures may leave committed side effects and an evidence gap; the broker provides read-only reconciliation. SQLite, fixture roles and the filesystem owner share a local trust boundary; this is an offline reference implementation rather than a deployed cloud service.

## Run the paper evaluation

Start the guided evaluation prompts:

```bash
PYTHONPATH=src python3 -m ssrsf
```

It asks for experiments (choose `all`, or comma-separated numbers/names), trials,
random seed, modeled invocation cost, and the output folder. Press Enter to accept
each default, or Ctrl+C to cancel. Invalid answers are prompted again. Experiments
use built-in test events and attack scenarios; the prompts configure the run.
Existing report files in the chosen output folder will be replaced.

| Prompt | Accepted input | Default |
|---|---|---|
| Experiments | `all`, or comma-separated menu numbers/names, such as `1,2` or `events,billing` | All seven experiments |
| Trials per case | Whole number from 2 to 200 | `30` |
| Random seed | Whole number from 0 to 4294967295 | `42` |
| Modeled cost per invocation | Positive, finite number up to 1000000 | `0.000001` |
| Output folder | Folder path; `~` is supported | `results` |

After the last answer, the evaluation starts automatically. When it finishes,
open `report.md` in your chosen output folder for the readable results.
The same folder contains `results.json`, `metrics.csv`, and evidence metadata.

You can also start the prompts with `PYTHONPATH=src python3 -m ssrsf interactive`
(or `ssrsf` / `ssrsf interactive` after installation).

For a run without prompts:

```bash
PYTHONPATH=src python3 -m ssrsf evaluate --trials 30 --seed 42 --output results
```

Select individual experiments or change the modeled invocation price:

```bash
PYTHONPATH=src python3 -m ssrsf evaluate --experiment persistence --trials 20 --output results-persistence
PYTHONPATH=src python3 -m ssrsf evaluate --experiment billing --unit-price 0.000001 --output results-billing
```

## Scope mapped to the article

| Experiment | Article location | What runs locally |
|---|---|---|
| Events | Section 6, pp. 8–9 | Consumer-side input validation and authenticated event integrity, compared with unchecked input |
| Authorization | Section 6, pp. 8–9 | Authentication and exact capabilities at each function boundary, compared with gateway-only authentication and broad permissions |
| Dependencies | Section 6, p. 9 | A trusted artifact inventory rejects modified or unlisted files, compared with untracked artifacts |
| Persistence | Section 6, pp. 10–11; warm reuse discussion p. 8 | Marker survival in reused scratch storage, compared with monitored storage and a fresh workspace |
| Side channels | Section 6, pp. 9–10, Figure 2 | Demonstrates role inference from branching function traces and measured timing; no added defense |
| Rollouts | Section 6, p. 10 | Demonstrates revoked access through old replicas during a partial update; no added defense |
| Billing | Section 6, p. 11 | Uncontrolled dispatch, fixed spending alerts and fixed invocation quotas under paired demand |

The event schema, HMAC-SHA256, SHA-256 inventory, exact capability representation, scratch allowlist, quota values and measurement protocols are concrete local implementation choices. The paper does not specify them. HMAC provides shared-key integrity rather than the public-key digital signatures used as an example in the review. Hash inventory checks address artifact integrity, not dependency vulnerability scanning. A per-minute invocation cap models the quota idea, not an actual provider concurrency limit.

The document workflow is our security framework implementation, grounded in the article's threats and recommendations. Its audit chain, approval broker and exact-policy gate are our concrete framework mechanisms; the article does not supply their algorithms or benchmarks. The paper experiments retain their existing scope; extended ablation, sensitivity, lifecycle and robustness studies, timing-padding defenses and the EWMA detector remain excluded.

## Results and interpretation

Read [the measured report](results/report.md). [results.json](results/results.json) retains observations, workload buckets, parameters, machine details and source hashes; [metrics.csv](results/metrics.csv) contains aggregate measurements. [research/methodology.md](research/methodology.md) records the protocol and article mapping. [research/article.json](research/article.json) records the supplied PDF's identity and fingerprint.

The default retained run uses 30 trials and seed 42. Legitimate completion is reported separately from attack-fixture acceptance. Rates have descriptive 95% Wilson intervals. Repeated fixed cases and correlated synthetic buckets do not establish effectiveness on real attack populations. Latencies are measured on the local host and include the stated execution boundaries.

Side-channel roles have deliberately constructed 1 ms and 3 ms service delays. Separate balanced training and test calls evaluate a limited attacker. The rollout experiment deliberately leaves three of four replicas stale. These experiments demonstrate possible information exposure and stale access, not their frequency in a deployed platform or the effectiveness of a mitigation.

Billing uses 70 synthetic minute buckets that advance without waiting. Accepted invocations execute a tiny local function and enter an accounting ledger. Fixed spending alerts check each closed bucket against a predefined modeled limit and do not reject requests. A separate fixed quota admits at most 20 calls per bucket. Ground-truth labels are used only for scoring. Legitimate bursts can trigger alerts and lose requests; low-rate attacks can pass below both limits. Prices are arbitrary cost units, not provider pricing or actual bills. No custom anomaly detector or legitimate/attack request classifier is implemented.

## Tests and evidence verification

Run the workflow and experiment tests:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Retained evidence includes hashes of source files, tests and documentation. After changing these files, regenerate the seven-experiment bundle before recording test outcomes and verifying it:

```bash
PYTHONPATH=src python3 -m ssrsf evaluate --trials 30 --seed 42 --output results
python3 scripts/validate.py --python python3
python3 scripts/check_evidence.py
```

To record an additional installed interpreter, pass another `--python` argument to `scripts/validate.py`, for example:

```bash
python3 scripts/validate.py --python .venv/bin/python --python python3
```

`results/validation.json` binds interpreter versions and complete test logs to the retained source and results. `results/SHA256SUMS` binds the evidence files. Same-host compatibility checks do not establish independent replication.

## Limits

This is an offline local research testbed. Python checks are not IAM; subprocess workspaces are not a hostile-code sandbox; replica objects are not distributed cloud nodes. All markers and dependency artifacts are inert. Temporary experiment storage is disposable. Existing ignored `.ssrsf/` application data is preserved and unused.

Platform-isolation comparisons, adversarial co-location, CPU/cache channels, provider scheduling, IAM convergence and real billing remain outside the evidence. Reliability measurements cover legitimate fixture completion and execution timing; production availability SLOs, error budgets and incident recovery are not evaluated.
