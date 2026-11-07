# Serverless SRSF: Site Reliability and Security Framework

**Serverless SRSF** is a local experimental framework that implements and evaluates selected countermeasures discussed in **Marin, Perino and Di Pietro, “Serverless computing: a security perspective,” Journal of Cloud Computing 11, 69 (2022)**. [Article](https://doi.org/10.1186/s13677-022-00347-w).

The article is a security review. It does not propose the SRSF implementation or provide numerical experimental results to reproduce. This repository turns its recommendations and research questions into executable local experiments, compares vulnerable baselines with mitigations, and reports newly measured results. The article's qualitative Tables 1 and 2 are contextual comparisons, not benchmark targets.

The reliability scope of this version is legitimate-request completion under controls, local rollout consistency and execution-lifecycle latency. Production uptime SLOs, error budgets and incident recovery have not been evaluated. The research manuscript is [main.tex](main.tex).

## Run everything locally

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

The previous document-processing application, browser console, AWS deployment resources, purge workflow, operational runbooks and their old tests have been removed. Existing ignored `.ssrsf/` data is left untouched and is not used by this version.

## Repository

- `src/ssrsf/`: controls, process runtime, seven experiments, metrics, evidence writer and CLI.
- `tests/`: adversarial control, concurrency, lifecycle, accounting and evidence-integrity tests.
- `research/`: article identity and methodology/coverage mapping.
- `results/`: retained measured run, raw observations, CSV, report and checksums.
