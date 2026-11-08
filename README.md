# Serverless SRSF: A Site Reliability and Security Framework

**Implementation and Empirical Evaluation of Serverless Security Countermeasures**

This project implements and evaluates selected security recommendations from **Marin, Perino and Di Pietro, “Serverless computing: a security perspective,” Journal of Cloud Computing 11, 69 (2022)**. DOI: [10.1186/s13677-022-00347-w](https://doi.org/10.1186/s13677-022-00347-w).

The approved article is a review. It identifies threats and suggests countermeasures; it supplies no complete algorithm, implementation, dataset or numerical benchmarks to reproduce. These experiments measure selected recommendations and demonstrate two threats that the paper leaves open. They do not implement the entire paper.

## Run

Requires Python 3.11 or newer. Runtime and tests use only the standard library. No cloud account, credentials, Docker, network or external services are required.

```bash
PYTHONPATH=src python3 -m ssrsf evaluate --trials 30 --seed 42 --output results
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Optional package installation:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
ssrsf evaluate --trials 30 --seed 42 --output results
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

The project contains no document-processing application, purge-approval broker, audit-chain system, policy-expansion gate, persistent recovery service, timing-padding defense, atomic-cutover defense or EWMA detector. Extended ablation, sensitivity and follow-up comparator studies have also been removed.

## Results and interpretation

Read [the measured report](results/report.md). [results.json](results/results.json) retains observations, workload buckets, parameters, machine details and source hashes; [metrics.csv](results/metrics.csv) contains aggregate measurements. [research/methodology.md](research/methodology.md) records the protocol and article mapping. [research/article.json](research/article.json) records the supplied PDF's identity and fingerprint.

The default retained run uses 30 trials and seed 42. Legitimate completion is reported separately from attack-fixture acceptance. Rates have descriptive 95% Wilson intervals. Repeated fixed cases and correlated synthetic buckets do not establish effectiveness on real attack populations. Latencies are measured on the local host and include the stated execution boundaries.

Side-channel roles have deliberately constructed 1 ms and 3 ms service delays. Separate balanced training and test calls evaluate a limited attacker. The rollout experiment deliberately leaves three of four replicas stale. These experiments demonstrate possible information exposure and stale access, not their frequency in a deployed platform or the effectiveness of a mitigation.

Billing uses 70 synthetic minute buckets that advance without waiting. Accepted invocations execute a tiny local function and enter an accounting ledger. Fixed spending alerts check each closed bucket against a predefined modeled limit and do not reject requests. A separate fixed quota admits at most 20 calls per bucket. Ground-truth labels are used only for scoring. Legitimate bursts can trigger alerts and lose requests; low-rate attacks can pass below both limits. Prices are arbitrary cost units, not provider pricing or actual bills. No custom anomaly detector or legitimate/attack request classifier is implemented.

## Verify retained evidence

After regenerating results, record test outcomes and check the evidence:

```bash
python3 scripts/validate.py --python .venv/bin/python --python python3
python3 scripts/check_evidence.py
```

`results/validation.json` binds interpreter versions and complete test logs to the retained source and results. `results/SHA256SUMS` binds the evidence files. Same-host compatibility checks do not establish independent replication.

## Limits

This is an offline local research testbed. Python checks are not IAM; subprocess workspaces are not a hostile-code sandbox; replica objects are not distributed cloud nodes. All markers and dependency artifacts are inert. Temporary experiment storage is disposable. Existing ignored `.ssrsf/` application data is preserved and unused.

Platform-isolation comparisons, adversarial co-location, CPU/cache channels, provider scheduling, IAM convergence and real billing remain outside the evidence. Reliability measurements cover legitimate fixture completion and execution timing; production availability SLOs, error budgets and incident recovery are not evaluated.
