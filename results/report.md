# Local serverless security evaluation

Article: [Serverless computing: a security perspective](https://doi.org/10.1186/s13677-022-00347-w), Marin et al. (2022).

The article is a review with qualitative comparisons and countermeasure suggestions. It supplies no numerical benchmark results to reproduce. These are newly measured local experiments, with explicitly constructed workloads.

Run: 2026-11-09T10:48:40.918501+00:00; 30 trials; seed 42; Python 3.14.8.

Raw observations, configuration, machine details and source hashes are in `results.json`. `metrics.csv` contains aggregate rates/timings. Timings include initialization and vary by host. Binomial Wilson intervals are descriptive; repeated fixtures and correlated buckets do not establish population effectiveness.

## events

Article pp. 8–9. Validate internal and external event schemas; verify integrity before use.

Execution: executed local event consumer.

| Variant | Attack acceptance/success | Legitimate completion | Trial p50 / p95 (ms) |
|---|---|---|---|
| unchecked | 150/150 (100.0%; 95% CI 97.5–100.0%) | 60/60 (100.0%; 95% CI 94.0–100.0%) | 0.000 / 0.001 |
| validated-signed | 0/150 (0.0%; 95% CI 0.0–2.5%) | 60/60 (100.0%; 95% CI 94.0–100.0%) | 0.004 / 0.012 |

Limits:

- Constructed event corpus, not an injection vulnerability scanner.
- Acceptance measures schema/integrity violations; payload strings are never executed.
- HMAC is a local integrity mechanism, not a public-key signature or replay defense.

## authorization

Article pp. 8–9. Gateway authentication alone leaves internal entry points exposed; enforce exact capabilities.

Execution: executed local function/service access checks.

| Variant | Attack acceptance/success | Legitimate completion | Trial p50 / p95 (ms) |
|---|---|---|---|
| gateway-only-broad-role | 120/120 (100.0%; 95% CI 96.9–100.0%) | 90/90 (100.0%; 95% CI 95.9–100.0%) | 0.000 / 0.000 |
| per-function-least-privilege | 0/120 (0.0%; 95% CI 0.0–3.1%) | 90/90 (100.0%; 95% CI 95.9–100.0%) | 0.000 / 0.001 |

Limits:

- Python reference monitor, not OS isolation, IAM, tenant identity or cloud enforcement.

## dependencies

Article pp. 9. Track third-party artifacts; reject changed or unlisted components before use.

Execution: executed file integrity experiment.

| Variant | Attack acceptance/success | Legitimate completion | Trial p50 / p95 (ms) |
|---|---|---|---|
| hash-locked-inventory | 0/60 (0.0%; 95% CI 0.0–6.0%) | 30/30 (100.0%; 95% CI 88.6–100.0%) | 0.108 / 0.189 |
| untracked | 60/60 (100.0%; 95% CI 94.0–100.0%) | 30/30 (100.0%; 95% CI 88.6–100.0%) | 0.019 / 0.096 |

Limits:

- Hash pinning detects changes, not known vulnerabilities or malicious trusted artifacts.
- Trusted inventory storage is assumed; no exploit code is imported.

## persistence

Article pp. 10–11. Reuse retains attacker state; a fresh workspace or declared-content monitoring removes it.

Execution: real subprocesses and temporary filesystem.

| Variant | Attack acceptance/success | Legitimate completion | Trial p50 / p95 (ms) |
|---|---|---|---|
| fresh-workspace | 0/30 (0.0%; 95% CI 0.0–11.4%) | 30/30 (100.0%; 95% CI 88.6–100.0%) | 51.529 / 57.293 |
| warm-monitored | 0/30 (0.0%; 95% CI 0.0–11.4%) | 30/30 (100.0%; 95% CI 88.6–100.0%) | 26.241 / 31.734 |
| warm-unchecked | 30/30 (100.0%; 95% CI 88.6–100.0%) | 30/30 (100.0%; 95% CI 88.6–100.0%) | 25.600 / 28.762 |

Limits:

- The implant is an inert marker, not arbitrary malware or a container escape.
- A fixed cache allowlist operationalizes the paper's legitimate/malicious distinction.
- No host isolation guarantee; timing covers process startup, calls, cleanup and shutdown.
- All modes run one compromise and two legitimate calls; fresh mode starts a second process.

## side-channels

Article pp. 9–10, Figure 2. Branch-specific traces and response timing can reveal the caller's role.

Execution: local workflow information-exposure demonstration.

Attacker training and testing use different calls. Both splits contain equal numbers of roles. Chance accuracy is 50%.

| Variant | Trace role accuracy | Held-out timing role accuracy | Response p50 / p95 (ms) |
|---|---|---|---|
| exposed | 60/60 (100.0%; 95% CI 94.0–100.0%) | 60/60 (100.0%; 95% CI 94.0–100.0%) | 2.600 / 3.782 |

This experiment demonstrates the Figure 2 threat. It does not introduce a defense.

Limits:

- Threat demonstration only; the review specifies no workflow side-channel defense.
- Service delays (user 1 ms, admin 3 ms) are constructed; wall-clock times are measured.
- Training and test calls are disjoint, balanced and randomized.
- Inference accuracy depends on this host and the limited tested attacker.
- No shared-host CPU/cache channel or real cloud trace access is evaluated.

## rollouts

Article pp. 10. Partial updates leave revoked access reachable through stale replicas.

Execution: concurrent calls to a partially updated local replica pool.

| Variant | Attack acceptance/success | Legitimate completion | Trial p50 / p95 (ms) |
|---|---|---|---|
| rolling-stale-replicas | 30/30 (100.0%; 95% CI 88.6–100.0%) | 30/30 (100.0%; 95% CI 88.6–100.0%) | 0.547 / 1.146 |

Limits:

- Threat demonstration only; the review does not specify a rollout defense.
- Four replica objects share one process; they are not distributed nodes.
- The stale-version window is intentionally forced, not measured in production.
- No provider convergence or cloud availability claim.

## billing

Article pp. 11. Spending alerts notify without limiting work; fixed invocation quotas limit cost and may reject legitimate calls.

Execution: synthetic labeled demand; actual local function dispatch ledger.

Cost units are modeled, not currency. Rows show means across paired trials. Alert recall/FPR compare fixed spending alerts with attack-labeled post-warmup buckets; they do not measure production accuracy. Uncontrolled and fixed-quota variants have no detector.

| Workload | Variant | Attack calls accepted | Legitimate calls rejected | Modeled spend | Alert recall | False alert rate | Mean alert delay (min) |
|---|---|---:|---:|---:|---:|---:|---:|
| legitimate-burst | alert-only | 0.0 | 0.0 | 0.001178 | n/a | 12.0% | none |
| legitimate-burst | fixed-quota | 0.0 | 420.0 | 0.000758 | n/a | 0.0% | none |
| legitimate-burst | uncontrolled | 0.0 | 0.0 | 0.001178 | n/a | 0.0% | none |
| low-rate-attack | alert-only | 50.0 | 0.0 | 0.000747 | 0.0% | 0.0% | none |
| low-rate-attack | fixed-quota | 50.0 | 0.0 | 0.000747 | 0.0% | 0.0% | none |
| low-rate-attack | uncontrolled | 50.0 | 0.0 | 0.000747 | 0.0% | 0.0% | none |
| slow-ramp | alert-only | 117.0 | 0.0 | 0.000816 | 0.5% | 0.0% | 25.00 |
| slow-ramp | fixed-quota | 116.9 | 0.1 | 0.000816 | 0.0% | 0.0% | none |
| slow-ramp | uncontrolled | 117.0 | 0.0 | 0.000816 | 0.0% | 0.0% | none |
| steady | alert-only | 0.0 | 0.0 | 0.000704 | n/a | 0.0% | none |
| steady | fixed-quota | 0.0 | 0.0 | 0.000704 | n/a | 0.0% | none |
| steady | uncontrolled | 0.0 | 0.0 | 0.000704 | n/a | 0.0% | none |
| sustained-attack | alert-only | 2000.0 | 0.0 | 0.002702 | 100.0% | 0.0% | 1.00 |
| sustained-attack | fixed-quota | 444.0 | 194.2 | 0.000952 | 0.0% | 0.0% | none |
| sustained-attack | uncontrolled | 2000.0 | 0.0 | 0.002702 | 0.0% | 0.0% | none |

Alert-only has the same cost as uncontrolled dispatch. Spending alerts do not enforce a cap or classify requests. Fixed quotas can reject legitimate bursts; low-rate attacks may remain below both limits.

Limits:

- Simulated minutes advance immediately, not a wall-clock load or scalability benchmark.
- No cloud bill, real concurrency quota, network overhead, retries or downstream costs.
- Spending alerts use a fixed per-bucket limit, not an anomaly detector or request classifier.
- Labels are hidden from enforcement; legitimate bursts can trigger alerts or lose legitimate requests.
- The local per-bucket cap approximates the quota idea; it is not a provider concurrency limit.
- Bucket labels and repeated fixture trials are correlated; do not treat them as a real-world attack population.
- Demand for all control variants is paired exactly; alert-only never rejects an invocation.

## Scope of the findings

This evaluation operationalizes selected recommendations. It does not recreate the article's full threat model or prove its qualitative Tables 1 and 2. Provider-only topics remain outside local evidence:

- Hypervisor/container escape and isolation comparisons (Table 2)
- Cloud placement, adversarial co-location, CPU/cache/covert channels
- Real provider IAM convergence and billing
- Vulnerability intelligence for dependencies and production attack prevalence

The events, files, requests and attacks are controlled fixtures. Results describe these fixtures and this host. All affected storage is disposable; existing application data is never read.
