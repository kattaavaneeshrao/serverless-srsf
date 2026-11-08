# Local serverless security evaluation

Article: [Serverless computing: a security perspective](https://doi.org/10.1186/s13677-022-00347-w), Marin et al. (2022).

The article is a review with qualitative comparisons and countermeasure suggestions. It supplies no numerical benchmark results to reproduce. These are newly measured local experiments, with explicitly constructed workloads.

Run: 2026-11-08T05:07:07.382605+00:00; 30 trials; seed 42; Python 3.12.14.

Raw observations, configuration, machine details and source hashes are in `results.json`. `metrics.csv` contains aggregate rates/timings. Timings include initialization and vary by host. Binomial Wilson intervals are descriptive; repeated fixtures and correlated buckets do not establish population effectiveness.

## events

Article pp. 8–9. Validate internal and external event schemas; verify integrity before use.

Execution: executed local event consumer.

| Variant | Attack acceptance/success | Legitimate completion | Trial p50 / p95 (ms) |
|---|---|---|---|
| unchecked | 150/150 (100.0%; 95% CI 97.5–100.0%) | 60/60 (100.0%; 95% CI 94.0–100.0%) | 0.000 / 0.000 |
| validated-signed | 0/150 (0.0%; 95% CI 0.0–2.5%) | 60/60 (100.0%; 95% CI 94.0–100.0%) | 0.003 / 0.004 |

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
| per-function-least-privilege | 0/120 (0.0%; 95% CI 0.0–3.1%) | 90/90 (100.0%; 95% CI 95.9–100.0%) | 0.000 / 0.000 |

Limits:

- Python reference monitor, not OS isolation, IAM, tenant identity or cloud enforcement.

## dependencies

Article pp. 9. Track third-party artifacts; reject changed or unlisted components before use.

Execution: executed file integrity experiment.

| Variant | Attack acceptance/success | Legitimate completion | Trial p50 / p95 (ms) |
|---|---|---|---|
| hash-locked-inventory | 0/60 (0.0%; 95% CI 0.0–6.0%) | 30/30 (100.0%; 95% CI 88.6–100.0%) | 0.107 / 0.179 |
| untracked | 60/60 (100.0%; 95% CI 94.0–100.0%) | 30/30 (100.0%; 95% CI 88.6–100.0%) | 0.019 / 0.026 |

Limits:

- Hash pinning detects changes, not known vulnerabilities or malicious trusted artifacts.
- Trusted inventory storage is assumed; no exploit code is imported.

## persistence

Article pp. 10–11. Reuse retains attacker state; a fresh workspace or declared-content monitoring removes it.

Execution: real subprocesses and temporary filesystem.

| Variant | Attack acceptance/success | Legitimate completion | Trial p50 / p95 (ms) |
|---|---|---|---|
| fresh-workspace | 0/30 (0.0%; 95% CI 0.0–11.4%) | 30/30 (100.0%; 95% CI 88.6–100.0%) | 40.190 / 43.437 |
| warm-monitored | 0/30 (0.0%; 95% CI 0.0–11.4%) | 30/30 (100.0%; 95% CI 88.6–100.0%) | 20.754 / 22.204 |
| warm-unchecked | 30/30 (100.0%; 95% CI 88.6–100.0%) | 30/30 (100.0%; 95% CI 88.6–100.0%) | 20.102 / 22.135 |

Limits:

- The implant is an inert marker, not arbitrary malware or a container escape.
- A fixed cache allowlist operationalizes the paper's legitimate/malicious distinction.
- No host isolation guarantee; timing covers process startup, calls, cleanup and shutdown.
- All modes run one compromise and two legitimate calls; fresh mode starts a second process.

## side-channels

Article pp. 9–10, Figure 2. Branch-specific traces/timing reveal roles; a facade restricts trace visibility and padding reduces timing signal.

Execution: measured local workflows with controlled service delays.

Attacker training and testing use different calls. Both splits contain equal numbers of roles. Chance accuracy is 50%.

| Variant | Trace role accuracy | Held-out timing role accuracy | Response p50 / p95 (ms) | Mean CPU (ms) |
|---|---|---|---|---|
| exposed | 60/60 (100.0%; 95% CI 94.0–100.0%) | 60/60 (100.0%; 95% CI 94.0–100.0%) | 2.828 / 3.799 | 0.022 |
| facade-floor | 30/60 (50.0%; 95% CI 37.7–62.3%) | 52/60 (86.7%; 95% CI 75.8–93.1%) | 9.086 / 9.721 | 0.050 |
| facade-deadline | 30/60 (50.0%; 95% CI 37.7–62.3%) | 32/60 (53.3%; 95% CI 40.9–65.4%) | 8.000 / 8.006 | 1.196 |

Trace protection here comes from restricting the observer's exported names. A response floor is not proof against timing inference or shared-host channels.

Limits:

- Service delays (user 1 ms, admin 3 ms) are constructed; wall-clock times are measured.
- Training and test calls are disjoint, balanced and randomized; no attacker uses test labels to fit.
- Wilson intervals describe sample proportions, not proof of independence or zero leakage.
- The facade deliberately hides internal names from this observer; privileged telemetry observers still see them.
- Simple sleep padding can itself retain role-dependent timing on some hosts.
- Deadline padding spins for up to the final 2 ms, increasing CPU cost; no constant-time guarantee.
- Padding may leak under contention or slow handlers; accuracy need not equal chance.

## rollouts

Article pp. 10. Partial updates leave revoked access reachable; atomic code/policy cutover prevents post-cutover stale access.

Execution: concurrent requests to a local in-process replica pool.

| Variant | Attack acceptance/success | Legitimate completion | Trial p50 / p95 (ms) |
|---|---|---|---|
| atomic-cutover | 0/60 (0.0%; 95% CI 0.0–6.0%) | 60/60 (100.0%; 95% CI 94.0–100.0%) | 3.643 / 6.820 |
| rolling-stale-replicas | 60/60 (100.0%; 95% CI 94.0–100.0%) | 60/60 (100.0%; 95% CI 94.0–100.0%) | 0.592 / 1.234 |

Limits:

- Four replica objects share one host and synchronization lock, not distributed nodes.
- The stale-version window is intentionally forced; its production frequency is not estimated.
- In-flight requests admitted before revocation may finish; protected cutover waits for them.
- No packet loss, provider convergence or cloud availability claim.

## billing

Article pp. 11. Anomaly detection and quotas can limit wallet abuse, with missed attacks and legitimate drops.

Execution: synthetic labeled demand; actual local function dispatch ledger.

Cost units are modeled, not currency. Rows show means across paired trials. Detection recall/FPR use post-training bucket counts; they do not measure production accuracy.

| Workload | Variant | Attack calls accepted | Legitimate calls rejected | Modeled spend | Alert recall | False alert rate | Mean alert delay (min) |
|---|---|---:|---:|---:|---:|---:|---:|
| legitimate-burst | adaptive-quota | 0.0 | 210.3 | 0.000969 | n/a | 8.0% | none |
| legitimate-burst | alert-only | 0.0 | 0.0 | 0.001179 | n/a | 8.0% | none |
| legitimate-burst | fixed-quota | 0.0 | 420.3 | 0.000759 | n/a | 0.0% | none |
| legitimate-burst | uncontrolled | 0.0 | 0.0 | 0.001179 | n/a | 0.0% | none |
| low-rate-attack | adaptive-quota | 50.0 | 0.0 | 0.000750 | 0.0% | 0.0% | none |
| low-rate-attack | alert-only | 50.0 | 0.0 | 0.000750 | 0.0% | 0.0% | none |
| low-rate-attack | fixed-quota | 50.0 | 0.0 | 0.000750 | 0.0% | 0.0% | none |
| low-rate-attack | uncontrolled | 50.0 | 0.0 | 0.000750 | 0.0% | 0.0% | none |
| slow-ramp | adaptive-quota | 117.0 | 0.0 | 0.000819 | 0.4% | 0.0% | 7.00 |
| slow-ramp | alert-only | 117.0 | 0.0 | 0.000819 | 0.4% | 0.0% | 7.00 |
| slow-ramp | fixed-quota | 116.9 | 0.1 | 0.000819 | 0.0% | 0.0% | none |
| slow-ramp | uncontrolled | 117.0 | 0.0 | 0.000819 | 0.0% | 0.0% | none |
| steady | adaptive-quota | 0.0 | 0.0 | 0.000702 | n/a | 0.0% | none |
| steady | alert-only | 0.0 | 0.0 | 0.000702 | n/a | 0.0% | none |
| steady | fixed-quota | 0.0 | 0.0 | 0.000702 | n/a | 0.0% | none |
| steady | uncontrolled | 0.0 | 0.0 | 0.000702 | n/a | 0.0% | none |
| sustained-attack | adaptive-quota | 628.7 | 169.9 | 0.001161 | 92.0% | 0.0% | 3.00 |
| sustained-attack | alert-only | 2000.0 | 0.0 | 0.002702 | 92.0% | 0.0% | 3.00 |
| sustained-attack | fixed-quota | 441.1 | 192.0 | 0.000951 | 0.0% | 0.0% | none |
| sustained-attack | uncontrolled | 2000.0 | 0.0 | 0.002702 | 0.0% | 0.0% | none |

Alert-only has the same cost as uncontrolled dispatch. Adaptive quotas act in the minute after confirmation. Low-rate and ramp attacks can evade detection; quotas can reject legitimate bursts. See raw buckets for pre-alert excess calls and enforcement delay.

Limits:

- Simulated minutes advance immediately, not a wall-clock load or scalability benchmark.
- No cloud bill, real concurrency quota, network overhead, retries or downstream costs.
- Labels are hidden from enforcement; legitimate bursts can page and lose legitimate requests.
- Bucket labels and repeated fixture trials are correlated; do not treat them as a real-world attack population.
- Demand for all control variants is paired exactly; alert-only never rejects an invocation.

## framework

Article pp. 8–11. Independent audit, approval, policy and telemetry controls change admission and failure behavior.

Execution: integrated local text-document workflow and component ablations.

| Case | Variant | Completed / attempts | Side effect present | Evidence gap on recovery | p50 total (ms) |
|---|---|---|---|---|---|
| artifact-change | full | 0/30 | 0/30 | 0/30 | 2.338 |
| artifact-change | unprotected | 30/30 | 30/30 | 0/30 | 2.822 |
| artifact-change | without-integrity | 30/30 | 30/30 | 0/30 | 3.855 |
| audit-entry-outage | full | 0/30 | 0/30 | 0/30 | 2.439 |
| audit-entry-outage | unprotected | 30/30 | 30/30 | 0/30 | 2.811 |
| audit-entry-outage | without-audit | 30/30 | 30/30 | 0/30 | 2.875 |
| audit-exit-outage | full | 0/30 | 30/30 | 30/30 | 5.375 |
| audit-exit-outage | unprotected | 30/30 | 30/30 | 0/30 | 3.362 |
| audit-exit-outage | without-audit | 30/30 | 30/30 | 0/30 | 3.701 |
| legitimate-workflow | full | 30/30 | 0/30 | 0/30 | 5.051 |
| legitimate-workflow | unprotected | 30/30 | 0/30 | 0/30 | 3.213 |
| policy-expansion | full | 0/30 | 0/30 | 0/30 | 2.587 |
| policy-expansion | unprotected | 30/30 | 0/30 | 0/30 | 2.143 |
| policy-expansion | without-gate | 30/30 | 0/30 | 0/30 | 2.153 |
| private-telemetry | full | 0/30 | 30/30 | 0/30 | 3.951 |
| private-telemetry | unprotected | 30/30 | 30/30 | 0/30 | 2.844 |
| private-telemetry | without-telemetry | 30/30 | 30/30 | 0/30 | 3.967 |
| replaced-target | full | 0/30 | 30/30 | 0/30 | 5.903 |
| replaced-target | unprotected | 30/30 | 0/30 | 0/30 | 3.787 |
| replaced-target | without-broker | 30/30 | 0/30 | 0/30 | 6.084 |
| replayed-grant | full | 0/30 | 0/30 | 0/30 | 5.421 |
| replayed-grant | unprotected | 30/30 | 0/30 | 0/30 | 3.189 |
| replayed-grant | without-broker | 30/30 | 0/30 | 0/30 | 4.427 |
| unapproved-purge | full | 0/30 | 30/30 | 0/30 | 4.057 |
| unapproved-purge | unprotected | 30/30 | 0/30 | 0/30 | 3.254 |
| unapproved-purge | without-broker | 30/30 | 0/30 | 0/30 | 4.290 |
| unsigned-event | full | 0/30 | 0/30 | 0/30 | 2.129 |
| unsigned-event | unprotected | 30/30 | 30/30 | 0/30 | 2.706 |
| unsigned-event | without-integrity | 30/30 | 30/30 | 0/30 | 3.881 |

Completion is the attempted operation, including adversarial operations. Audit fault cases are availability/evidence outcomes, not attack-success rates. Side effects report whether the document exists after the attempted operation (before recovery).

Limits:

- SQLite and trusted Python objects model service boundaries; they are not IAM or process isolation.
- Audit ACK is a FULL synchronous SQLite commit; it is not provider retention or proof against the filesystem owner.
- Replaced-target success measures acceptance of a mismatched grant, not deletion of the replacement in every ablation.
- Fault outcomes report side effects separately; exit audit failure cannot undo committed work.
- Initialization, local storage setup and scenario work are included in total trial timing.

## sensitivity

Article pp. 11. Detector sensitivity and admission budgets trade missed attacks against legitimate rejection.

Execution: paired 3-by-3 detector threshold and invocation quota sweep.

Cost units are modeled, not currency. Rows show means across paired trials. Detection recall/FPR use post-training bucket counts; they do not measure production accuracy.

| Workload | Variant | Attack calls accepted | Legitimate calls rejected | Modeled spend | Alert recall | False alert rate | Mean alert delay (min) |
|---|---|---:|---:|---:|---:|---:|---:|
| legitimate-burst | d2-q10 | 0.0 | 276.7 | 0.000903 | n/a | 11.3% | none |
| legitimate-burst | d2-q20 | 0.0 | 240.6 | 0.000939 | n/a | 11.3% | none |
| legitimate-burst | d2-q40 | 0.0 | 172.0 | 0.001007 | n/a | 11.3% | none |
| legitimate-burst | d4-q10 | 0.0 | 240.9 | 0.000938 | n/a | 8.0% | none |
| legitimate-burst | d4-q20 | 0.0 | 210.3 | 0.000969 | n/a | 8.0% | none |
| legitimate-burst | d4-q40 | 0.0 | 150.3 | 0.001029 | n/a | 8.0% | none |
| legitimate-burst | d6-q10 | 0.0 | 240.9 | 0.000938 | n/a | 8.0% | none |
| legitimate-burst | d6-q20 | 0.0 | 210.3 | 0.000969 | n/a | 8.0% | none |
| legitimate-burst | d6-q40 | 0.0 | 150.3 | 0.001029 | n/a | 8.0% | none |
| low-rate-attack | d2-q10 | 48.8 | 5.6 | 0.000747 | 12.8% | 1.1% | 6.42 |
| low-rate-attack | d2-q20 | 50.0 | 0.0 | 0.000754 | 12.8% | 1.1% | 6.42 |
| low-rate-attack | d2-q40 | 50.0 | 0.0 | 0.000754 | 12.8% | 1.1% | 6.42 |
| low-rate-attack | d4-q10 | 50.0 | 0.0 | 0.000754 | 0.0% | 0.0% | none |
| low-rate-attack | d4-q20 | 50.0 | 0.0 | 0.000754 | 0.0% | 0.0% | none |
| low-rate-attack | d4-q40 | 50.0 | 0.0 | 0.000754 | 0.0% | 0.0% | none |
| low-rate-attack | d6-q10 | 50.0 | 0.0 | 0.000754 | 0.0% | 0.0% | none |
| low-rate-attack | d6-q20 | 50.0 | 0.0 | 0.000754 | 0.0% | 0.0% | none |
| low-rate-attack | d6-q40 | 50.0 | 0.0 | 0.000754 | 0.0% | 0.0% | none |
| slow-ramp | d2-q10 | 83.6 | 56.4 | 0.000729 | 62.4% | 4.9% | 7.30 |
| slow-ramp | d2-q20 | 116.9 | 0.1 | 0.000819 | 62.4% | 4.9% | 7.30 |
| slow-ramp | d2-q40 | 117.0 | 0.0 | 0.000819 | 62.4% | 4.9% | 7.30 |
| slow-ramp | d4-q10 | 117.0 | 0.0 | 0.000819 | 0.0% | 0.0% | none |
| slow-ramp | d4-q20 | 117.0 | 0.0 | 0.000819 | 0.0% | 0.0% | none |
| slow-ramp | d4-q40 | 117.0 | 0.0 | 0.000819 | 0.0% | 0.0% | none |
| slow-ramp | d6-q10 | 117.0 | 0.0 | 0.000819 | 0.0% | 0.0% | none |
| slow-ramp | d6-q20 | 117.0 | 0.0 | 0.000819 | 0.0% | 0.0% | none |
| slow-ramp | d6-q40 | 117.0 | 0.0 | 0.000819 | 0.0% | 0.0% | none |
| steady | d2-q10 | 0.0 | 0.7 | 0.000702 | n/a | 1.3% | none |
| steady | d2-q20 | 0.0 | 0.0 | 0.000703 | n/a | 1.3% | none |
| steady | d2-q40 | 0.0 | 0.0 | 0.000703 | n/a | 1.3% | none |
| steady | d4-q10 | 0.0 | 0.0 | 0.000703 | n/a | 0.0% | none |
| steady | d4-q20 | 0.0 | 0.0 | 0.000703 | n/a | 0.0% | none |
| steady | d4-q40 | 0.0 | 0.0 | 0.000703 | n/a | 0.0% | none |
| steady | d6-q10 | 0.0 | 0.0 | 0.000703 | n/a | 0.0% | none |
| steady | d6-q20 | 0.0 | 0.0 | 0.000703 | n/a | 0.0% | none |
| steady | d6-q40 | 0.0 | 0.0 | 0.000703 | n/a | 0.0% | none |
| sustained-attack | d2-q10 | 404.4 | 201.0 | 0.000903 | 93.6% | 2.1% | 2.60 |
| sustained-attack | d2-q20 | 605.2 | 176.7 | 0.001129 | 93.6% | 2.1% | 2.60 |
| sustained-attack | d2-q40 | 1005.2 | 128.0 | 0.001577 | 93.6% | 2.1% | 2.60 |
| sustained-attack | d4-q10 | 435.3 | 196.7 | 0.000939 | 92.0% | 0.0% | 3.00 |
| sustained-attack | d4-q20 | 632.2 | 173.4 | 0.001159 | 92.0% | 0.0% | 3.00 |
| sustained-attack | d4-q40 | 1024.5 | 125.7 | 0.001599 | 92.0% | 0.0% | 3.00 |
| sustained-attack | d6-q10 | 435.3 | 196.7 | 0.000939 | 92.0% | 0.0% | 3.00 |
| sustained-attack | d6-q20 | 632.2 | 173.4 | 0.001159 | 92.0% | 0.0% | 3.00 |
| sustained-attack | d6-q40 | 1024.5 | 125.7 | 0.001599 | 92.0% | 0.0% | 3.00 |

Alert-only has the same cost as uncontrolled dispatch. Adaptive quotas act in the minute after confirmation. Low-rate and ramp attacks can evade detection; quotas can reject legitimate bursts. See raw buckets for pre-alert excess calls and enforcement delay.

Limits:

- Prespecified settings are reported together; no best configuration is selected on these workloads.
- Independent workload seeds vary traffic within the same five constructed workload families.
- Synthetic buckets and modeled costs do not measure cloud scalability or bills.

## lifecycle

Article pp. 10–11. Key continuity and audited policy history preserve revocation and permit independently authorized recovery after a grant expires.

Execution: two isolated Python interpreters per trial sharing durable local state.

| Variant | Attack acceptance/success | Legitimate completion | Trial p50 / p95 (ms) |
|---|---|---|---|
| durable-restart | n/a | 30/30 (100.0%; 95% CI 88.6–100.0%) | 73.504 / 76.736 |

Limits:

- Normal interpreter exit/restart, not host power loss, filesystem corruption or distributed failover.
- The fixed clock advances from 1000 to 1040 seconds without waiting; this tests expiry semantics.
- Keys remain in an owner-readable mode-0600 file; no external key manager or key rotation is claimed.
- Invocation budgets are process-local and reset on restart; their restart continuity is not evaluated.
- A complete local owner can replace state and keys; independently retained anchors remain necessary.

## robustness

Article pp. 11. A frozen training reference and adapting EWMA differ under legitimate drift and intermittent abuse.

Execution: paired nonstationary and intermittent demand with a fixed-training comparator.

Cost units are modeled, not currency. Rows show means across paired trials. Detection recall/FPR use post-training bucket counts; they do not measure production accuracy.

| Workload | Variant | Attack calls accepted | Legitimate calls rejected | Modeled spend | Alert recall | False alert rate | Mean alert delay (min) |
|---|---|---:|---:|---:|---:|---:|---:|
| flash-crowd | adaptive-quota | 0.0 | 120.1 | 0.001277 | n/a | 7.5% | none |
| flash-crowd | alert-only | 0.0 | 0.0 | 0.001397 | n/a | 7.5% | none |
| flash-crowd | fixed-quota | 0.0 | 298.4 | 0.001099 | n/a | 0.0% | none |
| flash-crowd | training-quota | 0.0 | 120.1 | 0.001277 | n/a | 7.5% | none |
| flash-crowd | uncontrolled | 0.0 | 0.0 | 0.001397 | n/a | 0.0% | none |
| growing-legitimate | adaptive-quota | 0.0 | 0.0 | 0.001420 | n/a | 0.0% | none |
| growing-legitimate | alert-only | 0.0 | 0.0 | 0.001420 | n/a | 0.0% | none |
| growing-legitimate | fixed-quota | 0.0 | 44.6 | 0.001375 | n/a | 0.0% | none |
| growing-legitimate | training-quota | 0.0 | 44.4 | 0.001375 | n/a | 36.1% | none |
| growing-legitimate | uncontrolled | 0.0 | 0.0 | 0.001420 | n/a | 0.0% | none |
| pulsed-attack | adaptive-quota | 840.0 | 0.0 | 0.001836 | 0.0% | 0.0% | none |
| pulsed-attack | alert-only | 840.0 | 0.0 | 0.001836 | 0.0% | 0.0% | none |
| pulsed-attack | fixed-quota | 241.5 | 98.2 | 0.001139 | 0.0% | 0.0% | none |
| pulsed-attack | training-quota | 840.0 | 0.0 | 0.001836 | 0.0% | 0.0% | none |
| pulsed-attack | uncontrolled | 840.0 | 0.0 | 0.001836 | 0.0% | 0.0% | none |
| ramp-attack | adaptive-quota | 220.0 | 0.0 | 0.001215 | 0.0% | 0.0% | none |
| ramp-attack | alert-only | 220.0 | 0.0 | 0.001215 | 0.0% | 0.0% | none |
| ramp-attack | fixed-quota | 218.8 | 1.5 | 0.001212 | 0.0% | 0.0% | none |
| ramp-attack | training-quota | 218.8 | 1.4 | 0.001212 | 31.7% | 0.0% | 26.17 |
| ramp-attack | uncontrolled | 220.0 | 0.0 | 0.001215 | 0.0% | 0.0% | none |
| seasonal-legitimate | adaptive-quota | 0.0 | 0.0 | 0.001075 | n/a | 0.0% | none |
| seasonal-legitimate | alert-only | 0.0 | 0.0 | 0.001075 | n/a | 0.0% | none |
| seasonal-legitimate | fixed-quota | 0.0 | 0.0 | 0.001075 | n/a | 0.0% | none |
| seasonal-legitimate | training-quota | 0.0 | 0.0 | 0.001075 | n/a | 0.0% | none |
| seasonal-legitimate | uncontrolled | 0.0 | 0.0 | 0.001075 | n/a | 0.0% | none |
| stationary | adaptive-quota | 0.0 | 0.0 | 0.000998 | n/a | 0.0% | none |
| stationary | alert-only | 0.0 | 0.0 | 0.000998 | n/a | 0.0% | none |
| stationary | fixed-quota | 0.0 | 0.0 | 0.000998 | n/a | 0.0% | none |
| stationary | training-quota | 0.0 | 0.0 | 0.000998 | n/a | 0.0% | none |
| stationary | uncontrolled | 0.0 | 0.0 | 0.000998 | n/a | 0.0% | none |

Alert-only has the same cost as uncontrolled dispatch. Adaptive quotas act in the minute after confirmation. Low-rate and ramp attacks can evade detection; quotas can reject legitimate bursts. See raw buckets for pre-alert excess calls and enforcement delay.

Limits:

- Six new synthetic workload families, not production traces or an unseen real-world attack sample.
- Added after the initial study; these are disclosed follow-up probes, not a preregistered validation set.
- Training-reference parameters are fixed and all comparator outcomes retained; no best setting selected.
- Detection labels remain hidden; legitimate growth can be flagged and confirmation can miss pulses.
- Only local dispatch and arbitrary cost units; no cloud billing or distributed enforcement.

## Scope of the findings

This evaluation operationalizes selected recommendations. It does not recreate the article's full threat model or prove its qualitative Tables 1 and 2. Provider-only topics remain outside local evidence:

- Hypervisor/container escape and isolation comparisons (Table 2)
- Cloud placement, adversarial co-location, CPU/cache/covert channels
- Real provider IAM convergence and billing
- Vulnerability intelligence for dependencies and production attack prevalence

The events, files, requests and attacks are controlled fixtures. Results describe these fixtures and this host. All affected storage is disposable; existing application data is never read.
