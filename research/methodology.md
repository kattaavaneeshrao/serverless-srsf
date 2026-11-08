# Article mapping and experimental protocol

Source: Marin E., Perino D., Di Pietro R. (2022), *Serverless computing: a security perspective*, Journal of Cloud Computing 11:69, DOI [10.1186/s13677-022-00347-w](https://doi.org/10.1186/s13677-022-00347-w). The supplied PDF has twelve pages; `article.json` records its identity and SHA-256.

## Implemented scope

The article calls itself a review. Section 6 describes attacks, suggests countermeasures and identifies research directions. It supplies no runnable artifact, dataset, complete detection algorithm or numeric reference outcomes. Tables 1 and 2 are qualitative comparisons, not benchmark targets.

| Source | Paper recommendation or threat | Local scope |
|---|---|---|
| Injection, pp. 8–9 | Validate all received events, including internal events | Strict consumer schema and data-only handling versus unchecked admission |
| De-serialization, p. 9 | Avoid unsafe handling and protect data against tampering | Canonical JSON authenticated using HMAC; HMAC is an implementation choice, not the paper's digital-signature example |
| Authentication bypass / privilege misconfiguration, pp. 8–9 | Authenticate invocations and minimize permissions | Exact per-function capabilities versus gateway-only authentication and overbroad permissions |
| Third-party libraries, p. 9 | Track dependencies and establish function security perimeters | Trusted SHA-256 artifact inventory; modification and unlisted-artifact checks only |
| Long-lasting attacks, pp. 10–11; warm reuse, p. 8 | Monitor persistent scratch contents or avoid reuse | Real reused/fresh subprocesses and scratch workspaces with a declared cache allowlist |
| Side channels, pp. 9–10 / Figure 2 | Branching traces and metadata can reveal caller roles | Threat demonstration with held-out inference; no added mitigation |
| Race conditions, p. 10 | Partial updates leave old function permissions reachable | Threat demonstration with a partially updated local replica pool; no added mitigation |
| Billing attacks, p. 11 | Spending alerts and quotas exist but have limitations | Fixed closed-bucket spending alert and fixed local invocation quota versus uncontrolled dispatch |
| Section 5 / Tables 1–2 | Isolation and scheduling trade security against performance | Not evaluated; requires platform infrastructure beyond the local testbed |

The paper does not prescribe the schema, cryptographic algorithms, allowlists, numeric thresholds, workload generator or measurement procedures. These are disclosed implementation and evaluation choices required to make the selected recommendations executable. The custom workflow/audit/broker/recovery extensions, EWMA controller, side-channel padding and atomic-cutover defense are outside the current scope and are removed.

## Adversary and controls

The attacker controls selected event fields, direct invocation attempts, artifact bytes, one inert workspace marker, offered invocation volumes and access to stale local replicas. The evaluator, credentials, shared integrity key, inventory and monitor are trusted. All files are disposable. No command payload, unsafe deserialization exploit, malware or network traffic is executed.

Event cases include ordinary values, metacharacters treated as data, internal delete commands, traversal, extra fields, oversized values and transit tampering. Oversize/extra-field events have valid authentication to ensure schema validation is tested separately. Transit tampering retains the original authentication tag. Acceptance means admission of a declared schema/integrity violation, not a successful shell exploit. The same in-memory consumer handles baseline and protected events.

Authorization cases include valid gateway/internal calls, direct unauthenticated entry, forged credentials, forbidden operations and wrong resources. Gateway-only authentication intentionally leaves internal entry unauthenticated and permissions broad. Protected checks require both identity and an exact action/resource grant. This is a Python reference monitor, not protection against an attacker controlling that process.

Dependency cases read actual files. Checks include unchanged bytes, same-size changes with restored modification times and unlisted additions. The inventory is trusted. This does not establish that approved artifacts are vulnerability-free; CVE scanning, signature-chain verification and verify/use races are not evaluated.

Persistence cases use isolated-mode Python subprocesses with empty environments and temporary roots. Warm variants reuse one process/root; fresh execution starts another process/root for subsequent calls. Each variant performs one marker-writing operation and two legitimate calls. Monitoring before/after calls preserves a known bounded cache file and removes unknown files. Unrecognized legitimate files would also be removed. Size checks run after creation and do not enforce an OS disk quota. Total timing includes startup, calls, cleanup and shutdown, not provider cold starts.

## Threat demonstrations

The side-channel observer is assumed to see function names and total response times. Two roles follow the Figure 2 branches, with constructed service delays of 1 ms (user) and 3 ms (administrator). Measured calls are split into independently shuffled balanced training/test sets. A trace classifier learns each trace's majority role; ties choose user. A timing classifier freezes a threshold midway between training role medians and its direction before testing. Test labels are used only for scoring. Results describe this limited attacker and host. No padding, facade or shared-host CPU/cache experiment is included.

The rollout experiment has four replica objects in one process. A partial update changes only one to the version revoking a retired reader. Concurrent calls target all four replicas, and active-reader completion is measured separately. The deliberately reachable stale window demonstrates the paper's concern; it does not estimate production frequency. No atomic-cutover implementation or distributed revocation guarantee is included.

## Billing protocol

Each trial constructs paired 70-bucket traces. Each bucket represents one minute and has uniformly sampled baseline legitimate demand of 8–12 calls. The initial 20 buckets are warmup and excluded from alert-scoring metrics; no detector is trained.

- Steady: baseline only.
- Legitimate burst: 80 extra legitimate calls in buckets 30–35.
- Sustained attack: 80 attack calls in buckets 30–54.
- Low-rate attack: 2 attack calls in buckets 30–54.
- Slow ramp: 1–9 attack calls, increasing every three buckets in buckets 30–54.

Labels are shuffled within each bucket and hidden from controls. All variants receive identical arrivals:

- Uncontrolled: admit every invocation, no alerts.
- Alert-only: admit every invocation and alert when that closed bucket's modeled spend exceeds `20 * unit_price`.
- Fixed quota: admit at most the first 20 invocations per bucket, no detector or automatic alerts.

Each accepted invocation executes the same small arithmetic operation and appends a ledger entry. Cost is accepted calls times an arbitrary supplied unit price (default 0.000001). The alert period and limit are experimental choices. The invocation cap approximates the paper's quota idea; it is not a cloud concurrency quota. No provider pricing, duration/network charges, retries or downstream costs are included.

Confusion metrics compare alerts with whether a post-warmup bucket contains attack calls. A spending alert is not an attack classifier: legitimate bursts can alert, and attack-positive buckets below the limit do not. Uncontrolled/fixed-quota variants have no detector; their zero alert recall must not be interpreted as detection performance. Legitimate rejection and accepted attack work are reported separately. Alert delay counts closed buckets through the first qualifying alert. Enforcement delay records the first applied fixed cap relative to attack onset. Missing alerts/caps retain null delay. Pre-alert accepted attack work includes the confirmation bucket because its calls have already run. Synthetic minutes advance without waiting.

## Reproducibility and interpretation

The CLI defaults to 30 trials per case and seed 42. Stable experiment-index seeds preserve inputs when selecting subsets. Variant order is randomized where multiple variants exist. Timing varies with Python, host scheduling and other activity.

`results.json` retains observations, billing buckets, side-channel splits/predictions, parameters, timestamp, interpreter/platform and source hashes. `metrics.csv` contains aggregates and `report.md` the measured narrative. `SHA256SUMS` binds evidence files. `scripts/validate.py` records test logs and installed interpreter versions against the retained source/evidence; `scripts/check_evidence.py` verifies that binding. Hashes detect changes, not owner-controlled rewriting. Same-host compatibility is not independent replication.

Attack-fixture acceptance and legitimate completion are distinct. Quantiles use linear interpolation; rates have descriptive 95% Wilson intervals. Repeated deterministic fixtures and temporally correlated buckets do not estimate real attack prevalence or general security effectiveness. Tests establish implementation behavior and evidence integrity, separately from empirical results.

Reliability scope is legitimate fixture completion and local execution timing. Production availability SLOs, error budgets, incident recovery, provider IAM convergence, scheduling, co-location and platform isolation are not evaluated.
