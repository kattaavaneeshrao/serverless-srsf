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

The paper does not prescribe the schema, cryptographic algorithms, allowlists, numeric thresholds, workload generator or measurement procedures. These are disclosed implementation and evaluation choices required to make the selected recommendations executable. The interactive document workflow and its audit, approval, policy and persistent-state components constitute our reusable security framework. The seven supporting experiments evaluate individual paper-related security topics; they do not measure the integrated framework end to end. Extended ablation, lifecycle, sensitivity and robustness studies, the EWMA controller, side-channel padding and the atomic-cutover defense remain excluded.

## Document workflow mapped to the paper

Our security framework applies selected Section 6 concerns through an interactive document workflow. The document pipeline is the framework's working implementation; its design and protocols are our contribution, motivated by the paper. Source: [Marin et al., Section 6](https://link.springer.com/article/10.1186/s13677-022-00347-w), using the subsection titles below and the supplied PDF page numbering.

| Paper subsection | Workflow implementation and boundary | Behavior checked in tests |
|---|---|---|
| Injection, pp. 8–9: validate received events | `ReferenceApp.ingest` calls `accept_event` at the processing boundary, including explicitly supplied internal envelopes. Exact fields, operation, resource and the 128-character limit are checked; text remains data and document SQL uses parameters. Extract/classify are local steps within that boundary, not independently deployed functions. | `test_reference.py`: gateway/internal-envelope rejection; `test_controls.py`: signed malformed events and metacharacters; `test_console.py`: oversized file rejection |
| Bypass authentication / Privilege misconfiguration, pp. 8–9: enforce access permissions | Fixture identity and document ownership checks protect ingestion and reads; the active exact policy guards processing. Purge requires an administrator-bound grant. These Python checks model application authorization, not cloud IAM or separate service identities. | `test_reference.py`: missing credentials, second-user reads/replacements, self-approval, policy revocation and explicit deny |
| De-serialization and usage of third-party libraries, p. 9: protect integrity and track components | Canonical JSON/HMAC authenticates events; a trusted SHA-256 inventory checks the local `parser.rules` artifact. HMAC is our shared-key choice. The artifact is a fixture, not a dependency vulnerability scanner or full SBOM; no arbitrary user objects are deserialized. | `test_reference.py`: changed envelope and artifact rejection; `test_recovery.py`: restart retains artifact trust |
| Long-lasting attacks, pp. 10–11: monitor reused scratch contents | `InvocationEvidence` records scratch inventories at entry and exit and compares the next entry with the previous exit. A mismatch is an audit signal; it neither removes unknown files nor identifies malware. The separate `persistence` experiment evaluates cleanup/fresh-workspace variants. | `test_reference.py`: scratch mismatch, entry/exit failure and evidence-gap behavior |
| Billing attacks, p. 11: quotas constrain invocation exposure | `InvocationBudget` caps admitted ingests at 20 per manually closed bucket. This local call-count cap is our approximation, not a timed rate limit, concurrency quota, spending alert or attack detector. Other API operations are outside this budget; restart and `budget` reset it. | `test_reference.py`: quota rejection preserves the document; explicit reset permits processing |
| Side channel attacks, pp. 9–10 / Figure 2: traces may expose roles | `telemetry` restricts detailed application traces to privileged fixtures. This is our access restriction, not a paper-specified defense or proof against timing, shared-host or metadata inference. The separate `side-channels` experiment demonstrates exposure. | `test_reference.py` and `test_console.py`: user detailed-telemetry rejection |
| Race conditions, p. 10: stale replicas can retain access | The workflow has one local active policy and version-bound deletion. It does not simulate replicated deployment or establish distributed consistency. The separate `rollouts` experiment demonstrates stale-replica access. | `test_reference.py`: policy revocation and replacement-version rejection; `test_experiments.py`: stale replicas |

### Project-specific supporting mechanisms

The HMAC audit chain and acknowledged SQLite receipts support evidence collection; the paper does not prescribe that audit protocol. Entry-audit failure prevents processing, while exit-audit failure can follow committed side effects. Audit-chain verification without an independently retained receipt cannot prove that a valid tail was not removed.

The expiring, exact-version, single-use purge grant and transactional nonce consumption are our concrete deletion protocol. They support authorization and replay resistance but are not an algorithm supplied by the article. `test_reference.py` checks forgery, expiry, substitution, version replacement, concurrent replay and reconciliation.

The policy expansion gate, local dispatch lock and trusted restart state are also our engineering choices. They retain restrictive policy history and prevent silent trust reinitialization; they do not establish cloud-wide revocation, process isolation or disaster recovery. `test_recovery.py` covers restart behavior and missing/changed trust material.

The seven retained experiment groups remain separate measurements of the paper-related topics. Their success rates do not measure end-to-end security of `ReferenceApp`. Workflow behavior is established by the focused tests above. Word-count classification, the one-document slot and CLI commands are workload/UI choices with no claimed security algorithm in the paper.

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
