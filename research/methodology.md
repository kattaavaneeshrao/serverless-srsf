# Methodology

Source: Marin, Perino and Di Pietro (2022), *Serverless computing: a security perspective*, Journal of Cloud Computing 11:69, [DOI](https://doi.org/10.1186/s13677-022-00347-w). `article.json` records the supplied twelve-page PDF’s identity and hash.

The article is a qualitative review with no runnable benchmark or numeric reference results. This project implements selected Section 6 recommendations through a document workflow and seven supporting experiments. The protocols are engineering choices; experiment rates do not measure the integrated application’s end-to-end security. Provider isolation and scheduling comparisons in Tables 1–2 are outside the evaluation.

## Document workflow mapped to the paper

Our security framework applies selected Section 6 concerns through an interactive document workflow. The document pipeline is the framework's working implementation; its design and protocols are our contribution, motivated by the paper. Source: [Marin et al., Section 6](https://link.springer.com/article/10.1186/s13677-022-00347-w), using the subsection titles below and the supplied PDF page numbering.

| Paper subsection | Workflow implementation and boundary | Behavior checked in tests |
|---|---|---|
| Injection, pp. 8–9: validate received events | `ReferenceApp.ingest` calls `accept_event` at the processing boundary, including explicitly supplied internal envelopes. Exact fields, operation, resource and the 128-character limit are checked; text remains data and document SQL uses parameters. Extract/classify are local steps within that boundary, not independently deployed functions. | `test_reference.py`: gateway/internal-envelope rejection; `test_controls.py`: signed malformed events and metacharacters; `test_console.py`: oversized file rejection |
| Bypass authentication / Privilege misconfiguration, pp. 8–9: enforce access permissions | Fixture identity and document ownership checks protect ingestion and reads; the active exact policy guards processing. Purge requires an administrator-bound grant. These Python checks model application authorization, not cloud IAM or separate service identities. | `test_reference.py`: missing credentials, second-user reads/replacements, self-approval, policy revocation and explicit deny |
| De-serialization and usage of third-party libraries, p. 9: protect integrity and track components | Canonical JSON/HMAC authenticates events; a trusted SHA-256 inventory checks the local `parser.rules` artifact. HMAC is our shared-key choice. The artifact is a fixture, not a dependency vulnerability scanner or full SBOM; no arbitrary user objects are deserialized. | `test_reference.py`: changed envelope and artifact rejection; `test_recovery.py`: restart retains artifact trust |
| Long-lasting attacks, pp. 10–11: monitor reused scratch contents | `InvocationEvidence` records scratch inventories at entry and exit and compares the next entry with the previous exit. A mismatch is an audit signal; it neither removes unknown files nor identifies malware. The separate `persistence` experiment evaluates cleanup/fresh-workspace variants. | `test_reference.py`: scratch mismatch, entry/exit failure and evidence-gap behavior |
| Billing attacks, p. 11: quotas constrain invocation exposure | `InvocationBudget` caps admitted ingests at 20 per manually closed bucket. This local call-count cap is our approximation, not a timed rate limit, concurrency quota, spending alert or attack detector. Other API operations are outside this budget; restart and `budget` reset it. | `test_reference.py`: quota rejection preserves the document; explicit reset permits processing |
| Side channel attacks, pp. 9–10 / Figure 2: traces may expose roles | `telemetry` restricts detailed application traces to privileged fixtures. This is our access restriction, not a paper-specified defense or proof against timing, shared-host or metadata inference. The separate `side-channels` experiment compares exposure with uniform public traces and work schedules. | `test_reference.py` and `test_console.py`: user detailed-telemetry rejection |
| Race conditions, p. 10: stale replicas can retain access | The workflow has one local active policy and version-bound deletion. It does not simulate replicated deployment or establish distributed consistency. The separate `rollouts` experiment compares stale-replica access with a current-policy admission gate. | `test_reference.py`: policy revocation and replacement-version rejection; `test_experiments.py`: stale replicas |

### Supporting protocols

Audit, purge grants, policy gating and restart trust are project-specific protocols. Entry-audit failure prevents work; exit failure can follow committed side effects. Detecting a removed audit tail requires an independently retained receipt. Purge grants bind requester, exact versions, operation, nonce and expiry; consumption and deletion share one SQLite transaction. Policy history survives restart, but the local dispatch lock does not provide distributed revocation. See `test_reference.py` and `test_recovery.py` for these behaviors.

## Experimental controls

Experiment code lives in `src/ssrsf/experiments/`. The attacker controls selected event fields, invocation attempts, artifact bytes, an inert scratch marker, offered demand and access to stale replicas. The evaluator, fixture credentials, integrity keys, inventory and monitor are trusted. Experiments use disposable storage; no payload strings or marker bytes are executed as code.

### Events, authorization and dependencies

- **Events:** compare the same consumer with unchecked input and schema/HMAC validation. Cases include ordinary values, metacharacters as data, internal delete commands, resource traversal, extra fields, oversized values and transit tampering. Oversized/extra-field fixtures have valid authentication; transit tampering retains the original tag. Acceptance records a schema/integrity violation, not a shell exploit.
- **Authorization:** compare gateway-only authentication and broad permissions with identity plus exact action/resource checks. Cases include legitimate gateway/internal calls, unauthenticated direct calls, forged credentials, forbidden actions and wrong resources. Checks run in Python, not cloud IAM.
- **Dependencies:** read real fixture files and compare untracked artifacts with a trusted SHA-256 inventory. Cases include unchanged bytes, same-size modification with restored timestamps and unlisted files. Vulnerability scanning, signature chains and verify/use races are not evaluated.

### Persistence

Warm variants reuse one isolated-mode Python subprocess and temporary workspace; fresh mode starts a second process/workspace. Each variant performs one marker-writing call and two legitimate calls. Processes have empty environments. Monitoring before/after calls removes unknown files and preserves only the known bounded cache; it would remove unrecognized legitimate files too. Size checks occur after creation, not through an OS disk quota. Timing includes startup, calls, cleanup and shutdown, not provider cold starts.

### Side channels and rollouts

The side-channel observer sees function names and total response time. User/admin branches have constructed 1 ms/3 ms delays. Training and test calls are disjoint, balanced and independently shuffled. The trace classifier learns the majority role per trace (ties choose user). The timing classifier freezes a threshold halfway between training-role medians and its direction before testing. Test labels are scoring-only. The protected `uniform-workflow` variant exposes only authenticate/process/complete and executes the same 1 ms then 3 ms schedule for both roles. It removes the constructed role-dependent branch; real elapsed times are recorded without rounding, substitution or label-dependent adjustment. The same classifiers score both variants. Trace accuracy is exactly chance on balanced fixtures; timing accuracy varies with host scheduling and is not a proof against all timing inference. There is no shared-host CPU/cache experiment.

The rollout experiment updates one of four replica objects to revoke a retired reader. Concurrent calls target all replicas; active-reader completion is recorded separately. The paired `current-policy-gate` variant keeps that same forced stale window but checks a trusted current reader policy at every replica invocation as well as the replica's own permission set. Retired readers are rejected before work, while active readers remain admitted. This local shared policy is an engineering defense, not a distributed consensus protocol or an estimate of production frequency.

## Billing protocol

Each trial uses the same 70 synthetic minute buckets for every variant. Baseline legitimate demand is uniformly sampled from 8–12 calls per bucket. The initial 20 buckets are warmup, excluded from alert scoring; no detector is trained.

| Workload | Demand added to baseline |
|---|---|
| Steady | None |
| Legitimate burst | 80 legitimate calls in buckets 30–35 |
| Sustained attack | 80 attack calls in buckets 30–54 |
| Low-rate attack | 2 attack calls in buckets 30–54 |
| Slow ramp | 1–9 attack calls, increasing every three buckets in buckets 30–54 |

Arrivals are shuffled within each bucket. Each arrival carries a credential independently of its scoring label. Legitimate fixtures carry a customer credential with exact invoke permission. Attack fixtures cycle through forged, revoked and authenticated read-only credentials. Attack labels are used only for scoring, never for admission; tests swap labels to verify the decision does not change.

| Variant | Admission and notification |
|---|---|
| Uncontrolled | Admit every call; no alerts |
| Alert-only | Admit every call; alert when closed-bucket spend exceeds `20 * unit_price` |
| Fixed quota | Admit the first 20 calls per bucket; no detector or alerts |
| Authenticated quota | Check credential and exact invoke permission before dispatch; admit at most 20 authorized calls per bucket. Rejected credentials do not consume the cap; no spending alerts |

Every admitted call executes the same arithmetic operation and adds a ledger entry. Modeled spend is admitted calls times `unit_price` (default `0.000001` arbitrary units). Synthetic minutes advance immediately. Provider pricing, duration/network charges, retries and downstream costs are excluded; the cap is not a provider concurrency quota.

Confusion metrics score alerts against attack-positive post-warmup buckets. Legitimate bursts can alert; low-rate attacks can remain below the limit. Only alert-only emits spending alerts, so zero alert recall for admission-control variants is not detector performance. Authenticated quota rejects unauthorized requests even below the rate threshold; stolen invoke credentials and authorized abuse remain subject only to the quota. Authentication and rejected-request infrastructure costs are outside the dispatch ledger. Accepted attack work and legitimate rejection are separate outcomes.

Alert delay counts closed buckets through the first alert after attack onset. Enforcement delay measures the first applied cap or authorization rejection relative to onset. Missing alerts/caps have null delays. Pre-alert accepted attack work includes the confirmation bucket because its calls have already run.

## Reproducibility and interpretation

Default runs use 30 trials and seed 42. Stable experiment-index seeds preserve inputs when selecting subsets; variant order is randomized where applicable. Host scheduling, interpreter and load affect timing.

- `results.json`: raw observations, billing buckets, inference splits/predictions, parameters, environment and source hashes.
- `metrics.csv` and `report.md`: aggregate measurements and their interpretation.
- `validation.json`: interpreter versions and test logs bound to the source/results.
- `SHA256SUMS`: evidence-file checksums.

`ssrsf.evidence.source_hashes` defines the shared source inventory, including nested experiment modules. `scripts/validate.py` records tests; `scripts/check_evidence.py` verifies the retained bundle. Hashes detect changes, not owner-controlled rewriting. Same-host compatibility is not independent replication.

Attack acceptance and legitimate completion are distinct. Quantiles use linear interpolation; rates use descriptive 95% Wilson intervals. Repeated fixtures and correlated buckets do not estimate attack prevalence or general effectiveness. Reliability evidence covers fixture completion and local timing, not availability SLOs, error budgets or incident recovery. See [SECURITY.md](../SECURITY.md) for the trust boundary and [README.md](../README.md) for usage and proposed cloud ports.
