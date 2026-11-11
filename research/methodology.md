# Methodology

Source: Marin, Perino and Di Pietro (2022), *Serverless computing: a security perspective*, Journal of Cloud Computing 11:69, [DOI](https://doi.org/10.1186/s13677-022-00347-w). `article.json` records the supplied twelve-page PDF’s identity and hash.

The article is a qualitative review with no runnable benchmark or numeric reference results. This project implements selected Section 6 recommendations through a document workflow and seven supporting experiments. The protocols are engineering choices; experiment rates do not measure the integrated application’s end-to-end security. Provider isolation and scheduling comparisons in Tables 1–2 are outside the evaluation.

## Document workflow mapped to the paper

Our security framework applies selected Section 6 concerns through an interactive document workflow. The document pipeline is the framework's working implementation; its design and protocols are our contribution, motivated by the paper. Source: [Marin et al., Section 6](https://link.springer.com/article/10.1186/s13677-022-00347-w), using the subsection titles below and the supplied PDF page numbering.

| Paper subsection | Implementation and boundary | Behavior checked in tests |
|---|---|---|
| Injection, pp. 8–9: validate received events | The Docker controller validates exact submission fields and bounded text. Workers process text as data; SQLite queries use parameters. Separate event fixtures compare unchecked input with schema/HMAC validation. | `test_prototype.py`: malformed schemas and oversized requests; `test_prototype_cli.py`: empty/oversized input and bounded file reads; `test_controls.py`: signed event validation |
| Bypass authentication / Privilege misconfiguration, pp. 8–9: enforce access permissions | The guard authenticates service identities and allows only assigned operations. Workers have separate credentials and networks, and no direct controller storage access. Document reads/replacements enforce ownership, with administrator access across owners. | `test_prototype.py`: credential and role denials; scripted `check`: worker storage, credential and direct TCP probes |
| De-serialization and usage of third-party libraries, p. 9: protect integrity and track components | The separate dependency experiment compares untracked fixture artifacts with a trusted SHA-256 inventory. The Docker reference app separately verifies an image-source inventory established at build time. | `test_controls.py` and `test_experiments.py`: artifact changes and unlisted files |
| Long-lasting attacks, pp. 10–11: monitor reused scratch contents | The separate persistence experiment compares reused subprocess workspaces with monitoring/cleanup and fresh workspaces. These are experimental fixtures, not hostile-code sandboxes. | `test_experiments.py`: cleanup, cache preservation and subprocess execution |
| Billing attacks, p. 11: quotas constrain invocation exposure | The controller persists a cap of 20 submissions/replacements per client per fixed minute; administrator resets are audited. Separate billing fixtures compare alerts, quotas and authorization before metered dispatch. | `test_prototype.py`: quota persistence and idempotent submission; `test_experiments.py`: billing admission and scoring |
| Side channel attacks, pp. 9–10 / Figure 2: traces may expose roles | The separate side-channel experiment compares exposed traces/timing with uniform traces and the same work schedule for both roles. This is not a Docker workflow timing defense. | `test_experiments.py`: disjoint inference splits, balanced roles and uniform work |
| Race conditions, p. 10: stale replicas can retain access | The separate rollout experiment compares stale-replica access with a trusted current-policy admission gate. The Docker prototype has one controller and does not evaluate distributed policy consistency. | `test_experiments.py`: stale replicas and current-policy rejection |

### Workflow protocols

The Docker implementation is the reference app. The interactive menu, scripted commands and Python API all invoke the same role-scoped HTTP operations for reporting, version-bound deletion approval/purge, outcome reconciliation, telemetry, audit receipts, budget reporting/reset and bounded exact-policy deployment. The source inventory is generated in trusted image builds. Request bodies carry path-bound HMACs. Worker scratch entry/exit inventories are stored in audit events; they are worker-reported evidence. `test_reference_app.py` and `test_reference_menu.py` check these controls and interactive flows independently of the seven experiment protocols below.

The Docker controller's task grants and audit protocol are project-specific choices. Grants bind workflow ID, immutable version, stage and input hash, and expire after 30 seconds. Stage advancement, retained completion outcomes and audit events commit in one SQLite transaction. Identical completed requests return their retained outcomes; conflicting requests fail. Audit-write failure rolls back a transition, and startup verifies the audit chain. Detecting removal of a valid audit tail requires an independently retained checkpoint. See `test_prototype.py` for ordering, concurrent completion, lease recovery, quota persistence and audit rollback tests.

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

Attack acceptance and legitimate completion are distinct. Quantiles use linear interpolation; rates use descriptive 95% Wilson intervals. Repeated fixtures and correlated buckets do not estimate attack prevalence or general effectiveness. Reliability evidence covers fixture completion and local timing, not availability SLOs, error budgets or incident recovery. See [SECURITY.md](../SECURITY.md) for the trust boundary and [README.md](../README.md) for usage and the implemented deployment scope.
