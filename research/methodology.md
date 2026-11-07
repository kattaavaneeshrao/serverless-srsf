# Article mapping and experimental protocol

Source: Marin E., Perino D., Di Pietro R. (2022), *Serverless computing: a security perspective*, Journal of Cloud Computing 11:69, DOI [10.1186/s13677-022-00347-w](https://doi.org/10.1186/s13677-022-00347-w). The supplied PDF has twelve pages. Its identity and SHA-256 are recorded in `article.json`.

## What is being implemented

The paper calls itself a review. Section 6 outlines application- and infrastructure-level attacks, countermeasures and research directions. It supplies no train/test dataset, detection algorithm, runnable artifact, numeric attack-success results or latency targets. Table 1 (p. 6) qualitatively compares monoliths, microservices and serverless. Table 2 (p. 7) qualitatively compares execution environments. This project neither invents numeric values for those tables nor labels local observations as reproduced article results.

The implemented approach is an operationalization of selected countermeasures and open questions:

| Source | Claim/recommendation | Testable local hypothesis | Status |
|---|---|---|---|
| Section 6, Injection, pp. 8–9 | Validate all events, including trusted internal sources | A consumer-side schema rejects internal malicious command envelopes and malformed resources | Executed |
| Section 6, De-serialization, p. 9 | Minimize unsafe deserialization and protect data integrity | A canonical authenticated JSON envelope rejects modified data; payload strings remain data | Executed; HMAC instead of the paper's example of digital signatures |
| Section 6, Bypass authentication / Privilege misconfiguration, pp. 8–9 | Authenticate invocation and minimize permissions | Direct internal invocation and overprivileged resource access fail at a per-function guard | Executed with a Python reference monitor |
| Section 6, Third-party libraries, p. 9 | Track dependencies and establish function security perimeters | Changed or unlisted dependency artifacts fail a trusted inventory check | Executed; does not establish vulnerability-free dependencies |
| Section 6, Side channels, pp. 9–10 / Figure 2 | Branching sequences and invocation metadata can reveal roles | Traces/timing allow held-out role inference; restricting traces and padding reduces exposed signal | Executed with constructed delays and a declared observer; mitigation is a project design |
| Section 6, Race conditions, p. 10 | Mixed versions/configurations can retain revoked access | Partial local updates expose revoked readers; atomic cutover and draining eliminate tested post-cutover access | Executed with actual threads; the lock is a local countermeasure design |
| Section 6, Long-lasting attacks, pp. 10–11 | Warm scratch state can retain attacks; monitor contents after calls and minimize storage | A marker survives unmonitored reuse and is removed by fixed-content inspection or discarded by a fresh workspace | Executed with actual subprocesses and files; no arbitrary malicious code |
| Section 6, Billing attacks, p. 11 | Alerts/quotas need abnormal-behavior detection and careful treatment of legitimate traffic | Count anomalies can trigger mitigation and reduce accepted attack work, while bursts and slow attacks reveal tradeoffs | Executed local dispatcher, synthetic labeled demand, modeled price |
| Section 5, pp. 6–8 / Tables 1–2 | Platform isolation and scheduling involve security/performance/cost tradeoffs | Would require multiple isolation platforms and realistic placement behavior | Not evaluated; no provider-level results inferred |

## Controls and adversary boundaries

The attacker controls selected event fields, direct invocation attempts, one fixed workspace-writing operation, dependency artifact bytes, request arrival volumes and a local stale-replica selection. The experiment harness, credential map, HMAC key, trusted inventory, monitor and evaluator are trusted. Files are disposable. Markers are inert; no shell payload, deserialization exploit, downloaded code, malware, credential theft or network traffic is executed.

Event outcomes measure admission of a declared schema/integrity violation, not successful shell injection. Valid metacharacter values are accepted as data. Oversize/extra-field events are signed by a simulated internal producer to ensure signatures do not replace schema checks. Transit modifications retain the old signature. The same in-memory consumer executes admitted baseline/protected events.

Authorization cases use exact action/resource capabilities. A gateway-only baseline deliberately leaves internal queue entry unauthenticated and its function role overbroad. The countermeasure checks both identity and permission at the consumer. This is an executable local model of the access boundary, not isolation from an attacker controlling the Python process.

Artifact checks hash bytes, including a same-size change with restored mtime. Unlisted additions invalidate the inventory. The inventory is trusted. This is not CVE scanning, signature-chain verification or a defense against malicious originally approved packages. Concurrent writers and verify/use races are outside this fixture.

Workspace tests start isolated-mode Python subprocesses with empty environments and separate temporary roots. Warm modes reuse one worker; fresh mode uses a second worker/root for subsequent calls. All variants run one marker-writing call and two legitimate calls. Monitoring before/after calls retains only a known bounded cache file and records hashes of removed unknown files. Unrecognized legitimate files would also be removed. Size checks apply to observed files after creation; they do not enforce an OS disk quota or prevent transient resource exhaustion. Lifecycle timing includes worker startup/shutdown and all operations, not provider cold starts.

The side-channel observer sees exported trace labels and total wall-clock response time. Baseline internal names expose the Figure 2 role split. The facade exports one common name. Two roles have deliberately different sleep-based service times (1 ms and 3 ms), measured rather than substituted as output. The shared floor is configurable, default 8 ms. A third variant (`facade-deadline`) sleeps until near an absolute monotonic deadline, then spins toward that deadline for up to the final 2 ms. It is evaluated separately because simple relative sleeps can have role-dependent overshoot on some operating systems. Process CPU time is retained alongside wall-clock latency, exposing the spin cost. Neither padding method is asserted to be constant-time. Delays beyond the floor remain observable. Training/test schedules independently shuffle balanced role/variant pairs. The trace classifier maps each training trace to its majority role; ties choose user. The timing classifier fixes a threshold halfway between training role medians and selects direction from those medians. Accuracy is scored on held-out calls without retuning. This limited attacker is not an optimal timing attacker.

Rollout tests model four replicas as objects in one process. The baseline updates one of four replicas, deliberately creating a reachable stale-version window. Concurrent calls target each replica. A second test blocks a preauthorized request while another thread attempts full revocation. The baseline may finish cutover before the old admitted request resumes. The protected implementation holds one dispatch lock through admitted work and updates code/permissions as one immutable version snapshot; cutover waits for old requests to finish. An old request completed before cutover is not counted as a post-cutover violation. Thread events force the opportunity rather than estimating its frequency. Atomic locking can reduce throughput; measured trial duration includes thread setup and deliberate waiting, not an availability SLO.

## Billing protocol

Each trial constructs paired traces of 70 synthetic one-minute buckets. Baseline demand is a seeded uniform integer from 8 to 12. The first 20 buckets are marked training and excluded from detection accuracy; the detector continues normal baseline learning on subsequent non-anomalous buckets.

- Steady: baseline demand only.
- Legitimate burst: 80 extra legitimate calls in buckets 30–35.
- Sustained attack: 80 malicious calls in buckets 30–54.
- Low-rate attack: 2 malicious calls in buckets 30–54.
- Slow ramp: malicious calls rise from 1 to 9, increasing every three buckets, in buckets 30–54.

Ground-truth labels are shuffled within each bucket and used only for scoring. The detector sees offered invocation counts. EWMA alpha is 0.2; candidate anomalies exceed mean plus four times the larger of 1 or estimated standard deviation. Three consecutive candidates confirm an alert; anomalous observations do not train the baseline. An alert clears on a non-anomalous bucket.

All variants receive identical arrival order within a trial:

- Uncontrolled: dispatch everything, no detector.
- Alert-only: detect but dispatch everything.
- Adaptive quota: after an alert, admit at most 20 invocations in the next bucket. Otherwise dispatch everything.
- Fixed quota: always admit at most 20 invocations per bucket.

Each accepted call executes a small deterministic arithmetic function and appends a ledger entry. Accepted-call counts and checksums are retained. Aggregate bucket records retain offered/accepted/rejected counts separately for attack and legitimate traffic. The quota is a local per-minute admission budget, not AWS concurrency control. Offered counts remain observable even after rejection, so enforcement does not hide attack demand from the detector.

Cost is accepted invocations times a supplied arbitrary unit price, default 0.000001. No provider cost is claimed; computation duration, network, retries, queueing, minimum billing units and downstream services are excluded. Alert delay counts completed buckets through confirmation (three for an immediate sustained spike); enforcement delay counts minute boundaries from first attack to first applied quota. Pre-alert attack invocations include the confirmation bucket because it has already executed. Missing alerts retain `null` delay and all accepted attack calls as pre-alert work.

Detection confusion matrices score whether a post-training bucket contains any malicious invocation. A legitimate burst can therefore produce false alerts; a mixed bucket counts as attack-positive. This is bucket detection, not request classification. Legitimate drops and accepted malicious requests are separate outcomes. Fixed quotas have no detector and should not be interpreted as successful alerting.

## Reproducibility and interpretation

The CLI defaults to thirty trials per case, seed 42. Each experiment derives a stable seed from its fixed index; selecting a subset preserves that experiment's input stream. Variant order is randomized. Real timings are not deterministic and may change with Python version, OS, scheduler noise and concurrent activity.

`results.json` retains all trial/case/variant observations, billing buckets, side-channel training/test samples and predictions, parameters, timestamp, interpreter/platform and source hashes. `metrics.csv` exports aggregates. `report.md` explains results and limits. `SHA256SUMS` binds the three outputs; hashes detect changes, not malicious rewriting by the local owner.

Attack and legitimate completion rates are reported separately. Timing quantiles use linear interpolation between ordered observations. Proportions include descriptive 95% Wilson score intervals. Repeated deterministic cases are not independent samples from real attack traffic; bucket observations are temporally correlated. Intervals do not prove broad protection. The important comparison is the paired fixture behavior and its explicitly measured tradeoffs. Timing leakage and evasive attacks are findings, not conditions to hide or tune away.

Tests validate guards against adversarial inputs, hash changes with preserved metadata, worker cleanup and cache retention, held-out attacker fitting, actual in-flight revocation, cost conservation, confirmation/enforcement ordering, false-positive bursts, low-rate misses and evidence checksums. CI reruns tests and a fresh evidence bundle. Test success establishes implementation behavior; it is distinct from empirical attack metrics.
