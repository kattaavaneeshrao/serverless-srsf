# Security scope

The seven controlled benchmarks have a trust boundary at the local process and filesystem owner: fixture identities, shared keys and artifact inventories are trusted. Python authorization is not cloud IAM; subprocess workspaces are not sandboxes for hostile code.

Benchmark markers and dependency artifacts are inert; storage is disposable. Hash inventories detect changes, not vulnerabilities. Side-channel control benchmarks compare exposed traces/timing with uniform traces and role-independent work; real timing remains subject to scheduling noise. Rollout control benchmarks compare stale replicas with a trusted current-policy gate. Billing adds exact credential/permission checks before metered dispatch alongside modeled prices, alerts and quotas. These checks reject unauthorized fixture requests, not abuse using valid invoke credentials, and do not establish production cost protection.

See the [methodology](research/methodology.md) for measurement assumptions and the [README](README.md#implementing-on-serverless-platforms) for the implemented deployment scope. Cloud isolation, durable retention and distributed enforcement require separate implementation and evaluation.

The primary menu routes document work to the Docker reference app and runs the seven control benchmarks without Docker. Automatic startup uses the current user’s Docker access; it does not make the host or Docker administrator untrusted.

## Docker reference app

The `ssrsf.prototype` stack places ingest/extract/classify workers in non-root containers with read-only root filesystems, distinct service credentials and separate internal networks. The trusted guard authenticates service identities; the trusted controller alone holds SQLite storage and the audit key. No worker receives controller credentials or a state mount. Only the guard publishes a host port, bound to loopback. All host/Docker administrators remain trusted.

The controller binds expiring task grants to workflow IDs, immutable document versions, stages and input hashes. Stage advancement, retained idempotent outcomes and HMAC audit events share a transaction. Fixed-window submission quotas persist across restart. A crashed worker's lease expires; an identical committed completion returns the retained outcome. Audit write failure prevents transition commit. These properties do not establish correct computation by a compromised worker or protect availability from a worker that claims and withholds tasks. Each stage identity can claim any ready workflow for that stage; this is a fixture deployment with two document owners and privileged roles, not tenant-isolated worker scheduling.

Local secret files live under ignored mode-0700 directories; each file is mounted read-only only into its required containers. Private-network HTTP uses bearer credentials without TLS. A compromised guard/controller or Docker host is outside the threat model. Audit-tail deletion needs an independently retained checkpoint to detect. No container escape, syscall/TLS interception, DNS/covert-channel prevention or production scalability claim is made. Container tests are separate from the seven original local control benchmarks.

## Restored reference-app controls

Client identities can read/replace only their own documents; administrators can read/replace any document and issue/consume exact-version deletion grants. Investigators can inspect audit/telemetry and reconcile deletion outcomes but cannot read or delete documents. These fixture roles use separately provisioned credentials; the trusted host operator can access them. Administrator approval and execution are not independent human approvals.

Requests are authenticated and carry path-bound body HMACs. Signatures do not encrypt traffic or independently prevent replay. Stage grants, submission IDs and one-use purge grants enforce their own retry/replay contracts. Purge, approval consumption, outcome and audit commit atomically. Reconciliation cannot reexecute deletion. Restrictive policy cutovers persist, explicit deny wins, and permission expansions are held for review. Administrator quota resets are audited.

Image source inventories are established during trusted builds and checked at startup and before work; a trusted rebuild may change the inventory. Hashes do not establish code safety or vulnerability freedom. Workers have bounded scratch tmpfs mounts and report entry/exit inventories. Scratch mismatch evidence is not independent attestation from a compromised worker.
