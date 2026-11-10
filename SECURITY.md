# Security scope

Serverless SRSF is a local document security framework with seven controlled experiments. Its trust boundary is the local process and filesystem owner: fixture identities, approval services, shared keys, audit collector and artifact inventory are trusted. Python authorization is not cloud IAM; subprocess workspaces are not sandboxes for hostile code.

The document workflow accepts bounded UTF-8 text and retains it only when a `--state` directory is selected. Approval is administrator-bound, expiring and single-use. Audit entry failure blocks work; exit failure can leave committed effects requiring reconciliation. Detecting audit-tail removal requires an independently retained receipt. The ingest quota resets with `budget` or restart.

Experiment markers and dependency artifacts are inert; storage is disposable. Existing ignored `.ssrsf/` data is preserved and unused. Hash inventories detect changes, not vulnerabilities. Side-channel experiments compare exposed traces/timing with uniform traces and role-independent work; real timing remains subject to scheduling noise. Rollout experiments compare stale replicas with a trusted current-policy gate. Billing adds exact credential/permission checks before metered dispatch alongside modeled prices, alerts and quotas. These checks reject unauthorized fixture requests, not abuse using valid invoke credentials, and do not establish production cost protection.

See the [methodology](research/methodology.md) for measurement assumptions and the [README](README.md#implementing-on-serverless-platforms) for proposed cloud adaptations. Cloud isolation, durable retention and distributed enforcement require separate implementation and evaluation.
