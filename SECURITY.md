# Security scope

Serverless SRSF is a local security framework implemented through an interactive document workflow, grounded in selected threats and recommendations in Marin et al. (2022). Seven supporting experiments evaluate individual security topics. All adversarial events are controlled fixtures; workspace markers and dependency artifacts are inert. Experiment storage is temporary. Existing `.ssrsf/` application data is preserved and unused.

The harness, fixture credentials, shared HMAC key, workspace monitor and trusted artifact inventory share the local owner's trust boundary. Python access checks are not cloud IAM. Subprocess/workspace separation is not a sandbox for arbitrary untrusted programs. Hash inventories detect changes, not vulnerabilities or malicious originally approved dependencies.

Side-channel and rollout experiments demonstrate threats without implementing defenses. Billing alerts use a fixed modeled spending limit; quotas use a fixed local invocation cap. Neither classifies individual requests or establishes production protection. Modeled cost is not a provider bill.

See `research/methodology.md` for the adversary assumptions, measurement boundaries and limitations.

The interactive document workflow accepts bounded user-supplied UTF-8 text and may retain it in an explicitly selected `--state` directory. Its credentials are local fixtures, HMAC audit records require independently retained receipts to detect tail truncation, and approval/broker objects are trusted Python components rather than independent OS identities. The fixed ingest quota is reset by `budget` or restart. These local controls do not establish production cloud isolation, durable retention or provider billing protection.
