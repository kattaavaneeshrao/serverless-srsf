# Security scope

This repository is an offline testbed for selected threats and recommendations in Marin et al. (2022). All adversarial events are controlled fixtures; workspace markers and dependency artifacts are inert. Experiment storage is temporary. Existing `.ssrsf/` application data is preserved and unused.

The harness, fixture credentials, shared HMAC key, workspace monitor and trusted artifact inventory share the local owner's trust boundary. Python access checks are not cloud IAM. Subprocess/workspace separation is not a sandbox for arbitrary untrusted programs. Hash inventories detect changes, not vulnerabilities or malicious originally approved dependencies.

Side-channel and rollout experiments demonstrate threats without implementing defenses. Billing alerts use a fixed modeled spending limit; quotas use a fixed local invocation cap. Neither classifies individual requests or establishes production protection. Modeled cost is not a provider bill.

See `research/methodology.md` for the adversary assumptions, measurement boundaries and limitations.
