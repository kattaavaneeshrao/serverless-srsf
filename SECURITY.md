# Security scope

This repository is an offline research testbed. Its adversarial inputs are controlled fixtures; workspace markers and dependency artifacts are inert. All experiment workspaces are temporary. Existing `.ssrsf/` application data is preserved but unused.

Python checks and subprocess workspaces are not a sandbox for arbitrary untrusted programs. The harness, credentials, monitor and trusted inventory share the local owner's trust boundary. Hash inventories detect changes but do not establish vulnerability-free software. The response floor is not a constant-time guarantee. Modeled cost is not a bill. See `research/methodology.md` for the declared adversary and measurement limits.

The integrated reference workflow uses trusted Python services and SQLite files in disposable directories. An audit receipt acknowledges a FULL-synchronous SQLite commit, not owner-resistant storage or a tested power-loss guarantee. HMAC chains need an independently retained anchor to detect tail truncation. Audit exit failure can follow committed application/deletion work. Reconciliation reads a committed purge operation without repeating deletion; the current grant-based path requires an unexpired grant. The local exact-rule policy language is not IAM and blocks unsupported cases. All credentials and data in examples are fixtures.
