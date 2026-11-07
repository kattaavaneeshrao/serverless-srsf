# Security scope

This repository is an offline research testbed. Its adversarial inputs are controlled fixtures; workspace markers and dependency artifacts are inert. All experiment workspaces are temporary. Existing `.ssrsf/` application data is preserved but unused.

Python checks and subprocess workspaces are not a sandbox for arbitrary untrusted programs. The harness, credentials, monitor and trusted inventory share the local owner's trust boundary. Hash inventories detect changes but do not establish vulnerability-free software. The response floor is not a constant-time guarantee. Modeled cost is not a bill. See `research/methodology.md` for the declared adversary and measurement limits.
