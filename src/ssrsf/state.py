"""Owner-trusted local bootstrap state, never a secret-management service."""
from __future__ import annotations

import json
import os
import secrets
from pathlib import Path

from .controls import Rejected, inventory


def bootstrap(root: Path):
    """Create once; never silently replace keys or trust changed existing bytes.

    Initialization is single-writer. Committed SQLite state without its key file
    is an explicit recovery error. The local owner can still replace both.
    """
    path = root / "trusted-state.json"
    artifacts = root / "artifacts"
    if path.is_symlink():
        raise Rejected("Symlink bootstrap state")
    if path.exists():
        try:
            state = json.loads(path.read_text())
            if set(state) != {"schema", "keys", "inventory"} or state["schema"] != 1:
                raise ValueError("Unknown bootstrap schema")
            if set(state["keys"]) != {"audit", "approval", "events"}:
                raise ValueError("Missing keys")
            keys = {name: bytes.fromhex(value) for name, value in state["keys"].items()}
            if any(len(value) != 32 for value in keys.values()):
                raise ValueError("Invalid key length")
            if not isinstance(state["inventory"], dict):
                raise ValueError("Missing inventory")
            return keys, state["inventory"]
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise Rejected("Invalid trusted state; operator recovery required") from exc
    if (root / "audit.sqlite").exists() or (root / "documents.sqlite").exists() or artifacts.exists():
        raise Rejected("Existing state without keys; refusing silent reinitialization")
    artifacts.mkdir()
    (artifacts / "parser.rules").write_text("utf8-text; max-value=128; whitespace-normalization")
    keys = {name: secrets.token_bytes(32) for name in ("audit", "approval", "events")}
    expected = inventory(artifacts)
    payload = json.dumps({"schema": 1, "keys": {k: v.hex() for k, v in keys.items()}, "inventory": expected})
    # Exclusive creation refuses a competing initializer rather than overwriting it.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    if os.name == "posix":
        directory = os.open(root, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    return keys, expected
