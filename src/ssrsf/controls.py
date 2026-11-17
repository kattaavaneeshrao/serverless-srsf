"""Executable local countermeasures, not algorithms attributed to the review."""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from pathlib import Path


class Rejected(ValueError):
    pass


def canonical(event: dict) -> bytes:
    return json.dumps(event, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sign_event(event: dict, key: bytes) -> str:
    return hmac.new(key, canonical(event), hashlib.sha256).hexdigest()


def validate_event(event: object) -> dict:
    if not isinstance(event, dict) or set(event) != {"action", "resource", "value"}:
        raise Rejected("Unexpected event fields")
    if event["action"] != "read" or not isinstance(event["resource"], str):
        raise Rejected("Unsupported operation")
    if not re.fullmatch(r"public/[a-z0-9_-]{1,40}", event["resource"]):
        raise Rejected("Invalid resource")
    if not isinstance(event["value"], str) or len(event["value"]) > 128:
        raise Rejected("Invalid value")
    # Values remain data: never pass to a shell, eval, pickle or a query string.
    return event


def accept_event(event: object, signature: str, key: bytes) -> dict:
    if not isinstance(signature, str) or not isinstance(event, dict):
        raise Rejected("Invalid envelope")
    try:
        expected = sign_event(event, key)
    except (ValueError, TypeError):
        raise Rejected("Noncanonical event") from None
    if not hmac.compare_digest(signature, expected):
        raise Rejected("Event integrity failure")
    return validate_event(event)


@dataclass(frozen=True)
class Identity:
    subject: str
    role: str


class AccessControl:
    """Opaque credentials and exact capabilities checked at every function boundary."""
    def __init__(self, credentials: dict[str, Identity], grants: dict[str, set[tuple[str, str]]]):
        self.credentials = dict(credentials)
        self.grants = {role: frozenset(items) for role, items in grants.items()}

    def authorize(self, credential: str, action: str, resource: str) -> Identity:
        identity = self.credentials.get(credential)
        if identity is None or (action, resource) not in self.grants.get(identity.role, ()):
            raise Rejected("Denied at function boundary")
        return identity


def inventory(root: Path) -> dict[str, str]:
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise Rejected("Symlink in dependency/workspace inventory")
        if path.is_file():
            result[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def verify_inventory(root: Path, expected: dict[str, str]) -> bool:
    try:
        return inventory(root) == expected
    except (OSError, Rejected):
        return False
