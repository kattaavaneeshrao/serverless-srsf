"""Executable local countermeasures, not algorithms attributed to the review."""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import threading
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


class RateDetector:
    """Frozen EWMA; the paper suggests anomaly detection without specifying EWMA."""
    def __init__(self, alpha=.2, deviations=4., confirmations=3):
        if not math.isfinite(alpha) or not 0 < alpha <= 1 or not math.isfinite(deviations) or deviations <= 0:
            raise ValueError("Invalid detector parameters")
        if isinstance(confirmations, bool) or not isinstance(confirmations, int) or confirmations < 1:
            raise ValueError("Invalid confirmation count")
        self.alpha, self.deviations, self.confirmations = alpha, deviations, confirmations
        self.mean, self.variance, self.streak = None, 0., 0

    def observe(self, count: int) -> bool:
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("Count must be a nonnegative integer")
        if self.mean is None:
            self.mean = float(count)
            return False
        if count > self.mean + self.deviations * max(1., math.sqrt(self.variance)):
            self.streak += 1
        else:
            delta = count - self.mean
            self.mean += self.alpha * delta
            self.variance = (1 - self.alpha) * (self.variance + self.alpha * delta * delta)
            self.streak = 0
        return self.streak >= self.confirmations


@dataclass(frozen=True)
class Version:
    name: str
    readers: frozenset[str]


class LocalRollout:
    """Local replica pool; synchronized cutover drains admitted calls.

    One-process synchronization is not a distributed cloud rollout protocol.
    """
    def __init__(self, replicas=4, atomic=False):
        self.replicas = [Version("v1", frozenset({"retired", "active"}))] * replicas
        self.atomic = atomic
        self.lock = threading.RLock()
        self.generation = 1

    def update(self, first_replica_only=False):
        with self.lock:
            replacement = Version("v2", frozenset({"active"}))
            if first_replica_only and not self.atomic:
                self.replicas[0] = replacement
            else:
                self.replicas = [replacement] * len(self.replicas)
            self.generation = 2

    def invoke(self, replica: int, subject: str, admitted=None):
        def execute():
            version = self.replicas[replica]
            allowed = subject in version.readers
            if admitted:
                admitted()
            return {"version": version.name, "allowed": allowed, "generation": self.generation}
        if self.atomic:
            with self.lock:
                return execute()
        return execute()
