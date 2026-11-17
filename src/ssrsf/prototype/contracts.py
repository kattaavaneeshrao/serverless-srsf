"""Shared strict contracts for the Docker reference application."""
import re

STAGES = ("ingest", "extract", "classify")
ID = re.compile(r"[a-zA-Z0-9_-]{1,80}\Z")


class Denied(ValueError):
    pass


def exact(body, fields):
    if not isinstance(body, dict) or set(body) != set(fields):
        raise Denied("Unexpected request fields")


def identifier(value):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise Denied("Invalid identifier")
    return value


