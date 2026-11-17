#!/usr/bin/env python3
"""Compatibility commands for Compose checks; use python -m ssrsf for the main menu."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ssrsf.prototype.client import main
from ssrsf.prototype.transport import RemoteError


if __name__ == "__main__":
    try:
        if not sys.argv[1:] or sys.argv[1:] == ["interactive"]:
            from ssrsf.cli import main as application
            raise SystemExit(application([]))
        main()
    except FileNotFoundError:
        raise SystemExit("prototype: Missing credentials; run python3 scripts/prototype.py init first.")
    except (RemoteError, RuntimeError) as exc:
        raise SystemExit(f"prototype: {exc}")
