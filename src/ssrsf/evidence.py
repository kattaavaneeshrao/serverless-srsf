"""One source inventory for generating and verifying retained evidence."""
from __future__ import annotations

import hashlib
from pathlib import Path


def source_hashes(root: Path) -> dict[str, str]:
    paths = [*root.glob("src/ssrsf/**/*.py"), *root.glob("tests/*.py"),
             *root.glob("scripts/*.py"), *root.glob("research/*"),
             root / "pyproject.toml", root / "README.md", root / "SECURITY.md"]
    return {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(paths) if path.is_file()}
