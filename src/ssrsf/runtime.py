"""Fresh or reused local function processes with bounded monitored scratch state."""
from __future__ import annotations

import json
import selectors
import subprocess
import sys
from pathlib import Path

from .controls import inventory


class FunctionProcess:
    def __init__(self, root: Path, *, monitored=False, max_bytes=4096):
        self.root, self.monitored, self.max_bytes = root, monitored, max_bytes
        root.mkdir(parents=True, exist_ok=True)
        self.quarantined = []
        self.process = subprocess.Popen(
            [sys.executable, "-I", str(Path(__file__).with_name("worker.py")), str(root)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1, env={}, cwd=root,
        )

    def _inspect(self):
        manifests = inventory(self.root)
        for name in manifests:
            path = self.root / name
            allowed = name == "cache.txt" and path.read_bytes() == b"bounded application cache"
            if not allowed or path.stat().st_size > self.max_bytes:
                self.quarantined.append({"path": name, "sha256": manifests[name]})
                path.unlink()

    def invoke(self, operation: str) -> dict:
        if self.monitored:
            self._inspect()
        self.process.stdin.write(json.dumps({"operation": operation}) + "\n")
        self.process.stdin.flush()
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            if not selector.select(timeout=5):
                raise RuntimeError("Function process timed out")
        line = self.process.stdout.readline()
        if not line:
            raise RuntimeError("Function process exited unexpectedly")
        result = json.loads(line)
        if self.monitored:
            self._inspect()
        return result

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
        try:
            self.process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        for pipe in (self.process.stdin, self.process.stdout, self.process.stderr):
            pipe.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
