"""Fixed subprocess workload. Marker bytes are never imported or executed.

Subprocess/workspace separation is a lifecycle experiment, not a hostile-code sandbox.
"""
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
for line in sys.stdin:
    request = json.loads(line)
    operation = request["operation"]
    if operation == "compromise":
        (root / "implant.marker").write_bytes(b"simulated persistence")
        result = {"marker_written": True}
    elif operation == "legitimate":
        (root / "cache.txt").write_text("bounded application cache")
        result = {"persistent_marker_observed": (root / "implant.marker").exists()}
    else:
        raise ValueError("Unknown fixed workload")
    print(json.dumps(result), flush=True)
