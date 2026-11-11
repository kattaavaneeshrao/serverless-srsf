"""Verify image source against the inventory created at image build time."""
import json
from pathlib import Path

from ssrsf.controls import inventory, verify_inventory


def verify_image(root=Path("/app/src"), manifest=Path("/app/integrity.json")):
    if not manifest.is_file() or not verify_inventory(root, json.loads(manifest.read_text())):
        raise RuntimeError('Image artifact integrity failure; rebuild from trusted source')


if __name__ == '__main__':
    Path('/app/integrity.json').write_text(json.dumps(inventory(Path('/app/src')), sort_keys=True))
