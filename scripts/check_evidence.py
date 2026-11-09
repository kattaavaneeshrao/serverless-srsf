#!/usr/bin/env python3
"""Verify retained evidence and its binding to current source and test logs."""
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from ssrsf.evaluation import EXPERIMENTS
from ssrsf.evidence import source_hashes


def main():
    evidence = ROOT / 'results'
    expected = {'results.json', 'report.md', 'metrics.csv', 'validation.json'}
    manifest = {}
    for line in (evidence / 'SHA256SUMS').read_text().splitlines():
        digest, name = line.split('  ')
        if name not in expected or name in manifest:
            raise ValueError(f'Unexpected or repeated evidence entry: {name}')
        manifest[name] = digest
        if hashlib.sha256((evidence / name).read_bytes()).hexdigest() != digest:
            raise ValueError(f'Evidence checksum mismatch: {name}')
    if set(manifest) != expected:
        raise ValueError('Evidence manifest is incomplete')
    bundle = json.loads((evidence / 'results.json').read_text())
    if tuple(bundle['experiments']) != EXPERIMENTS:
        raise ValueError('Retained experiments do not match the current paper scope')
    current = source_hashes(ROOT)
    if current != bundle['source_sha256']:
        raise ValueError('Source inventory changed; regenerate evaluation and validation')
    validation = json.loads((evidence / 'validation.json').read_text())
    if validation['results_sha256'] != manifest['results.json']:
        raise ValueError('Validation refers to different results')
    if validation['source_sha256'] != current or not validation['runs']:
        raise ValueError('Validation source record mismatch')
    if any(r['exit_code'] != 0 or r['tests'] <= 0 for r in validation['runs']):
        raise ValueError('Recorded tests did not pass')
    print('Seven paper-scoped experiments, evidence hashes and recorded tests verified.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
