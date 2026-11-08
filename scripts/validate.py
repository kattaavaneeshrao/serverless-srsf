#!/usr/bin/env python3
"""Retain interpreter compatibility checks against the current source/evidence.

Runs the Python test suite with each selected interpreter.
"""
import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--python', action='append', dest='interpreters')
    args = parser.parse_args()
    evidence = ROOT / 'results'
    source = json.loads((evidence / 'results.json').read_text())
    for name, digest in source['source_sha256'].items():
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != digest:
            raise ValueError(f'Source changed: {name}; regenerate evaluation first')
    runs = []
    for executable in args.interpreters or [sys.executable]:
        version = subprocess.run([executable, '--version'], capture_output=True, text=True, check=True).stdout.strip()
        start = time.perf_counter()
        command = [executable, '-m', 'unittest', 'discover', '-s', 'tests', '-v']
        environment = {**os.environ, 'PYTHONPATH': str(ROOT / 'src')}
        result = subprocess.run(command, cwd=ROOT, env=environment, capture_output=True, text=True, timeout=180)
        counts = re.findall(r'Ran (\d+) tests?', result.stderr)
        runs.append({'python': version, 'command': command, 'exit_code': result.returncode,
                     'tests': int(counts[-1]) if counts else 0, 'elapsed_seconds': time.perf_counter() - start,
                     'stdout': result.stdout, 'stderr': result.stderr})
        print(f"{version}: {runs[-1]['tests']} tests, exit {result.returncode}")
    payload = {'timestamp_utc': datetime.now(timezone.utc).isoformat(), 'platform': platform.platform(),
               'results_sha256': hashlib.sha256((evidence / 'results.json').read_bytes()).hexdigest(),
               'source_sha256': source['source_sha256'], 'runs': runs,
               'limits': 'Same host; interpreter compatibility, not independent cloud or multi-host validation.'}
    output = evidence / 'validation.json'
    output.write_text(json.dumps(payload, indent=2) + '\n')
    names = {line.split('  ')[1] for line in (evidence / 'SHA256SUMS').read_text().splitlines()}
    names.add(output.name)
    (evidence / 'SHA256SUMS').write_text(''.join(f"{hashlib.sha256((evidence / name).read_bytes()).hexdigest()}  {name}\n" for name in sorted(names)))
    return 0 if all(r['exit_code'] == 0 and r['tests'] > 0 for r in runs) else 1


if __name__ == '__main__':
    raise SystemExit(main())
