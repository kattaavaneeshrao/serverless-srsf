#!/usr/bin/env python3
"""Check LaTeX source structure and references."""
import re
import argparse
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--manuscript', type=Path, default=Path(__file__).resolve().parents[1] / 'main.tex')
path = parser.parse_args().manuscript
source = path.read_text()
# Remove comments and inline verbatim before parsing TeX delimiters.
source = re.sub(r'(?<!\\)%[^\n]*', '', source)
source = re.sub(r'\\verb(.).*?\1', '', source)
stack = []
for match in re.finditer(r'\\(begin|end)\{([^}]+)\}', source):
    kind, env = match.groups()
    if kind == 'begin':
        stack.append(env)
    elif not stack or stack.pop() != env:
        raise SystemExit(f'Environment mismatch: {env}')
if stack:
    raise SystemExit(f'Unclosed environments: {stack}')
# Escaped braces and the escape sequence for a literal backslash are not groups.
plain = re.sub(r'\\[{}%\\]', '', source)
depth = 0
for char in plain:
    if char == '{':
        depth += 1
    if char == '}':
        depth -= 1
    if depth < 0:
        raise SystemExit('Unmatched closing brace')
if depth:
    raise SystemExit(f'Unclosed brace groups: {depth}')
labels = re.findall(r'\\label\{([^}]+)\}', source)
if len(labels) != len(set(labels)):
    raise SystemExit('Duplicate labels')
refs = set(re.findall(r'\\(?:ref|pageref)\{([^}]+)\}', source))
if refs - set(labels):
    raise SystemExit(f'Undefined references: {refs - set(labels)}')
bib = set(re.findall(r'\\bibitem\{([^}]+)\}', source))
cites = {key.strip() for group in re.findall(r'\\cite\{([^}]+)\}', source) for key in group.split(',')}
if cites - bib:
    raise SystemExit(f'Undefined citations: {cites - bib}')
if re.search(r'\\(?:input|include|includegraphics)\b', source):
    raise SystemExit('Unexpected external artifact dependency in single-file manuscript')
print(f'Static source checks passed: {len(labels)} labels, {len(cites)} cited sources.')
