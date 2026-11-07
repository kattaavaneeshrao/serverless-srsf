"""One local evaluation command; no credentials, services or network required."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .evaluation import EXPERIMENTS, evaluate, write_bundle


def main(argv=None):
    parser = argparse.ArgumentParser(prog="ssrsf", description="Local evaluation of selected serverless security countermeasures (Marin et al., 2022)")
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("evaluate", help="Run paired local experiments and write measured evidence")
    run.add_argument("--trials", type=int, default=30, help="Repeated trials per case (2–200)")
    run.add_argument("--seed", type=int, default=42)
    run.add_argument("--floor-ms", type=float, default=8.)
    run.add_argument("--unit-price", type=float, default=.000001, help="Arbitrary cost units per accepted invocation")
    run.add_argument("--experiment", choices=EXPERIMENTS, action="append", help="Run only these experiments (repeatable)")
    run.add_argument("--output", type=Path, default=Path("results"))
    args = parser.parse_args(argv)
    try:
        bundle = evaluate(args.trials, args.seed, args.floor_ms, args.unit_price, args.experiment or EXPERIMENTS)
        write_bundle(bundle, args.output)
    except (ValueError, OSError, RuntimeError) as exc:
        print(f"ssrsf: {exc}", file=sys.stderr)
        return 1
    print(f"Completed {len(bundle['experiments'])} local experiments. Report: {args.output / 'report.md'}")
    return 0
