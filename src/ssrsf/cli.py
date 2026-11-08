"""Run the interactive document workflow or local evaluation."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .evaluation import EXPERIMENTS, evaluate, write_bundle


def main(argv=None):
    parser = argparse.ArgumentParser(prog="ssrsf", description="Local reference workflow and security evaluation motivated by Marin et al. (2022)")
    commands = parser.add_subparsers(dest="command", required=True)
    demo = commands.add_parser("demo", help="Process your own text or explore the workflow interactively")
    source = demo.add_mutually_exclusive_group()
    source.add_argument("--text", help="Process this text and print the stored document")
    source.add_argument("--file", type=Path, help="Process a UTF-8 text file")
    demo.add_argument("--state", type=Path, help="Keep demo state in this directory across runs")
    run = commands.add_parser("evaluate", help="Run paired local experiments and write measured evidence")
    run.add_argument("--trials", type=int, default=30, help="Repeated trials per case (2–200)")
    run.add_argument("--seed", type=int, default=42)
    run.add_argument("--floor-ms", type=float, default=8.)
    run.add_argument("--unit-price", type=float, default=.000001, help="Arbitrary cost units per accepted invocation")
    run.add_argument("--experiment", choices=EXPERIMENTS, action="append", help="Run only these experiments (repeatable)")
    run.add_argument("--output", type=Path, default=Path("results"))
    args = parser.parse_args(argv)
    try:
        if args.command == "demo":
            from .demo import run
            return run(args)
        bundle = evaluate(args.trials, args.seed, args.floor_ms, args.unit_price, args.experiment or EXPERIMENTS)
        write_bundle(bundle, args.output)
    except (ValueError, OSError, RuntimeError) as exc:
        print(f"ssrsf: {exc}", file=sys.stderr)
        return 1
    print(f"Completed {len(bundle['experiments'])} local experiments. Report: {args.output / 'report.md'}")
    return 0
