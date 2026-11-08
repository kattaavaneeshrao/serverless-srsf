"""Run the Serverless SRSF document workflow and security evaluation."""
from __future__ import annotations

import argparse
import math
import sys
from pathlib import Path

from .evaluation import EXPERIMENTS, evaluate, write_bundle


def _prompt(label, default, parse):
    while True:
        answer = input(f"{label} [{default}]: ").strip()
        try:
            return parse(answer or str(default))
        except ValueError as exc:
            print(f"Invalid input: {exc}")


def _integer(value, low, high):
    try:
        number = int(value)
    except ValueError:
        raise ValueError(f"Enter a whole number from {low} to {high}") from None
    if not low <= number <= high:
        raise ValueError(f"Enter a whole number from {low} to {high}")
    return number


def _price(value):
    try:
        number = float(value)
    except ValueError:
        raise ValueError("Enter a positive number up to 1000000") from None
    if not math.isfinite(number) or not 0 < number <= 1e6:
        raise ValueError("Enter a positive number up to 1000000")
    return number


def _experiments(value):
    if value.lower() == "all":
        return list(EXPERIMENTS)
    selected = []
    for item in value.split(","):
        item = item.strip().lower()
        if item.isdigit() and 1 <= int(item) <= len(EXPERIMENTS):
            item = EXPERIMENTS[int(item) - 1]
        if item not in EXPERIMENTS:
            raise ValueError("Enter all, or experiment numbers/names separated by commas")
        if item in selected:
            raise ValueError("Choose each experiment only once")
        selected.append(item)
    return selected


def _output(value):
    path = Path(value).expanduser()
    if path.exists() and not path.is_dir():
        raise ValueError("Enter a folder path, not an existing file")
    return path


def _interactive():
    print("Serverless SRSF — guided evaluation")
    print("Press Enter to accept a default. Press Ctrl+C to cancel.")
    print("Experiments use built-in test events and attack scenarios.")
    for index, name in enumerate(EXPERIMENTS, 1):
        print(f"  {index}. {name}")
    selected = _prompt("Experiments (all, or comma-separated numbers/names)", "all", _experiments)
    trials = _prompt("Trials per case (2–200)", 30, lambda value: _integer(value, 2, 200))
    seed = _prompt("Random seed (0–4294967295)", 42, lambda value: _integer(value, 0, 2**32 - 1))
    price = _prompt("Modeled cost per invocation (arbitrary cost units)", "0.000001", _price)
    output = _prompt("Output folder (existing report files will be replaced)", "results", _output)
    return argparse.Namespace(trials=trials, seed=seed, unit_price=price,
                              experiment=selected, output=output)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="ssrsf", description="Reusable local document security workflow and evaluation of selected recommendations in Marin et al. (2022)")
    def workflow_options(target):
        source = target.add_mutually_exclusive_group()
        source.add_argument("--text", help="Process this text and print the stored document")
        source.add_argument("--file", type=Path, help="Process a UTF-8 text file")
        target.add_argument("--state", type=Path, help="Keep document workflow state across runs")

    workflow_options(parser)
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("interactive", help="Choose evaluation settings through guided prompts")
    run = commands.add_parser("evaluate", help="Run paired local experiments and write measured evidence")
    run.add_argument("--trials", type=int, default=30, help="Repeated trials per case (2–200)")
    run.add_argument("--seed", type=int, default=42)
    run.add_argument("--unit-price", type=float, default=.000001, help="Arbitrary cost units per accepted invocation")
    run.add_argument("--experiment", choices=EXPERIMENTS, action="append", help="Run only these experiments (repeatable)")
    run.add_argument("--output", type=Path, default=Path("results"))
    args = parser.parse_args(argv)
    try:
        if args.command is None:
            from .console import run as run_console
            return run_console(args)
        if args.command == "interactive":
            args = _interactive()
            print(f"Running {len(args.experiment)} experiments with {args.trials} trials per case…")
        bundle = evaluate(args.trials, args.seed, args.unit_price, args.experiment or EXPERIMENTS)
        write_bundle(bundle, args.output)
    except EOFError:
        print("\nInput ended; evaluation cancelled.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nEvaluation cancelled.", file=sys.stderr)
        return 130
    except (ValueError, OSError, RuntimeError) as exc:
        print(f"ssrsf: {exc}", file=sys.stderr)
        return 1
    print(f"Completed {len(bundle['experiments'])} local experiments. Report: {args.output / 'report.md'}")
    return 0
