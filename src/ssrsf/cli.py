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


def _interactive(defaults=None):
    if defaults is None:
        defaults = argparse.Namespace(trials=30, seed=42, unit_price=.000001,
                                      experiment=None, output=Path("results"))
    print("Serverless SRSF — guided evaluation")
    print("Press Enter to accept a default. Press Ctrl+C to cancel.")
    print("Experiments use built-in test events and attack scenarios.")
    for index, name in enumerate(EXPERIMENTS, 1):
        print(f"  {index}. {name}")
    selected = _prompt("Experiments (all, or comma-separated numbers/names)",
                       ",".join(defaults.experiment) if defaults.experiment else "all", _experiments)
    trials = _prompt("Trials per case (2–200)", defaults.trials, lambda value: _integer(value, 2, 200))
    seed = _prompt("Random seed (0–4294967295)", defaults.seed, lambda value: _integer(value, 0, 2**32 - 1))
    price = _prompt("Modeled cost per invocation (arbitrary cost units)", defaults.unit_price, _price)
    output = _prompt("Output folder (existing report files will be replaced)", defaults.output, _output)
    return argparse.Namespace(trials=trials, seed=seed, unit_price=price,
                              experiment=selected, output=output)


def _run_evaluation(args):
    if not getattr(args, "non_interactive", False):
        print(f"Running {len(args.experiment)} experiments with {args.trials} trials per case…")
    bundle = evaluate(args.trials, args.seed, args.unit_price, args.experiment or EXPERIMENTS)
    write_bundle(bundle, args.output)
    print(f"Completed {len(bundle['experiments'])} local experiments. Report: {args.output / 'report.md'}")
    return 0


def _activity_menu():
    while True:
        print("\nServerless SRSF")
        print("  1. Document workflow\n  2. Experiments\n  3. Quit")
        try:
            choice = _prompt("Choose an activity", 1, lambda value: _integer(value, 1, 3))
            if choice == 3:
                return 0
            if choice == 1:
                from .prototype.client import interactive, start_services
                print("Preparing document services…")
                start_services(reuse=True)
                interactive("http://127.0.0.1:8080", return_to_main=True)
            else:
                _run_evaluation(_interactive())
        except EOFError:
            print("\nSession ended. Document services keep running if already started.")
            return 0
        except KeyboardInterrupt:
            print("\nActivity cancelled. Returning to the main menu.")
        except (ValueError, OSError, RuntimeError) as exc:
            print(f"ssrsf: {exc}", file=sys.stderr)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="ssrsf", description="Interactive document workflow with Docker isolation and seven local security experiments")
    def workflow_options(target):
        source = target.add_mutually_exclusive_group()
        source.add_argument("--text", help="Process text with the local reference implementation (no Docker)")
        source.add_argument("--file", type=Path, help="Process a UTF-8 file with the local reference implementation")
        target.add_argument("--state", type=Path, help="Keep local reference state across runs")

    workflow_options(parser)
    parser.add_argument("--local", action="store_true", help=argparse.SUPPRESS)
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("interactive", help="Choose evaluation settings through guided prompts")
    run = commands.add_parser("evaluate", help="Run paired local experiments and write measured evidence")
    run.add_argument("--non-interactive", action="store_true", help="Run without prompts (for scripts and CI)")
    run.add_argument("--trials", type=int, default=30, help="Repeated trials per case (2–200)")
    run.add_argument("--seed", type=int, default=42)
    run.add_argument("--unit-price", type=float, default=.000001, help="Arbitrary cost units per accepted invocation")
    run.add_argument("--experiment", choices=EXPERIMENTS, action="append", help="Run only these experiments (repeatable)")
    run.add_argument("--output", type=Path, default=Path("results"))
    args = parser.parse_args(argv)
    try:
        if args.command is None:
            if args.local or args.text is not None or args.file is not None or args.state is not None:
                from .console import run as run_console
                return run_console(args)
            return _activity_menu()
        elif args.command == "interactive" or not args.non_interactive:
            args = _interactive(args if args.command == "evaluate" else None)
        return _run_evaluation(args)
    except EOFError:
        print("\nInput ended; evaluation cancelled.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nEvaluation cancelled.", file=sys.stderr)
        return 130
    except (ValueError, OSError, RuntimeError) as exc:
        print(f"ssrsf: {exc}", file=sys.stderr)
        return 1
