"""Reproducible experiment orchestration and portable evidence bundle."""
from __future__ import annotations

import csv
import hashlib
import json
import math
import platform
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .application import authorization, dependencies, events
from .billing import billing
from .infrastructure import persistence, rollouts, side_channels
from .integration import framework
from .sensitivity import sensitivity
from .metrics import latency, proportion

PAPER = {"title": "Serverless computing: a security perspective", "authors": "Marin, Perino, Di Pietro",
         "year": 2022, "doi": "10.1186/s13677-022-00347-w",
         "url": "https://doi.org/10.1186/s13677-022-00347-w", "type": "review",
         "numerical_reference_results": None}
EXPERIMENTS = ("events", "authorization", "dependencies", "persistence", "side-channels", "rollouts", "billing", "framework", "sensitivity")


def summarize(experiment):
    rows = experiment["observations"]
    summary = {}
    for variant in sorted({r["variant"] for r in rows}):
        selected = [r for r in rows if r["variant"] == variant]
        item = {"observations": len(selected), "latency": latency([r["latency_ms"] for r in selected])}
        attacks = [r for r in selected if r.get("attack")]
        legitimate = [r for r in selected if "legitimate_succeeded" in r and (not r.get("attack") or "accepted" not in r)]
        if attacks:
            item["attack_success"] = proportion(sum(r["attack_succeeded"] for r in attacks), len(attacks))
        if legitimate:
            item["legitimate_success"] = proportion(sum(r["legitimate_succeeded"] for r in legitimate), len(legitimate))
        summary[variant] = item
    return summary


def evaluate(trials=30, seed=42, floor_ms=8., unit_price=.000001, selected=EXPERIMENTS):
    if isinstance(trials, bool) or not isinstance(trials, int) or not 2 <= trials <= 200:
        raise ValueError("Use 2–200 trials")
    if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed <= 2**32 - 1:
        raise ValueError("Seed must be an integer in [0, 2^32 - 1]")
    if not math.isfinite(floor_ms) or not 1 <= floor_ms <= 100:
        raise ValueError("Timing floor must be 1–100 ms")
    if not math.isfinite(unit_price) or not 0 < unit_price <= 1e6:
        raise ValueError("Unit price must be finite and positive (at most 1e6)")
    if not selected or len(set(selected)) != len(selected) or any(name not in EXPERIMENTS for name in selected):
        raise ValueError("Choose unique known experiments")
    runners = {"events": lambda s: events(trials, s), "authorization": lambda s: authorization(trials, s),
               "dependencies": lambda s: dependencies(trials, s), "persistence": lambda s: persistence(trials, s),
               "side-channels": lambda s: side_channels(trials, s, floor_ms),
               "rollouts": lambda s: rollouts(trials, s), "billing": lambda s: billing(trials, s, unit_price),
               "framework": lambda s: framework(trials, s), "sensitivity": lambda s: sensitivity(trials, s, unit_price)}
    results = {}
    for name in selected:
        # Stable per-experiment seeds: selecting a subset does not change its inputs.
        experiment_seed = seed + EXPERIMENTS.index(name)
        results[name] = {"seed": experiment_seed, **runners[name](experiment_seed)}
        results[name]["summary"] = summarize(results[name])
    return {"schema": "serverless-security-review.local.v1", "package_version": __version__, "paper": PAPER,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "environment": {"python": sys.version, "platform": platform.platform(), "machine": platform.machine()},
            "configuration": {"trials": trials, "seed": seed, "floor_ms": floor_ms, "unit_price": unit_price,
                              "experiments": list(selected)},
            "interpretation": "Tests selected qualitative hypotheses in a constructed local testbed; not reproduction of numerical paper results.",
            "unimplemented_provider_topics": ["Hypervisor/container escape and isolation comparisons (Table 2)",
                "Cloud placement, adversarial co-location, CPU/cache/covert channels", "Real provider IAM convergence and billing",
                "Vulnerability intelligence for dependencies and production attack prevalence"],
            "experiments": results}


def _rate(metric):
    if metric["rate"] is None:
        return "n/a"
    lo, hi = metric["wilson95"]
    return f'{metric["count"]}/{metric["total"]} ({100 * metric["rate"]:.1f}%; 95% CI {100 * lo:.1f}–{100 * hi:.1f}%)'


def render_report(bundle):
    config = bundle["configuration"]
    lines = ["# Local serverless security evaluation", "", f'Article: [{PAPER["title"]}]({PAPER["url"]}), Marin et al. (2022).', "",
             "The article is a review with qualitative comparisons and countermeasure suggestions. It supplies no numerical benchmark results to reproduce. These are newly measured local experiments, with explicitly constructed workloads.", "",
             f'Run: {bundle["timestamp_utc"]}; {config["trials"]} trials; seed {config["seed"]}; Python {platform.python_version()}.', "",
             "Raw observations, configuration, machine details and source hashes are in `results.json`. `metrics.csv` contains aggregate rates/timings. Timings include initialization and vary by host. Binomial Wilson intervals are descriptive; repeated fixtures and correlated buckets do not establish population effectiveness.", ""]
    for name, experiment in bundle["experiments"].items():
        lines += [f"## {name}", "", f'Article pp. {experiment["paper_pages"]}. {experiment["hypothesis"]}', "", f'Execution: {experiment["kind"]}.', ""]
        if name == "side-channels":
            lines += ["Attacker training and testing use different calls. Both splits contain equal numbers of roles. Chance accuracy is 50%.", "",
                      "| Variant | Trace role accuracy | Held-out timing role accuracy | Response p50 / p95 (ms) | Mean CPU (ms) |", "|---|---|---|---|---|"]
            for variant, metric in experiment["metrics"].items():
                t = metric["latency"]
                lines.append(f'| {variant} | {_rate(metric["trace_attacker_accuracy"])} | {_rate(metric["timing_attacker"]["held_out_accuracy"])} | {t["p50_ms"]:.3f} / {t["p95_ms"]:.3f} | {metric["mean_cpu_ms"]:.3f} |')
            lines += ["", "Trace protection here comes from restricting the observer's exported names. A response floor is not proof against timing inference or shared-host channels.", ""]
        elif name in ("billing", "sensitivity"):
            lines += ["Cost units are modeled, not currency. Rows show means across paired trials. Detection recall/FPR use post-training bucket counts; they do not measure production accuracy.", "",
                      "| Workload | Variant | Attack calls accepted | Legitimate calls rejected | Modeled spend | Alert recall | False alert rate | Mean alert delay (min) |", "|---|---|---:|---:|---:|---:|---:|---:|"]
            for case in sorted({r["case"] for r in experiment["observations"]}):
                for variant in sorted(experiment["summary"]):
                    rows = [r for r in experiment["observations"] if r["case"] == case and r["variant"] == variant]
                    mean = lambda key: statistics.mean(r[key] for r in rows)
                    tp = sum(r["detection"]["tp"] for r in rows)
                    fn = sum(r["detection"]["fn"] for r in rows)
                    fp = sum(r["detection"]["fp"] for r in rows)
                    tn = sum(r["detection"]["tn"] for r in rows)
                    recall = f"{tp / (tp + fn):.1%}" if tp + fn else "n/a"
                    fpr = f"{fp / (fp + tn):.1%}" if fp + tn else "n/a"
                    delays = [r["alert_delay_minutes"] for r in rows if r["alert_delay_minutes"] is not None]
                    delay = f"{statistics.mean(delays):.2f}" if delays else "none"
                    lines.append(f'| {case} | {variant} | {mean("accepted_attack"):.1f} | {mean("rejected_legitimate"):.1f} | {mean("modeled_spend"):.6f} | {recall} | {fpr} | {delay} |')
            lines += ["", "Alert-only has the same cost as uncontrolled dispatch. Adaptive quotas act in the minute after confirmation. Low-rate and ramp attacks can evade detection; quotas can reject legitimate bursts. See raw buckets for pre-alert excess calls and enforcement delay.", ""]
        elif name == "framework":
            lines += ["| Case | Variant | Completed / attempts | Side effect present | Evidence gap on recovery | p50 total (ms) |",
                      "|---|---|---|---|---|---|"]
            for case in sorted(experiment["cases"]):
                for variant in sorted({r["variant"] for r in experiment["observations"] if r["case"] == case}):
                    selected = [r for r in experiment["observations"] if r["case"] == case and r["variant"] == variant]
                    lines.append(f'| {case} | {variant} | {sum(r["completed"] for r in selected)}/{len(selected)} | '
                                 f'{sum(r["side_effect"] for r in selected)}/{len(selected)} | '
                                 f'{sum(r["gap_observed"] for r in selected)}/{len(selected)} | '
                                 f'{latency([r["latency_ms"] for r in selected])["p50_ms"]:.3f} |')
            lines += ["", "Completion is the attempted operation, including adversarial operations. Audit fault cases are availability/evidence outcomes, not attack-success rates. Side effects report whether the document exists after the attempted operation (before recovery).", ""]
        else:
            lines += ["| Variant | Attack acceptance/success | Legitimate completion | Trial p50 / p95 (ms) |", "|---|---|---|---|"]
            for variant, metric in experiment["summary"].items():
                attack = _rate(metric["attack_success"]) if "attack_success" in metric else "n/a"
                legitimate = _rate(metric["legitimate_success"]) if "legitimate_success" in metric else "n/a"
                t = metric["latency"]
                lines.append(f'| {variant} | {attack} | {legitimate} | {t["p50_ms"]:.3f} / {t["p95_ms"]:.3f} |')
            lines.append("")
        lines += ["Limits:", "", *[f"- {limit}" for limit in experiment["limits"]], ""]
    lines += ["## Scope of the findings", "", "This evaluation operationalizes selected recommendations. It does not recreate the article's full threat model or prove its qualitative Tables 1 and 2. Provider-only topics remain outside local evidence:", "",
              *[f"- {item}" for item in bundle["unimplemented_provider_topics"]], "",
              "The events, files, requests and attacks are controlled fixtures. Results describe these fixtures and this host. All affected storage is disposable; existing application data is never read.", ""]
    return "\n".join(lines)


def write_bundle(bundle, output: Path):
    output.mkdir(parents=True, exist_ok=True)
    root = Path(__file__).resolve().parents[2]
    paths = [*root.glob("src/ssrsf/*.py"), *root.glob("tests/*.py"),
             *root.glob("scripts/*.py"), *root.glob("research/*"),
             root / "pyproject.toml", root / "README.md", root / "SECURITY.md"]
    bundle["source_sha256"] = {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                               for p in sorted(paths) if p.is_file()}
    payload = json.dumps(bundle, indent=2, allow_nan=False) + "\n"
    (output / "results.json").write_text(payload, encoding="utf-8")
    (output / "report.md").write_text(render_report(bundle), encoding="utf-8")
    with (output / "metrics.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(["experiment", "variant", "metric", "value", "count", "total", "ci95_low", "ci95_high"])
        for name, experiment in bundle["experiments"].items():
            for variant, summary in experiment["summary"].items():
                for metric, item in summary.items():
                    if isinstance(item, dict) and "rate" in item:
                        writer.writerow([name, variant, metric, item["rate"], item["count"], item["total"], *(item["wilson95"] or [None, None])])
                    elif metric == "latency":
                        for label, value in item.items():
                            writer.writerow([name, variant, label, value, "", "", "", ""])
            if name == "side-channels":
                for variant, metric in experiment["metrics"].items():
                    for label, value in (("trace_accuracy", metric["trace_attacker_accuracy"]),
                                         ("timing_accuracy", metric["timing_attacker"]["held_out_accuracy"])):
                        writer.writerow([name, variant, label, value["rate"], value["count"], value["total"], *value["wilson95"]])
                    writer.writerow([name, variant, "mean_cpu_ms", metric["mean_cpu_ms"], "", "", "", ""])
            if name in ("billing", "sensitivity"):
                for case in sorted({r["case"] for r in experiment["observations"]}):
                    for variant in sorted(experiment["summary"]):
                        rows = [r for r in experiment["observations"] if r["case"] == case and r["variant"] == variant]
                        for key in ("modeled_spend", "modeled_attack_spend", "accepted_attack", "rejected_legitimate", "attack_invocations_before_alert"):
                            writer.writerow([name + "/" + case, variant, "mean_" + key, statistics.mean(r[key] for r in rows), "", len(rows), "", ""])
            if name == "framework":
                for case in experiment["cases"]:
                    for variant in sorted({r["variant"] for r in experiment["observations"] if r["case"] == case}):
                        rows = [r for r in experiment["observations"] if r["case"] == case and r["variant"] == variant]
                        for key in ("completed", "side_effect", "gap_observed"):
                            writer.writerow([name + "/" + case, variant, key, statistics.mean(r[key] for r in rows), sum(r[key] for r in rows), len(rows), "", ""])
    files = ["results.json", "report.md", "metrics.csv"]
    (output / "SHA256SUMS").write_text("".join(f'{hashlib.sha256((output / name).read_bytes()).hexdigest()}  {name}\n' for name in files))
