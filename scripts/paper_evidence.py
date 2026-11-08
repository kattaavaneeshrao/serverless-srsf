#!/usr/bin/env python3
"""Refresh/check inline manuscript evidence. Never invokes a TeX engine."""
from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))


def escape(text):
    return ''.join({'\\': r'\textbackslash{}', '&': r'\&', '%': r'\%', '$': r'\$',
                    '#': r'\#', '_': r'\_', '{': r'\{', '}': r'\}',
                    '~': r'\textasciitilde{}', '^': r'\textasciicircum{}'}.get(c, c) for c in str(text))


def proportion(metric):
    return f"{metric['count']}/{metric['total']}"


def percent(metric):
    return 'n/a' if metric['rate'] is None else f"{100 * metric['rate']:.1f}\\%"


def selected(bundle, group, case, variant):
    return [r for r in bundle['experiments'][group]['observations'] if r['case'] == case and r['variant'] == variant]


def mean(rows, key):
    return statistics.mean(r[key] for r in rows)


def recall(rows, false=False):
    a, b = ('fp', 'tn') if false else ('tp', 'fn')
    numerator = sum(r['detection'][a] for r in rows)
    denominator = numerator + sum(r['detection'][b] for r in rows)
    return 'n/a' if not denominator else f'{100 * numerator / denominator:.1f}\\%'


def table(columns, header, rows, caption, label, *, small='small'):
    return '\n'.join([r'\begin{table}[htbp]', '\\centering\\' + small,
        r'\begin{tabularx}{\linewidth}{@{}' + columns + r'@{}}', r'\toprule',
        header + r' \\', r'\midrule', *[row + r' \\' for row in rows],
        r'\bottomrule', r'\end{tabularx}', r'\caption{' + caption + r'}\label{' + label + '}',
        r'\end{table}', ''])


def render(bundle):
    config = bundle['configuration']
    count = unittest.defaultTestLoader.discover(str(ROOT / 'tests')).countTestCases()
    macros = '\n'.join([
        r'\newcommand{\TrialCount}{' + str(config['trials']) + '}',
        r'\newcommand{\SeedValue}{' + str(config['seed']) + '}',
        r'\newcommand{\RunUTC}{' + escape(bundle['timestamp_utc'].split('.')[0].replace('T', ' ')) + ' UTC}',
        r'\newcommand{\RunPython}{' + escape(bundle['environment']['python'].split()[0]) + '}',
        r'\newcommand{\RunPlatform}{' + escape(bundle['environment']['platform']) + '}',
        r'\newcommand{\ObservationCount}{' + str(sum(len(e['observations']) for e in bundle['experiments'].values())) + '}',
        r'\newcommand{\TestCount}{' + str(count) + '}',
    ])
    lines = [r'\section{Results}\label{sec:results}', '',
             r'All values in this section are generated from the retained evidence, not transcribed from the source review. Counts describe the labeled fixtures and comparison variants defined in Section~\ref{sec:method}.', '',
             r'\subsection{Component Admission and Lifecycle Outcomes}']
    rows = []
    pairs = [('events', 'Events', 'unchecked', 'validated-signed'),
             ('authorization', 'Authorization', 'gateway-only-broad-role', 'per-function-least-privilege'),
             ('dependencies', 'Artifact integrity', 'untracked', 'hash-locked-inventory'),
             ('persistence', 'Warm monitoring', 'warm-unchecked', 'warm-monitored'),
             ('persistence', 'Fresh workspace', 'warm-unchecked', 'fresh-workspace'),
             ('rollouts', 'Synchronized cutover', 'rolling-stale-replicas', 'atomic-cutover')]
    for group, label, base, full in pairs:
        summary = bundle['experiments'][group]['summary']
        rows.append(f"{label} & {proportion(summary[base]['attack_success'])} & {proportion(summary[full]['attack_success'])} & {proportion(summary[full]['legitimate_success'])}")
    lines.append(table('Yrrr', 'Experiment & Baseline attack & Protected attack & Valid completion', rows,
        'Component outcomes: event/authorization admission, changed-artifact admission, marker survival or stale-access success. The two persistence rows share the same warm baseline. Valid completion is measured separately; it does not estimate production uptime.', 'tab:components'))
    p = bundle['experiments']['persistence']['summary']
    r = bundle['experiments']['rollouts']['summary']
    lines.append(f"Median persistence lifecycle times were {p['warm-unchecked']['latency']['p50_ms']:.3f} ms (warm unchecked), "
                 f"{p['warm-monitored']['latency']['p50_ms']:.3f} ms (warm monitored) and {p['fresh-workspace']['latency']['p50_ms']:.3f} ms (fresh). "
                 f"The fresh variant starts a second process. Median rollout trial durations were {r['rolling-stale-replicas']['latency']['p50_ms']:.3f} ms "
                 f"for the stale baseline and {r['atomic-cutover']['latency']['p50_ms']:.3f} ms for synchronized cutover. "
                 'These boundaries include lifecycle work, thread setup or forced coordination; they are not cloud cold-start times or isolated synchronization overhead.\n')
    lines.append(r'\subsection{Integrated Ablations and Dependency Failures}')
    framework = bundle['experiments']['framework']
    rows = []
    for case, control in framework['cases'].items():
        if case.startswith('audit-') or case == 'legitimate-workflow':
            continue
        variants = [selected(bundle, 'framework', case, v) for v in ('unprotected', 'full', 'without-' + control)]
        counts = [f"{sum(r['completed'] for r in rs)}/{len(rs)}" for rs in variants]
        rows.append(' & '.join([escape(case), *counts, escape(control)]))
    lines.append(table('Yrrrl', 'Attempt & No controls & Full & Ablation & Removed', rows,
        'Attempted adversarial operation acceptance. Each ablation removes only the named control. Replay counts acceptance, not repeated physical deletion; replaced-target counts a new target parameter paired with an old grant.', 'tab:ablations', small='footnotesize'))
    rows = []
    for case in ('audit-entry-outage', 'audit-exit-outage', 'legitimate-workflow'):
        for variant in ('unprotected', 'full', 'without-audit'):
            rs = selected(bundle, 'framework', case, variant)
            if not rs:
                continue
            outcomes = [f"{sum(r[key] for r in rs)}/{len(rs)}" for key in ('completed', 'side_effect', 'gap_observed')]
            rows.append(' & '.join([escape(case), escape(variant), *outcomes, f"{statistics.median(r['latency_ms'] for r in rs):.3f}"]))
    lines.append(table('Ylrrrr', 'Case & Variant & Complete & Doc exists & Gap & p50 ms', rows,
        'Fault and legitimate workflow outcomes. Document existence is sampled before recovery; gap status is sampled on recovery. Legitimate completion includes authorized deletion, so no document remains. Total latency includes initialization and recovery where applicable.', 'tab:faults', small='footnotesize'))
    lines.append('Entry acknowledgement failure prevents document creation in the full variant. Exit failure follows committed creation; after service recovery the next invocation records an evidence gap. Removing audit admission restores completion under both injected failures but provides no gap record. These differences expose an availability/evidence tradeoff rather than an attack-detection rate.\n')
    lines.append(r'\subsection{Held-Out Information Exposure}')
    rows = []
    side = bundle['experiments']['side-channels']['metrics']
    for variant in ('exposed', 'facade-floor', 'facade-deadline'):
        metric = side[variant]
        timing = metric['timing_attacker']['held_out_accuracy']
        low, high = timing['wilson95']
        rows.append(' & '.join([escape(variant), proportion(metric['trace_attacker_accuracy']), proportion(timing),
            f'{100*low:.1f}--{100*high:.1f}', f"{metric['latency']['p50_ms']:.3f}", f"{metric['mean_cpu_ms']:.3f}"]))
    lines.append(table('Yrrrrr', 'Variant & Trace & Timing & Timing CI (\\%) & p50 ms & CPU ms', rows,
        'Correct held-out role predictions, descriptive 95\\% Wilson intervals for timing accuracy, response median and mean process CPU time. Each split is balanced by role; chance accuracy is 50\\%. Intervals do not establish independence or prove zero leakage.', 'tab:leakage', small='footnotesize'))
    floor = side['facade-floor']['timing_attacker']['held_out_accuracy']
    deadline = side['facade-deadline']['timing_attacker']['held_out_accuracy']
    lines.append(f"Simple-floor timing accuracy was {percent(floor)}, versus {percent(deadline)} for deadline padding in this run. "
                 'The facade removes role separation for the tested trace classifier, but floor timing remains informative. '
                 'Deadline padding incurs additional CPU work and provides no constant-time guarantee. These observations are host- and attacker-dependent.\n')
    lines.append(r'\subsection{Billing Control Outcomes}')
    rows = []
    cases = {'steady': 'Steady', 'legitimate-burst': 'Valid burst', 'sustained-attack': 'Sustained', 'low-rate-attack': 'Low rate', 'slow-ramp': 'Ramp'}
    for case, label in cases.items():
        for variant, short in [('uncontrolled', 'None'), ('alert-only', 'Alert'), ('adaptive-quota', 'Adaptive'), ('fixed-quota', 'Fixed')]:
            rs = selected(bundle, 'billing', case, variant)
            rows.append(' & '.join([label, short, f"{mean(rs,'accepted_attack'):.1f}", f"{mean(rs,'rejected_legitimate'):.1f}",
                                  f"{mean(rs,'modeled_spend'):.6f}", recall(rs), recall(rs, True)]))
    lines.append(table('Ylrrrrr', 'Workload & Control & Attack calls & Valid drops & Cost units & Recall & FPR', rows,
        'Mean admitted attack calls, rejected legitimate calls and modeled total spend per trial. Recall and FPR use post-training bucket counts. No detector is present in None/Fixed variants; zero recall there is not a detector evaluation. Alert-only does not reduce spend.', 'tab:billing', small='footnotesize'))
    sustained = selected(bundle, 'billing', 'sustained-attack', 'adaptive-quota')
    delays = [r['alert_delay_minutes'] for r in sustained if r['alert_delay_minutes'] is not None]
    ramp = selected(bundle, 'billing', 'slow-ramp', 'adaptive-quota')
    ramp_detected = sum(r['alert_delay_minutes'] is not None for r in ramp)
    lines.append(f"Sustained attack confirmation occurred in {len(delays)}/{len(sustained)} trials, with conditional mean alert delay "
                 f"{statistics.mean(delays):.2f} synthetic minutes. Quotas apply in the following bucket. "
                 f"Slow-ramp alerts occurred in only {ramp_detected}/{len(ramp)} trials. "
                 'Low-rate misses and legitimate-burst rejections remain in the evidence. Cost reductions therefore cannot be interpreted as accurate identification of malicious requests.\n')
    lines.append(r'\subsection{Prespecified Threshold/Quota Sensitivity}')
    rows = []
    for d in (2, 4, 6):
        for q in (10, 20, 40):
            v = f'd{d}-q{q}'
            sus = selected(bundle, 'sensitivity', 'sustained-attack', v)
            burst = selected(bundle, 'sensitivity', 'legitimate-burst', v)
            low = selected(bundle, 'sensitivity', 'low-rate-attack', v)
            ramp = selected(bundle, 'sensitivity', 'slow-ramp', v)
            rows.append(' & '.join([str(d), str(q), f"{mean(sus,'accepted_attack'):.1f}", f"{mean(sus,'rejected_legitimate'):.1f}",
                                   f"{mean(burst,'rejected_legitimate'):.1f}", recall(low), recall(ramp)]))
    lines.append(table('llYrrrr', '$d$ & $q$ & Sust. attack & Sust. drops & Burst drops & Low recall & Ramp recall', rows,
        'All nine prespecified settings over paired independent workload seeds. Call columns are per-trial means; recalls are pooled post-training bucket proportions. The full evidence also retains steady traffic, costs, false alerts, delays and dispatch checksums. The sweep is descriptive and is not used to select a best setting.', 'tab:sensitivity', small='footnotesize'))
    lines.append('Changing the quota changes admitted work and legitimate rejection after an alert; changing the threshold changes which buckets trigger it. The sweep varies only two parameters within fixed workload families. It does not cover baseline seasonality, delayed telemetry, distributed enforcement or an adaptive attacker.\n')
    return macros, '\n\n'.join(lines)


def replace_block(text, label, content):
    start, end = f'% BEGIN EVIDENCE {label}', f'% END EVIDENCE {label}'
    if text.count(start) != 1 or text.count(end) != 1:
        raise ValueError(f'Expected exactly one {label} block')
    a = text.index(start) + len(start)
    b = text.index(end, a)
    return text[:a] + '\n' + content.strip() + '\n' + text[b:]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    evidence = ROOT / 'results'
    for line in (evidence / 'SHA256SUMS').read_text().splitlines():
        digest, name = line.split('  ')
        if hashlib.sha256((evidence / name).read_bytes()).hexdigest() != digest:
            raise ValueError(f'Evidence checksum mismatch: {name}')
    bundle = json.loads((evidence / 'results.json').read_text())
    for name, digest in bundle['source_sha256'].items():
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != digest:
            raise ValueError(f'Evidence source mismatch: {name}; regenerate evaluation first')
    macros, results = render(bundle)
    path = ROOT / 'main.tex'
    original = path.read_text()
    expected = replace_block(replace_block(original, 'MACROS', macros), 'RESULTS', results)
    if args.check:
        if expected != original:
            print('Manuscript evidence differs; run scripts/paper_evidence.py', file=sys.stderr)
            return 1
        print('Inline evidence matches checksummed results and current source. No compilation performed.')
    else:
        path.write_text(expected)
        print('Updated inline evidence in main.tex. No compilation performed.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
