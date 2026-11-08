#!/usr/bin/env python3
"""Refresh or check inline manuscript evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import math
import statistics
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
TIMING_FIGURE = '\\begin{figure*}[t]\n\\centering\n\\begin{minipage}{0.49\\textwidth}\n\\centering\n\\begin{tikzpicture}\n\\begin{axis}[width=\\linewidth,height=5cm,ybar,bar width=12pt,ymin=0,ymax=110,\n ylabel={Held-out timing accuracy (\\%)},symbolic x coords={Exposed,Floor,Deadline},xtick=data,\n tick label style={font=\\small},label style={font=\\small},nodes near coords,\n every node near coord/.append style={font=\\small},enlarge x limits=.25,grid=major,grid style={gray!15}]\n\\addplot[fill=controlblue!75,draw=controlblue] coordinates {(Exposed,100.000) (Floor,88.333) (Deadline,91.667)};\n\\draw[dashed,attackred] (axis cs:Exposed,50) -- (axis cs:Deadline,50);\n\\end{axis}\n\\end{tikzpicture}\n\\end{minipage}\\hfill\n\\begin{minipage}{0.49\\textwidth}\n\\centering\n\\begin{tikzpicture}\n\\begin{axis}[width=\\linewidth,height=5cm,ybar,bar width=12pt,ymin=0,ymax=1.4,\n ylabel={Mean process CPU per response (ms)},symbolic x coords={Exposed,Floor,Deadline},xtick=data,\n tick label style={font=\\small},label style={font=\\small},nodes near coords,\n every node near coord/.append style={font=\\small},enlarge x limits=.25,grid=major,grid style={gray!15}]\n\\addplot[fill=mutedgreen!75,draw=mutedgreen] coordinates {(Exposed,0.023300) (Floor,0.045367) (Deadline,0.709717)};\n\\end{axis}\n\\end{tikzpicture}\n\\end{minipage}\n\\caption{Measured timing inference and CPU tradeoff on the retained host. Each accuracy uses 60 held-out balanced-role responses; the dashed line marks 50\\pct\\ chance accuracy. CPU bars are mean process times for the same test responses. Training data are separate. Service delays and the 8~ms target are constructed experimental parameters.}\n\\label{fig:timing}\n\\end{figure*}'


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
    return '\n'.join([r'\begin{table*}[t]', '\\centering\\' + small,
        r'\begin{tabularx}{\linewidth}{@{}' + columns + r'@{}}', r'\toprule',
        header + r' \\', r'\midrule', *[row + r' \\' for row in rows],
        r'\bottomrule', r'\end{tabularx}', r'\caption{' + caption + r'}\label{' + label + '}',
        r'\end{table*}', ''])


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
    metrics = bundle['experiments']['side-channels']['metrics']
    validation = json.loads((ROOT / 'results/validation.json').read_text())
    versions = ', '.join(dict.fromkeys(r['python'] for r in validation['runs']))
    extras = [
        r'\newcommand{\RunVersion}{' + escape(bundle['package_version']) + '}',
        r'\newcommand{\ValidationVersions}{' + escape(versions) + '}',
        r'\newcommand{\FloorAccuracy}{' + percent(metrics['facade-floor']['timing_attacker']['held_out_accuracy']) + '}',
        r'\newcommand{\DeadlineAccuracy}{' + percent(metrics['facade-deadline']['timing_attacker']['held_out_accuracy']) + '}',
    ]
    digest = hashlib.sha256((ROOT / 'results/results.json').read_bytes()).hexdigest()
    extras.append(r'\newcommand{\ResultsDigest}{' + digest[:32] + r'\\' + '\n' + digest[32:] + '}')
    group_labels = {'events': 'Events', 'authorization': 'Authorization', 'dependencies': 'Artifacts',
                    'persistence': 'Persistence', 'side-channels': 'Side channels', 'rollouts': 'Rollouts',
                    'billing': 'Primary billing', 'framework': 'Integrated workflow', 'sensitivity': 'Sensitivity',
                    'lifecycle': 'Restart recovery', 'robustness': 'Follow-up probes'}
    counts = [r'\begin{table}[t]', r'\centering\small',
              r'\caption{Retained observations across variants. Billing units are complete traces; side-channel units include both splits; integrated units are scenario/variant trials; restart units each contain two interpreters.}',
              r'\label{tab:counts}', r'\begin{tabularx}{\columnwidth}{Yrr}', r'\toprule',
              r'Group & Variants & Observations\\', r'\midrule']
    for name, experiment in bundle['experiments'].items():
        rows = experiment['observations']
        counts.append(f"{group_labels[name]} & {len({r['variant'] for r in rows})} & {len(rows)}" + r'\\')
    counts += [r'\bottomrule', r'\end{tabularx}', r'\end{table}']
    extras.append(r'\newcommand{\ObservationTable}{' + '\n'.join(counts) + '}')
    macros += '\n' + '\n'.join(extras)
    lines = [r'\section{Results}\label{sec:results}', '',
             r'All values in this section are generated from the retained evidence, not transcribed from the source review. Counts describe the labeled fixtures and comparison variants defined in Section~\ref{sec:protocol}.', '',
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
    figure = TIMING_FIGURE
    accuracies = [(name, metrics[v]['timing_attacker']['held_out_accuracy']['rate'] * 100)
                  for name, v in [('Exposed', 'exposed'), ('Floor', 'facade-floor'), ('Deadline', 'facade-deadline')]]
    cpus = [(name, metrics[v]['mean_cpu_ms'])
            for name, v in [('Exposed', 'exposed'), ('Floor', 'facade-floor'), ('Deadline', 'facade-deadline')]]
    coordinates = iter([' '.join(f'({name},{value:.6f})' for name, value in accuracies),
                        ' '.join(f'({name},{value:.6f})' for name, value in cpus)])
    figure = re.sub(r'coordinates \{[^}]+\}', lambda m: 'coordinates {' + next(coordinates) + '}', figure)
    figure = figure.replace('ymax=1.4', f'ymax={max(1.4, math.ceil(max(value for _, value in cpus) * 12) / 10):g}')
    lines.append(figure)
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
    lines.append(r'\subsection{Normal-Interpreter Restart and Post-Expiry Recovery}')
    lifecycle = bundle['experiments']['lifecycle']['observations']
    checks = [('exit_audit_failure_observed', 'Injected exit failure observed'),
              ('expired_grant_rejected', 'Expired deletion grant rejected'),
              ('operation_recovered', 'Independent operation receipt recovered'),
              ('revocation_retained', 'Extraction revocation retained'),
              ('retained_version_matches', 'Unrelated document version retained'),
              ('anchored_chain_valid', 'Retained chain anchor verified'),
              ('single_nonce_consumption', 'Exactly one nonce consume'),
              ('deleted_document_absent', 'Deleted document remains absent')]
    rows = [f"{label} & {sum(r[key] for r in lifecycle)}/{len(lifecycle)}" for key, label in checks]
    lines.append(table('Yr', 'Recovery invariant & Observed / trials', rows,
        'Each trial uses two separate isolated-mode Python interpreters and advances a fixed test clock. These are normal exit/restart checks, not power-loss, key-rotation or distributed-failover results.', 'tab:recovery'))
    lines.append(f"Median total lifecycle duration was {statistics.median(r['latency_ms'] for r in lifecycle):.3f} ms, including both interpreters and all setup, commit and recovery work. "
                 'The original grant cannot authorize deletion after expiry; an independently authenticated investigator reads the committed operation without deleting again. '
                 'Keys remain owner-trusted and invocation budgets reset on restart.\n')
    lines.append(r'\subsection{Follow-Up Billing Families and Fixed-Training Reference}')
    labels = {'stationary': 'Stationary', 'seasonal-legitimate': 'Seasonal', 'growing-legitimate': 'Growth',
              'flash-crowd': 'Crowds', 'pulsed-attack': 'Pulses', 'ramp-attack': 'Ramp'}
    rows = []
    for case, label in labels.items():
        for variant, short in [('adaptive-quota', 'EWMA'), ('training-quota', 'Training reference'), ('fixed-quota', 'Fixed quota')]:
            rs = selected(bundle, 'robustness', case, variant)
            rows.append(' & '.join([label, short, f"{mean(rs, 'accepted_attack'):.1f}",
                                    f"{mean(rs, 'rejected_legitimate'):.1f}", recall(rs), recall(rs, True)]))
    lines.append(table('YYrrrr', 'Family & Control & Attack calls & Valid drops & Recall & FPR', rows,
        'Disclosed follow-up probes over paired seeds: means per trial and pooled post-training bucket rates. The frozen training reference is a project comparator, not a published defense. Uncontrolled and alert-only outcomes and all compact bucket records are also retained in the artifact.', 'tab:robustness', small='footnotesize'))
    lines.append('These probes were introduced after the initial study. They test whether legitimate seasonality/growth and intermittent abuse expose failure modes beyond the primary workloads; they are not a preregistered holdout or production validation. '
                 'No configuration or retained host run is selected as a best result.\n')
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
    parser.add_argument('--evidence-only', action='store_true', help='Verify retained evidence without reading a manuscript')
    parser.add_argument('--manuscript', type=Path, default=ROOT / 'main.tex')
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
    validation = json.loads((evidence / 'validation.json').read_text())
    if validation['results_sha256'] != hashlib.sha256((evidence / 'results.json').read_bytes()).hexdigest():
        raise ValueError('Validation record refers to different results; run scripts/validate.py')
    if validation['source_sha256'] != bundle['source_sha256'] or not validation['runs']:
        raise ValueError('Validation source record mismatch')
    if any(r['exit_code'] != 0 or r['tests'] <= 0 for r in validation['runs']):
        raise ValueError('Manuscript requires successful recorded tests')
    if args.evidence_only:
        print('Evidence, source hashes and recorded tests verified.')
        return 0
    expected_config = {'trials': 30, 'seed': 42, 'floor_ms': 8., 'unit_price': .000001}
    if any(bundle['configuration'][key] != value for key, value in expected_config.items()):
        raise ValueError('This manuscript methods section assumes the retained default protocol; revise methods before using other parameters')
    if len(bundle['experiments']) != 11:
        raise ValueError('Canonical manuscript requires all eleven experiment groups')
    macros, results = render(bundle)
    path = args.manuscript
    original = path.read_text()
    expected = replace_block(replace_block(original, 'MACROS', macros), 'RESULTS', results)
    if args.check:
        if expected != original:
            print('Manuscript evidence differs; run scripts/paper_evidence.py', file=sys.stderr)
            return 1
        print('Inline evidence matches checksummed results and current source.')
    else:
        path.write_text(expected)
        print(f'Updated inline evidence in {path.name}.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
