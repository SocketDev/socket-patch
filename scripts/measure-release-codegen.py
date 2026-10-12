import hashlib
import json
import os
import platform
import shutil
import statistics
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'release-codegen-results.json'
TARGET = 'x86_64-unknown-linux-gnu'
BINARY = 'socket-patch'
TOOLCHAINS = ('1.93.1', '1.99.0')


def command(args, *, env=None, timeout=5400):
    return subprocess.run(
        args,
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
        check=False,
    )


def record_failure(row, reason):
    row['error'] = reason
    return row


def build(toolchain, units, sample):
    label = 'default' if units is None else 'units1'
    target_dir = Path(os.environ['RUNNER_TEMP']) / f'target-{toolchain}-{label}-{sample}'
    if target_dir.exists():
        raise RuntimeError('owned sample target path already exists')
    env = os.environ.copy()
    env.pop('CARGO_PROFILE_RELEASE_CODEGEN_UNITS', None)
    env.pop('RUSTFLAGS', None)
    env['CARGO_TARGET_DIR'] = str(target_dir)
    if units is not None:
        env['CARGO_PROFILE_RELEASE_CODEGEN_UNITS'] = str(units)
    started = time.monotonic()
    row = {
        'compiler': toolchain,
        'codegen_units': 'implicit-default' if units is None else units,
        'sample': sample,
        'target': TARGET,
        'profile': 'release: lto=true, opt-level=s, strip=true',
        'order': len(RESULTS) + 1,
        'elapsed_seconds': None,
        'exit_code': None,
        'binary_bytes': None,
        'binary_sha256': None,
        'version_output_sha256': None,
        'help_output_sha256': None,
        'error': None,
    }
    try:
        result = command(
            ['cargo', f'+{toolchain}', 'build', '--locked', '--release',
             '-p', 'socket-patch-cli', '--target', TARGET],
            env=env,
        )
        row['elapsed_seconds'] = round(time.monotonic() - started, 3)
        row['exit_code'] = result.returncode
        if result.returncode:
            return record_failure(row, f'cargo build failed; exit={result.returncode}')
        binary = target_dir / TARGET / 'release' / BINARY
        if not binary.is_file():
            return record_failure(row, 'expected executable missing')
        row['binary_bytes'] = binary.stat().st_size
        row['binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
        outputs = {}
        for flag in ('--version', '--help'):
            check = command([str(binary), flag], timeout=30)
            if check.returncode:
                return record_failure(row, f'{flag} failed; exit={check.returncode}')
            outputs[flag] = hashlib.sha256(check.stdout.encode()).hexdigest()
        row['version_output_sha256'] = outputs['--version']
        row['help_output_sha256'] = outputs['--help']
        return row
    except subprocess.TimeoutExpired:
        row['elapsed_seconds'] = round(time.monotonic() - started, 3)
        return record_failure(row, 'build timed out after 90 minutes')
    finally:
        shutil.rmtree(target_dir, ignore_errors=True)


def median(values):
    return round(statistics.median(values), 3)


RESULTS = []
REPORT = {
    'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
    'lock_sha256': hashlib.sha256((ROOT / 'Cargo.lock').read_bytes()).hexdigest(),
    'runner_os': platform.platform(),
    'cpu': platform.processor() or 'GitHub-hosted runner CPU',
    'logical_cpus': os.cpu_count(),
    'target': TARGET,
    'dependency_cache': 'GitHub-hosted runner; dependencies fetched before timed builds and Cargo download cache shared',
    'method': 'sequential builds with unique clean target directories; paired default/units1; same source and locked dependencies',
    'toolchains': {},
    'samples': RESULTS,
    'conclusion': 'inconclusive',
}

for toolchain in TOOLCHAINS:
    version = command(['rustc', f'+{toolchain}', '-Vv'], timeout=30)
    REPORT['toolchains'][toolchain] = version.stdout.strip() if version.returncode == 0 else 'rustc -Vv failed'
    pairs = []
    for pair_index in range(1, 4):
        order = [('default', None), ('units1', 1)]
        if pair_index % 2 == 0:
            order.reverse()
        pair_rows = []
        for label, units in order:
            row = build(toolchain, units, pair_index)
            RESULTS.append(row)
            pair_rows.append(row)
            OUTPUT.write_text(json.dumps(REPORT, indent=2) + '\n')
            if row['error']:
                REPORT['conclusion'] = f'inconclusive: {toolchain} {label} sample failed'
                OUTPUT.write_text(json.dumps(REPORT, indent=2) + '\n')
                raise SystemExit(1)
        by_label = {r['codegen_units'] if isinstance(r['codegen_units'], str) else 'units1': r for r in pair_rows}
        pairs.append((by_label['implicit-default'], by_label['units1']))

    base_times = [p[0]['elapsed_seconds'] for p in pairs]
    candidate_times = [p[1]['elapsed_seconds'] for p in pairs]
    improvements = [1 - c / b for b, c in zip(base_times, candidate_times)]
    report = {
        'pairs': len(pairs),
        'default_median_seconds': median(base_times),
        'units1_median_seconds': median(candidate_times),
        'median_improvement_percent': round(100 * statistics.median(improvements), 2),
        'each_pair_faster': all(x > 0 for x in improvements),
        'paired_improvements_percent': [round(100 * x, 2) for x in improvements],
    }
    REPORT['toolchains'][toolchain] = {'rustc': REPORT['toolchains'][toolchain], 'comparison': report}
    OUTPUT.write_text(json.dumps(REPORT, indent=2) + '\n')
    if report['median_improvement_percent'] >= 5 and report['each_pair_faster']:
        for pair_index in range(4, 6):
            order = [('default', None), ('units1', 1)]
            if pair_index % 2 == 0:
                order.reverse()
            pair_rows = []
            for label, units in order:
                row = build(toolchain, units, pair_index)
                RESULTS.append(row)
                pair_rows.append(row)
                OUTPUT.write_text(json.dumps(REPORT, indent=2) + '\n')
                if row['error']:
                    REPORT['conclusion'] = f'inconclusive: {toolchain} {label} sample failed'
                    OUTPUT.write_text(json.dumps(REPORT, indent=2) + '\n')
                    raise SystemExit(1)
            by_label = {r['codegen_units'] if isinstance(r['codegen_units'], str) else 'units1': r for r in pair_rows}
            pairs.append((by_label['implicit-default'], by_label['units1']))
        base_times = [p[0]['elapsed_seconds'] for p in pairs]
        candidate_times = [p[1]['elapsed_seconds'] for p in pairs]
        improvements = [1 - c / b for b, c in zip(base_times, candidate_times)]
        report.update({
            'pairs': len(pairs),
            'default_median_seconds': median(base_times),
            'units1_median_seconds': median(candidate_times),
            'median_improvement_percent': round(100 * statistics.median(improvements), 2),
            'each_pair_faster': all(x > 0 for x in improvements),
            'paired_improvements_percent': [round(100 * x, 2) for x in improvements],
        })
        REPORT['toolchains'][toolchain]['comparison'] = report
        OUTPUT.write_text(json.dumps(REPORT, indent=2) + '\n')

comparisons = [REPORT['toolchains'][v]['comparison'] for v in TOOLCHAINS]
output_equivalence = all(
    len({row[key] for row in RESULTS}) == 1
    for key in ('version_output_sha256', 'help_output_sha256')
)
REPORT['cli_output_equivalence'] = output_equivalence
sizes = [row['binary_bytes'] for row in RESULTS]
REPORT['binary_size_bytes'] = {
    'minimum': min(sizes),
    'maximum': max(sizes),
    'all_equal': len(set(sizes)) == 1,
}
if output_equivalence and all(c['pairs'] >= 5 and c['median_improvement_percent'] >= 5 and c['each_pair_faster'] for c in comparisons):
    REPORT['conclusion'] = 'units1 meets the timing threshold on both toolchains; inspect size and correctness before considering a production change'
else:
    REPORT['conclusion'] = 'no demonstrated units1 benefit across both toolchains; no production change supported'
OUTPUT.write_text(json.dumps(REPORT, indent=2) + '\n')
