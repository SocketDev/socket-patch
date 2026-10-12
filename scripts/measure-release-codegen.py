import hashlib
import json
import os
import platform
import re
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
RESULTS = []
FAILURES = []


def sanitize(text):
    return (text
            .replace(str(ROOT), '<workspace>')
            .replace(os.environ.get('RUNNER_TEMP', '<missing>'), '<runner-temp>')
            .replace(os.environ.get('HOME', '<missing>'), '<home>')[-6000:])


def command(args, *, env=None, timeout=5400):
    return subprocess.run(
        args, cwd=ROOT, env=env, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True, timeout=timeout, check=False,
    )


def median(values):
    return round(statistics.median(values), 3)


def build(toolchain, units, sample, order, preserve=False):
    label = 'default' if units is None else 'units1'
    target_dir = Path(os.environ['RUNNER_TEMP']) / f'target-{toolchain}-{label}-{sample}'
    if target_dir.exists():
        raise RuntimeError('owned sample target path already exists')
    env = os.environ.copy()
    for key in ('CARGO_PROFILE_RELEASE_CODEGEN_UNITS', 'RUSTFLAGS',
                'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER',
                'RUSTC_WORKSPACE_WRAPPER', 'CARGO_PROFILE_RELEASE_LTO',
                'CARGO_PROFILE_RELEASE_OPT_LEVEL', 'CARGO_PROFILE_RELEASE_STRIP'):
        env.pop(key, None)
    env['CARGO_TARGET_DIR'] = str(target_dir)
    env['CARGO_INCREMENTAL'] = '0'
    if units is not None:
        env['CARGO_PROFILE_RELEASE_CODEGEN_UNITS'] = str(units)
    started = time.monotonic()
    row = {
        'compiler': toolchain,
        'codegen_units': 'implicit-default' if units is None else units,
        'sample': sample,
        'order': order,
        'target': TARGET,
        'profile': 'release: lto=true, opt-level=s, strip=true',
        'cargo_overrides': {
            'release_codegen_units': 'unset' if units is None else str(units),
            'RUSTFLAGS': 'unset', 'CARGO_ENCODED_RUSTFLAGS': 'unset',
            'RUSTC_WRAPPER': 'unset', 'RUSTC_WORKSPACE_WRAPPER': 'unset',
            'profile_overrides': 'LTO, opt-level, strip unset',
            'CARGO_INCREMENTAL': '0',
        },
        'elapsed_seconds': None,
        'exit_code': None,
        'binary_bytes': None,
        'binary_sha256': None,
        'version_output_sha256': None,
        'help_output_sha256': None,
        'error': None,
    }
    try:
        result = command([
            'cargo', f'+{toolchain}', 'build', '--locked', '--release',
            '--verbose', '-p', 'socket-patch-cli', '--target', TARGET,
        ], env=env)
        row['elapsed_seconds'] = round(time.monotonic() - started, 3)
        row['exit_code'] = result.returncode
        if result.returncode:
            row['error'] = f"cargo build failed; exit={result.returncode}; output_tail={sanitize(result.stdout)}"
            FAILURES.append({'stage': 'build', 'compiler': toolchain, 'sample': sample, 'output_tail': sanitize(result.stdout)})
            return row
        cli_invocations = [
            line for line in result.stdout.splitlines()
            if 'Running ' in line and '--crate-name socket_patch ' in line
        ]
        if len(cli_invocations) != 1:
            row['error'] = 'could not identify the CLI compiler invocation'
            return row
        invocation = cli_invocations[0]
        codegen_flags = re.findall(r'codegen-units(?:=|%3D)([^\s"%]+)', invocation)
        effective = {
            'codegen_units_flags': codegen_flags,
            'opt_level_s': 'opt-level=s' in invocation,
            'strip_enabled': 'strip=' in invocation and 'strip=none' not in invocation,
            'lto_enabled': ('linker-plugin-lto' in invocation or
                            ' -C lto ' in invocation or '-Clto' in invocation or
                            bool(re.search(r'\blto(?:%3D|=)(?:thin|fat|true)', invocation))),
        }
        row['effective_flags'] = effective
        if (units is None and codegen_flags) or (units == 1 and codegen_flags != ['1']):
            row['error'] = f'unexpected effective codegen-units flags: {codegen_flags}'
            return row
        if not (effective['opt_level_s'] and effective['strip_enabled'] and effective['lto_enabled']):
            row['error'] = 'release profile flags differ from expected lto=true, opt-level=s, strip=true'
            return row
        binary = target_dir / TARGET / 'release' / BINARY
        if not binary.is_file():
            row['error'] = 'expected executable missing'
            return row
        data = binary.read_bytes()
        row['binary_bytes'] = len(data)
        row['binary_sha256'] = hashlib.sha256(data).hexdigest()
        outputs = {}
        for flag in ('--version', '--help'):
            check = command([str(binary), flag], timeout=30)
            if check.returncode:
                row['error'] = f'{flag} failed; exit={check.returncode}'
                return row
            outputs[flag] = hashlib.sha256(check.stdout.encode()).hexdigest()
        row['version_output_sha256'] = outputs['--version']
        row['help_output_sha256'] = outputs['--help']
        if preserve:
            retained = Path(os.environ['RUNNER_TEMP']) / f'candidate-{toolchain}-{label}'
            shutil.copy2(binary, retained)
            row['retained_binary_sha256'] = hashlib.sha256(retained.read_bytes()).hexdigest()
        return row
    except subprocess.TimeoutExpired as error:
        output_tail = sanitize(error.stdout or '') if isinstance(error.stdout, str) else ''
        row['elapsed_seconds'] = round(time.monotonic() - started, 3)
        row['error'] = f'build timed out after 90 minutes; output_tail={output_tail}'
        FAILURES.append({'stage': 'timeout', 'compiler': toolchain, 'sample': sample, 'output_tail': output_tail})
        return row
    finally:
        shutil.rmtree(target_dir, ignore_errors=True)


def save():
    OUTPUT.write_text(json.dumps(REPORT, indent=2) + '\n')


REPORT = {
    'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
    'lock_sha256': hashlib.sha256((ROOT / 'Cargo.lock').read_bytes()).hexdigest(),
    'runner_image': 'ubuntu-24.04',
    'runner_os': platform.platform(),
    'cpu': platform.processor() or 'GitHub-hosted runner CPU',
    'logical_cpus': os.cpu_count(),
    'ram_bytes': int(next(line for line in open('/proc/meminfo', encoding='utf-8')
                          if line.startswith('MemTotal:')).split()[1]) * 1024,
    'target': TARGET,
    'dependency_policy': 'cargo fetch --locked for each compiler before all timed builds; shared download cache; separate clean target dirs',
    'method': 'four conditions interleaved in balanced blocks on one runner; 3 blocks initially, extend to 5 blocks if either units1 candidate is promising',
    'toolchains': {},
    'samples': RESULTS,
    'failures': FAILURES,
    'conclusion': 'inconclusive',
}

base_env = os.environ.copy()
for key in ('CARGO_PROFILE_RELEASE_CODEGEN_UNITS', 'RUSTFLAGS',
            'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER',
            'RUSTC_WORKSPACE_WRAPPER', 'CARGO_PROFILE_RELEASE_LTO',
            'CARGO_PROFILE_RELEASE_OPT_LEVEL', 'CARGO_PROFILE_RELEASE_STRIP'):
    base_env.pop(key, None)
base_env['CARGO_INCREMENTAL'] = '0'
for toolchain in TOOLCHAINS:
    ver = command(['rustc', f'+{toolchain}', '-Vv'], timeout=30)
    if ver.returncode:
        FAILURES.append({'stage': 'rustc-version', 'compiler': toolchain, 'output_tail': sanitize(ver.stdout)})
        REPORT['conclusion'] = f'inconclusive: failed to inspect Rust {toolchain}'
        save()
        raise SystemExit(1)
    REPORT['toolchains'][toolchain] = {'rustc_verbose': ver.stdout.strip()}
    fetched = command(['cargo', f'+{toolchain}', 'fetch', '--locked', '--target', TARGET], env=base_env)
    if fetched.returncode:
        FAILURES.append({'stage': 'cargo-fetch', 'compiler': toolchain, 'output_tail': sanitize(fetched.stdout)})
        REPORT['conclusion'] = f'inconclusive: locked dependency fetch failed for Rust {toolchain}'
        save()
        raise SystemExit(1)


def run_blocks(count, first_index):
    patterns = [
        [('1.93.1', None), ('1.99.0', 1), ('1.93.1', 1), ('1.99.0', None)],
        [('1.99.0', None), ('1.93.1', 1), ('1.99.0', 1), ('1.93.1', None)],
        [('1.93.1', 1), ('1.99.0', None), ('1.93.1', None), ('1.99.0', 1)],
        [('1.99.0', 1), ('1.93.1', None), ('1.99.0', None), ('1.93.1', 1)],
    ]
    for block in range(count):
        for toolchain, units in patterns[(first_index + block) % len(patterns)]:
            sample = first_index + block + 1
            index = len(RESULTS) + 1
            row = build(toolchain, units, sample, index, preserve=block == 0)
            RESULTS.append(row)
            save()
            if row['error']:
                REPORT['conclusion'] = f"inconclusive: {toolchain} build or executable check failed"
                save()
                raise SystemExit(1)


def compare(toolchain):
    rows = [row for row in RESULTS if row['compiler'] == toolchain]
    defaults = [row['elapsed_seconds'] for row in rows if row['codegen_units'] == 'implicit-default']
    units1 = [row['elapsed_seconds'] for row in rows if row['codegen_units'] == 1]
    default_sizes = [row['binary_bytes'] for row in rows if row['codegen_units'] == 'implicit-default']
    units1_sizes = [row['binary_bytes'] for row in rows if row['codegen_units'] == 1]
    paired = []
    for sample in sorted({row['sample'] for row in rows}):
        pair = [row for row in rows if row['sample'] == sample]
        if len(pair) == 2:
            baseline = next(row for row in pair if row['codegen_units'] == 'implicit-default')
            candidate = next(row for row in pair if row['codegen_units'] == 1)
            paired.append(1 - candidate['elapsed_seconds'] / baseline['elapsed_seconds'])
    return {
        'pairs': len(paired),
        'default_median_seconds': median(defaults),
        'units1_median_seconds': median(units1),
        'median_improvement_percent': round(100 * statistics.median(paired), 2),
        'each_pair_faster': all(value > 0 for value in paired),
        'paired_improvements_percent': [round(100 * value, 2) for value in paired],
        'default_median_binary_bytes': int(statistics.median(default_sizes)),
        'units1_median_binary_bytes': int(statistics.median(units1_sizes)),
        'units1_size_change_percent': round(100 * (statistics.median(units1_sizes) / statistics.median(default_sizes) - 1), 2),
        'units1_no_larger': statistics.median(units1_sizes) <= statistics.median(default_sizes),
    }


def compare_compilers(units):
    setting = 'implicit-default' if units is None else 1
    pairs = []
    old_sizes = []
    new_sizes = []
    for sample in sorted({row['sample'] for row in RESULTS}):
        old = next((row for row in RESULTS if row['sample'] == sample and
                    row['compiler'] == '1.93.1' and row['codegen_units'] == setting), None)
        new = next((row for row in RESULTS if row['sample'] == sample and
                    row['compiler'] == '1.99.0' and row['codegen_units'] == setting), None)
        if old and new:
            pairs.append(1 - new['elapsed_seconds'] / old['elapsed_seconds'])
            old_sizes.append(old['binary_bytes'])
            new_sizes.append(new['binary_bytes'])
    return {
        'codegen_units': setting,
        'pairs': len(pairs),
        '1.93.1_median_seconds': median([row['elapsed_seconds'] for row in RESULTS
                                        if row['compiler'] == '1.93.1' and row['codegen_units'] == setting]),
        '1.99.0_median_seconds': median([row['elapsed_seconds'] for row in RESULTS
                                        if row['compiler'] == '1.99.0' and row['codegen_units'] == setting]),
        'median_improvement_percent': round(100 * statistics.median(pairs), 2),
        'each_pair_faster': all(value > 0 for value in pairs),
        'paired_improvements_percent': [round(100 * value, 2) for value in pairs],
        '1.93.1_median_binary_bytes': int(statistics.median(old_sizes)),
        '1.99.0_median_binary_bytes': int(statistics.median(new_sizes)),
        '1.99.0_no_larger': statistics.median(new_sizes) <= statistics.median(old_sizes),
    }


run_blocks(3, 0)
comparisons = {toolchain: compare(toolchain) for toolchain in TOOLCHAINS}
REPORT['comparisons'] = comparisons
compiler_comparisons = {
    label: compare_compilers(setting)
    for label, setting in (('default', None), ('units1', 1))
}
REPORT['compiler_comparisons'] = compiler_comparisons
save()
promising = any(value['median_improvement_percent'] >= 5 and value['each_pair_faster']
                for value in comparisons.values())
promising = promising or any(value['median_improvement_percent'] >= 5 and value['each_pair_faster']
                             for value in compiler_comparisons.values())
if promising:
    run_blocks(2, 3)
    comparisons = {toolchain: compare(toolchain) for toolchain in TOOLCHAINS}
    REPORT['comparisons'] = comparisons
    compiler_comparisons = {
        label: compare_compilers(setting)
        for label, setting in (('default', None), ('units1', 1))
    }
    REPORT['compiler_comparisons'] = compiler_comparisons

REPORT['cli_output_equivalence'] = all(
    len({row[key] for row in RESULTS}) == 1
    for key in ('version_output_sha256', 'help_output_sha256')
)
REPORT['offline_fixture_checks'] = {}
for toolchain in TOOLCHAINS:
    fixture_check = command([
        'cargo', f'+{toolchain}', 'test', '--locked', '-p',
        'socket-patch-core', '--test', 'redirect_golden', '--test',
        'redirect_sbt_golden',
    ], env=base_env, timeout=1800)
    REPORT['offline_fixture_checks'][toolchain] = {
        'exit_code': fixture_check.returncode,
        'output_tail': sanitize(fixture_check.stdout),
    }
    if fixture_check.returncode:
        REPORT['conclusion'] = f'inconclusive: offline redirect fixture checks failed on Rust {toolchain}'
        FAILURES.append({'stage': 'offline-fixtures', 'compiler': toolchain,
                         'output_tail': sanitize(fixture_check.stdout)})
        save()
        raise SystemExit(1)
sizes = [row['binary_bytes'] for row in RESULTS]
REPORT['binary_size_bytes'] = {'minimum': min(sizes), 'maximum': max(sizes), 'all_equal': len(set(sizes)) == 1}
units_benefits = {
    toolchain: value['pairs'] >= 5 and value['median_improvement_percent'] >= 5 and
    value['each_pair_faster'] and value['units1_no_larger']
    for toolchain, value in comparisons.items()
}
compiler_benefit = compiler_comparisons['default']['pairs'] >= 5 and \
    compiler_comparisons['default']['median_improvement_percent'] >= 5 and \
    compiler_comparisons['default']['each_pair_faster'] and \
    compiler_comparisons['default']['1.99.0_no_larger']
REPORT['production_signal'] = {
    'units1_by_compiler': units_benefits,
    'rust_1_99_default': compiler_benefit,
    'requires_cli_output_equivalence': REPORT['cli_output_equivalence'],
}
if not REPORT['cli_output_equivalence']:
    REPORT['conclusion'] = 'no production change supported: CLI version/help output differs'
elif any(units_benefits.values()) or compiler_benefit:
    REPORT['conclusion'] = 'timing signal meets threshold for at least one independent change; review fixture results and signal scope before a production PR'
else:
    REPORT['conclusion'] = 'no demonstrated settings or compiler benefit; no production change supported'
save()
