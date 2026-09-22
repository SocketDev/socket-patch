#!/usr/bin/env python3
"""Bounded diagnostics for historical Linux Bun crashes before lockfile edits.

Run after a failed binary matrix. This never changes its acceptance result or
downloads replacement tools. Each installed Bun gets a pristine package project
and a 30-second total budget, including an optional strace reproduction.
"""

import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import tempfile
import time


def run(command, cwd, env, output, label, timeout):
    started = time.monotonic()
    row = {'command': [str(part) for part in command], 'timeoutSeconds': timeout}
    try:
        with (output / f'{label}.stdout').open('wb') as stdout, \
                (output / f'{label}.stderr').open('wb') as stderr:
            process = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                       stdout=stdout, stderr=stderr, start_new_session=True)
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                row['timedOut'] = True
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
            row['returnCode'] = process.returncode
            if process.returncode < 0:
                row['signal'] = signal.Signals(-process.returncode).name
    except (OSError, subprocess.SubprocessError) as error:
        row['error'] = str(error)
    row['elapsedSeconds'] = round(time.monotonic() - started, 3)
    (output / f'{label}.json').write_text(json.dumps(row, indent=2) + '\n')
    print(json.dumps({'probe': label, **row}), flush=True)
    return row


def fixture(root):
    # Match the acceptance test's Unicode/spaced path and isolated cache/temp.
    project = root / 'binary project café'
    project.mkdir(parents=True)
    (project / 'package.json').write_text(json.dumps({
        'name': 'native-binary-bun', 'version': '1.0.0', 'private': True,
        'dependencies': {'minimist': '1.2.2', 'is-number': '7.0.0'},
    }) + '\n')
    (project / 'bunfig.toml').write_text('[install]\nsaveTextLockfile = false\n')
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('BUN_', 'SOCKET_', 'NPM_CONFIG_', 'npm_config_'))}
    for key, name in {
        'HOME': 'home', 'XDG_CONFIG_HOME': 'config', 'XDG_CACHE_HOME': 'cache',
        'BUN_INSTALL': 'bun-home', 'BUN_INSTALL_CACHE_DIR': 'bun-cache',
        'TMPDIR': 'temporary', 'TMP': 'temporary', 'TEMP': 'temporary',
        'BUN_TMPDIR': 'temporary',
    }.items():
        path = root / name
        path.mkdir(exist_ok=True)
        env[key] = str(path)
    return project, env


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tools', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if platform.system() != 'Linux':
        print('Historical Linux diagnostics require Linux; no probes run.')
        return

    context = {'platform': platform.platform(), 'strace': shutil.which('strace')}
    for name in ['kernel/io_uring_disabled', 'kernel/io_uring_group', 'vm/mmap_rnd_bits']:
        path = Path('/proc/sys') / name
        context[name] = path.read_text().strip() if path.exists() else None
    for name in ['status', 'limits']:
        path = Path('/proc/self') / name
        (output / f'process-{name}.txt').write_text(path.read_text())
    (output / 'context.json').write_text(json.dumps(context, indent=2) + '\n')
    for executable, arguments in [('uname', ['-a']), ('lscpu', []), ('ldd', ['--version'])]:
        if program := shutil.which(executable):
            run([program, *arguments], output, os.environ.copy(), output, executable, 5)

    summary = []
    for version in ['0.5.9', '0.6.7', '0.6.8']:
        matches = sorted((args.tools / version).glob('bun-linux-*/bun'))
        if not matches:
            summary.append({'version': version, 'error': 'downloaded Bun executable missing'})
            continue
        bun = matches[0].resolve()
        deadline = time.monotonic() + 30
        with tempfile.TemporaryDirectory(prefix=f'bun-linux-probe-{version}-', dir=output) as temporary:
            root = Path(temporary)
            project, env = fixture(root / 'pristine')
            plain = run([bun, 'install', '--ignore-scripts'], project, env, output,
                        f'{version}-pristine', min(10, deadline - time.monotonic()))
            row = {'version': version, 'pristine': plain}
            if plain.get('returnCode') != 0 and context['strace']:
                project, env = fixture(root / 'traced')
                row['strace'] = run([
                    context['strace'], '-f', '-tt', '-s', '160', '-o',
                    output / f'{version}.strace', bun, 'install', '--ignore-scripts',
                ], project, env, output, f'{version}-traced', max(1, deadline - time.monotonic()))
            summary.append(row)
    (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')


if __name__ == '__main__':
    main()
