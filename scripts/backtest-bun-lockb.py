#!/usr/bin/env python3
"""Run native binary Bun end-to-end tests across binary layout boundaries.

The Rust suite uses a local patch service and real Bun installers. Each reader
must accept hosted and vendored binary rewrites, both takeover directions,
dry runs, idempotence, artifact repair, detached scans and byte-exact rollback.
Fresh frozen installs use empty caches and compare installed package bytes.

Modern releases write native binary locks using install.saveTextLockfile=false.
Additional reader cells consume a 1.1.45 lock without converting it.
Missing releases/tools and skipped required tests fail, with per-release logs.
"""

import argparse
import concurrent.futures
import importlib.util
import json
import os
import platform
from pathlib import Path
import subprocess
from datetime import datetime, timezone

spec = importlib.util.spec_from_file_location('bun_matrix', Path(__file__).with_name('backtest-bun.py'))
bun_matrix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bun_matrix)

# 0.1.1 and 0.1.6: version 1 (different dependency layouts); 0.1.7:
# version 2; 0.6.7/0.6.8: package scripts field; each subsequent minor era.
VERSIONS = ['0.1.1', '0.1.6', '0.1.7', '0.5.9', '0.6.7', '0.6.8', '0.8.1',
            '1.0.0', '1.0.36', '1.1.0', '1.1.38', '1.1.45',
            '1.2.0', '1.2.23', '1.3.0', '1.3.14', '1.4.2']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tools', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--versions', nargs='+', default=VERSIONS)
    parser.add_argument('--jobs', type=int, default=2)
    parser.add_argument('--test-binary', type=Path, help='use an already built e2e_bun_lockb binary')
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    binary = args.test_binary
    if binary is None:
        build = subprocess.run(['cargo', 'test', '-p', 'socket-patch-cli', '--test',
                                'e2e_bun_lockb', '--locked', '--no-run', '--message-format=json'],
                               cwd=root, text=True, stdout=subprocess.PIPE)
        if build.returncode:
            return build.returncode
        for line in build.stdout.splitlines():
            message = json.loads(line)
            if message.get('reason') == 'compiler-artifact' and message.get('target', {}).get('name') == 'e2e_bun_lockb':
                binary = Path(message['executable'])
        if binary is None:
            raise RuntimeError('Cargo did not return the required test executable')
    binary = binary.resolve()
    test_binary_sha256 = bun_matrix.sha256(binary.read_bytes())
    tools = args.tools.resolve()

    def cell(pair):
        version, writer_version = pair
        row = dict(reader=version, writer=writer_version, passed=False,
                   capturedAt=datetime.now(timezone.utc).isoformat(),
                   platform=platform.platform(), testBinarySha256=test_binary_sha256)
        if bun_matrix.ver(writer_version) < (0, 5, 9):
            row['upstreamLimitations'] = ['Bun before 0.5.9 has no tarball installer; the original '
                                         f'binary format is exercised with reader {version}.']
        try:
            reader = bun_matrix.install_tool(tools, version)
            writer = bun_matrix.install_tool(tools, writer_version)
            env = dict(os.environ, SOCKET_PATCH_BUN_LOCKB_REQUIRED='1',
                       SOCKET_PATCH_BUN_LOCKB_READER=str(reader),
                       SOCKET_PATCH_BUN_LOCKB_WRITER=str(writer),
                       SOCKET_PATCH_BUN_LOCKB_VERSION=version)
            if bun_matrix.ver(writer_version) < (0, 1, 7):
                env['SOCKET_PATCH_BUN_LOCKB_LEGACY_READER'] = str(bun_matrix.install_tool(tools, '0.5.9'))
            # npm aliases and overrides are installed by 1.0.36 and newer.
            if bun_matrix.ver(writer_version) >= (1, 0, 36):
                env['SOCKET_PATCH_BUN_LOCKB_EXTENDED'] = '1'
            else:
                env.pop('SOCKET_PATCH_BUN_LOCKB_EXTENDED', None)
            result = subprocess.run([binary, 'native_binary_', '--nocapture', '--test-threads=1'],
                                    cwd=root, env=env, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, timeout=600)
            log = result.stdout.decode(errors='replace')
            (output / f'{version}-writer-{writer_version}.log').write_text(log)
            row.update(extendedLayouts='SOCKET_PATCH_BUN_LOCKB_EXTENDED' in env,
                       exitCode=result.returncode, passed=result.returncode == 0 and
                       '3 passed;' in log and 'SKIP binary Bun E2E' not in log,
                       readerSha256=bun_matrix.sha256(reader.read_bytes()),
                       writerSha256=bun_matrix.sha256(writer.read_bytes()))
        except Exception as error:
            row['error'] = str(error)
        print(version, f'writer={writer_version}', 'PASS' if row['passed'] else 'FAIL', row.get('error', ''), flush=True)
        return row

    # Before 0.5.9 Bun's installer silently ignores tarball resolutions.
    # Keep the original-format writer coverage, using the first reader that
    # actually implements tarballs; report this limitation in every row.
    pairs = [(version if bun_matrix.ver(version) >= (0, 5, 9) else '0.5.9', version)
             for version in args.versions]
    pairs += [(version, '1.1.45') for version in args.versions if bun_matrix.ver(version) >= (1, 2, 0)]
    pairs += [('1.4.2', writer) for writer in ['0.1.1', '0.1.6', '0.6.7'] if writer in args.versions]
    # Downloads run before concurrent cells so two readers cannot race while
    # extracting their shared writer archive.
    try:
        for version in dict.fromkeys(v for pair in pairs for v in pair):
            bun_matrix.install_tool(tools, version)
    except Exception as error:
        bun_matrix.save(output / 'summary.json', [dict(passed=False, error=f'tool install failed: {error}')])
        print(f'tool install failed: {error}', flush=True)
        return 1
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        rows = list(pool.map(cell, pairs))
    bun_matrix.save(output / 'summary.json', rows)
    return 0 if rows and all(row['passed'] for row in rows) else 1


if __name__ == '__main__':
    raise SystemExit(main())
