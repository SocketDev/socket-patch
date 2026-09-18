#!/usr/bin/env python3
"""Native Bun / public Socket patch compatibility, with no service doubles."""

import argparse
import concurrent.futures
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import urllib.request
import zipfile

VERSIONS = ['0.8.1', '1.0.0', '1.0.36', '1.1.0', '1.1.38', '1.1.39', '1.1.45',
            '1.2.0', '1.2.23', '1.3.0', '1.3.14', '1.4.0', '1.4.2']
SHAPES = ['direct', 'dev', 'optional', 'alias', 'transitive', 'two-versions',
          'workspace', 'workspace-nested', 'peer', 'crlf', 'space-unicode',
          'custom-registry', 'text', 'isolated', 'hoisted', 'lockfile-only', 'production',
          'get-uuid', 'get-search']
PURL = 'pkg:npm/minimist@1.2.2'
UUID = '80630680-4da6-45f9-bba8-b888e0ffd58c'


def save(path, data):
    path.write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')


def run(command, cwd, env, log, required=True):
    try:
        result = subprocess.run([str(x) for x in command], cwd=cwd, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=180)
    except subprocess.TimeoutExpired as error:
        log.write_bytes(error.stdout or b'')
        raise
    log.write_bytes(result.stdout)
    if required and result.returncode:
        raise RuntimeError(f'{command}: {result.stdout.decode(errors="replace")[-4000:]}')
    return result.returncode, result.stdout.decode(errors='replace')


def git_hash(data):
    return hashlib.sha256(f'blob {len(data)}\0'.encode() + data).hexdigest()


def install_tool(root, version):
    system = platform.system().lower()
    arch = 'aarch64' if platform.machine().lower() in ('arm64', 'aarch64') else 'x64'
    if system == 'windows':
        arch = 'x64'
    asset = f'bun-{system}-{arch}'
    directory = root / version
    binary = directory / asset / ('bun.exe' if system == 'windows' else 'bun')
    if not binary.exists():
        directory.mkdir(parents=True, exist_ok=True)
        archive = directory / 'bun.zip'
        urllib.request.urlretrieve(
            f'https://github.com/oven-sh/bun/releases/download/bun-v{version}/{asset}.zip', archive)
        with zipfile.ZipFile(archive) as zipped:
            zipped.extractall(directory)
        archive.unlink()
        binary.chmod(0o755)
    actual = subprocess.check_output([binary, '--version'], text=True).strip()
    if actual != version:
        raise RuntimeError(f'Expected Bun {version}, got {actual}')
    return binary


def project_files(shape):
    manifest = dict(name='bun-patch-backtest', version='1.0.0', private=True,
                    dependencies={'minimist': '1.2.2'})
    files = {}
    if shape in ('dev', 'optional', 'peer'):
        key = {'dev': 'devDependencies', 'optional': 'optionalDependencies',
               'peer': 'peerDependencies'}[shape]
        manifest[key] = manifest.pop('dependencies')
    elif shape == 'alias':
        manifest['dependencies'] = {'alias': 'npm:minimist@1.2.2'}
    elif shape == 'transitive':
        manifest['dependencies'] = {'mkdirp': '0.5.3'}
        manifest['overrides'] = {'minimist': '1.2.2'}
    elif shape == 'two-versions':
        manifest['dependencies']['other'] = 'npm:minimist@1.2.8'
    elif shape == 'production':
        manifest['devDependencies'] = {'other': 'npm:minimist@1.2.8'}
    elif shape.startswith('workspace'):
        manifest['workspaces'] = ['packages/*']
        manifest['dependencies'] = {'consumer': 'workspace:*'}
        files['packages/consumer/package.json'] = json.dumps(dict(
            name='consumer', version='1.0.0',
            dependencies={'minimist': '1.2.2'})) + '\n'
        if shape == 'workspace-nested':
            manifest['dependencies']['minimist'] = '1.2.8'
    elif shape in ('isolated', 'hoisted'):
        files['bunfig.toml'] = f'[install]\nlinker = "{shape}"\n'
    elif shape == 'custom-registry':
        files['.npmrc'] = 'registry=https://registry.npmjs.org/\n'
    files['package.json'] = json.dumps(manifest, indent=2) + '\n'
    return {name: (data.replace('\n', '\r\n') if shape == 'crlf' else data).encode()
            for name, data in files.items()}


def installed_targets(project):
    targets = []
    for manifest in project.rglob('package.json'):
        if 'node_modules' not in manifest.parts or '.socket' in manifest.parts:
            continue
        data = json.loads(manifest.read_text(encoding='utf-8'))
        if data.get('name') == 'minimist' and data.get('version') == '1.2.2':
            targets.append(manifest.parent)
    return targets


def oracle(project, record, side):
    targets = installed_targets(project)
    checks = {}
    for target in targets:
        for filename, hashes in record['files'].items():
            file = target / filename.removeprefix('package/')
            expected = hashes.get(side + 'Hash')
            checks[str(file.relative_to(project))] = (
                git_hash(file.read_bytes()) == expected if expected and file.is_file()
                else expected is None and not file.exists())
    return bool(targets) and bool(checks) and all(checks.values()), checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cli', type=Path, required=True)
    parser.add_argument('--cli-revision', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--tools', type=Path)
    parser.add_argument('--versions', nargs='+', default=VERSIONS)
    parser.add_argument('--shapes', nargs='+', default=SHAPES, choices=SHAPES)
    parser.add_argument('--modes', nargs='+', default=['hosted', 'vendored'],
                        choices=['hosted', 'vendored', 'vendored-detached'])
    parser.add_argument('--jobs', type=int, default=4)
    args = parser.parse_args()
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=True)
    cli = root / ('socket-patch.exe' if platform.system() == 'Windows' else 'socket-patch')
    shutil.copy2(args.cli.resolve(), cli)
    toolroot = (args.tools or root / 'tools').resolve()
    tools = {v: install_tool(toolroot, v) for v in args.versions}
    base_env = {k: v for k, v in os.environ.items()
                if not k.startswith(('SOCKET_', 'BUN_', 'npm_config_', 'NPM_CONFIG_'))}
    base_env.update(SOCKET_NO_CONFIG='1', SOCKET_NO_UPDATE_CHECK='1', NO_COLOR='1')
    provenance = dict(capturedAt=datetime.now(timezone.utc).isoformat(),
                      os=platform.system().lower(), platform=platform.platform(),
                      cliRevision=args.cli_revision,
                      cliSha256=hashlib.sha256(cli.read_bytes()).hexdigest())

    def backtest(job):
        version, shape, mode = job
        case = root / 'captures' / f'{version}-{shape}-{mode}'
        case.mkdir(parents=True, exist_ok=True)
        project = case / ('project space café' if shape == 'space-unicode' else 'project')
        if project.exists():
            shutil.rmtree(project)
        project.mkdir()
        row = dict(bun=version, shape=shape, mode=mode, passed=False, **provenance)
        checks = {}
        row['checks'] = checks
        try:
            bun = tools[version]
            env = dict(base_env, PATH=str(bun.parent) + os.pathsep + base_env['PATH'],
                       BUN_INSTALL_CACHE_DIR=str(case / 'cache'),
                       BUN_INSTALL=str(case / 'bun-home'))
            files = project_files(shape)
            for name, data in files.items():
                (project / name).parent.mkdir(parents=True, exist_ok=True)
                (project / name).write_bytes(data)
            install_args = ['install', '--ignore-scripts']
            if shape == 'text':
                install_args += ['--save-text-lockfile']
            run([bun, *install_args], project, env, case / 'baseline.log')
            original = {name: (project / name).read_bytes()
                        for name in [*files, 'bun.lock', 'bun.lockb'] if (project / name).exists()}
            row['originalSha256'] = {n: hashlib.sha256(b).hexdigest() for n, b in original.items()}
            checks['installedBefore'] = bool(installed_targets(project))
            if shape == 'lockfile-only':
                shutil.rmtree(project / 'node_modules')
            verb = ['get', UUID if shape == 'get-uuid' else PURL] if shape.startswith('get-') else ['scan']
            command = [cli, *verb, '--mode', 'vendored' if mode == 'vendored-detached' else mode, '--cwd', project,
                       '--json', '--yes', '--no-telemetry']
            if mode == 'vendored-detached':
                command.append('--detached')
            code, output = run(command, project, env, case / 'cli.log', False)
            envelope = json.loads(output[output.index('{'):])
            save(case / 'cli-output.json', envelope)
            applied = (envelope.get('redirect', {}).get('redirected', 0) if mode == 'hosted'
                       else envelope.get('vendor', {}).get('summary', {}).get('applied', 0))
            warnings = (envelope.get('redirect', {}).get('warnings', []) if mode == 'hosted'
                        else envelope.get('vendor', {}).get('events', []))
            row['refusals'] = [w.get('code', w.get('errorCode')) for w in warnings]
            row['refusals'] += [p['errorCode'] for p in envelope.get('download', {}).get('patches', [])
                               if p.get('errorCode')]
            row['refusals'] += [p['errorCode'] for p in envelope.get('patches', []) if p.get('errorCode')]
            row['applied'] = applied
            if not checks['installedBefore'] and version in ['0.8.1', '1.0.0'] and shape in ['peer', 'transitive']:
                row['supported'] = False
                row['upstreamLimitations'] = ['This Bun release does not install the requested peer or honor the transitive override']
                del checks['installedBefore']
                checks['noPatchApplied'] = applied == 0
                checks['unchanged'] = all((project / n).read_bytes() == b for n, b in original.items())
            elif any('bun_workspace_unsupported' in (x or '') for x in row['refusals']):
                row['supported'] = False
                checks['refused'] = applied == 0
                checks['unchanged'] = all((project / n).read_bytes() == b for n, b in original.items())
            elif 'bun.lockb' in original and not (project / 'bun.lock').exists():
                row['supported'] = False
                checks['refusedOrNoDiscoverablePackages'] = applied == 0 and (
                    any('bun_lockb' in (x or '') or shape == 'alias' and x == 'package_not_installed' for x in row['refusals'])
                    or shape == 'lockfile-only' and envelope.get('scannedPackages') == 0
                    and envelope.get('packagesWithPatches') == 0)
                checks['unchanged'] = all((project / n).read_bytes() == b for n, b in original.items())
            else:
                row['supported'] = True
                checks['cliSuccess'] = code == 0 and applied == 1
                if not checks['cliSuccess']:
                    raise RuntimeError(f'Expected one applied patch: {output[-4000:]}')
                ledger = project / ('.socket/vendor/redirect-state.json' if mode == 'hosted'
                                    else '.socket/vendor/state.json' if mode == 'vendored-detached'
                                    else '.socket/manifest.json')
                state = json.loads(ledger.read_text())
                record = (state['records'][PURL] if mode == 'hosted' else
                          state['entries'][PURL]['record'] if mode == 'vendored-detached' else state['patches'][PURL])
                row['patchUuid'] = record['uuid']
                checks['publishedPatch'] = record['uuid'] == UUID
                if mode == 'vendored-detached':
                    checks['noManifest'] = not (project / '.socket/manifest.json').exists()
                capture = case / 'tree'
                if capture.exists():
                    shutil.rmtree(capture)
                capture.mkdir()
                names = [*files, 'bun.lock', 'bun.lockb', '.socket/manifest.json']
                for name in names:
                    source = project / name
                    if source.is_file():
                        destination = capture / name
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copyfile(source, destination)
                row['manifestSha256'] = {p.relative_to(capture).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                                         for p in capture.rglob('*') if p.is_file()}
                patched_lock = (project / 'bun.lock').read_bytes()
                for label, flags in [('frozen', ['--frozen-lockfile']), ('ordinary', [])]:
                    if shape == 'production':
                        flags = [*flags, '--production']
                    for modules in sorted(project.rglob('node_modules'), key=lambda p: len(p.parts)):
                        if modules.exists() and not modules.is_symlink():
                            shutil.rmtree(modules)
                    fresh_env = dict(env, BUN_INSTALL_CACHE_DIR=str(case / ('cache-' + label)))
                    run([bun, 'install', '--ignore-scripts', *flags], project, fresh_env, case / (label + '.log'))
                    correct, hashes = oracle(project, record, 'after')
                    checks[label + 'PatchedBytes'] = correct
                    row[label + 'Files'] = hashes
                    checks[label + 'StableLock'] = (project / 'bun.lock').read_bytes() == patched_lock
                _, repeat = run(command, project, env, case / 'repeat.log', False)
                row['repeat'] = json.loads(repeat[repeat.index('{'):])
                checks['repeatStableLock'] = (project / 'bun.lock').read_bytes() == patched_lock
                tampered = b''.join(re.sub(rb'sha512-[A-Za-z0-9+/=]+(?="\])', b'sha512-' + b'A' * 86 + b'==', line) if UUID.encode() in line else line for line in patched_lock.splitlines(keepends=True))
                checks['tamperedDigest'] = tampered != patched_lock
                (project / 'bun.lock').write_bytes(tampered)
                for modules in sorted(project.rglob('node_modules'), key=lambda p: len(p.parts)):
                    if modules.exists() and not modules.is_symlink():
                        shutil.rmtree(modules)
                code, output = run([bun, 'install', '--ignore-scripts', '--frozen-lockfile'], project,
                                   dict(env, BUN_INSTALL_CACHE_DIR=str(case / 'cache-corrupt')),
                                   case / 'corrupt.log', False)
                row['rejectsCorruptDigest'] = code != 0 and ('integrity' in output.lower() or 'checksum' in output.lower())
                # Older Bun accepts tarball hashes but does not enforce them.
                if tuple(map(int, version.split('.'))) < (1, 3, 14):
                    checks['legacyDigestBehavior'] = code == 0
                    row.setdefault('upstreamLimitations', []).append('Bun does not verify tarball integrity on this release')
                else:
                    checks['rejectCorruptDigest'] = row['rejectsCorruptDigest']
                (project / 'bun.lock').write_bytes(patched_lock)
                run([cli, 'rollback', '--cwd', project, '--json', '--yes', '--no-telemetry'],
                    project, env, case / 'rollback.log')
                checks['rollbackOriginalFiles'] = all((project / n).exists() and (project / n).read_bytes() == b
                                                       for n, b in original.items())
                for modules in sorted(project.rglob('node_modules'), key=lambda p: len(p.parts)):
                    if modules.exists() and not modules.is_symlink():
                        shutil.rmtree(modules)
                run([bun, 'install', '--ignore-scripts'], project,
                    dict(env, BUN_INSTALL_CACHE_DIR=str(case / 'cache-rollback')), case / 'reinstall.log')
                checks['rollbackOriginalBytes'], row['rollbackFiles'] = oracle(project, record, 'before')
            if not row.get('supported'):
                manifest = project / '.socket/manifest.json'
                checks['noFalseManifestAnnotation'] = not manifest.exists() or PURL not in json.loads(manifest.read_text())['patches']
                checks['unchangedLockPresence'] = all((project / name).exists() == (name in original)
                                                      for name in ['bun.lock', 'bun.lockb'])
            row['passed'] = all(checks.values())
        except Exception as error:
            row['error'] = str(error)
        save(case / 'result.json', row)
        print(version, shape, mode, 'PASS' if row['passed'] else 'FAIL',
              [k for k, v in checks.items() if not v], row.get('error', '')[:200], flush=True)
        return row

    jobs = [(v, s, m) for v in args.versions for s in args.shapes for m in args.modes
            if (s not in ('isolated', 'hoisted') or tuple(map(int, v.split('.'))) >= (1, 3, 0))
            and (s != 'text' or tuple(map(int, v.split('.'))) >= (1, 1, 38))
            and (not s.startswith('get-') or m != 'vendored-detached')]
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        rows = list(pool.map(backtest, jobs))
    save(root / 'summary.json', rows)
    return 0 if all(row['passed'] for row in rows) else 1


if __name__ == '__main__':
    raise SystemExit(main())
