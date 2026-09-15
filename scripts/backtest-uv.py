import concurrent.futures
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import zipfile

import argparse
import io
import platform
import sys
import urllib.request

VERSIONS = [
    '0.0.5',
    '0.1.45',
    '0.2.37',
    '0.3.5',
    '0.4.30',
    '0.5.31',
    '0.6.0',
    '0.6.17',
    '0.7.22',
    '0.8.24',
    '0.9.30',
    '0.10.12',
    '0.11.33',
    '0.12.13',
]
parser = argparse.ArgumentParser()
parser.add_argument('--socket-patch', type=Path, required=True)
parser.add_argument('--socket-patch-revision', required=True)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--python', default=sys.executable)
parser.add_argument('--versions', nargs='+', default=VERSIONS)
args = parser.parse_args()
ROOT = args.output.resolve()
CLI = args.socket_patch.resolve()
BOOTSTRAP = ROOT / 'bin/0.12.13/uv'
WHEEL = ROOT / 'urllib3-1.26.18-py2.py3-none-any.whl'
ENV = {
    key: value
    for key, value in os.environ.items()
    if not key.startswith(('UV_', 'PIP_', 'PYTHON', 'SOCKET_')) and key != 'VIRTUAL_ENV'
}
ENV['SOCKET_NO_CONFIG'] = '1'
ENV['SOCKET_TELEMETRY_DISABLED'] = '1'
ROOT.mkdir(parents=True, exist_ok=True)


def fetch_json(url):
    with urllib.request.urlopen(url, timeout=90) as response:
        return json.load(response)


def download(file):
    with urllib.request.urlopen(file['url'], timeout=90) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != file['digests']['sha256']:
        raise ValueError('download hash mismatch: ' + file['filename'])
    return data


def install_binaries():
    system = platform.system()
    machine = platform.machine().lower()
    if system == 'Darwin':
        marker = 'macosx'
        architecture = 'arm64' if machine in ['arm64', 'aarch64'] else 'x86_64'
    elif system == 'Linux':
        marker = 'manylinux'
        architecture = 'aarch64' if machine in ['arm64', 'aarch64'] else 'x86_64'
    else:
        raise ValueError('This backtest requires macOS or Linux')
    registry = fetch_json('https://pypi.org/pypi/uv/json')
    records = []
    for version in dict.fromkeys([*args.versions, '0.12.13']):
        file = next(
            file
            for file in registry['releases'][version]
            if marker in file['filename'] and architecture in file['filename']
        )
        folder = ROOT / 'bin' / version
        folder.mkdir(parents=True, exist_ok=True)
        archive = zipfile.ZipFile(io.BytesIO(download(file)))
        executable = next(name for name in archive.namelist() if name.endswith('/uv'))
        (folder / 'uv').write_bytes(archive.read(executable))
        (folder / 'uv').chmod(0o755)
        records.append(
            {
                'version': version,
                'url': file['url'],
                'sha256': file['digests']['sha256'],
                'uploaded': file['upload_time_iso_8601'],
                'filename': file['filename'],
            }
        )
    (ROOT / 'binaries.json').write_text(json.dumps(records, indent=2) + '\n')
    release = fetch_json('https://pypi.org/pypi/urllib3/1.26.18/json')
    file = next(file for file in release['urls'] if file['filename'] == WHEEL.name)
    WHEEL.write_bytes(download(file))


def run(exe, args, cwd, key, rows):
    env = dict(ENV, UV_CACHE_DIR=str(cwd / '.uv-cache'))
    try:
        out = subprocess.run(
            [str(exe), *args],
            cwd=cwd,
            env=env,
            text=True,
            capture_output=True,
            timeout=180,
        )
        row = {
            'key': key,
            'command': [str(exe), *args],
            'cwd': str(cwd),
            'exitCode': out.returncode,
            'stdout': out.stdout,
            'stderr': out.stderr,
        }
    except subprocess.TimeoutExpired as err:
        row = {
            'key': key,
            'command': [str(exe), *args],
            'cwd': str(cwd),
            'exitCode': 124,
            'stdout': err.stdout.decode()
            if isinstance(err.stdout, bytes)
            else err.stdout or '',
            'stderr': 'timed out',
        }
    rows.append(row)
    return row


def bootstrap(path, rows):
    run(BOOTSTRAP, ['venv', '.venv', '--python', args.python], path, 'venv', rows)
    run(
        BOOTSTRAP,
        ['pip', 'install', '--python', str(path / '.venv/bin/python'), str(WHEEL)],
        path,
        'install-original',
        rows,
    )


def project_matrix(version):
    exe = ROOT / 'bin' / version / 'uv'
    base = ROOT / 'matrix' / version
    original = base / 'original'
    original.mkdir(parents=True, exist_ok=True)
    generation = []
    (original / 'pyproject.toml').write_text(
        '[project]\nname = "socket-uv-patch-fixture"\n'
        'version = "0.1.0"\nrequires-python = ">=3.9"\n'
        'dependencies = ["urllib3==1.26.18"]\n'
    )
    run(exe, ['lock', '--python', args.python], original, 'lock', generation)
    if not (original / 'requirements.txt').exists():
        (original / 'requirements.in').write_text('urllib3==1.26.18\n')
        run(
            exe,
            [
                'pip',
                'compile',
                'requirements.in',
                '--generate-hashes',
                '-o',
                'requirements.txt',
            ],
            original,
            'compile',
            generation,
        )
    (base / 'generate.json').write_text(
        json.dumps({'version': version, 'commands': generation}, indent=2) + '\n'
    )
    rows = []
    for kind in ['project', 'requirements']:
        if kind == 'project' and not (original / 'uv.lock').exists():
            continue
        for mode in ['hosted', 'vendored']:
            case = base / (kind + '-' + mode)
            case.mkdir(exist_ok=True)
            for name in (
                ['pyproject.toml', 'uv.lock']
                if kind == 'project'
                else ['requirements.txt']
            ):
                shutil.copyfile(original / name, case / name)
            bootstrap(case, rows)
            scan = run(
                CLI,
                [
                    'scan',
                    '--cwd',
                    str(case),
                    '--mode',
                    mode,
                    '--json',
                    '--yes',
                    '--no-telemetry',
                ],
                case,
                kind + '-' + mode + '-socket-patch',
                rows,
            )
            if scan['exitCode'] != 0:
                continue
            if kind == 'project':
                for fmt, filename in [
                    ('requirements-txt', 'export-requirements.txt'),
                    ('pylock.toml', 'pylock.toml'),
                ]:
                    run(
                        exe,
                        [
                            'export',
                            '--frozen',
                            '--format',
                            fmt,
                            '--output-file',
                            filename,
                        ],
                        case,
                        kind + '-' + mode + '-export-' + fmt,
                        rows,
                    )
                help_out = subprocess.run(
                    [str(exe), 'sync', '--help'], capture_output=True, text=True
                )
                sync_args = ['sync', '--python', args.python]
                if '--frozen' in help_out.stdout:
                    sync_args.append('--frozen')
                if '--no-install-project' in help_out.stdout:
                    sync_args.append('--no-install-project')
                else:
                    package = case / 'socket_uv_patch_fixture'
                    package.mkdir(exist_ok=True)
                    (package / '__init__.py').write_text('')
                shutil.rmtree(case / '.venv')
                shutil.rmtree(case / '.uv-cache', ignore_errors=True)
                if mode == 'vendored' and '--offline' in help_out.stdout:
                    sync_args.append('--offline')
                locked = (case / 'uv.lock').read_bytes()
                sync = run(
                    exe, sync_args, case, kind + '-' + mode + '-lock-sync', rows
                )
                sync['lockUnchanged'] = (case / 'uv.lock').read_bytes() == locked
                if not sync['lockUnchanged']:
                    raise ValueError('Install modified the patched uv lock')
            else:
                shutil.rmtree(case / '.venv')
                run(
                    BOOTSTRAP,
                    ['venv', '.venv', '--python', args.python],
                    case,
                    kind + '-' + mode + '-fresh-venv',
                    rows,
                )
                shutil.rmtree(case / '.uv-cache', ignore_errors=True)
                sync = run(
                    exe,
                    ['pip', 'sync', 'requirements.txt'],
                    case,
                    kind + '-' + mode + '-pip-sync',
                    rows,
                )
            if sync['exitCode'] == 0:
                targets = list(
                    (case / '.venv/lib').glob(
                        'python*/site-packages/urllib3/response.py'
                    )
                )
                sync['installedResponseSha256'] = (
                    hashlib.sha256(targets[0].read_bytes()).hexdigest()
                    if targets
                    else None
                )
                wheels = (
                    list((case / '.socket/vendor/pypi').glob('*/*.whl'))
                    if mode == 'vendored'
                    else []
                )
                if wheels:
                    sync['patchedResponseSha256'] = hashlib.sha256(
                        zipfile.ZipFile(wheels[0]).read('urllib3/response.py')
                    ).hexdigest()
    (base / 'backtest.json').write_text(
        json.dumps({'version': version, 'commands': rows}, indent=2) + '\n'
    )
    return {
        'version': version,
        'commands': [
            (r['key'], r['exitCode'])
            for r in rows
            if r['key'] not in ['venv', 'install-original']
        ],
    }


def requirements_matrix(version):
    exe = ROOT / 'bin' / version / 'uv'
    base = ROOT / 'matrix' / version
    rows = []
    for mode in ['hosted', 'vendored']:
        case = base / ('requirements-plain-' + mode)
        case.mkdir(exist_ok=True)
        (case / 'requirements.in').write_text('urllib3==1.26.18\n')
        run(
            exe,
            ['pip', 'compile', 'requirements.in', '-o', 'requirements.txt'],
            case,
            'compile-plain',
            rows,
        )
        bootstrap(case, rows)
        scan = run(
            CLI,
            [
                'scan',
                '--cwd',
                str(case),
                '--mode',
                mode,
                '--json',
                '--yes',
                '--no-telemetry',
            ],
            case,
            'requirements-plain-' + mode + '-socket-patch',
            rows,
        )
        if scan['exitCode'] != 0:
            continue
        shutil.rmtree(case / '.venv')
        run(
            BOOTSTRAP,
            ['venv', '.venv', '--python', args.python],
            case,
            'fresh-venv',
            rows,
        )
        shutil.rmtree(case / '.uv-cache', ignore_errors=True)
        sync = run(
            exe,
            ['pip', 'sync', 'requirements.txt'],
            case,
            'requirements-plain-' + mode + '-pip-sync',
            rows,
        )
        if sync['exitCode'] == 0:
            target = next(
                (case / '.venv/lib').glob('python*/site-packages/urllib3/response.py')
            )
            sync['installedResponseSha256'] = hashlib.sha256(
                target.read_bytes()
            ).hexdigest()
    if version == '0.2.37':
        case = base / 'project-vendored'
        sync = run(
            exe,
            ['sync', '--frozen', '--python', args.python],
            case,
            'project-vendored-frozen-sync-root-build-networked',
            rows,
        )
        if sync['exitCode'] == 0:
            target = next(
                (case / '.venv/lib').glob('python*/site-packages/urllib3/response.py')
            )
            sync['installedResponseSha256'] = hashlib.sha256(
                target.read_bytes()
            ).hexdigest()
    (base / 'backtest-extensions.json').write_text(
        json.dumps({'version': version, 'commands': rows}, indent=2) + '\n'
    )
    return {
        'version': version,
        'commands': [
            (r['key'], r['exitCode'])
            for r in rows
            if r['key']
            not in ['venv', 'install-original', 'fresh-venv', 'compile-plain']
        ],
    }


def format_matrix(version):
    exe = ROOT / 'bin' / version / 'uv'
    base = ROOT / 'matrix' / version
    rows = []
    for mode in ['hosted', 'vendored']:
        for kind, name in [
            ('requirements', 'export-requirements.txt'),
            ('pylock', 'pylock.toml'),
        ]:
            source = base / ('project-' + mode)
            if not (source / name).is_file():
                continue
            case = base / ('export-' + kind + '-' + mode)
            case.mkdir(exist_ok=True)
            target_name = (
                'requirements.txt' if kind == 'requirements' else 'pylock.toml'
            )
            shutil.copyfile(source / name, case / target_name)
            if mode == 'vendored':
                shutil.copytree(
                    source / '.socket', case / '.socket', dirs_exist_ok=True
                )
            run(
                BOOTSTRAP,
                ['venv', '.venv', '--python', args.python],
                case,
                'venv',
                rows,
            )
            sync_args = ['pip', 'sync', target_name]
            if mode == 'vendored':
                sync_args.append('--offline')
            out = run(exe, sync_args, case, kind + '-' + mode + '-export-sync', rows)
            if out['exitCode'] == 0:
                target = next(
                    (case / '.venv/lib').glob(
                        'python*/site-packages/urllib3/response.py'
                    )
                )
                out['installedResponseSha256'] = hashlib.sha256(
                    target.read_bytes()
                ).hexdigest()
    for kind in ['script', 'pylock']:
        for mode in ['hosted', 'vendored']:
            case = base / (kind + '-direct-' + mode)
            case.mkdir(exist_ok=True)
            if kind == 'script':
                (case / 'example.py').write_text(
                    '# /// script\n# requires-python = ">=3.9"\n# dependencies = ["urllib3==1.26.18"]\n# ///\n'
                    'import hashlib\nfrom pathlib import Path\nimport urllib3.response\n'
                    'print(hashlib.sha256(Path(urllib3.response.__file__).read_bytes()).hexdigest())\n'
                )
                out = run(
                    exe,
                    ['lock', '--script', 'example.py', '--python', args.python],
                    case,
                    'script-lock-' + mode,
                    rows,
                )
            else:
                (case / 'requirements.in').write_text('urllib3==1.26.18\n')
                out = run(
                    exe,
                    [
                        'pip',
                        'compile',
                        'requirements.in',
                        '--python-version',
                        '3.9',
                        '-o',
                        'pylock.toml',
                    ],
                    case,
                    'compile-pylock-' + mode,
                    rows,
                )
                if (
                    not (case / 'pylock.toml').is_file()
                    or 'lock-version = ' not in (case / 'pylock.toml').read_text()
                ):
                    out['formatSupported'] = False
                    continue
                out['formatSupported'] = True
            if out['exitCode']:
                continue
            bootstrap(case, rows)
            scan = run(
                CLI,
                [
                    'scan',
                    '--cwd',
                    str(case),
                    '--mode',
                    mode,
                    '--json',
                    '--yes',
                    '--no-telemetry',
                ],
                case,
                kind + '-direct-' + mode + '-socket-patch',
                rows,
            )
            if scan['exitCode']:
                continue
            shutil.rmtree(case / '.venv')
            shutil.rmtree(case / '.uv-cache', ignore_errors=True)
            if kind == 'script':
                install_args = [
                    'run',
                    '--frozen',
                    '--python',
                    args.python,
                    '--script',
                    'example.py',
                ]
            else:
                run(
                    BOOTSTRAP,
                    ['venv', '.venv', '--python', args.python],
                    case,
                    'fresh-venv',
                    rows,
                )
                install_args = ['pip', 'sync', 'pylock.toml']
            if mode == 'vendored':
                install_args.insert(1, '--offline')
            lockfile = case / (
                'example.py.lock' if kind == 'script' else 'pylock.toml'
            )
            locked = lockfile.read_bytes()
            installed = run(
                exe,
                install_args,
                case,
                kind + '-direct-' + mode + '-install',
                rows,
            )
            installed['lockUnchanged'] = lockfile.read_bytes() == locked
            if not installed['lockUnchanged']:
                raise ValueError('Install modified the patched standalone lock')
            if installed['exitCode'] == 0:
                if kind == 'script':
                    digest = installed['stdout'].strip()
                    if not re.fullmatch(r'[0-9a-f]{64}', digest):
                        raise ValueError('Script did not report installed file hash')
                else:
                    target = next(
                        (case / '.venv/lib').glob(
                            'python*/site-packages/urllib3/response.py'
                        )
                    )
                    digest = hashlib.sha256(target.read_bytes()).hexdigest()
                installed['installedResponseSha256'] = digest
    (base / 'format-backtest.json').write_text(
        json.dumps({'version': version, 'commands': rows}, indent=2) + '\n'
    )
    return {
        'version': version,
        'commands': [
            (x['key'], x['exitCode'])
            for x in rows
            if x['key'] not in ['venv', 'install-original']
        ],
    }


def unfrozen_matrix(version):
    exe = ROOT / 'bin' / version / 'uv'
    base = ROOT / 'matrix' / version
    rows = []
    for kind in ['project', 'script']:
        for mode in ['hosted', 'vendored']:
            source = base / (
                kind + ('-direct-' if kind == 'script' else '-') + mode
            )
            names = (
                ['pyproject.toml', 'uv.lock']
                if kind == 'project'
                else ['example.py', 'example.py.lock']
            )
            lockfile = source / names[1]
            if (
                not lockfile.is_file()
                or 'e828efa5-5c6d-43f3-9909-03f5ac232b98'
                not in lockfile.read_text()
            ):
                continue
            case = base / (kind + '-unfrozen-' + mode)
            case.mkdir(exist_ok=True)
            for name in names:
                shutil.copyfile(source / name, case / name)
            if mode == 'vendored' and (source / '.socket').is_dir():
                shutil.copytree(
                    source / '.socket', case / '.socket', dirs_exist_ok=True
                )
            if kind == 'project':
                install_args = ['sync', '--python', args.python]
                help_out = subprocess.run(
                    [str(exe), 'sync', '--help'], capture_output=True, text=True
                )
                if '--no-install-project' in help_out.stdout:
                    install_args.append('--no-install-project')
                else:
                    package = case / 'socket_uv_patch_fixture'
                    package.mkdir(exist_ok=True)
                    (package / '__init__.py').write_text('')
            else:
                install_args = [
                    'run', '--python', args.python, '--script', 'example.py'
                ]
                help_out = subprocess.run(
                    [str(exe), 'run', '--help'], capture_output=True, text=True
                )
            variants = [('unfrozen', install_args)]
            if '--locked' in help_out.stdout:
                variants.insert(
                    0, ('locked', [install_args[0], '--locked', *install_args[1:]])
                )
            for label, command in variants:
                locked = (case / names[1]).read_bytes()
                installed = run(
                    exe,
                    command,
                    case,
                    kind + '-' + mode + '-' + label + '-install',
                    rows,
                )
                if label == 'locked':
                    installed['lockUnchanged'] = (
                        (case / names[1]).read_bytes() == locked
                    )
                    if not installed['lockUnchanged']:
                        raise ValueError('Locked install modified the lockfile')
                if installed['exitCode'] == 0:
                    if kind == 'script':
                        digest = installed['stdout'].strip()
                        if not re.fullmatch(r'[0-9a-f]{64}', digest):
                            raise ValueError('Script did not report installed file hash')
                    else:
                        target = next(
                            (case / '.venv/lib').glob(
                                'python*/site-packages/urllib3/response.py'
                            )
                        )
                        digest = hashlib.sha256(target.read_bytes()).hexdigest()
                    installed['installedResponseSha256'] = digest
    (base / 'unfrozen-backtest.json').write_text(
        json.dumps({'version': version, 'commands': rows}, indent=2) + '\n'
    )
    return {
        'version': version,
        'commands': [(row['key'], row['exitCode']) for row in rows],
    }


def write_summary():
    patched_response = (
        '21d9a7810de52973c88d9170f437e98921456bce445ab0618576987478a6a6e4'
    )
    versions = []
    command_catalog = {}
    for version in args.versions:
        base = ROOT / 'matrix' / version
        lockfile = base / 'original' / 'uv.lock'
        lock = lockfile.read_text() if lockfile.exists() else ''
        revision = re.search(r'^revision = (\d+)$', lock, re.MULTILINE)
        observations = []
        for filename in [
            'generate.json',
            'backtest.json',
            'backtest-extensions.json',
            'format-backtest.json',
            'unfrozen-backtest.json',
        ]:
            path = base / filename
            if not path.exists():
                continue
            for row in json.loads(path.read_text())['commands']:
                key = row['key']
                if key in ['venv', 'install-original', 'fresh-venv'] or key.endswith(
                    '-fresh-venv'
                ):
                    continue
                if filename == 'generate.json' and key not in ['lock', 'version']:
                    continue
                command = row['command']
                if command and not command[0].startswith('/'):
                    command = [str(ROOT / 'bin' / version / 'uv'), *command]
                spec = {
                    'args': [
                        x.replace(str(CLI), '<socket-patch>')
                        .replace(str(ROOT), '<output>')
                        .replace(version, '<uv-version>')
                        for x in command
                    ],
                    'cwd': row.get('cwd', str(base / 'original'))
                    .replace(str(ROOT), '<output>')
                    .replace(version, '<uv-version>'),
                }
                command_id = key
                variant = 1
                while (
                    command_id in command_catalog
                    and command_catalog[command_id] != spec
                ):
                    variant += 1
                    command_id = key + '-variant-' + str(variant)
                command_catalog[command_id] = spec
                item = {
                    'command': command_id,
                    'exitCode': row.get('exitCode', row.get('status')),
                }
                if 'formatSupported' in row:
                    item['formatSupported'] = row['formatSupported']
                if 'lockUnchanged' in row:
                    item['lockUnchanged'] = row['lockUnchanged']
                if row.get('installedResponseSha256'):
                    item['installedResponseSha256'] = row['installedResponseSha256']
                    item['installedPatch'] = (
                        row['installedResponseSha256'] == patched_response
                    )
                if key.endswith('socket-patch'):
                    payload = json.loads(row['stdout'])
                    redirect = payload.get('redirect')
                    vendor = payload.get('vendor')
                    if redirect:
                        item['rewrittenFiles'] = redirect.get('rewrittenFiles', [])
                        item['redirected'] = redirect.get('redirected', 0)
                        item['warnings'] = [
                            warning['code'] for warning in redirect.get('warnings', [])
                        ]
                    if vendor:
                        item['vendorSummary'] = {
                            key: vendor.get('summary', {}).get(key)
                            for key in ['applied', 'failed']
                        }
                        item['vendorErrors'] = [
                            event
                            for event in vendor.get('events', [])
                            if event.get('action') == 'failed'
                        ]
                elif item['exitCode']:
                    item['diagnostic'] = row['stderr'].replace(str(ROOT), '<output>')[
                        :1000
                    ]
                observations.append(item)
        versions.append(
            {
                'version': version,
                'lockSchema': 'distribution'
                if '[[distribution]]' in lock
                else 'package'
                if lock
                else None,
                'lockVersion': 1 if lock else None,
                'lockRevision': int(revision.group(1)) if revision else None,
                'observations': observations,
            }
        )
    result = {
        'date': datetime.date.today().isoformat(),
        'scope': f'{len(args.versions)} pinned uv releases on {platform.platform()}; interpreter {args.python}',
        'socketPatchRevision': args.socket_patch_revision,
        'socketPatchVersion': subprocess.check_output(
            [str(CLI), '--version'], text=True
        ).strip(),
        'socketPatchBinarySha256': hashlib.sha256(CLI.read_bytes()).hexdigest(),
        'patchUuid': 'e828efa5-5c6d-43f3-9909-03f5ac232b98',
        'originalWheelSha256': hashlib.sha256(WHEEL.read_bytes()).hexdigest(),
        'patchedWheelSha256': 'ccc9a9e0b18a5efc7038c504cfc580e47d2e02e5390f2e29cad833cbccb956b6',
        'patchedResponseSha256': patched_response,
        'commands': command_catalog,
        'versions': versions,
    }
    text = json.dumps(result, indent=2) + '\n'
    text = re.sub(
        r'(https://patch\.socket\.dev/patch/pypi/urllib3/1\.26\.18/)[0-9a-f-]{36}/',
        r'\g<1>11111111-1111-4111-8111-111111111111/',
        text,
    )
    (ROOT / 'results.json').write_text(text)


def backtest(version):
    return [
        project_matrix(version),
        requirements_matrix(version),
        format_matrix(version),
        unfrozen_matrix(version),
    ]


if __name__ == '__main__':
    install_binaries()
    provenance = {
        'socketPatchRevision': args.socket_patch_revision,
        'socketPatchBinarySha256': hashlib.sha256(CLI.read_bytes()).hexdigest(),
        'socketPatchVersion': subprocess.check_output(
            [str(CLI), '--version'], text=True
        ).strip(),
        'platform': platform.platform(),
        'python': args.python,
    }
    (ROOT / 'provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        for result in executor.map(backtest, args.versions):
            print(json.dumps(result), flush=True)

    write_summary()
