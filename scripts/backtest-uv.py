import concurrent.futures
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import textwrap
import zipfile

import argparse
import io
import platform
import sys
import urllib.request

# Every 0.x release family, first and latest release of each, plus the
# releases on either side of each behaviour boundary observed with real
# binaries (the lower one is the last release WITHOUT the feature):
#   0.1.23 / 0.1.24  `uv pip sync` accepts bare `./wheel` requirement paths
#   0.1.44 / 0.1.45  `uv lock` writes a lock (the subcommand exists from 0.1.42
#                    but panics "not yet implemented" through 0.1.44)
#   0.2.5  / 0.2.6   `[[distribution]]` artifacts: `[distribution.sdist]` /
#                    `[[distribution.wheel]]` tables -> inline `sdist = {…}` /
#                    `wheels = [...]` values
#   0.2.17 / 0.2.18  `[[distribution]]` sources: `"registry+…"` strings ->
#                    inline tables (`{ registry = … }`)
#   0.2.34 / 0.2.35  uv.lock `[[distribution]]` -> `[[package]]` grammar
#   0.2.36 / 0.2.37  root `[package.metadata]` (requires-dist) appears
#   0.4.0  / 0.4.1   `uv export`
#   0.5.16 / 0.5.17  `uv lock --script`
#   0.6.14 / 0.6.15  PEP 751 `pip compile -o pylock.toml`; lock revision 1 -> 2
#   0.8.3  / 0.8.4   lock revision 2 -> 3
VERSIONS = [
    '0.0.5',
    '0.1.0',
    '0.1.23',
    '0.1.24',
    '0.1.44',
    '0.1.45',
    '0.2.0',
    '0.2.5',
    '0.2.6',
    '0.2.17',
    '0.2.18',
    '0.2.34',
    '0.2.35',
    '0.2.36',
    '0.2.37',
    '0.3.0',
    '0.3.5',
    '0.4.0',
    '0.4.1',
    '0.4.30',
    '0.5.0',
    '0.5.16',
    '0.5.17',
    '0.5.31',
    '0.6.0',
    '0.6.14',
    '0.6.15',
    '0.6.17',
    '0.7.0',
    '0.7.22',
    '0.8.0',
    '0.8.3',
    '0.8.4',
    '0.8.24',
    '0.9.0',
    '0.9.30',
    '0.10.0',
    '0.10.12',
    '0.11.0',
    '0.11.33',
    '0.12.0',
    '0.12.15',
]
parser = argparse.ArgumentParser()
parser.add_argument('--socket-patch', type=Path)
parser.add_argument('--socket-patch-revision')
parser.add_argument('--output', type=Path)
parser.add_argument('--python', default=sys.executable)
parser.add_argument('--versions', nargs='+', default=VERSIONS)
parser.add_argument(
    '--render-doc-table',
    type=Path,
    metavar='RESULTS_JSON',
    help='print the generated section of docs/testing/uv-compatibility.md '
    'from an existing results.json instead of running the matrix',
)
args = parser.parse_args()
if args.render_doc_table is None:
    missing = [
        flag
        for flag, value in [
            ('--socket-patch', args.socket_patch),
            ('--socket-patch-revision', args.socket_patch_revision),
            ('--output', args.output),
        ]
        if value is None
    ]
    if missing:
        parser.error('the following arguments are required: ' + ', '.join(missing))
ROOT = args.output.resolve() if args.output else None
CLI = args.socket_patch.resolve() if args.socket_patch else None
BOOTSTRAP = ROOT / 'bin/0.12.15/uv' if ROOT else None
WHEEL = ROOT / 'urllib3-1.26.18-py2.py3-none-any.whl' if ROOT else None
ENV = {
    key: value
    for key, value in os.environ.items()
    if not key.startswith(('UV_', 'PIP_', 'PYTHON', 'SOCKET_')) and key != 'VIRTUAL_ENV'
}
ENV['SOCKET_NO_CONFIG'] = '1'
ENV['SOCKET_TELEMETRY_DISABLED'] = '1'
if ROOT:
    ROOT.mkdir(parents=True, exist_ok=True)
PATCHED_RESPONSE = '21d9a7810de52973c88d9170f437e98921456bce445ab0618576987478a6a6e4'
PATCH_UUID = 'e828efa5-5c6d-43f3-9909-03f5ac232b98'


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
    for version in dict.fromkeys([*args.versions, '0.12.15']):
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
                # `uv export` exists from 0.4.1 but `--output-file` only from
                # 0.4.7, so capture stdout instead of passing the flag: the
                # export-boundary release 0.4.1 otherwise records exit 2 for a
                # lane whose stdout export installs fine. Write the file only on
                # success; an empty file would masquerade as a lock for
                # format_matrix.
                for fmt, filename in [
                    ('requirements-txt', 'export-requirements.txt'),
                    ('pylock.toml', 'pylock.toml'),
                ]:
                    export = run(
                        exe,
                        ['export', '--frozen', '--format', fmt],
                        case,
                        kind + '-' + mode + '-export-' + fmt,
                        rows,
                    )
                    if export['exitCode'] == 0 and export['stdout']:
                        (case / filename).write_text(export['stdout'])
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
    # Older uv binaries (0.2.x, 0.3.0) cannot build the ROOT fixture from an
    # empty cache under --offline: `setuptools>=40.8.0` is a build dependency
    # of the fixture itself, not of the patched wheel. Distinguish that from a
    # failure to install the patched wheel by retrying the frozen install with
    # network access and recording it as its own row.
    backtest = json.loads((base / 'backtest.json').read_text())['commands']
    offline_root_build_failure = any(
        row['key'] == 'project-vendored-lock-sync'
        and row['exitCode'] != 0
        and 'setuptools' in row['stderr']
        for row in backtest
    )
    if offline_root_build_failure:
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
            if not lockfile.is_file() or PATCH_UUID not in lockfile.read_text():
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


VARIANT_HEAD = (
    '[project]\nname = "socket-uv-patch-fixture"\n'
    'version = "0.1.0"\nrequires-python = ">=3.9"\n'
)
# Project shapes the plain `dependencies = ["urllib3==1.26.18"]` fixture never
# reaches: the `[tool.uv] dev-dependencies` and PEP 735 `[dependency-groups]`
# requires-dev paths, a duplicate requires-dist entry (extras), a `[manifest]`
# constraints entry, and the transitive (override-dependencies) branch.
# Each is locked fresh, scanned in both modes, then installed with `--frozen`,
# `--locked` (where the binary has it) and a plain `uv sync`, recording the
# installed bytes and whether the patched lock survived untouched.
# `requires` is the lock predicate that must hold for the fixture to be
# meaningful on that binary; failing it records `formatSupported: false`.
VARIANTS = [
    (
        'tool-uv-dev',
        VARIANT_HEAD
        + 'dependencies = []\n\n[tool.uv]\ndev-dependencies = ["urllib3==1.26.18"]\n',
        lambda lock: 'name = "urllib3"' in lock,
    ),
    (
        'dependency-groups',
        VARIANT_HEAD
        + 'dependencies = []\n\n[dependency-groups]\ndev = ["urllib3==1.26.18"]\n',
        # PEP 735 groups are honoured from uv 0.4.27; older binaries lock an
        # empty project.
        lambda lock: 'name = "urllib3"' in lock,
    ),
    (
        'extras-duplicate',
        VARIANT_HEAD
        + 'dependencies = ["urllib3==1.26.18"]\n\n'
        '[project.optional-dependencies]\nhttp = ["urllib3==1.26.18"]\n',
        lambda lock: 'name = "urllib3"' in lock,
    ),
    (
        'constraints',
        VARIANT_HEAD
        + 'dependencies = ["urllib3==1.26.18"]\n\n'
        '[tool.uv]\nconstraint-dependencies = ["urllib3==1.26.18"]\n',
        # Older uv locks the project without recording the constraint.
        lambda lock: re.search(r'^constraints = \[', lock, re.MULTILINE) is not None,
    ),
    (
        'transitive',
        # requests 2.28.2 pins urllib3 <1.27; the cut-off keeps it at 1.26.18.
        # It lives in pyproject rather than on the `uv lock` command line so
        # every later `uv sync` sees the same setting: a command-line
        # `--exclude-newer` is recorded under `[options]` and its absence on
        # sync makes uv re-resolve ("removal of global exclude newer"), which
        # would fail `--locked` for a reason unrelated to the patch.
        VARIANT_HEAD
        + 'dependencies = ["requests==2.28.2"]\n\n'
        '[tool.uv]\nexclude-newer = "2024-01-01T00:00:00Z"\n',
        lambda lock: 'name = "urllib3"\nversion = "1.26.18"' in lock,
    ),
]
VARIANT_INSTALLS = ['frozen', 'locked', 'plain']


def variant_matrix(version):
    exe = ROOT / 'bin' / version / 'uv'
    base = ROOT / 'matrix' / version
    original_lock = base / 'original' / 'uv.lock'
    if (
        not original_lock.is_file()
        or '[[package]]' not in original_lock.read_text()
    ):
        # `[[distribution]]`-grammar binaries cannot vendor natively and the
        # hosted path is covered by project_matrix; nothing to add here.
        return {'version': version, 'commands': []}
    sync_help = subprocess.run(
        [str(exe), 'sync', '--help'], capture_output=True, text=True
    ).stdout
    rows = []
    for name, pyproject, requires in VARIANTS:
        for mode in ['hosted', 'vendored']:
            prefix = 'variant-' + name + '-' + mode
            case = base / prefix
            if case.exists():
                shutil.rmtree(case)
            case.mkdir(parents=True)
            (case / 'pyproject.toml').write_text(pyproject)
            lock = run(
                exe, ['lock', '--python', args.python], case, prefix + '-lock', rows
            )
            lock_text = (
                (case / 'uv.lock').read_text() if (case / 'uv.lock').is_file() else ''
            )
            lock['formatSupported'] = lock['exitCode'] == 0 and bool(requires(lock_text))
            if not lock['formatSupported']:
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
                prefix + '-socket-patch',
                rows,
            )
            scan['patchInLock'] = PATCH_UUID in (case / 'uv.lock').read_text()
            if scan['exitCode'] != 0 or not scan['patchInLock']:
                continue
            sync_args = ['sync', '--python', args.python]
            if '--no-install-project' in sync_help:
                sync_args.append('--no-install-project')
            else:
                package = case / 'socket_uv_patch_fixture'
                package.mkdir(exist_ok=True)
                (package / '__init__.py').write_text('')
            locked = (case / 'uv.lock').read_bytes()
            for label in VARIANT_INSTALLS:
                flag = {'frozen': '--frozen', 'locked': '--locked', 'plain': None}[label]
                if flag and flag not in sync_help:
                    continue
                shutil.rmtree(case / '.venv', ignore_errors=True)
                if label == 'frozen':
                    shutil.rmtree(case / '.uv-cache', ignore_errors=True)
                command = [sync_args[0], *([flag] if flag else []), *sync_args[1:]]
                sync = run(exe, command, case, prefix + '-' + label + '-sync', rows)
                # Recorded, never raised: a plain `uv sync` that re-resolves
                # the lock (uv < 0.5.6 on the transitive fixture) is a real
                # observation the doc explains, not a harness error.
                sync['lockUnchanged'] = (case / 'uv.lock').read_bytes() == locked
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
    (base / 'variant-backtest.json').write_text(
        json.dumps({'version': version, 'commands': rows}, indent=2) + '\n'
    )
    return {
        'version': version,
        'commands': [
            (row['key'], row['exitCode'])
            for row in rows
            if row['key'] not in ['venv', 'install-original']
        ],
    }


def variant_status(observations, name, mode):
    """Collapse one fixture/mode's observations into the doc-table verdict.

    Returns None when the lane did not run (uv < 0.2.35), 'unsupported' when
    the binary cannot lock the fixture shape, 'refused' when the CLI left the
    lock unpatched, 'pass' when every executed install delivered the patched
    bytes and the `--locked` install left the lock untouched, otherwise
    ('fail', [failing install labels]).
    """
    prefix = 'variant-' + name + '-' + mode + '-'
    rows = {
        re.sub(r'-variant-\d+$', '', item['command'])[len(prefix):]: item
        for item in observations
        if item['command'].startswith(prefix)
    }
    if not rows:
        return None
    lock = rows.get('lock')
    if lock is None or lock.get('formatSupported') is False or lock['exitCode']:
        return 'unsupported'
    scan = rows.get('socket-patch')
    if scan is None or scan['exitCode']:
        return ('fail', ['scan'])
    if scan.get('patchInLock') is False:
        return 'refused'
    failed = []
    for label in VARIANT_INSTALLS:
        item = rows.get(label + '-sync')
        if item is None:
            continue
        ok = item['exitCode'] == 0 and item.get('installedPatch') is True
        if label == 'locked' and item.get('lockUnchanged') is not True:
            ok = False
        if not ok:
            failed.append(label)
    return 'pass' if not failed else ('fail', failed)


def write_summary():
    patched_response = PATCHED_RESPONSE
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
            'variant-backtest.json',
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
                if 'patchInLock' in row:
                    item['patchInLock'] = row['patchInLock']
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
                'variants': {
                    name: {
                        mode: variant_status(observations, name, mode)
                        for mode in ['hosted', 'vendored']
                    }
                    for name, _, _ in VARIANTS
                },
                'observations': observations,
            }
        )
    result = {
        'date': datetime.date.today().isoformat(),
        'scope': f'{len(args.versions)} pinned uv releases on {platform.platform()}; interpreter {args.python}',
        'pythonVersion': subprocess.check_output(
            [args.python, '--version'], text=True, stderr=subprocess.STDOUT
        )
        .strip()
        .split()[-1],
        'socketPatchRevision': args.socket_patch_revision,
        'socketPatchVersion': subprocess.check_output(
            [str(CLI), '--version'], text=True
        ).strip(),
        'socketPatchBinarySha256': hashlib.sha256(CLI.read_bytes()).hexdigest(),
        'patchUuid': PATCH_UUID,
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


def render_doc_table(results):
    """Render the generated section of docs/testing/uv-compatibility.md.

    Everything between the GENERATED markers in that document comes from
    here, so the merger can paste a fresh run's tables without hand-editing:
    the run header, the per-release results table and the project-variant
    table. The prose that explains the nonzero outcomes stays hand-written
    outside the markers.
    """
    hosted_vendored = ['hosted', 'vendored']

    def installs(obs):
        return [
            item
            for item in obs
            if item['exitCode'] == 0 and item.get('installedResponseSha256')
        ]

    def verdict(obs, unavailable_when_empty=True):
        # Pass: every completed install delivered the patched bytes and every
        # recorded lock check held; a failed install is a Fail unless it is
        # the cold-offline root build the harness retried with network (the
        # retry row is one of `obs` and counts like any other install).
        if not obs:
            return '—' if unavailable_when_empty else 'Fail'
        done = installs(obs)
        failed = [
            item
            for item in obs
            if item['exitCode'] != 0 and 'root-build-networked' not in item['command']
        ]
        retried = any('root-build-networked' in item['command'] for item in obs)
        if failed and not (retried and all('lock-sync' in item['command'] for item in failed)):
            return 'Fail'
        if not done:
            return '—' if unavailable_when_empty else 'Fail'
        if all(item.get('installedPatch') for item in done) and all(
            item.get('lockUnchanged', True) for item in obs
        ):
            return 'Pass¹' if retried else 'Pass'
        return 'Fail'

    def rows_matching(obs, patterns):
        return [
            item
            for item in obs
            if any(
                re.fullmatch(pattern + r'(-variant-\d+)?', item['command'])
                for pattern in patterns
            )
        ]

    def refusal(obs, pattern):
        scans = rows_matching(obs, [pattern])
        if not scans:
            return None
        scan = scans[0]
        if scan['exitCode'] == 0 and not scan.get('vendorErrors'):
            return False
        if scan.get('vendorErrors') or scan.get('warnings'):
            return 'refused'
        return 'Fail'

    def paragraph(text):
        lines.extend(textwrap.wrap(text, width=80, break_long_words=False, break_on_hyphens=False))
        lines.append('')

    lines = []
    platform_name = results['scope'].split(' on ', 1)[1].split(';')[0]
    python_version = results.get('pythonVersion') or results['scope'].split(
        'interpreter ', 1
    )[-1]
    paragraph(
        f"The complete run finished on **{results['date']}**, using "
        f"**{platform_name}** and Python **{python_version}**. It tested "
        f"socket-patch source commit `{results['socketPatchRevision']}` "
        f"(`{results['socketPatchVersion']}`), with binary SHA-256:"
    )
    lines.extend(['```text', results['socketPatchBinarySha256'], '```', ''])
    all_obs = [item for version in results['versions'] for item in version['observations']]
    compared = [item for item in all_obs if 'installedPatch' in item]
    mismatches = [item for item in compared if not item['installedPatch']]
    lock_checks = [item for item in all_obs if 'lockUnchanged' in item]
    lock_changed = [item for item in lock_checks if not item['lockUnchanged']]
    locked_rows = [item for item in lock_checks if 'locked' in item['command']]
    locked_ok = sum(1 for item in locked_rows if item['exitCode'] == 0)
    paragraph(
        f"**{len(compared)} installed-byte comparisons** ran, with "
        f"**{len(mismatches)} mismatch{'es' if len(mismatches) != 1 else ''}**. "
        f"**{len(lock_checks)} lock-preservation checks** were recorded — every "
        "install attempt against a patched lock (`--frozen` and `--locked` where "
        "the binary provides them, plain `uv sync` where it does not, "
        "`uv run --frozen --script`, `uv pip sync pylock.toml`, and the "
        "project-variant installs), including failed installs whose lock was left "
        f"untouched — and **{len(lock_changed)} changed the lock**. `--frozen` "
        f"never writes the lock, so the {len(locked_rows)} `--locked` rows are the "
        f"ones that measure preservation; {locked_ok} of them exited 0. The "
        "[machine-readable results](uv-compatibility/results.json) contain all "
        f"{len(all_obs)} observations and their command definitions. The "
        "[binary catalog](uv-compatibility/binaries.json) records each uv wheel's "
        "public PyPI source and verified hash."
    )
    paragraph(
        'Each paired result below is **hosted / vendored**. “Pass” means the '
        'installed `urllib3/response.py` matched the published patch; “—” means '
        'that uv binary did not provide the format or command. Requirements '
        'include plain and hashed compilation. PEP 751 covers both standalone '
        'locks and exported locks.'
    )
    lines.append(
        '| uv | Native grammar | Native H/V | Requirements H/V | Requirements export H/V | Scripts H/V | PEP 751 H/V | Verified installs |'
    )
    lines.append(
        '|----|----------------|------------|------------------|-------------------------|-------------|-------------|-------------------|'
    )
    for version in results['versions']:
        obs = version['observations']
        schema = version.get('lockSchema')
        if not schema:
            grammar = 'No native lock'
        else:
            grammar = f"`{schema}`, v{version.get('lockVersion') or 1}"
            if version.get('lockRevision'):
                grammar += f" r{version['lockRevision']}"
        cells = []
        native = []
        for mode in hosted_vendored:
            refused = refusal(obs, f'project-{mode}-socket-patch')
            if refused is None:
                native.append('—')
            elif refused:
                native.append(refused)
            else:
                native.append(
                    verdict(
                        rows_matching(
                            obs,
                            [
                                f'project-{mode}-lock-sync',
                                f'project-{mode}-locked-install',
                                f'project-{mode}-unfrozen-install',
                                f'project-{mode}-frozen-sync-root-build-networked',
                            ],
                        ),
                        unavailable_when_empty=False,
                    )
                )
        cells.append(' / '.join(native))
        requirements = []
        for mode in hosted_vendored:
            syncs = rows_matching(
                obs, [f'requirements-{mode}-pip-sync', f'requirements-plain-{mode}-pip-sync']
            )
            if any(
                "Unexpected '.'" in item.get('diagnostic', '')
                for item in syncs
                if item['exitCode']
            ):
                requirements.append('rejected path')
            else:
                requirements.append(verdict(syncs))
        cells.append(' / '.join(requirements))
        cells.append(
            ' / '.join(
                verdict(rows_matching(obs, [f'requirements-{mode}-export-sync']))
                for mode in hosted_vendored
            )
        )
        cells.append(
            ' / '.join(
                verdict(
                    rows_matching(
                        obs,
                        [
                            f'script-direct-{mode}-install',
                            f'script-{mode}-locked-install',
                            f'script-{mode}-unfrozen-install',
                        ],
                    )
                )
                for mode in hosted_vendored
            )
        )
        cells.append(
            ' / '.join(
                verdict(
                    rows_matching(
                        obs,
                        [f'pylock-{mode}-export-sync', f'pylock-direct-{mode}-install'],
                    )
                )
                for mode in hosted_vendored
            )
        )
        verified = sum(1 for item in obs if item.get('installedPatch'))
        lines.append(
            f"| {version['version']} | {grammar} | {' | '.join(cells)} | {verified} |"
        )
    lines.append('')
    lines.extend(['### Project variants (uv ≥ 0.2.35)', ''])
    paragraph(
        'Each `[[package]]`-grammar binary also locks five further project shapes '
        '(`variant-*` cases in the results), scans them in both modes, and '
        'installs from the patched lock with `--frozen`, `--locked` (where '
        'available) and a plain `uv sync`, each into a fresh environment. “Pass” '
        'requires the patched bytes from every executed install and an untouched '
        'lock after `--locked`; “Fail: …” names the installs that missed; '
        '“refused” means the CLI reported the shape unsupported and left the lock '
        'unpatched; “—” means the binary cannot lock that shape (no '
        '`[dependency-groups]`, no `[manifest]` constraints, or no '
        '`exclude-newer` setting).'
    )
    names = [name for name, _, _ in VARIANTS]
    variant_rows = []
    for version in results['versions']:
        statuses = version.get('variants') or {
            name: {
                mode: variant_status(version['observations'], name, mode)
                for mode in hosted_vendored
            }
            for name in names
        }
        if all(statuses[name][mode] is None for name in names for mode in hosted_vendored):
            continue
        cells = []
        for name in names:
            pair = []
            for mode in hosted_vendored:
                status = statuses[name][mode]
                if status is None or status == 'unsupported':
                    pair.append('—')
                elif status == 'pass':
                    pair.append('Pass')
                elif status == 'refused':
                    pair.append('refused')
                else:
                    pair.append('Fail: ' + ', '.join(status[1]))
            cells.append(' / '.join(pair))
        variant_rows.append(f"| {version['version']} | {' | '.join(cells)} |")
    if variant_rows:
        lines.append('| uv | ' + ' | '.join(name + ' H/V' for name in names) + ' |')
        lines.append('|----|' + '|'.join('-' * (len(name) + 6) for name in names) + '|')
        lines.extend(variant_rows)
    else:
        lines.append(
            '_This results.json predates the project-variant lane; rerun the '
            'matrix to populate this table._'
        )
    return '\n'.join(lines) + '\n'


def backtest(version):
    return [
        project_matrix(version),
        requirements_matrix(version),
        format_matrix(version),
        unfrozen_matrix(version),
        variant_matrix(version),
    ]


if __name__ == '__main__':
    if args.render_doc_table is not None:
        sys.stdout.write(
            render_doc_table(json.loads(args.render_doc_table.read_text()))
        )
        sys.exit(0)
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
