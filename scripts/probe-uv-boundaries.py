"""Probe uv behaviour boundaries with real binaries.

For every requested uv release this downloads the PyPI wheel for the current
platform (hash-verified), extracts the `uv` binary, and records:

- whether the `uv lock` subcommand exists (`lockCommand`; it appears in
  0.1.42 but panics "not yet implemented" through 0.1.44) and whether it
  actually writes a lock (`lock`; first true at 0.1.45), which native lock
  grammar it writes (`[[distribution]]` vs `[[package]]`), whether sources
  are strings or inline tables, whether artifacts are sub-tables or inline
  values, plus the lock `revision`;
- whether `uv export` (0.4.1), its `--output-file` flag (0.4.7; the backtest
  reads stdout below that) and `uv lock --script` (0.5.17) exist;
- whether `uv pip compile --output-file pylock.toml` writes PEP 751;
- whether `uv pip sync` accepts a bare `./wheel --hash=…` requirement line
  (the shape vendored requirements use).

It is the bisection tool behind the boundary versions pinned in
`scripts/backtest-uv.py`; see docs/testing/uv-compatibility.md. One JSON object
per version is printed to stdout.

    python3 scripts/probe-uv-boundaries.py --output /tmp/uv-probe \
        --python /path/to/python3.9 0.2.34 0.2.35 0.8.3 0.8.4
"""
import argparse
import hashlib
import io
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--python', default=sys.executable)
parser.add_argument('versions', nargs='+')
args = parser.parse_args()
ROOT = args.output.resolve()
ROOT.mkdir(parents=True, exist_ok=True)
WHEEL_NAME = 'urllib3-1.26.18-py2.py3-none-any.whl'
ENV = {
    key: value
    for key, value in os.environ.items()
    if not key.startswith(('UV_', 'PIP_', 'PYTHON')) and key != 'VIRTUAL_ENV'
}


def fetch_json(url):
    with urllib.request.urlopen(url, timeout=90) as response:
        return json.load(response)


def download(file):
    with urllib.request.urlopen(file['url'], timeout=180) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != file['digests']['sha256']:
        raise ValueError('download hash mismatch: ' + file['filename'])
    return data


def platform_markers():
    system = platform.system()
    machine = platform.machine().lower()
    if system == 'Darwin':
        return 'macosx', 'arm64' if machine in ['arm64', 'aarch64'] else 'x86_64'
    if system == 'Linux':
        return 'manylinux', 'aarch64' if machine in ['arm64', 'aarch64'] else 'x86_64'
    raise ValueError('This probe requires macOS or Linux')


REGISTRY = fetch_json('https://pypi.org/pypi/uv/json')


def binary(version):
    folder = ROOT / 'bin' / version
    exe = folder / 'uv'
    if exe.exists():
        return exe
    marker, architecture = platform_markers()
    file = next(
        file
        for file in REGISTRY['releases'][version]
        if marker in file['filename'] and architecture in file['filename']
    )
    folder.mkdir(parents=True, exist_ok=True)
    archive = zipfile.ZipFile(io.BytesIO(download(file)))
    member = next(name for name in archive.namelist() if name.endswith('/uv'))
    exe.write_bytes(archive.read(member))
    exe.chmod(0o755)
    return exe


def wheel():
    path = ROOT / WHEEL_NAME
    if not path.exists():
        release = fetch_json('https://pypi.org/pypi/urllib3/1.26.18/json')
        file = next(file for file in release['urls'] if file['filename'] == WHEEL_NAME)
        path.write_bytes(download(file))
    return path


def run(exe, arguments, cwd):
    process = subprocess.run(
        [str(exe), *arguments],
        cwd=cwd,
        env=dict(ENV, UV_CACHE_DIR=str(cwd / '.cache')),
        capture_output=True,
        text=True,
        timeout=300,
    )
    return process.returncode, process.stdout, process.stderr


def diagnostic_line(stderr):
    """The line that names the failure: a panic location or `error:` line if
    present (a panic's LAST line is only the RUST_BACKTRACE hint), else the
    last non-empty line."""
    lines = [line for line in stderr.strip().splitlines() if line.strip()]
    if not lines:
        return ''
    for line in lines:
        if 'panicked at' in line or line.startswith('error'):
            return line[:160]
    return lines[-1][:160]


def probe(version):
    exe = binary(version)
    with tempfile.TemporaryDirectory() as raw:
        cwd = Path(raw)
        (cwd / 'pyproject.toml').write_text(
            '[project]\nname = "probe"\nversion = "0.1.0"\n'
            'requires-python = ">=3.9"\ndependencies = ["urllib3==1.26.18"]\n'
        )
        lock_rc, _, lock_err = run(exe, ['lock', '--python', args.python], cwd)
        lock = (cwd / 'uv.lock').read_text() if (cwd / 'uv.lock').exists() else ''
        # clap reports a missing subcommand as exit 2 "unrecognized subcommand";
        # 0.1.42–0.1.44 accept `lock` and then panic (exit 101), so the
        # subcommand's existence and a written lock are separate facts.
        lock_command = 'unrecognized subcommand' not in lock_err
        if '[[distribution]]' in lock:
            schema = 'distribution'
        elif '[[package]]' in lock:
            schema = 'package'
        else:
            schema = None
        revision = next(
            (line.split('=')[1].strip() for line in lock.splitlines() if line.startswith('revision =')),
            None,
        )
        # uv 0.2.x switched `source = "registry+…"` strings (plus
        # `[[distribution.dependencies]]` / `[[distribution.wheel]]` tables) to
        # inline tables (`source = { registry = … }`, `wheels = [...]`) while
        # still writing `[[distribution]]`; the rewriter must follow the
        # entry's own shape, not the table name.
        source_lines = [line for line in lock.splitlines() if line.startswith('source = ')]
        source_style = None
        if source_lines:
            source_style = 'table' if source_lines[0].startswith('source = {') else 'string'
        # …and, separately, whether artifacts are `[distribution.sdist]` /
        # `[[distribution.wheel]]` tables or inline `sdist = { … }` /
        # `wheels = [ … ]` values (the two flipped at different releases).
        artifact_style = None
        if '[[distribution.wheel]]' in lock or '[distribution.sdist]' in lock:
            artifact_style = 'tables'
        elif 'wheels = [' in lock or 'sdist = {' in lock:
            artifact_style = 'inline'
        _, help_out, _ = run(exe, ['--help'], cwd)
        _, lock_help, _ = run(exe, ['lock', '--help'], cwd)
        _, export_help, _ = run(exe, ['export', '--help'], cwd)
        (cwd / 'requirements.in').write_text('urllib3==1.26.18\n')
        run(
            exe,
            ['pip', 'compile', 'requirements.in', '--python-version', '3.9', '-o', 'pylock.toml'],
            cwd,
        )
        pylock = (cwd / 'pylock.toml').read_text() if (cwd / 'pylock.toml').exists() else ''
        source = wheel()
        shutil.copy(source, cwd / source.name)
        sha = hashlib.sha256(source.read_bytes()).hexdigest()
        (cwd / 'requirements.txt').write_text(f'./{source.name} --hash=sha256:{sha}\n')
        venv_rc, _, _ = run(exe, ['venv', '.venv', '--python', args.python], cwd)
        sync_rc, _, sync_err = run(exe, ['pip', 'sync', 'requirements.txt'], cwd)
        local_ok = venv_rc == 0 and sync_rc == 0
        return {
            'uv': version,
            'lockCommand': lock_command,
            'lock': lock_rc == 0 and bool(lock),
            'lockError': '' if lock_rc == 0 else diagnostic_line(lock_err),
            'lockSchema': schema,
            'lockRevision': int(revision) if revision else None,
            'lockSourceStyle': source_style,
            'lockArtifactStyle': artifact_style,
            'export': 'export' in help_out,
            'exportOutputFile': '--output-file' in export_help,
            'lockScript': '--script' in lock_help,
            'pep751Compile': 'lock-version = ' in pylock,
            'localWheelRequirements': local_ok,
            'localWheelError': '' if local_ok else sync_err.strip().splitlines()[-1][:160] if sync_err.strip() else '',
        }


if __name__ == '__main__':
    for version in args.versions:
        print(json.dumps(probe(version)), flush=True)
