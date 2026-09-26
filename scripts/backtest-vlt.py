#!/usr/bin/env python3
"""Native vlt / public Socket patch compatibility, with no service doubles.

Every (vlt release, mode, project shape) cell builds an isolated project with
a REAL vlt release (`npm pack`, sha512 checked against the registry, run as
`node vlt.js`), runs the socket-patch CLI against the public free
minimist@1.2.2 patch on the production service, and proves the result with
the same vlt. The verdict is checked against `expected_verdict`, an oracle of
the DOCUMENTED boundaries (docs/testing/vlt-compatibility.md, DESIGN §2.1),
never the CLI's own codes, so a CLI regression that refuses a supported cell
(or patches a refused one) fails the cell.

Modes: hosted (`scan|get --mode hosted`), vendored (`--mode vendored`) and
agent (`--mode agent`).

Checks (hosted): serveEncodingIdentity (the cell's own curl probe of the
artifact, fetched the way vlt fetches it), cliSuccess, publishedPatch,
referenceWritten, lockFormatPreserved, othersUntouched, freshCi /
freshOrdinary (cold caches: patched bytes, lock byte-stable), tamperedDigest
(a wrong slot [2] fails a cold `vlt ci`), vexManifestless, repeatStableLock,
warmOrdinary / warmCi (the project's own tree after the heal),
rollbackByteIdentical and rollbackOriginalBytes.
Checks (vendored): cliSuccess, publishedPatch, referenceWritten,
lockFormatPreserved, freshCi, freshOrdinary, vexManifestless,
repeatStableLock, warmOrdinary / warmCi (the project's own tree, which still
links the registry copy; from 0.0.0-30 `vlt install` keeps an optional one),
repair (a deleted payload is rebuilt and installs
patched),
rollbackByteIdentical (`vendor --revert`) and rollbackOriginalBytes.
Checks (agent): cliSuccess, manifestWritten, lockUnchanged, patchedBytes,
survivesNoopInstall, repeatStableLock, rollbackByteIdentical and
rollbackOriginalBytes.

Hosted cells whose expected verdict is `patched` first probe the artifact
(`accept-encoding: gzip;q=1.0, identity;q=0.5`, no decoding). While the
service re-encodes it, vlt would fail `EINTEGRITY`, so the only correct CLI
outcome is the clean refusal (`redirect_vlt_artifact_unverifiable`, nothing
written): the cell records `blocked-by-server-encoding`. That verdict is
never recorded without the probe seeing a non-identity `Content-Encoding`;
any other hosted failure is an error.

Rows are written in the shape of depscan's capture-vlt.py `result.json`
(`os, vlt, mode, shape, verdict, codes, manifestSha256, patches` plus the
`tree/` of SBOM inputs), so `audit-captures.py` and `generate-fixtures.py
--captures` read them directly.

`--identity-mirror` serves the production API and artifacts through a
loopback mirror that fetches the artifact with `accept-encoding: identity`
(the state the serve fix produces). Its rows name the mirror and pin
loopback URLs: a local preview of the hosted proof, never an import source.
`--downgrade-cli <published socket-patch>` runs the downgrade scenario
instead of the matrix: vlt ledgers written by `--cli` must be either left
untouched or fully reverted by the published release, never half-reverted.
`--canary-checks` runs the nightly canary's watchdogs: every published vlt
release is listed as supported or excluded, and a lock with a
`lockfileVersion` other than 0 or 1 is refused (`redirect_vlt_lock_unsupported`).
`--diff-locks DIR...` compares the `vlt-lock.json` of the same cell across
operating systems in downloaded result rows (they must be byte-identical).
`--serve-probe` is the serve watchdog: it fetches the public minimist
artifact the way vlt does and fails unless it is identity-encoded with the
API's sha512.
"""

import argparse
import base64
import concurrent.futures
from datetime import datetime, timezone
import gzip
import hashlib
import http.server
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
LEG_MANIFEST = ROOT / 'crates' / 'socket-patch-cli' / 'tests' / 'vlt-leg-manifest.json'
HISTORICAL_INTEGRITY = Path(__file__).with_name('vlt-historical-integrity.json')

VERSIONS = ['0.0.0-16', '0.0.0-32', '1.0.0-rc.14', '1.0.0-rc.32', '1.0.4', '1.0.10', '1.2.0']
MODES = ['hosted', 'vendored', 'agent']
PURL = 'pkg:npm/minimist@1.2.2'
UUID = '80630680-4da6-45f9-bba8-b888e0ffd58c'
NAME = 'minimist'
VERSION = '1.2.2'
TARGET = f'{NAME}@{VERSION}'
API_URL = 'https://patches-api.socket.dev'
PATCH_HOST = 'https://patch.socket.dev'
NPM_REGISTRY = 'https://registry.npmjs.org/'
# An alias whose URL is not the default registry (vlt treats an alias whose
# URL equals the lock's scalar `registry` as the default one).
ACME_REGISTRY = 'https://registry.yarnpkg.com/'
VLT_ACCEPT_ENCODING = 'gzip;q=1.0, identity;q=0.5'
BLOCKED = 'blocked-by-server-encoding'
BLOCKED_CODES = ['redirect_vlt_artifact_unverifiable']
VERDICTS = ['patched', 'safe-refusal', 'unsafe', 'error', 'unsupported', BLOCKED]
COMMAND_TIMEOUT = 600
VEX_PRODUCT = 'pkg:npm/vlt-patch-backtest@1.0.0'
OPTIONAL_HELD = 'unpatched copies of optional dependencies'
A0_SKIPPED_OPTIONAL = 'Could not read package.json file'
OPTIONAL_ONLY_LOCK = ('installs no optional dependency from the lock of a project that declares '
                      'only optional dependencies')


# ---------------------------------------------------------------------------
# Releases.

def version_key(version):
    """Semver precedence of a vlt release (`0.0.0-16`, `1.0.0-rc.14`, `1.2.0`)."""
    match = re.fullmatch(r'(\d+)\.(\d+)\.(\d+)(?:-(rc\.)?(\d+))?', version)
    if not match:
        raise ValueError(f'not a vlt release version: {version!r}')
    core = tuple(int(match.group(i)) for i in (1, 2, 3))
    if match.group(5) is None:
        return core + (1, 0)
    return core + (0, int(match.group(5)))


def at_least(version, floor):
    return version_key(version) >= version_key(floor)


def between(version, low, high):
    return version_key(low) <= version_key(version) <= version_key(high)


def era_of(version):
    """DESIGN §1.1 era of the release that wrote the lock."""
    for floor, era in (('1.2.0', 'F'), ('1.0.8', 'E'), ('1.0.0-rc.33', 'D'),
                       ('1.0.0-rc.15', 'C'), ('1.0.0-rc.9', 'B'), ('0.0.0-19', 'A')):
        if at_least(version, floor):
            return era
    return 'A0'


def lockfile_version(era):
    return None if era == 'A0' else 0 if era in ('A', 'B') else 1


def release_lists(manifest_path=LEG_MANIFEST):
    """(supported, excluded) releases of the leg manifest, which is derived
    from the Releases table of docs/testing/vlt-compatibility.md."""
    data = json.loads(Path(manifest_path).read_text(encoding='utf-8'))
    return list(data['supported']), list(data['excluded'])


def release_status(version, supported, excluded):
    """'supported', 'excluded' or 'unlisted' (DESIGN §1.1 exclusion list:
    the named releases plus every `0.0.0-0.<timestamp>` build)."""
    if version in excluded or re.fullmatch(r'0\.0\.0-0\.\d+', version):
        return 'excluded'
    return 'supported' if version in supported else 'unlisted'


def unlisted_releases(published, supported, excluded):
    """Published releases the matrix does not know: the canary watchdog."""
    return [v for v in published if release_status(v, supported, excluded) == 'unlisted']


# ---------------------------------------------------------------------------
# Shapes (a subset of depscan's capture-vlt.py SHAPES, with the same names).
# The oracle follows the committed boundary table; capture-vlt.py does not yet
# match it for optional-only cells on 0.0.0-24 … 0.0.0-31. The production
# patch is minimist@1.2.2 only, so shapes that need a scoped, transitive-only
# or peer-bearing patch are left to the hermetic suites and the local capture.

def manifest(name='vlt-patch-backtest', **sections):
    data = dict(name=name, version='1.0.0', private=True)
    for key in ('dependencies', 'devDependencies', 'optionalDependencies'):
        if sections.get(key):
            data[key] = sections[key]
    return json.dumps(data, indent=2) + '\n'


def shape(files, runtime, modes=MODES, members=(), **extra):
    """`files` maps a project path to package.json text; `runtime` lists the
    (importer dir, dependency name) pairs whose installed copy must hold the
    patched bytes."""
    return dict(files=files, runtime=list(runtime), modes=list(modes), members=list(members),
                **extra)


SHAPES = {
    'direct': shape({'package.json': manifest(dependencies={NAME: VERSION})}, [('.', NAME)]),
    'dev': shape({'package.json': manifest(devDependencies={NAME: VERSION})}, [('.', NAME)]),
    'optional': shape({'package.json': manifest(optionalDependencies={NAME: VERSION})},
                      [('.', NAME)], optional=True, optional_only=True),
    'optional-mixed': shape({'package.json': manifest(dependencies={'left-pad': '1.3.0'},
                                                      optionalDependencies={NAME: VERSION})},
                            [('.', NAME)], optional=True),
    'alias': shape({'package.json': manifest(dependencies={'mm': f'npm:{TARGET}'})},
                   [('.', 'mm')], no_bare_ids=True),
    'two-versions': shape({'package.json': manifest(
        dependencies={NAME: VERSION, 'other': 'npm:minimist@1.2.8'})}, [('.', NAME)]),
    'workspace': shape({'package.json': manifest(dependencies={NAME: VERSION}),
                        'packages/a/package.json': manifest('a', dependencies={NAME: VERSION})},
                       [('.', NAME), ('packages/a', NAME)], members=['packages/a']),
    'workspace-member-vendored': shape(
        {'package.json': manifest(),
         'packages/a/package.json': manifest('a', dependencies={NAME: VERSION})},
        [('packages/a', NAME)], modes=['vendored'], members=['packages/a']),
    'crlf-lock': shape({'package.json': manifest(dependencies={NAME: VERSION})}, [('.', NAME)],
                       crlf_lock=True),
    'custom-registry': shape({'package.json': manifest(dependencies={NAME: f'acme:{TARGET}'})},
                             [('.', NAME)], registries={'acme': ACME_REGISTRY},
                             no_bare_ids=True, from_version='0.0.0-14'),
    'lockfile-only': shape({'package.json': manifest(dependencies={NAME: VERSION})},
                           [('.', NAME)], lockfile_only=True),
    'hosted-then-vendored': shape({'package.json': manifest(dependencies={NAME: VERSION})},
                                  [('.', NAME)], modes=['vendored'], before='hosted',
                                  from_version='0.0.0-19'),
    'vendored-then-hosted': shape({'package.json': manifest(dependencies={NAME: VERSION})},
                                  [('.', NAME)], modes=['hosted'], before='vendored',
                                  from_version='0.0.0-19'),
    'get-uuid': shape({'package.json': manifest(dependencies={NAME: VERSION})}, [('.', NAME)],
                      driver='get'),
}


# ---------------------------------------------------------------------------
# The oracle: the documented boundaries only, never the CLI's codes.

def applicable(version, mode, shape_name):
    spec = SHAPES[shape_name]
    if mode not in spec['modes']:
        return False
    if spec.get('optional_only') and between(version, '0.0.0-24', '0.0.0-29'):
        return False  # these releases write no vlt-lock.json for an optional-only project
    return 'from_version' not in spec or at_least(version, spec['from_version'])


def expected_verdict(version, mode, shape_name):
    """The verdict DESIGN §2.1 promises, or None when the cell is not part of
    the matrix."""
    if not applicable(version, mode, shape_name):
        return None
    spec = SHAPES[shape_name]
    if mode == 'agent':
        # Agent mode patches installed files: the scan lists a lockfile-only
        # package and skips it.
        return 'safe-refusal' if spec.get('lockfile_only') else 'patched'
    if shape_name == 'custom-registry':
        return 'safe-refusal'
    if mode == 'vendored' and era_of(version) == 'A0':
        return 'safe-refusal'
    return 'patched'


def lock_era(version, shape_name):
    """The era the CLI sniffs from the lock: an era-A lock whose only
    registry ids are `npm:` aliases or a named registry has no `··` id, which
    is what tells A from B."""
    era = era_of(version)
    return 'B' if era == 'A' and SHAPES[shape_name].get('no_bare_ids') else era


def hosted_lock_warnings(version, shape_name):
    """The lock-level warnings DESIGN §3.8 derives from the lock and vlt.json
    the cell writes (a default-valued `registry` never reaches the lock)."""
    spec = SHAPES[shape_name]
    era = era_of(version)
    text = write_vlt_json(version, spec)
    data = json.loads(text) if text else {}
    settings = data.get('config', data)
    registry = settings.get('registry')
    scalar = isinstance(registry, str) and registry != NPM_REGISTRY
    npm = isinstance((settings.get('registries') or {}).get('npm'), str)
    v0 = lockfile_version(era) in (None, 0)
    legacy_ids = era in ('A0', 'A') and (scalar or not spec.get('no_bare_ids'))
    codes = []
    if era == 'A0':
        codes.append('redirect_vlt_lockfile_version_missing')
    if v0 and legacy_ids and 'modifiers' not in data:
        codes.append('redirect_vlt_old_lockfile_ignored')
    if scalar and (v0 or not npm):
        codes.append('redirect_vlt_scalar_registry_ignored')
    return codes


def expected_codes(version, mode, shape_name):
    """Codes DESIGN §2.1/§2.3 require for the cell."""
    if not applicable(version, mode, shape_name):
        return []
    era = lock_era(version, shape_name)
    codes = []
    if mode == 'agent':
        if SHAPES[shape_name].get('lockfile_only'):
            codes.append('package_not_installed')
    elif mode == 'hosted':
        codes += hosted_lock_warnings(version, shape_name)
        if shape_name == 'custom-registry':
            codes.append('redirect_vlt_custom_registry_skipped')
    elif era == 'A0':
        codes.append('vendor_lockfile_version_unsupported')
    elif shape_name == 'custom-registry':
        codes.append('vendor_lock_entry_unsupported')
    elif era == 'A':
        codes.append('vendor_vlt_legacy_lockfile')
    return codes


def known_vlt_limitation(version, mode, shape_name):
    """The measured vlt limitation that may leave a must-patch cell
    unproven (docs/testing/vlt-compatibility.md boundary table), or None."""
    if mode in ('hosted', 'vendored') and SHAPES[shape_name].get('optional_only') and \
            at_least(version, '0.0.0-30') and not at_least(version, '1.0.5'):
        return OPTIONAL_ONLY_LOCK
    return None


def optional_warm_kept(version, mode, shape_name):
    """From 0.0.0-30 a plain `vlt install` keeps an installed optional
    dependency whose spec moved to the vendored `file:` directory; `vlt ci`
    relinks it (boundary table)."""
    return mode == 'vendored' and bool(SHAPES[shape_name].get('optional')) and at_least(
        version, '0.0.0-30')


def integrity_enforced(version, optional, code, err, installed, patched_bytes_used):
    """The tampered checkout failed on the digest. vlt skips an optional
    dependency that fails to fetch, and 0.0.0-16 then fails reading its
    package.json: when the untampered checkout installed the patched bytes,
    only the wrong digest kept the target out (depscan's capture-vlt.py
    rule)."""
    if code != 0 and 'integrity' in err.lower():
        return True
    skipped = code == 0 or (era_of(version) == 'A0' and A0_SKIPPED_OPTIONAL in err)
    return bool(optional) and not installed and skipped and patched_bytes_used is True


def churn_exempt(version, mode, shape_name):
    """rc.14 rewrites an alias-named `file:` dependency's peer-edge bareSpec on
    its first `ci` (DESIGN §8.3 byte-stability oracle)."""
    return era_of(version) == 'B' and mode == 'vendored' and shape_name in ('alias',
                                                                            'two-versions')


def cells(versions, modes, shapes):
    return [(v, m, s) for v in versions for m in modes for s in shapes
            if expected_verdict(v, m, s) is not None]


def observed_verdict(row):
    if row.get('error'):
        return 'error' if row.get('supported', True) else 'unsupported'
    if row.get('blocked'):
        return BLOCKED
    if row.get('safeRefusal'):
        return 'safe-refusal'
    if row.get('passed'):
        return 'patched'
    if row.get('vltLimitations') and not row.get('failingChecks'):
        return 'unsupported'
    return 'unsafe'


def required_codes(row):
    """The codes the row must carry. A blocked cell's dep is withheld from
    every rewriter (and a conversion never reaches its second run), so only
    the refusal's own code is due, not the cell's lock-level or vendored
    codes."""
    if row.get('verdict') == BLOCKED:
        return BLOCKED_CODES
    return row.get('expectedCodes', [])


def matches_expectation(row):
    """Observed == expected. Two allowances: a must-patch hosted cell whose
    probe saw a content-encoded artifact and whose CLI refused cleanly
    (BLOCKED), and a must-patch cell whose only unproven checks are the
    documented vlt limitation (`expectedLimitation`)."""
    if not set(required_codes(row)) <= set(row.get('codes', [])):
        return False
    verdict, expected = row.get('verdict'), row.get('expectedVerdict')
    if verdict == expected:
        return True
    if verdict == BLOCKED:
        return expected == 'patched' and bool(row.get('blockedByProbe'))
    return (expected == 'patched' and verdict == 'unsupported'
            and bool(row.get('expectedLimitation')) and bool(row.get('vltLimitations'))
            and not row.get('failingChecks') and not row.get('error'))


# ---------------------------------------------------------------------------
# vlt configuration per era (DESIGN §8.3 registry table).

def write_vlt_json(version, spec=None, registry=NPM_REGISTRY):
    """vlt.json text for the release, or None when none is needed.

    ≤ 0.0.0-13 flat keys; 0.0.0-14 … rc.6 `config.registry`; rc.7 … rc.29 the
    public registry (lock-driven installs re-resolve from it anyway);
    rc.30 … rc.32 `config.registry`; ≥ rc.33 `config.registries.npm` (plus
    `config.registry` through 1.0.4). vlt strips a `registry` equal to its
    built-in npmjs default from the lock, so that value is only written where
    the release requires registry config (≥ rc.33)."""
    spec = spec or {}
    config = {}
    registries = dict(spec.get('registries') or {})
    if at_least(version, '1.0.0-rc.33'):
        registries.setdefault('npm', registry)
        if not at_least(version, '1.0.5'):
            config['registry'] = registry
    elif registry != NPM_REGISTRY:
        hermetic = not between(version, '1.0.0-rc.7', '1.0.0-rc.29')
        config['registry'] = registry if hermetic else NPM_REGISTRY
    if registries:
        config['registries'] = registries
    flat = not at_least(version, '0.0.0-14')
    data = dict(config) if flat else ({'config': config} if config else {})
    if spec.get('members') and at_least(version, '0.0.0-13'):
        data['workspaces'] = 'packages/*'
    if between(version, '0.0.0-16', '0.0.0-24'):
        data['modifiers'] = {}
    return json.dumps(data) + '\n' if data else None


def project_files(version, spec, registry=NPM_REGISTRY):
    files = dict(spec['files'])
    text = write_vlt_json(version, spec, registry)
    if text is not None:
        files['vlt.json'] = text
    if spec.get('members') and not at_least(version, '0.0.0-13'):
        files['vlt-workspaces.json'] = json.dumps({'packages': 'packages/*'}) + '\n'
    return files


# ---------------------------------------------------------------------------
# Processes, hashes and files.

def sha256(data):
    return hashlib.sha256(data).hexdigest()


def git_hash(data):
    return hashlib.sha256(f'blob {len(data)}\0'.encode() + data).hexdigest()


def sri_sha512(data):
    return 'sha512-' + base64.b64encode(hashlib.sha512(data).digest()).decode()


def tail(text, limit=4000):
    return text if len(text) <= limit else text[-limit:]


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def run(command, cwd, env, log, check=False, timeout=COMMAND_TIMEOUT):
    started = time.time()
    try:
        proc = subprocess.run([str(c) for c in command], cwd=cwd, env=env, capture_output=True,
                              timeout=timeout)
        code = proc.returncode
        out = proc.stdout.decode(errors='replace')
        err = proc.stderr.decode(errors='replace')
    except subprocess.TimeoutExpired as error:
        code = -9
        out = (error.stdout or b'').decode(errors='replace')
        err = f'timed out after {timeout}s'
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open('a', encoding='utf-8') as handle:
        handle.write(f'$ (cd {cwd} && {" ".join(map(str, command))})  '
                     f'# exit {code} in {time.time() - started:.1f}s\n')
        for text in (out, err):
            handle.write(tail(text, 20000) + ('\n' if text and not text.endswith('\n') else ''))
    if check and code != 0:
        raise RuntimeError(f'{Path(str(command[0])).name} {" ".join(map(str, command[1:4]))} '
                           f'exited {code}: {tail(err or out, 2000)}')
    return code, out, err


def line_endings(data):
    crlf = data.count(b'\r\n')
    lf = data.count(b'\n') - crlf
    return 'crlf' if crlf and not lf else 'lf' if lf and not crlf else 'mixed' if crlf else 'none'


def to_crlf(data):
    return data.replace(b'\r\n', b'\n').replace(b'\n', b'\r\n')


def skipped_dir(parts):
    """node_modules is never committed, except the vendored payload's own
    `<leaf>/node_modules/<name>` dir under .socket/vendor/."""
    if 'node_modules' not in parts:
        return False
    if parts[:2] != ('.socket', 'vendor'):
        return True
    # vlt links a vendored dir's own dependencies inside it.
    first = parts.index('node_modules')
    return 'node_modules' in parts[first + 1:]


# The CLI's run lock, never committed.
UNCOMMITTED = {'.socket/apply.lock'}


def is_link(path):
    """A symlink, or a Windows junction (which `is_symlink` does not report)."""
    return os.path.islink(path) or bool(getattr(os.path, 'isjunction', lambda _: False)(path))


def walk(project):
    """Every regular file under `project` outside the skipped node_modules
    trees, never descending into a link or junction."""
    for top, dirs, names in os.walk(project):
        base = Path(top)
        rel_top = base.relative_to(project).parts
        dirs[:] = sorted(d for d in dirs if not is_link(base / d)
                         and not skipped_dir(rel_top + (d,)))
        for name in sorted(names):
            path = base / name
            if not is_link(path) and path.is_file():
                yield path, Path(*rel_top, name)


def snapshot(project):
    """The committable files: what a fresh checkout would hold."""
    files = {}
    for path, rel in walk(project):
        if rel.as_posix() not in UNCOMMITTED:
            files[rel.as_posix()] = path.read_bytes()
    return dict(sorted(files.items()))


def captured(name):
    """The SBOM inputs depscan's fixtures import (DESIGN §7.3 tree list)."""
    parts = name.split('/')
    leaf = parts[-1]
    if leaf in ('package.json', 'vlt-lock.json', 'vlt.json', 'vlt-workspaces.json'):
        return True
    if leaf == 'npm-shrinkwrap.json' and parts[:2] == ['.socket', 'vendor']:
        return True
    return name in ('.socket/manifest.json', '.socket/vendor/state.json',
                    '.socket/vendor/redirect-state.json')


def capture_tree(project, tree):
    """Copy the SBOM inputs into `tree`; return their sha256 by path."""
    if tree.exists():
        shutil.rmtree(tree)
    digests = {}
    for name, data in snapshot(project).items():
        if not captured(name):
            continue
        destination = tree / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        digests[name] = sha256(data)
    return digests


def write_checkout(files, destination):
    if destination.exists():
        shutil.rmtree(destination)
    for name, data in files.items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    destination.mkdir(parents=True, exist_ok=True)
    return destination


def remove_node_modules(project):
    """Delete every installed tree (the root's and each workspace member's),
    never a vendored payload's own `node_modules/<name>` directory."""
    for top, dirs, _ in os.walk(project):
        base = Path(top)
        rel_top = base.relative_to(project).parts
        if rel_top[:2] == ('.socket', 'vendor'):
            dirs[:] = []
            continue
        for d in list(dirs):
            path = base / d
            if d == 'node_modules':
                dirs.remove(d)
                if is_link(path):
                    os.unlink(path) if os.path.islink(path) else os.rmdir(path)
                else:
                    shutil.rmtree(path, ignore_errors=True)
            elif is_link(path):
                dirs.remove(d)


# ---------------------------------------------------------------------------
# vlt-lock.json.

def split_dep_id(dep_id):
    """(registry segment, name, version, extra) of a registry DepID, or None.
    Both grammars: `~<reg>~<name>@<ver>[~<extra>]` and the legacy
    `·<reg>·<name>@<ver>[·<extra>]` (unscoped names only need no decoding;
    scoped ones use `+` / `§` for `/`)."""
    if not dep_id or dep_id[0] not in '~·':
        return None
    delim = dep_id[0]
    parts = dep_id[1:].split(delim)
    if len(parts) < 2:
        return None
    registry, spec = parts[0], parts[1]
    extra = delim.join(parts[2:]) or None
    spec = spec.replace('§' if delim == '·' else '+', '/')
    at = spec.rfind('@')
    if at <= 0:
        return None
    return registry, spec[:at], spec[at + 1:], extra


def target_instances(lock_text, any_registry=False):
    """DepIDs of minimist@1.2.2's registry nodes (default registry only
    unless `any_registry`)."""
    lock = json.loads(lock_text)
    found = []
    for dep_id in lock.get('nodes') or {}:
        identity = split_dep_id(dep_id)
        if not identity or identity[1:3] != (NAME, VERSION):
            continue
        if any_registry or identity[0] in ('', 'npm'):
            found.append(dep_id)
    return found


def tamper_lock(lock_bytes, dep_ids):
    """The lock with a wrong slot [2] on every `dep_ids` node line."""
    wrong = sri_sha512(b'tampered by backtest-vlt.py')
    out = []
    for line in lock_bytes.split(b'\n'):
        text = line.decode('utf-8')
        for dep_id in dep_ids:
            if text.lstrip().startswith(json.dumps(dep_id, ensure_ascii=False) + ':'):
                text = re.sub(r'"sha512-[A-Za-z0-9+/=]+"', json.dumps(wrong), text, count=1)
        out.append(text.encode('utf-8'))
    return b'\n'.join(out)


# ---------------------------------------------------------------------------
# The production service.

def api_post(api_url, path, body, timeout=60):
    request = urllib.request.Request(
        api_url.rstrip('/') + path, data=json.dumps(body).encode(), method='POST',
        headers={'content-type': 'application/json', 'accept': 'application/json',
                 'user-agent': 'socket-patch-backtest-vlt'})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read())


def api_get(api_url, path, timeout=60):
    request = urllib.request.Request(api_url.rstrip('/') + path, headers={
        'accept': 'application/json', 'user-agent': 'socket-patch-backtest-vlt'})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read())


def with_retries(fn, attempts=5):
    for attempt in range(1, attempts + 1):
        try:
            return fn()
        except (urllib.error.URLError, TimeoutError, ConnectionError, json.JSONDecodeError) as error:
            final = isinstance(error, urllib.error.HTTPError) and error.code < 500 \
                and error.code != 429
            if final or attempt == attempts:
                raise
            time.sleep(5 * attempt)


def fetch_grant(api_url=API_URL):
    """The public tarball artifact of the patch: (url, sha512)."""
    data = with_retries(lambda: api_post(api_url, '/patch/package',
                                         {'uuids': [UUID], 'freeOnly': True}))
    return select_tarball(data)


def select_tarball(data):
    result = (data.get('results') or {}).get(UUID) or {}
    if result.get('status') not in ('granted', 'reused'):
        raise RuntimeError(f'patch {UUID} is not granted: {result.get("status")!r}')
    for artifact in result.get('artifacts') or []:
        if artifact.get('kind') == 'tarball':
            sha512 = (artifact.get('integrity') or {}).get('sha512')
            if not sha512:
                raise RuntimeError('the tarball artifact has no sha512 integrity')
            return artifact.get('url') or result.get('url'), sha512
    raise RuntimeError('no tarball artifact in the grant')


def fetch_record(api_url=API_URL):
    return with_retries(lambda: api_get(api_url, f'/patch/view/{UUID}'))


def parse_header_blocks(text):
    """The last response's headers of a `curl -D` dump (redirects add blocks)."""
    blocks = [b for b in re.split(r'\r?\n\r?\n', text) if b.strip()]
    if not blocks:
        return None, {}
    lines = blocks[-1].splitlines()
    match = re.match(r'HTTP/\S+\s+(\d+)', lines[0]) if lines else None
    headers = {}
    for line in lines[1:]:
        key, _, value = line.partition(':')
        headers[key.strip().lower()] = value.strip()
    return (int(match.group(1)) if match else None), headers


def encoding_is_identity(value):
    return value is None or value.strip() == '' or value.strip().lower() == 'identity'


def probe_artifact(url, expected_sha512, workdir):
    """Fetch the artifact the way vlt does (DESIGN §1.9): its accept-encoding,
    no Authorization, up to 10 redirects, no decoding; hash the wire body."""
    workdir.mkdir(parents=True, exist_ok=True)
    headers_file, body_file = workdir / 'probe-headers.txt', workdir / 'probe-body.bin'
    code, _, err = run(['curl', '-sS', '-L', '--max-redirs', '10', '--max-time', '60',
                        '-D', headers_file, '-o', body_file,
                        '-H', f'accept-encoding: {VLT_ACCEPT_ENCODING}', url],
                       workdir, None, workdir / 'probe.log')
    status, headers = parse_header_blocks(
        headers_file.read_text(errors='replace') if headers_file.is_file() else '')
    body = body_file.read_bytes() if body_file.is_file() else b''
    body_file.unlink(missing_ok=True)
    encoding = headers.get('content-encoding')
    sha512 = sri_sha512(body) if body else None
    return dict(url=url, curlExit=code, curlError=tail(err, 500) if code else None, status=status,
                contentEncoding=encoding, cacheControl=headers.get('cache-control'),
                sha512=sha512, expectedSha512=expected_sha512,
                identity=code == 0 and status == 200 and encoding_is_identity(encoding),
                verifies=code == 0 and status == 200 and encoding_is_identity(encoding)
                and sha512 == expected_sha512)


class IdentityMirror:
    """A loopback view of production after the serve fix: API responses are
    forwarded with the patch host rewritten to the mirror, and artifacts are
    fetched with `accept-encoding: identity`, so they arrive un-encoded."""

    def __init__(self, api_url=API_URL, patch_host=PATCH_HOST):
        mirror = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def forward(self, method):
                length = int(self.headers.get('content-length') or 0)
                data = self.rfile.read(length) if length else None
                parts = self.path.split('?')[0].strip('/').split('/')
                artifact = len(parts) >= 5 and parts[0] == 'patch'
                base = patch_host if artifact else api_url
                headers = {'user-agent': 'socket-patch-backtest-vlt-mirror',
                           'accept-encoding': 'identity'}
                for key in ('content-type', 'accept'):
                    if self.headers.get(key):
                        headers[key] = self.headers[key]
                request = urllib.request.Request(base + self.path, data=data, method=method,
                                                 headers=headers)
                try:
                    with urllib.request.urlopen(request, timeout=120) as response:
                        body, status = response.read(), response.status
                        kind = response.headers.get('content-type', '')
                        encoding = response.headers.get('content-encoding')
                except urllib.error.HTTPError as error:
                    body, status = error.read(), error.code
                    kind = error.headers.get('content-type', '')
                    encoding = error.headers.get('content-encoding')
                if not encoding_is_identity(encoding):
                    body = gzip.decompress(body)
                if not artifact:
                    body = body.replace(patch_host.encode(), mirror.url.encode())
                self.send_response(status)
                self.send_header('content-type', kind or 'application/octet-stream')
                self.send_header('content-length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                self.forward('GET')

            def do_POST(self):
                self.forward('POST')

            def log_message(self, *_):
                pass

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.url = f'http://127.0.0.1:{self.server.server_address[1]}'
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.server.shutdown()
        self.server.server_close()


# ---------------------------------------------------------------------------
# vlt releases.

def npm_command():
    return shutil.which('npm') or shutil.which('npm.cmd') or 'npm'


def pinned_integrity(version):
    if not HISTORICAL_INTEGRITY.is_file():
        return None
    return json.loads(HISTORICAL_INTEGRITY.read_text(encoding='utf-8')).get(version)


def install_tool(root, version, log=None):
    """`<root>/<version>/node_modules/vlt/vlt.js`: `npm pack` (retried), the
    tarball's sha512 checked against the registry's `dist.integrity` and the
    committed pin (fail closed), then a prefix install without scripts. An
    existing install is reused after its `--version` check."""
    directory = root / version
    js = directory / 'node_modules' / 'vlt' / 'vlt.js'
    log = log or root / f'install-{version}.log'
    if not js.is_file():
        directory.mkdir(parents=True, exist_ok=True)
        env = dict(os.environ)
        npm = npm_command()
        tarball = None
        for attempt in range(1, 6):
            code, out, err = run([npm, 'pack', f'vlt@{version}', '--pack-destination', directory,
                                  '--silent'], directory, env, log)
            names = [n.strip() for n in out.splitlines() if n.strip().endswith('.tgz')]
            if code == 0 and names:
                tarball = directory / names[-1]
                break
            if attempt == 5:
                raise RuntimeError(f'npm pack vlt@{version} failed: {tail(err or out, 1000)}')
            time.sleep(5 * attempt)
        _, out, _ = run([npm, 'view', f'vlt@{version}', 'dist.integrity'], directory, env, log,
                        check=True)
        expected = out.strip()
        actual = sri_sha512(tarball.read_bytes())
        pinned = pinned_integrity(version)
        if actual != expected or (pinned is not None and pinned != expected):
            raise RuntimeError(f'vlt@{version} tarball {actual} != registry {expected}'
                               + (f' / pinned {pinned}' if pinned else ''))
        run([npm, 'install', '--prefix', directory, '--no-audit', '--no-fund', '--ignore-scripts',
             '--no-package-lock', tarball], directory, env, log, check=True)
        tarball.unlink(missing_ok=True)
    _, out, _ = run(['node', '--no-warnings', js, '--version'], directory, dict(os.environ), log,
                    check=True)
    if out.strip() != version:
        raise RuntimeError(f'expected vlt {version} at {js}, got {out.strip()!r}')
    return js


class Vlt:
    """One vlt release, run as `node --no-warnings vlt.js` with private state."""

    def __init__(self, js, version):
        self.js = Path(js)
        self.version = version
        self.sha256 = sha256(self.js.read_bytes())

    def env(self, home):
        env = {k: v for k, v in os.environ.items()
               if not k.upper().startswith(('VLT_', 'NPM_CONFIG_', 'XDG_', 'SOCKET_'))}
        for key, sub in (('XDG_CACHE_HOME', 'cache'), ('XDG_CONFIG_HOME', 'config'),
                         ('XDG_DATA_HOME', 'data'), ('XDG_STATE_HOME', 'state'),
                         ('XDG_RUNTIME_DIR', 'runtime')):
            (home / sub).mkdir(parents=True, exist_ok=True)
            env[key] = str(home / sub)
        env.update(HOME=str(home), USERPROFILE=str(home), VLT_CACHE=str(home / 'cache' / 'vlt'),
                   VLT_TELEMETRY='0', CI='1', NO_COLOR='1', LANG='C', LC_ALL='C')
        return env

    def run(self, args, cwd, home, log):
        return run(['node', '--no-warnings', self.js, *args], cwd, self.env(home), log)

    def locked_install(self):
        return ['ci'] if at_least(self.version, '0.0.0-19') else ['install']

    def reinstall(self, project, home, log):
        """Replace node_modules from the lock: `vlt ci`, or before it exists,
        delete node_modules and `vlt install`."""
        if not at_least(self.version, '0.0.0-19'):
            remove_node_modules(project)
        return self.run(self.locked_install(), project, home, log)


# ---------------------------------------------------------------------------
# CLI envelopes.

def parse_envelope(output):
    start = output.find('{')
    if start < 0:
        return None
    try:
        return json.loads(output[start:])
    except json.JSONDecodeError:
        return None


def envelope_codes(value):
    """Every `code` / `errorCode` / skipped `reason` code anywhere in it."""
    codes = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key in ('code', 'errorCode') and isinstance(item, str):
                codes.append(item)
            elif key == 'reason' and isinstance(item, str) and re.fullmatch(r'[a-z0-9_]+', item):
                codes.append(item)
            else:
                codes.extend(envelope_codes(item))
    elif isinstance(value, list):
        for item in value:
            codes.extend(envelope_codes(item))
    return codes


def envelope_details(value, code):
    found = []
    if isinstance(value, dict):
        if code in (value.get('code'), value.get('errorCode')) and isinstance(
                value.get('detail'), str):
            found.append(value['detail'])
        for item in value.values():
            found.extend(envelope_details(item, code))
    elif isinstance(value, list):
        for item in value:
            found.extend(envelope_details(item, code))
    return found


def vex_statements(doc, purl):
    def about(statement):
        return any(str(sub.get('@id', '')).split('?')[0] == purl
                   for product in statement.get('products', [])
                   for sub in product.get('subcomponents', []))
    return [st for st in (doc or {}).get('statements', []) if about(st)]


def vex_attested(doc, purl, uuid, marker, vulns):
    """`doc` attests `purl` for exactly the ids of `vulns` ({id: [cves]}),
    each not_affected, with every alias and the `Patched via Socket patch
    <uuid> (<marker>)` impact part."""
    statements = vex_statements(doc, purl)
    if not vulns or sorted(st['vulnerability']['name'] for st in statements) != sorted(vulns):
        return False
    part = f'Patched via Socket patch {uuid} ({marker})'
    for st in statements:
        aliases = set(st['vulnerability'].get('aliases', []))
        if (st.get('status') != 'not_affected'
                or not set(vulns[st['vulnerability']['name']]) <= aliases
                or part not in str(st.get('impact_statement', '')).split('; ')):
            return False
    return True


def record_vulns(record):
    return {vid: list(v.get('cves', [])) for vid, v in (record.get('vulnerabilities') or {}).items()}


def cli_env(extra=None):
    env = {k: v for k, v in os.environ.items()
           if not k.upper().startswith(('SOCKET_', 'VLT_', 'NPM_CONFIG_'))}
    env.update(SOCKET_NO_CONFIG='1', SOCKET_NO_UPDATE_CHECK='1', NO_COLOR='1', LANG='C',
               LC_ALL='C')
    env.update(extra or {})
    return env


# ---------------------------------------------------------------------------
# One cell.

class Cell:
    def __init__(self, ctx, version, mode, shape_name):
        self.ctx = ctx
        self.version = version
        self.mode = mode
        self.shape_name = shape_name
        self.spec = SHAPES[shape_name]
        self.name = f'{version}-{mode}-{shape_name}'
        self.case = ctx['out'] / 'captures' / self.name
        self.log = self.case / 'logs' / 'commands.log'
        self.project = self.case / 'project'
        self.record = ctx['record']
        self.envelopes = []
        self.fresh_patched = {}

    # CLI -------------------------------------------------------------------
    def cli(self, args, cwd=None):
        command = [self.ctx['cli'], *args, '--json', '--no-telemetry']
        if self.ctx.get('patch_server_url'):
            command += ['--patch-server-url', self.ctx['patch_server_url']]
        return run(command, cwd or self.project, self.ctx['cli_env'], self.log)

    def patch_run(self, mode, cwd=None):
        cwd = cwd or self.project
        verb = ['get', UUID] if self.spec.get('driver') == 'get' else ['scan']
        code, out, err = self.cli([*verb, '--mode', mode, '--yes', '--cwd', cwd], cwd)
        return code, parse_envelope(out), err

    def revert(self):
        if self.mode == 'hosted':
            return self.cli(['rollback', '--yes', '--cwd', self.project])
        if self.mode == 'vendored':
            return self.cli(['vendor', '--revert', '--yes', '--cwd', self.project])
        return self.cli(['rollback', '--yes', '--cwd', self.project])

    # vlt -------------------------------------------------------------------
    def home(self, label):
        return self.case / 'homes' / label

    def prepare(self, vlt):
        self.project.mkdir(parents=True)
        for rel, text in project_files(self.version, self.spec).items():
            path = self.project / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding='utf-8')
        lock = self.project / 'vlt-lock.json'
        previous = None
        for _ in range(3):
            code, out, err = vlt.run(['install'], self.project, self.home('install'), self.log)
            if code != 0:
                raise RuntimeError(f'vlt install exited {code}: {tail(err or out, 1500)}')
            if not lock.is_file():
                raise RuntimeError('vlt install wrote no vlt-lock.json')
            if lock.read_bytes() == previous:
                break
            previous = lock.read_bytes()
        else:
            raise RuntimeError('vlt-lock.json did not settle after three installs')
        if self.spec.get('crlf_lock'):
            lock.write_bytes(to_crlf(lock.read_bytes()))
        if self.spec.get('lockfile_only'):
            remove_node_modules(self.project)

    # bytes -------------------------------------------------------------------
    def copies(self, root, lock_text):
        """Every installed copy of minimist@1.2.2 the cell must judge: each
        importer's link and, outside vendored mode, every store copy."""
        paths = [root / importer / 'node_modules' / dep for importer, dep in self.spec['runtime']]
        if self.mode != 'vendored':
            paths += [root / 'node_modules' / '.vlt' / dep_id / 'node_modules' / NAME
                      for dep_id in target_instances(lock_text, any_registry=self.mode == 'agent')]
        return paths

    def holds(self, root, lock_text, side):
        """(every copy holds the record's `side` bytes, digests by copy)."""
        details = {}
        ok = True
        for copy_dir in self.copies(root, lock_text):
            for key, hashes in self.record['files'].items():
                path = copy_dir / key.split('/', 1)[1]
                digest = git_hash(path.read_bytes()) if path.is_file() else None
                details[str(path.relative_to(root))] = digest
                ok = ok and digest == hashes.get(f'{side}Hash')
        return ok and bool(details), details

    def fresh(self, vlt, label, files, command=None):
        checkout = write_checkout(files, self.case / label)
        code, out, err = vlt.run(command or vlt.locked_install(), checkout, self.home(label),
                                 self.log)
        return checkout, code, err or out

    def lock_stable(self, row, expected, observed, label):
        if observed == expected:
            return True
        if self.spec.get('crlf_lock') and observed == expected.replace(b'\r\n', b'\n'):
            # vlt re-saves a CRLF lock as LF on its own.
            row.setdefault('lockNormalizedByVlt', []).append(label)
            return True
        return False

    def limitation(self, row, checks, names):
        text = known_vlt_limitation(self.version, self.mode, self.shape_name)
        if not text:
            return
        failed = [n for n in names if checks.get(n) is False]
        if failed:
            for name in failed:
                checks[name] = None
            reason = f'vlt {self.version} {text}'
            limitations = row.setdefault('vltLimitations', [])
            if reason not in limitations:
                limitations.append(reason)

    # the cell ----------------------------------------------------------------
    def run_cell(self):
        expected = expected_verdict(self.version, self.mode, self.shape_name)
        row = dict(cell=self.name, vlt=self.version, era=era_of(self.version), mode=self.mode,
                   shape=self.shape_name, os=self.ctx['os'], arch=platform.machine(),
                   passed=False, expectedVerdict=expected,
                   expectedCodes=expected_codes(self.version, self.mode, self.shape_name),
                   expectedLimitation=known_vlt_limitation(self.version, self.mode,
                                                           self.shape_name),
                   patches=[dict(self.ctx['patch'])], **self.ctx['provenance'])
        row['supported'] = expected != 'unsupported'
        checks = row['checks'] = {}
        started = time.time()
        if self.case.exists():
            shutil.rmtree(self.case)
        self.case.mkdir(parents=True)
        try:
            vlt = Vlt(self.ctx['tools'][self.version], self.version)
            row['vltSha256'] = vlt.sha256
            self.prepare(vlt)
            lock_path = self.project / 'vlt-lock.json'
            before_lock = lock_path.read_bytes()
            row['lockfileVersion'] = json.loads(before_lock).get('lockfileVersion')
            row['lineEndings'] = line_endings(before_lock)
            if not self.spec.get('lockfile_only'):
                ok, row['baseline'] = self.holds(self.project, before_lock.decode(), 'before')
                checks['installedBefore'] = ok
                if not ok:
                    raise RuntimeError(f'installed bytes are not the upstream bytes: '
                                       f'{row["baseline"]}')
            pristine = self.pristine = snapshot(self.project)
            probing = 'hosted' in (self.mode, self.spec.get('before'))
            if probing:
                row['serveProbe'] = probe = probe_artifact(self.ctx['artifact_url'],
                                                           self.ctx['artifact_sha512'],
                                                           self.case / 'probe')
                checks['serveEncodingIdentity'] = probe['verifies']
            if self.spec.get('before'):
                code, envelope, _ = self.patch_run(self.spec['before'])
                row['beforeExitCode'] = code
                save(self.case / 'before-cli-output.json', envelope)
                if code != 0 or snapshot(self.project) == pristine:
                    if self.blocked_refusal(row, [envelope], pristine):
                        return self.finish(row, checks, started)
                    raise RuntimeError(f'the first {self.spec["before"]} run patched nothing '
                                       f'(exit {code})')
            original = snapshot(self.project)
            row['originalSha256'] = {n: sha256(b) for n, b in original.items()}

            code, envelope, err = self.patch_run(self.mode)
            self.envelopes = [envelope]
            save(self.case / 'cli-output.json', envelope)
            row['exitCode'] = code
            row['cliStderrTail'] = tail(err, 3000)
            row['codes'] = sorted(set(envelope_codes(envelope)))
            after = snapshot(self.project)
            row['changedFiles'] = sorted(n for n in set(original) | set(after)
                                         if original.get(n) != after.get(n))
            row['manifestSha256'] = capture_tree(self.project, self.case / 'tree')
            if self.mode == 'hosted' and self.blocked_refusal(row, [envelope], original):
                return self.finish(row, checks, started)
            if probing and 'serveEncodingIdentity' in checks and not checks[
                    'serveEncodingIdentity'] and expected == 'patched':
                # The probe says vlt cannot verify the artifact, yet this was
                # no clean refusal: whatever the CLI wrote is unsafe.
                checks['cleanRefusalWhileEncoded'] = False
            if not checks.get('serveEncodingIdentity', True) and expected != 'patched':
                checks.pop('serveEncodingIdentity')
            status_ok = isinstance(envelope, dict) and envelope.get('status') in ('success', 'ok')
            checks['cliSuccess'] = code == 0 and status_ok
            getattr(self, f'check_{self.mode}')(row, checks, before_lock, vlt, original)
            row['passed'] = (not row.get('safeRefusal') and bool(checks)
                             and all(v is True for v in checks.values()))
        except Exception as error:  # noqa: BLE001 — the row must explain the failure
            row['error'] = tail(f'{type(error).__name__}: {error}', 4000)
        return self.finish(row, checks, started)

    def blocked_refusal(self, row, envelopes, reference):
        """A clean refusal of a must-patch hosted run while the cell's own
        probe saw a content-encoded artifact."""
        probe = row.get('serveProbe') or {}
        encoded = probe.get('status') == 200 and not encoding_is_identity(
            probe.get('contentEncoding'))
        if not encoded or row['expectedVerdict'] != 'patched':
            return False
        details = [d for e in envelopes
                   for d in envelope_details(e, 'redirect_vlt_artifact_unverifiable')]
        row['codes'] = sorted(set(row.get('codes', [])) | {
            c for e in envelopes for c in envelope_codes(e)})
        clean = (snapshot(self.project) == reference
                 and any('content-encoding' in d and 'nothing was written' in d
                         for d in details))
        row['blockedDetails'] = details
        if clean:
            row['blocked'] = True
            row['blockedByProbe'] = probe.get('contentEncoding')
            row['expectedCodesUnblocked'] = row['expectedCodes']
            row['expectedCodes'] = BLOCKED_CODES
            row.pop('manifestSha256', None)
            row['manifestSha256'] = capture_tree(self.project, self.case / 'tree')
            row['checks'].pop('serveEncodingIdentity', None)
        return clean

    def finish(self, row, checks, started):
        row['failingChecks'] = [k for k, v in checks.items() if v is False]
        row['notEvaluated'] = [k for k, v in checks.items() if v is None]
        row.setdefault('codes', [])
        row.setdefault('manifestSha256', {})
        row['verdict'] = observed_verdict(row)
        row['matchesExpectation'] = matches_expectation(row)
        row['seconds'] = round(time.time() - started, 1)
        if not self.ctx.get('keep_projects'):
            for sub in list(self.case.iterdir()):
                if sub.is_dir() and sub.name not in ('tree', 'logs', 'probe'):
                    shutil.rmtree(sub, ignore_errors=True)
        save(self.case / 'result.json', row)
        mark = 'OK ' if row['matchesExpectation'] else 'BAD'
        print(f"{mark} {self.name}: {row['verdict']} (expected {row['expectedVerdict']}) "
              f"failing={row['failingChecks']} {row.get('error', '')[:300]}", flush=True)
        return row

    def unchanged(self, row):
        return not row['changedFiles']

    def installs(self, row, checks, vlt, lock_after, text):
        """Cold fresh checkouts: the locked install and an ordinary one."""
        files = snapshot(self.project)
        for label, command in (('freshCi', None), ('freshOrdinary', ['install'])):
            checkout, code, err = self.fresh(vlt, label, files, command)
            row[label + 'Exit'] = code
            if code:
                row[label + 'Tail'] = tail(err, 1500)
            stable = self.lock_stable(row, lock_after, (checkout / 'vlt-lock.json').read_bytes(),
                                      label)
            if not stable and churn_exempt(self.version, self.mode, self.shape_name):
                first = (checkout / 'vlt-lock.json').read_bytes()
                again, _, _ = vlt.run(vlt.locked_install(), checkout, self.home(label), self.log)
                stable = again == 0 and (checkout / 'vlt-lock.json').read_bytes() == first
                row.setdefault('churn', []).append(f'{label}: skip:vlt-own-churn')
            patched, row[label + 'Files'] = self.holds(checkout, text, 'after')
            checks[label] = code == 0 and stable and patched
            self.fresh_patched[label] = code == 0 and patched
            shutil.rmtree(checkout, ignore_errors=True)
        self.limitation(row, checks, ['freshCi', 'freshOrdinary'])

    def vex(self, row, checks, vlt, marker, record):
        """Manifest-less VEX on a fresh checkout: `.socket/manifest.json`
        dropped, a locked install, then standalone `vex`."""
        files = {n: b for n, b in snapshot(self.project).items() if n != '.socket/manifest.json'}
        checkout, code, _ = self.fresh(vlt, 'vex-checkout', files)
        out = checkout / 'out.vex.json'
        vex_code, output, _ = self.cli(['vex', '--output', out, '--product', VEX_PRODUCT,
                                        '--cwd', checkout], checkout)
        doc = json.loads(out.read_text(encoding='utf-8')) if out.is_file() else None
        attested = vex_attested(doc, PURL, UUID, marker, record_vulns(record))
        row['vex'] = dict(installExit=code, exit=vex_code, attested=attested,
                          codes=sorted(set(envelope_codes(parse_envelope(output)))))
        checks['vexManifestless'] = code == 0 and vex_code == 0 and attested
        shutil.rmtree(checkout, ignore_errors=True)
        self.limitation(row, checks, ['vexManifestless'])

    def repeat(self, row, checks, lock_after):
        code, envelope, _ = self.patch_run(self.mode)
        row['repeatExitCode'] = code
        row['repeatCodes'] = sorted(set(envelope_codes(envelope)))
        checks['repeatStableLock'] = code == 0 and (
            self.project / 'vlt-lock.json').read_bytes() == lock_after

    def rolled_back(self, row, checks, vlt, original, text):
        """The mode's revert restores the files the first socket-patch run
        found (a takeover already reverted the earlier mode, so a conversion
        shape goes back to the pristine project), and a fresh checkout of the
        reverted project installs the upstream bytes."""
        expected = dict(self.pristine if self.spec.get('before') else original)
        lock = (self.project / 'vlt-lock.json').read_bytes()
        if self.spec.get('crlf_lock') and line_endings(lock) == 'lf':
            # vlt re-saved the CRLF lock as LF during the warm installs; the
            # slot revert keeps vlt's own layout.
            expected['vlt-lock.json'] = expected['vlt-lock.json'].replace(b'\r\n', b'\n')
            row.setdefault('lockNormalizedByVlt', []).append('beforeRollback')
        code, out, _ = self.revert()
        row['rollbackExitCode'] = code
        row['rollbackCodes'] = sorted(set(envelope_codes(parse_envelope(out))))
        now = snapshot(self.project)
        stray = sorted(set(now) - set(expected))
        row['rollbackStray'] = stray
        checks['rollbackByteIdentical'] = code == 0 and all(
            now.get(n) == b for n, b in expected.items()) and not stray
        checkout, install_code, _ = self.fresh(vlt, 'rollback-checkout', now)
        pristine, row['rollbackFiles'] = self.holds(checkout, text, 'before')
        checks['rollbackOriginalBytes'] = install_code == 0 and pristine
        shutil.rmtree(checkout, ignore_errors=True)
        self.limitation(row, checks, ['rollbackOriginalBytes'])

    def ledger_record(self):
        if self.mode == 'hosted':
            path = self.project / '.socket/vendor/redirect-state.json'
            key = 'records'
        else:
            path = self.project / '.socket/vendor/state.json'
            key = 'entries'
        if not path.is_file():
            return None
        state = json.loads(path.read_text(encoding='utf-8'))
        item = (state.get(key) or {}).get(PURL)
        if item is None:
            return None
        return item if self.mode == 'hosted' else item.get('record')

    def check_hosted(self, row, checks, before_lock, vlt, original):
        if self.unchanged(row):
            row['safeRefusal'] = True
            checks.pop('cliSuccess', None)
            return
        lock_after = (self.project / 'vlt-lock.json').read_bytes()
        text = lock_after.decode()
        record = self.ledger_record()
        checks['publishedPatch'] = bool(record) and record.get('uuid') == UUID
        nodes = json.loads(text)['nodes']
        instances = target_instances(text)
        row['lockEntries'] = {d: nodes[d] for d in instances}
        checks['referenceWritten'] = bool(instances) and all(
            nodes[d][2] == self.ctx['artifact_sha512'] and len(nodes[d]) > 3
            and nodes[d][3] == self.ctx['artifact_url'] for d in instances)
        before, after = json.loads(before_lock), json.loads(lock_after)
        checks['lockFormatPreserved'] = (before.get('lockfileVersion') == after.get(
            'lockfileVersion') and line_endings(before_lock) == line_endings(lock_after))
        checks['othersUntouched'] = (
            before.get('options') == after.get('options')
            and before.get('edges') == after.get('edges')
            and {k: v for k, v in before['nodes'].items() if k not in instances}
            == {k: v for k, v in after['nodes'].items() if k not in instances})
        self.installs(row, checks, vlt, lock_after, text)
        tampered = tamper_lock(lock_after, instances)
        files = dict(snapshot(self.project), **{'vlt-lock.json': tampered})
        checkout, code, err = self.fresh(vlt, 'tamper', files)
        row['tamperTail'] = tail(err, 1500)
        installed = any(p.is_dir() for p in self.copies(checkout, text))
        checks['tamperedDigest'] = tampered != lock_after and integrity_enforced(
            self.version, self.spec.get('optional'), code, err, installed,
            self.fresh_patched.get('freshCi'))
        shutil.rmtree(checkout, ignore_errors=True)
        self.limitation(row, checks, ['tamperedDigest'])
        self.vex(row, checks, vlt, 'redirected', record or self.record)
        self.repeat(row, checks, lock_after)
        # The warm tree the heal left behind.
        if self.spec.get('optional'):
            kept, row['keptOptional'] = self.holds(self.project, text, 'before')
            details = [d for e in self.envelopes
                       for d in envelope_details(e, 'redirect_vlt_reinstall_required')]
            checks['optionalCopyKept'] = kept and any(OPTIONAL_HELD in d for d in details)
            code, _, _ = vlt.run(['install'], self.project, self.home('install'), self.log)
            _, row['warmOrdinaryFiles'] = self.holds(self.project, text, 'before')
        else:
            code, _, _ = vlt.run(['install'], self.project, self.home('install'), self.log)
            patched, row['warmOrdinaryFiles'] = self.holds(self.project, text, 'after')
            checks['warmOrdinary'] = code == 0 and patched
        self.warm_ci(row, checks, vlt, text)
        self.rolled_back(row, checks, vlt, original, text)

    def warm_ci(self, row, checks, vlt, text):
        code, _, _ = vlt.reinstall(self.project, self.home('install'), self.log)
        patched, row['warmCiFiles'] = self.holds(self.project, text, 'after')
        checks['warmCi'] = code == 0 and patched
        self.limitation(row, checks, ['warmOrdinary', 'warmCi'])

    def warm(self, row, checks, vlt, text):
        """The project's own tree, which still links the registry copy: an
        ordinary install lands the vendored bytes (or, where vlt keeps an
        optional dependency, leaves the upstream copy intact), then a locked
        one lands them."""
        code, _, _ = vlt.run(['install'], self.project, self.home('install'), self.log)
        patched, row['warmOrdinaryFiles'] = self.holds(self.project, text, 'after')
        if not patched and optional_warm_kept(self.version, self.mode, self.shape_name):
            patched, _ = self.holds(self.project, text, 'before')
            row['warmOrdinaryKeptUpstream'] = patched
        checks['warmOrdinary'] = code == 0 and patched
        self.warm_ci(row, checks, vlt, text)

    def check_vendored(self, row, checks, before_lock, vlt, original):
        if self.unchanged(row):
            row['safeRefusal'] = True
            checks.pop('cliSuccess', None)
            return
        lock_after = (self.project / 'vlt-lock.json').read_bytes()
        text = lock_after.decode()
        record = self.ledger_record()
        checks['publishedPatch'] = bool(record) and record.get('uuid') == UUID
        payload = f'.socket/vendor/npm/{UUID}/{NAME}-{VERSION}/node_modules/{NAME}'
        nodes = json.loads(text)['nodes']
        file_nodes = [d for d, t in nodes.items()
                      if d.startswith('file') and len(t) > 3 and t[3] == payload]
        manifest_path = self.project / payload / 'package.json'
        payload_ok = manifest_path.is_file() and json.loads(
            manifest_path.read_text(encoding='utf-8')).get('version') == VERSION
        specs = []
        for importer, dep in self.spec['runtime']:
            data = json.loads((self.project / importer / 'package.json').read_text(
                encoding='utf-8'))
            for section in ('dependencies', 'devDependencies', 'optionalDependencies'):
                value = (data.get(section) or {}).get(dep)
                if isinstance(value, str) and value.startswith('file:') and UUID in value:
                    specs.append(value)
        row['lockEntries'] = dict(fileNodes=file_nodes, payload=payload_ok, specs=specs)
        checks['referenceWritten'] = bool(file_nodes) and payload_ok and len(specs) == len(
            self.spec['runtime'])
        before, after = json.loads(before_lock), json.loads(lock_after)
        checks['lockFormatPreserved'] = (before.get('lockfileVersion') == after.get(
            'lockfileVersion') and line_endings(before_lock) == line_endings(lock_after))
        self.installs(row, checks, vlt, lock_after, text)
        self.vex(row, checks, vlt, 'vendored', record or self.record)
        self.repeat(row, checks, lock_after)
        self.warm(row, checks, vlt, text)
        lock_before_repair = (self.project / 'vlt-lock.json').read_bytes()
        payload_dir = self.project / payload
        shutil.rmtree(payload_dir)
        code, out, _ = self.cli(['repair', '--yes', '--cwd', self.project])
        repaired = parse_envelope(out) or {}
        row['repairExitCode'] = code
        rebuilt = payload_dir.is_dir() and any(
            e.get('action') == 'rebuilt' and str(e.get('purl', '')).split('?')[0] == PURL
            for e in repaired.get('events', []))
        checkout, install_code, _ = self.fresh(vlt, 'repair-checkout', snapshot(self.project))
        patched, row['repairFiles'] = self.holds(checkout, text, 'after')
        checks['repair'] = code == 0 and rebuilt and install_code == 0 and patched and (
            self.project / 'vlt-lock.json').read_bytes() == lock_before_repair
        shutil.rmtree(checkout, ignore_errors=True)
        self.limitation(row, checks, ['repair'])
        self.rolled_back(row, checks, vlt, original, text)

    def check_agent(self, row, checks, before_lock, vlt, original):
        lock_after = (self.project / 'vlt-lock.json').read_bytes()
        text = lock_after.decode()
        patched, row['installed'] = self.holds(self.project, text, 'after')
        if self.unchanged(row) and not patched:
            row['safeRefusal'] = True
            checks.pop('cliSuccess', None)
            return
        path = self.project / '.socket' / 'manifest.json'
        recorded = json.loads(path.read_text(encoding='utf-8')).get('patches', {}) \
            if path.is_file() else {}
        checks['manifestWritten'] = (recorded.get(PURL) or {}).get('uuid') == UUID
        checks['lockUnchanged'] = lock_after == before_lock
        checks['patchedBytes'] = patched
        code, _, _ = vlt.run(['install'], self.project, self.home('install'), self.log)
        still, row['afterNoopInstall'] = self.holds(self.project, text, 'after')
        rewritten = (self.project / 'vlt-lock.json').read_bytes()
        checks['survivesNoopInstall'] = code == 0 and still
        if rewritten != lock_after and self.spec.get('crlf_lock') and \
                rewritten == lock_after.replace(b'\r\n', b'\n'):
            row.setdefault('lockNormalizedByVlt', []).append('noopInstall')
            original = dict(original, **{'vlt-lock.json': rewritten})
            lock_after = rewritten
        self.repeat(row, checks, lock_after)
        code, out, _ = self.revert()
        row['rollbackExitCode'] = code
        now = {n: b for n, b in snapshot(self.project).items() if not n.startswith('.socket/')}
        expected = {n: b for n, b in original.items() if not n.startswith('.socket/')}
        checks['rollbackByteIdentical'] = code == 0 and now == expected
        pristine, row['afterRollback'] = self.holds(self.project, text, 'before')
        checks['rollbackOriginalBytes'] = pristine


def transient(row):
    """A failure the service's transport caused (a request error, or a probe
    that got no 2xx/4xx answer), never a functional one."""
    if row.get('matchesExpectation'):
        return False
    probe = row.get('serveProbe') or {}
    if probe and (probe.get('curlExit') or (probe.get('status') or 0) >= 500
                  or probe.get('status') is None):
        return True
    return 'error sending request for url (' in json.dumps(row)


def run_with_retries(cell_factory, job, attempts=3):
    """Re-run a cell from a clean tree while it fails for transport reasons;
    earlier attempts are listed on the row."""
    history = []
    for attempt in range(1, attempts + 1):
        cell = cell_factory(*job)
        row = cell.run_cell()
        if not transient(row) or attempt == attempts:
            if history:
                row['transportRetries'] = history
                save(cell.case / 'result.json', row)
            return row
        history.append(dict(attempt=attempt, error=row.get('error'),
                            failingChecks=row.get('failingChecks')))
        print(f'{row["cell"]}: transport failure; retrying ({attempt}/{attempts})', flush=True)
        time.sleep(10 * attempt)


# ---------------------------------------------------------------------------
# The downgrade scenario (DESIGN §2.4 / §8.4 `downgrade`).

def downgrade(args, ctx, vlt):
    """vlt ledgers written by this build, then the published release's
    `rollback` and `vendor --revert`: each must leave the project untouched
    (fail closed) or fully reverted, never half-reverted (a dropped record
    beside a still-redirected lock, a reverted lock with the payload left)."""
    out = ctx['out'] / 'downgrade'
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    log = out / 'commands.log'
    published = str(Path(args.downgrade_cli).resolve())
    code, version_out, _ = run([published, '--version'], out, ctx['cli_env'], log)
    rows = []
    for mode in ('hosted', 'vendored'):
        row = dict(scenario='downgrade', mode=mode, vlt=vlt.version, os=ctx['os'],
                   publishedCli=version_out.strip(), **ctx['provenance'])
        project = out / mode / 'project'
        project.mkdir(parents=True)
        spec = SHAPES['direct']
        for rel, text in project_files(vlt.version, spec).items():
            (project / rel).write_text(text, encoding='utf-8')
        try:
            vlt.run(['install'], project, out / mode / 'home', log)
            pristine = snapshot(project)
            env, extra = ctx['cli_env'], []
            mirror = None
            if mode == 'hosted' and not probe_artifact(
                    ctx['artifact_url'], ctx['artifact_sha512'], out / 'probe')['verifies']:
                # The live artifact is content-encoded, so this build refuses to
                # write a hosted vlt ledger; write it through the identity mirror.
                mirror = IdentityMirror().__enter__()
                env = dict(env, SOCKET_PROXY_URL=mirror.url)
                extra = ['--patch-server-url', mirror.url]
                row['identityMirror'] = True
            try:
                code, output, _ = run([ctx['cli'], 'scan', '--mode', mode, '--json', '--yes',
                                       '--no-telemetry', *extra, '--cwd', project],
                                      project, env, log)
            finally:
                if mirror:
                    mirror.__exit__()
            written = snapshot(project)
            ledger = '.socket/vendor/redirect-state.json' if mode == 'hosted' \
                else '.socket/vendor/state.json'
            state = json.loads(written.get(ledger, b'{}'))
            kinds = [e.get('kind') for e in state.get('edits', [])] if mode == 'hosted' else [
                e.get('flavor') for e in (state.get('entries') or {}).values()]
            row['ledgerKinds'] = kinds
            if code != 0 or ('redirect_vlt_lock_node' if mode == 'hosted' else 'vlt') not in kinds:
                raise RuntimeError(f'this build wrote no vlt {mode} ledger (exit {code}): '
                                   f'{tail(output, 1500)}')
            command = ['rollback'] if mode == 'hosted' else ['vendor', '--revert']
            code, output, _ = run([published, *command, '--json', '--yes', '--no-telemetry',
                                   '--cwd', project], project, ctx['cli_env'], log)
            row['publishedExitCode'] = code
            row['publishedCodes'] = sorted(set(envelope_codes(parse_envelope(output))))
            now = snapshot(project)
            untouched = now == written
            reverted = {n: b for n, b in now.items() if not n.startswith('.socket/')} == {
                n: b for n, b in pristine.items() if not n.startswith('.socket/')} and not any(
                n.startswith('.socket/vendor/') for n in now)
            row['untouched'] = untouched
            row['fullyReverted'] = reverted
            row['changedFiles'] = sorted(n for n in set(now) | set(written)
                                         if now.get(n) != written.get(n))
            row['passed'] = untouched or reverted
        except Exception as error:  # noqa: BLE001 — the row must explain the failure
            row['error'] = tail(f'{type(error).__name__}: {error}', 3000)
            row['passed'] = False
        rows.append(row)
        print(f"downgrade {mode}: {'OK' if row['passed'] else 'BAD'} "
              f"untouched={row.get('untouched')} reverted={row.get('fullyReverted')} "
              f"{row.get('error', '')[:300]}", flush=True)
    save(out / 'summary.json', rows)
    return 0 if all(r['passed'] for r in rows) else 1


# ---------------------------------------------------------------------------
# The canary watchdogs and the cross-OS lock comparison.

def published_versions():
    return json.loads(subprocess.run([npm_command(), 'view', 'vlt', 'versions', '--json'],
                                     capture_output=True, check=True).stdout)


def canary_checks(ctx, versions):
    """The release watchdog and the unsupported-lockfileVersion refusal."""
    out = ctx['out'] / 'canary'
    out.mkdir(parents=True, exist_ok=True)
    supported, excluded = release_lists()
    report = dict(unlisted=unlisted_releases(published_versions(), supported, excluded),
                  locks=[])
    ok = not report['unlisted']
    for version in versions:
        vlt = Vlt(ctx['tools'][version], version)
        project = out / version / 'project'
        if project.exists():
            shutil.rmtree(project)
        project.mkdir(parents=True)
        for rel, text in project_files(version, SHAPES['direct']).items():
            (project / rel).write_text(text, encoding='utf-8')
        log = out / version / 'commands.log'
        vlt.run(['install'], project, out / version / 'home', log)
        lock = project / 'vlt-lock.json'
        entry = dict(vlt=version, lockfileVersion=None, refused=None)
        if lock.is_file():
            entry['lockfileVersion'] = json.loads(lock.read_bytes()).get('lockfileVersion')
        if entry['lockfileVersion'] not in (None, 0, 1):
            before = snapshot(project)
            code, output, _ = run([ctx['cli'], 'scan', '--mode', 'hosted', '--dry-run', '--json',
                                   '--no-telemetry', '--cwd', project], project, ctx['cli_env'],
                                  log)
            codes = envelope_codes(parse_envelope(output))
            entry['refused'] = ('redirect_vlt_lock_unsupported' in codes
                                and snapshot(project) == before)
            ok = ok and entry['refused']
        report['locks'].append(entry)
    save(out / 'report.json', report)
    for version in report['unlisted']:
        print(f'::error::vlt {version} is published but neither supported nor excluded in '
              f'docs/testing/vlt-compatibility.md (Releases)', flush=True)
    for entry in report['locks']:
        print(f"vlt {entry['vlt']}: lockfileVersion {entry['lockfileVersion']!r}"
              + ('' if entry['refused'] is None else f", refused={entry['refused']}"), flush=True)
    return 0 if ok else 1


def serve_probe(out):
    """The artifact vlt would fetch: 200, no content encoding (or identity)
    and the API's sha512 over the wire bytes."""
    url, expected = fetch_grant()
    probe = probe_artifact(url, expected, out)
    save(out / 'serve-probe.json', probe)
    print(json.dumps(probe, indent=2, sort_keys=True), flush=True)
    if probe['verifies']:
        return 0
    if not probe['identity']:
        print(f"::error::{url} is served with content-encoding {probe['contentEncoding']!r} "
              f"(HTTP {probe['status']}); vlt fails EINTEGRITY on it", flush=True)
    else:
        print(f"::error::{url} sha512 {probe['sha512']} != API {expected}", flush=True)
    return 1


def compare_locks(rows):
    """{(vlt, mode, shape): {os: vlt-lock.json sha256}} for every cell seen
    on more than one OS, and the groups whose locks differ."""
    groups = {}
    for row in rows:
        lock = (row.get('manifestSha256') or {}).get('vlt-lock.json')
        if lock and row.get('os'):
            groups.setdefault((row['vlt'], row['mode'], row['shape']), {})[row['os']] = lock
    shared = {k: v for k, v in groups.items() if len(v) > 1}
    differing = sorted(k for k, v in shared.items() if len(set(v.values())) > 1)
    return shared, differing


def diff_locks(dirs, out, required):
    rows = []
    for directory in dirs:
        for result in sorted(Path(directory).rglob('result.json')):
            row = json.loads(result.read_text(encoding='utf-8'))
            tree_lock = result.parent / 'tree' / 'vlt-lock.json'
            if 'manifestSha256' in row and tree_lock.is_file() and sha256(
                    tree_lock.read_bytes()) != row['manifestSha256'].get('vlt-lock.json'):
                raise SystemExit(f'{result.parent}: tree/vlt-lock.json differs from its row')
            rows.append(row)
    shared, differing = compare_locks(rows)
    missing = []
    for key in required:
        oses = shared.get(key, {})
        if set(oses) != {'linux', 'darwin', 'windows'}:
            missing.append(f'{" ".join(key)}: locks from {sorted(oses) or "no OS"}')
    report = dict(groups={' '.join(k): v for k, v in sorted(shared.items())},
                  differing=[' '.join(k) for k in differing], missing=missing)
    save(out / 'lock-diff.json', report)
    for key in differing:
        print(f'::error::vlt-lock.json differs across OS for {" ".join(key)}: {shared[key]}')
    for line in missing:
        print(f'::error::no cross-OS lock set for {line}')
    print(f'{len(shared)} cells compared across OS; {len(differing)} differ', flush=True)
    return 1 if differing or missing else 0


# ---------------------------------------------------------------------------

def summarize(out, rows):
    save(out / 'summary.json', rows)
    marks = {'patched': 'P', 'safe-refusal': 'R', 'unsafe': 'U', 'error': 'E',
             'unsupported': 'N', BLOCKED: 'B'}
    lines = ['| cell | verdict | expected | failing | codes |', '|---|---|---|---|---|']
    for row in sorted(rows, key=lambda r: r.get('cell', '')):
        flag = '' if row.get('matchesExpectation') else ' ?'
        lines.append(f"| {row.get('cell')} | {marks.get(row.get('verdict'), '?')}{flag} | "
                     f"{marks.get(row.get('expectedVerdict'), '?')} | "
                     f"{', '.join(row.get('failingChecks', []))} | "
                     f"{', '.join(row.get('codes', []))} |")
    bad = [r.get('cell') for r in rows if not r.get('matchesExpectation')]
    lines += ['', f'{len(rows)} cells; {len(bad)} not as expected'
              + (': ' + ', '.join(bad) if bad else '')]
    (out / 'summary.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return bad


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--cli', type=Path, help='the socket-patch binary')
    parser.add_argument('--cli-revision', default=os.environ.get('CLI_REVISION') or None)
    parser.add_argument('--cli-build-sha', default=os.environ.get('CLI_BUILD_SHA') or None)
    parser.add_argument('--out', '--output', dest='out', type=Path, required=True)
    parser.add_argument('--serve-probe', action='store_true',
                        help='probe the public artifact as vlt fetches it (the serve watchdog)')
    parser.add_argument('--canary-checks', action='store_true',
                        help='run the release watchdog and the unsupported-lock refusal')
    parser.add_argument('--diff-locks', nargs='+', type=Path, metavar='DIR',
                        help='compare vlt-lock.json across OS in downloaded result rows')
    parser.add_argument('--require-cross-os', nargs='+', default=[], metavar='VLT:MODE:SHAPE',
                        help='cells --diff-locks must see on linux, darwin and windows')
    parser.add_argument('--tools', type=Path,
                        help='vlt install root (<root>/<version>/node_modules/vlt/vlt.js)')
    parser.add_argument('--versions', nargs='+', default=VERSIONS)
    parser.add_argument('--shapes', nargs='+', default=list(SHAPES), choices=list(SHAPES))
    parser.add_argument('--modes', nargs='+', default=MODES, choices=MODES)
    parser.add_argument('--jobs', type=int, default=2)
    parser.add_argument('--allow-unlisted', action='store_true',
                        help='accept a release the Releases table does not list (the canary)')
    parser.add_argument('--identity-mirror', action='store_true',
                        help='serve production through a loopback mirror with identity-encoded '
                             'artifacts (a local preview of the serve fix; never imported)')
    parser.add_argument('--downgrade-cli', type=Path,
                        help='run the downgrade scenario against this published socket-patch')
    parser.add_argument('--keep-projects', action='store_true')
    args = parser.parse_args(argv)
    if args.diff_locks:
        args.out.mkdir(parents=True, exist_ok=True)
        return diff_locks(args.diff_locks, args.out.resolve(),
                          [tuple(r.split(':', 2)) for r in args.require_cross_os])
    if args.serve_probe:
        return serve_probe(args.out.resolve())
    if args.cli is None:
        parser.error('--cli is required')
    supported, excluded = release_lists()
    for version in args.versions:
        status = release_status(version, supported, excluded)
        if status == 'excluded' or (status == 'unlisted' and not args.allow_unlisted):
            parser.error(f'vlt {version} is {status} (docs/testing/vlt-compatibility.md Releases)')
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    cli = out / ('socket-patch.exe' if platform.system() == 'Windows' else 'socket-patch')
    shutil.copy2(args.cli.resolve(), cli)
    tool_root = (args.tools or out / 'tools').resolve()
    provenance = dict(capturedAt=datetime.now(timezone.utc).isoformat(),
                      platform=platform.platform(), cliRevision=args.cli_revision,
                      cliBuildSha=args.cli_build_sha, cliSha256=sha256(cli.read_bytes()),
                      harness='socket-patch scripts/backtest-vlt.py')
    os_name = platform.system().lower()
    try:
        tools = {v: install_tool(tool_root, v, out / 'logs' / f'install-{v}.log')
                 for v in args.versions}
    except Exception as error:  # noqa: BLE001 — the artifact must explain the run
        save(out / 'summary.json', [dict(vlt=v, os=os_name, passed=False, verdict='error',
                                         matchesExpectation=False,
                                         error=f'vlt install failed: {error}', **provenance)
                                    for v in args.versions])
        print(f'vlt install failed: {error}', flush=True)
        return 1
    mirror = IdentityMirror().__enter__() if args.identity_mirror else None
    try:
        api = mirror.url if mirror else API_URL
        env = {'SOCKET_PROXY_URL': mirror.url} if mirror else {}
        artifact_url, artifact_sha512 = fetch_grant(api)
        record = fetch_record(api)
        ctx = dict(out=out, cli=cli, cli_env=cli_env(env), os=os_name, tools=tools,
                   provenance=dict(provenance, identityMirror=bool(mirror)),
                   keep_projects=args.keep_projects, artifact_url=artifact_url,
                   artifact_sha512=artifact_sha512, record=record,
                   patch_server_url=mirror.url if mirror else None,
                   patch=dict(name=NAME, version=VERSION, uuid=UUID, purl=PURL,
                              integrity=artifact_sha512, url=artifact_url,
                              files=record.get('files')))
        if args.downgrade_cli:
            return downgrade(args, ctx, Vlt(tools[args.versions[0]], args.versions[0]))
        if args.canary_checks:
            return canary_checks(ctx, args.versions)
        matrix = cells(args.versions, args.modes, args.shapes)
        if not matrix:
            reason = (f'no cell applies: versions={" ".join(args.versions)} '
                      f'modes={" ".join(args.modes)} shapes={" ".join(args.shapes)}')
            save(out / 'summary.json', [dict(noCells=True, passed=False, error=reason,
                                             **provenance)])
            print(f'::notice::{reason}', flush=True)
            return 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
            rows = list(pool.map(
                lambda c: run_with_retries(lambda *job: Cell(ctx, *job), c), matrix))
    finally:
        if mirror:
            mirror.__exit__()
    bad = summarize(out, rows)
    for version in args.versions:
        mine = [r for r in rows if r['vlt'] == version]
        print(f'vlt {version}: {sum(bool(r.get("matchesExpectation")) for r in mine)}/{len(mine)} '
              f'as expected, {sum(r.get("verdict") == BLOCKED for r in mine)} {BLOCKED}',
              flush=True)
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
