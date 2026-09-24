#!/usr/bin/env python3
"""Native Bun / public Socket patch compatibility, with no service doubles.

Every (bun release, project shape, mode) cell builds an isolated project with a
REAL Bun binary, runs the production CLI against the public free minimist@1.2.2
patch, and checks the outcome against `expected_outcome` — an oracle of the
DOCUMENTED boundaries, never the CLI's own refusal codes — so a CLI regression
that refuses a supported configuration (or "supports" a refused one) fails the
cell instead of being recorded as an unsupported PASS.

Shapes (project layouts; `--shapes`):
  direct / dev / optional / peer   the dependency section minimist lives in
  alias                            {"alias": "npm:minimist@1.2.2"}
  transitive                       mkdirp@0.5.3 + overrides.minimist=1.2.2
  two-versions / production        a second minimist (npm:minimist@1.2.8) as a
                                   dep / devDep (production installs --production)
  workspace / workspace-nested     a member declares minimist (nested: the root
                                   pins 1.2.8 beside it)
  workspace-root                   the root declares minimist, the member left-pad
  text-workspace                   the workspace project with a REAL version-0
                                   text lock (--save-text-lockfile, 1.1.39-1.1.45)
  workspace-get-uuid / -search     `get <uuid>` / `get <purl>` on the workspace
  crlf / crlf-lock                 CRLF package.json / a CRLF-converted bun.lock
  space-unicode                    project path with a space and a non-ASCII char
  custom-registry                  bun's full-URL registry slot injected into the
                                   registry tuple (a non-default registry)
  text                             text-lock opt-in on 1.1.39-1.1.45
  legacy-lockb                     bun.lockb written by Bun 1.1.38, patched natively
                                   and installed by the matrix release
  isolated / hoisted               bunfig [install] linker (>= 1.3.0)
  lockfile-only                    node_modules removed before the CLI runs
  get-uuid / get-search            `get <uuid>` / `get <purl>` instead of `scan`
  hosted-then-vendored             hosted redirect, then the vendored takeover
  vendored-then-hosted             vendored, then the hosted takeover
  already-vendored-workspace       wire a plain project (the cell's mode), add a
                                   workspace member, `bun install`, re-run the same
                                   mode (a clean no-op: already_vendored / redirected
                                   1), then `repair` rebuilds a deleted artifact
  preexisting-manifest             a foreign .socket/manifest.json record must
                                   survive a refused vendored run

Boundaries the oracle encodes (measured against real releases):
  <= 1.1.38                 binary bun.lockb only; 1.1.39-1.1.45 write it by default
  1.1.39                    first text lock (lockfileVersion 0, --save-text-lockfile)
  1.2.0                     text default, lockfileVersion 1;  1.4.0: lockfileVersion 2
  version-0 workspace lock  hosted refuses (redirect_bun_workspace_unsupported)
  pre-v2 workspace lock     vendored refuses (vendor_bun_workspace_unsupported)
  bun.lockb                native binary inventory and package-record rewrites
  1.3.10                    URL/local tarball sha512 enforced (registry tuples are
                            enforced on every text-lock release)
  0.8.1 / 1.0.0             peers not installed, overrides ignored (upstream)

Every cell records the CLI exit codes (main, repeat, rollback, conversion),
the exact refusal-code set, the repeat-run envelope semantics, digest
enforcement, and after rollback the lockfile presence rules and byte identity.

Provenance: `--cli-revision` is the branch-resolvable commit the row is about
(PR head, or the pushed commit); `--cli-build-sha` (or the CLI_BUILD_SHA
environment variable) is the commit the binary was actually built from —
`refs/pull/N/merge` on a pull request — recorded as `cliBuildSha` (null when
neither is given). A `--versions/--shapes/--modes` narrowing that leaves no
applicable cell is reported, writes a single `{"noCells": true}` summary row
and exits 0 — the default shape list always holds `direct`, which applies to
every release and mode, so an un-narrowed run can never go vacuous.
"""

import argparse
import base64
import concurrent.futures
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.request
import zipfile

VERSIONS = ['0.8.1', '1.0.0', '1.0.36', '1.1.0', '1.1.38', '1.1.39', '1.1.43', '1.1.45',
            '1.2.0', '1.2.23', '1.3.0', '1.3.9', '1.3.10', '1.3.14', '1.4.0', '1.4.2']
SHAPES = ['direct', 'dev', 'optional', 'alias', 'transitive', 'two-versions',
          'workspace', 'workspace-nested', 'workspace-root', 'text-workspace',
          'workspace-get-uuid', 'workspace-get-search', 'peer', 'crlf', 'crlf-lock',
          'space-unicode', 'custom-registry', 'text', 'legacy-lockb', 'isolated', 'hoisted',
          'lockfile-only', 'production', 'get-uuid', 'get-search',
          'hosted-then-vendored', 'vendored-then-hosted', 'already-vendored-workspace',
          'preexisting-manifest']
# Vendored mode is manifest-free (the vendor ledger embeds the record), so the
# former `vendored-detached` leg collapsed into `vendored`: same footprint.
MODES = ['hosted', 'vendored']
PURL = 'pkg:npm/minimist@1.2.2'
UUID = '80630680-4da6-45f9-bba8-b888e0ffd58c'
# The registry slot bun writes for a non-default registry: the full tarball URL.
REGISTRY_SLOT = 'https://registry.npmjs.org/minimist/-/minimist-1.2.2.tgz'
LOCAL_TUPLE_SPEC = f'minimist@.socket/vendor/npm/{UUID}/minimist-1.2.2.tgz'
HOSTED_TUPLE_PREFIX = 'minimist@https://patch.socket.dev/'
# A record for ANOTHER purl seeded into .socket/manifest.json by the
# `preexisting-manifest` shape; a refused vendored run must leave it intact.
OTHER_PURL = 'pkg:npm/left-pad@1.3.0'

# Release boundaries, measured against real binaries (docs/testing/bun-compatibility.md).
LEGACY_BUN = '1.1.38'                         # last binary-only release; legacy-lockb baseline
TEXT_LOCK_FROM = (1, 1, 39)                   # --save-text-lockfile (lockfileVersion 0)
TEXT_DEFAULT_FROM = (1, 2, 0)                 # bun.lock by default (lockfileVersion 1)
LOCK_V2_FROM = (1, 4, 0)                      # fresh locks are lockfileVersion 2
LINKER_FROM = (1, 3, 0)                       # bunfig [install] linker
TARBALL_INTEGRITY_ENFORCED_FROM = (1, 3, 10)  # URL/local tarball sha512 verified
NO_PEER_OR_OVERRIDE = ('0.8.1', '1.0.0')      # peers not installed, overrides ignored

# Advisory codes a SUPPORTED run may carry; everything else is a refusal.
INFORMATIONAL = {
    'vendor_prebuilt_downloaded', 'vendor_prebuilt_unavailable', 'vendor_prebuilt_pending',
    'vendor_fetched_missing', 'reinstall_required',
    'vendor_takeover_reverted_redirect', 'redirect_takeover_reverted_vendored',
}
# Codes that mean the rewriter or the takeover broke on a supported configuration.
REGRESSION_CODES = {
    'redirect_bun_entry_not_found', 'redirect_revert_failed',
}

WORKSPACE_SHAPES = {'workspace', 'workspace-nested', 'workspace-root', 'text-workspace',
                    'workspace-get-uuid', 'workspace-get-search', 'preexisting-manifest'}
GET_SHAPES = {'get-uuid', 'get-search', 'workspace-get-uuid', 'workspace-get-search'}
TEXT_OPT_IN_SHAPES = {'text', 'text-workspace'}
CONVERSION_SHAPES = {'hosted-then-vendored', 'vendored-then-hosted', 'already-vendored-workspace'}


def ver(version):
    return tuple(map(int, version.split('.')))


def save(path, data):
    path.write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')


def has_transport_failure(value):
    """Only explicit request transport errors qualify for a fresh-cell retry."""
    if isinstance(value, dict):
        return any(has_transport_failure(item) for item in value.values())
    if isinstance(value, list):
        return any(has_transport_failure(item) for item in value)
    return isinstance(value, str) and 'error sending request for url (' in value


def retry_network_cell(run_case, job, root, attempts=3):
    """Keep failed evidence and retry transient service failures from a clean tree."""
    name = '-'.join(job)
    case = root / 'captures' / name
    history = []
    for attempt in range(1, attempts + 1):
        row = run_case(job)
        if row['passed'] or not has_transport_failure(row) or attempt == attempts:
            if history:
                row['networkRetryAttempts'] = history
                save(case / 'result.json', row)
            return row
        evidence = root / 'attempts' / name / str(attempt)
        evidence.mkdir(parents=True, exist_ok=True)
        for source in case.iterdir():
            if source.is_file() and source.suffix in ('.log', '.json'):
                shutil.copy2(source, evidence / source.name)
            elif source.name == 'tree':
                shutil.copytree(source, evidence / source.name, dirs_exist_ok=True)
        history.append(dict(attempt=attempt, evidence=evidence.relative_to(root).as_posix(),
                            failedChecks=[key for key, passed in row.get('checks', {}).items() if not passed]))
        # Remove the failed project's package-manager caches too. A retry is
        # another cold proof, never a continuation from partially written state.
        shutil.rmtree(case)
        print(f'{name}: request transport failed; retrying fresh cell ({attempt}/{attempts})', flush=True)
        time.sleep(5 * attempt)


def run(command, cwd, env, log, required=True, timeout=180, tolerate_timeout=False):
    """(exit code, combined output). A hang is an error — except for the
    digest-tamper installs (`tolerate_timeout`), where Bun 1.3.9 and 1.3.10
    print the integrity error and then never exit on a workspace project:
    those return (None, output-so-far) so the caller can still judge the
    rejection (the error was reported and nothing was installed)."""
    try:
        result = subprocess.run([str(x) for x in command], cwd=cwd, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=timeout)
    except subprocess.TimeoutExpired as error:
        log.write_bytes(error.stdout or b'')
        if tolerate_timeout:
            return None, (error.stdout or b'').decode(errors='replace')
        raise
    log.write_bytes(result.stdout)
    if required and result.returncode:
        raise RuntimeError(f'{command}: {result.stdout.decode(errors="replace")[-4000:]}')
    return result.returncode, result.stdout.decode(errors='replace')


def git_hash(data):
    return hashlib.sha256(f'blob {len(data)}\0'.encode() + data).hexdigest()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


class DownloadError(RuntimeError):
    """A release asset arrived but failed verification (truncated / tampered)."""


RETRYABLE = (urllib.error.URLError, TimeoutError, ConnectionError, http.client.HTTPException)


def fetch(url, dest, attempts=5):
    """Download `url` to `dest` with backoff. 5xx / 429 / connection errors /
    stalls retry; any other HTTP error is final."""
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(url, timeout=60) as response, open(dest, 'wb') as out:
                shutil.copyfileobj(response, out)
            return
        except RETRYABLE as error:
            final = isinstance(error, urllib.error.HTTPError) and error.code < 500 and error.code != 429
            if final or attempt == attempts:
                raise
            print(f'download {url} attempt {attempt} failed: {error}; retrying', flush=True)
            time.sleep(10 * attempt)


def listed_sha256(sums, name):
    """The SHA-256 SHASUMS256.txt lists for `name`; fail closed when absent."""
    for line in sums.read_text(encoding='utf-8').splitlines():
        parts = line.strip().split()
        if len(parts) == 2 and parts[1] == name:
            return parts[0]
    raise RuntimeError(f'{name} is not listed in {sums}')


def bun_asset():
    system = platform.system().lower()
    arch = 'aarch64' if platform.machine().lower() in ('arm64', 'aarch64') else 'x64'
    if system == 'windows':
        arch = 'x64'
    return system, f'bun-{system}-{arch}'


def install_tool(root, version):
    """Return the Bun binary for `version` under `root/<version>/<asset>/`,
    downloading the release zip (retried, verified against the release's own
    SHASUMS256.txt, fail closed) when it is not already there — the CI
    pre-download step leaves the same layout plus SHASUMS256.txt behind."""
    system, asset = bun_asset()
    directory = root / version
    binary = directory / asset / ('bun.exe' if system == 'windows' else 'bun')
    if not binary.exists():
        directory.mkdir(parents=True, exist_ok=True)
        base = f'https://github.com/oven-sh/bun/releases/download/bun-v{version}'
        archive = directory / f'{asset}.zip'
        sums = directory / 'SHASUMS256.txt'
        for attempt in range(1, 6):
            try:
                # Bun 0.1.x predates published checksum manifests. Those
                # immutable release assets have reviewed SHA-256 pins in this
                # repository; all later releases use upstream SHASUMS256.txt.
                historical = json.loads(Path(__file__).with_name('bun-historical-shas.json').read_text())
                pins = {key.split('/', 1)[1]: digest for key, digest in historical.items()
                        if key.startswith(version + '/')}
                if pins:
                    sums.write_text(''.join(f'{digest}  {name}\n' for name, digest in pins.items()))
                else:
                    fetch(f'{base}/SHASUMS256.txt', sums)
                fetch(f'{base}/{asset}.zip', archive)
                expected = listed_sha256(sums, f'{asset}.zip')
                actual = sha256(archive.read_bytes())
                if actual != expected:
                    raise DownloadError(f'{asset}.zip sha256 {actual} != SHASUMS256.txt {expected}')
                with zipfile.ZipFile(archive) as zipped:
                    zipped.extractall(directory)
                break
            except (zipfile.BadZipFile, DownloadError, *RETRYABLE) as error:
                final = isinstance(error, urllib.error.HTTPError) and error.code < 500 and error.code != 429
                if final or attempt == 5:
                    raise
                print(f'bun {version} attempt {attempt} failed: {error}; retrying', flush=True)
                time.sleep(10 * attempt)
            finally:
                archive.unlink(missing_ok=True)
        binary.chmod(0o755)
    actual = subprocess.check_output([binary, '--version'], text=True).strip()
    if actual != version:
        raise RuntimeError(f'Expected Bun {version}, got {actual}')
    return binary


def archive_sha256(root, version):
    """The verified release-zip SHA-256 when SHASUMS256.txt sits beside the
    tool (written by install_tool or the CI pre-download step)."""
    sums = root / version / 'SHASUMS256.txt'
    try:
        return listed_sha256(sums, f'{bun_asset()[1]}.zip') if sums.exists() else None
    except RuntimeError:
        return None


def base_shape(shape):
    """The project layout a shape starts from."""
    if shape in ('text-workspace', 'workspace-get-uuid', 'workspace-get-search',
                 'preexisting-manifest'):
        return 'workspace'
    if shape in ('crlf-lock', 'legacy-lockb', 'custom-registry', *CONVERSION_SHAPES):
        return 'direct'
    return shape


def project_files(shape):
    layout = base_shape(shape)
    manifest = dict(name='bun-patch-backtest', version='1.0.0', private=True,
                    dependencies={'minimist': '1.2.2'})
    files = {}
    if layout in ('dev', 'optional', 'peer'):
        key = {'dev': 'devDependencies', 'optional': 'optionalDependencies',
               'peer': 'peerDependencies'}[layout]
        manifest[key] = manifest.pop('dependencies')
    elif layout == 'alias':
        manifest['dependencies'] = {'alias': 'npm:minimist@1.2.2'}
    elif layout == 'transitive':
        manifest['dependencies'] = {'mkdirp': '0.5.3'}
        manifest['overrides'] = {'minimist': '1.2.2'}
    elif layout == 'two-versions':
        manifest['dependencies']['other'] = 'npm:minimist@1.2.8'
    elif layout == 'production':
        manifest['devDependencies'] = {'other': 'npm:minimist@1.2.8'}
    elif layout.startswith('workspace'):
        manifest['workspaces'] = ['packages/*']
        manifest['dependencies'] = {'consumer': 'workspace:*'}
        member = {'minimist': '1.2.2'}
        if layout == 'workspace-nested':
            manifest['dependencies']['minimist'] = '1.2.8'
        elif layout == 'workspace-root':
            # The root declares the patched package; the member something else.
            manifest['dependencies']['minimist'] = '1.2.2'
            member = {'left-pad': '1.3.0'}
        files['packages/consumer/package.json'] = json.dumps(dict(
            name='consumer', version='1.0.0', dependencies=member)) + '\n'
    elif layout in ('isolated', 'hoisted'):
        files['bunfig.toml'] = f'[install]\nlinker = "{layout}"\n'
    files['package.json'] = json.dumps(manifest, indent=2) + '\n'
    return {name: (data.replace('\n', '\r\n') if shape == 'crlf' else data).encode()
            for name, data in files.items()}


def add_workspace_member(project):
    """Turn a plain project into a workspace with one member (left-pad) in
    place; returns the files it wrote/rewrote."""
    manifest = json.loads((project / 'package.json').read_text(encoding='utf-8'))
    manifest['workspaces'] = ['packages/*']
    manifest['dependencies']['consumer'] = 'workspace:*'
    files = {'package.json': (json.dumps(manifest, indent=2) + '\n').encode(),
             'packages/consumer/package.json': (json.dumps(dict(
                 name='consumer', version='1.0.0',
                 dependencies={'left-pad': '1.3.0'})) + '\n').encode()}
    for name, data in files.items():
        (project / name).parent.mkdir(parents=True, exist_ok=True)
        (project / name).write_bytes(data)
    return files


def seed_manifest(project):
    """Write a .socket/manifest.json holding one record for a purl the project
    does not install (the schema the CLI writes: uuid, exportedAt, files,
    vulnerabilities, description, license, tier) plus its after-blob under
    .socket/blobs/<afterHash>, so the record is locally satisfied exactly like
    a committed one — without the blob the vendor step aborts the whole run
    with `no_local_source` before it ever reaches the bun refusal."""
    after = b'// seeded by backtest-bun.py\n'
    manifest = {'patches': {OTHER_PURL: {
        'uuid': '00000000-0000-4000-8000-000000000000',
        'exportedAt': 'Mon, 05 Jan 2026 17:03:26 GMT',
        'files': {'package/index.js': {'beforeHash': git_hash(b'// pristine\n'),
                                       'afterHash': git_hash(after)}},
        'vulnerabilities': {}, 'description': 'seeded by backtest-bun.py',
        'license': 'MIT', 'tier': 'free'}}}
    (project / '.socket/blobs').mkdir(parents=True)
    (project / '.socket/blobs' / git_hash(after)).write_bytes(after)
    save(project / '.socket/manifest.json', manifest)
    return manifest


def get_verb(shape):
    if shape in ('get-uuid', 'workspace-get-uuid'):
        return ['get', UUID]
    if shape in ('get-search', 'workspace-get-search'):
        return ['get', PURL]
    return ['scan']


def cell_applies(version, shape, mode):
    """Which (version, shape, mode) cells exist: shapes need the Bun feature
    they exercise, and the two-mode shapes run only where both modes are
    supported (their `mode` is the vendored flavor)."""
    v = ver(version)
    if shape in ('isolated', 'hoisted') and v < LINKER_FROM:
        return False
    if shape in TEXT_OPT_IN_SHAPES and v < TEXT_LOCK_FROM:
        return False
    if shape == 'text-workspace' and v >= TEXT_DEFAULT_FROM:
        return False  # the text lock is the default there: identical to `workspace`
    if shape == 'legacy-lockb' and v < TEXT_LOCK_FROM:
        return False  # the matrix release would be the legacy writer itself
    if shape in ('crlf-lock', 'custom-registry') and v < TEXT_DEFAULT_FROM:
        return False  # both need a default text bun.lock to edit
    if shape == 'already-vendored-workspace' and v < TEXT_DEFAULT_FROM:
        return False  # this shape explicitly inspects text re-save syntax
    if shape in ('hosted-then-vendored', 'vendored-then-hosted') and mode == 'hosted':
        return False  # their `mode` is the vendored flavor of the conversion
    if shape == 'preexisting-manifest' and (mode == 'hosted' or v < TEXT_DEFAULT_FROM or v >= LOCK_V2_FROM):
        return False  # always a refused pre-v2 text-workspace vendored run
    return True


def expected_outcome(version, shape, mode):
    """The DOCUMENTED outcome of one cell — never derived from the CLI's output.

    supported: whether the patch must land;  codes: the EXACT refusal-code set
    (after removing INFORMATIONAL);  exit: 'zero' (supported, hosted refusals,
    upstream limitations) or 'nonzero' (vendored / get refusals);
    limitation: the row annotation for an unsupported cell;  rerun: the main
    command is a documented no-op re-run (already_vendored) rather than a
    first application."""
    v = ver(version)
    hosted = mode == 'hosted'
    scan = shape not in GET_SHAPES
    workspace = shape in WORKSPACE_SHAPES
    text_lock = (v >= TEXT_DEFAULT_FROM or (shape in TEXT_OPT_IN_SHAPES and v >= TEXT_LOCK_FROM)) \
        and shape != 'legacy-lockb'
    # lockfileVersion of a freshly written text lock.
    lock_version = 2 if v >= LOCK_V2_FROM else 1 if v >= TEXT_DEFAULT_FROM else 0

    def outcome(supported, codes=(), exit='zero', limitation=None, rerun=False):
        return dict(supported=supported, codes=set(codes), exit=exit,
                    limitation=limitation, rerun=rerun)

    if version in NO_PEER_OR_OVERRIDE and shape in ('peer', 'transitive'):
        return outcome(False, limitation='This Bun release does not install the requested '
                                         'peer or honor the transitive override')
    if shape == 'already-vendored-workspace':
        return outcome(True, rerun=True)
    if not text_lock:
        return outcome(True)
    if workspace:
        if hosted and lock_version == 0:
            return outcome(False, {'redirect_bun_workspace_unsupported'},
                           limitation='Version-0 workspace locks cannot carry hosted tarballs')
        if not hosted and lock_version < 2:
            return outcome(False, {'vendor_bun_workspace_unsupported'}, 'nonzero',
                           limitation='Pre-v2 workspace locks may be installed by Bun < 1.4, '
                                      'which resolves local tarballs relative to the member')
    return outcome(True)


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


def parse_envelope(output):
    return json.loads(output[output.index('{'):])


def envelope_codes(envelope):
    """(codes about the minimist patch or carrying no purl, codes about other
    purls) — every channel the CLI reports on: redirect.warnings, top-level
    warnings, vendor.events, download.patches, patches, error."""
    mine, others = [], []

    def take(purl, code):
        if code:
            (mine if purl in (None, PURL) else others).append(code)
    for w in envelope.get('redirect', {}).get('warnings', []):
        take(None, w.get('code'))
    for w in envelope.get('warnings', []):
        take(None, w.get('code') if isinstance(w, dict) else w)
    for e in envelope.get('vendor', {}).get('events', []):
        take(e.get('purl'), e.get('errorCode'))
    for p in envelope.get('download', {}).get('patches', []):
        take(p.get('purl'), p.get('errorCode'))
    for p in envelope.get('patches', []):
        take(p.get('purl'), p.get('errorCode'))
    if isinstance(envelope.get('error'), dict):
        take(None, envelope['error'].get('code'))
    return mine, others


def applied_count(envelope, mode):
    if mode == 'hosted':
        return envelope.get('redirect', {}).get('redirected', 0)
    return envelope.get('vendor', {}).get('summary', {}).get('applied', 0)


def downloaded_count(envelope):
    return envelope.get('download', {}).get('downloaded', envelope.get('downloaded', 0))


def rerun_clean(code, envelope, mode):
    """The documented no-op re-run: hosted re-confirms the wiring (redirected 1,
    nothing rewritten, no warnings beyond advisories); vendored skips exactly
    one already_vendored purl with nothing failed."""
    if code != 0 or envelope.get('status') != 'success':
        return False
    codes, _ = envelope_codes(envelope)
    if mode == 'hosted':
        return (envelope.get('redirect', {}).get('redirected') == 1
                and not set(codes) - INFORMATIONAL)
    vendor = envelope.get('vendor', {})
    summary, events = vendor.get('summary', {}), vendor.get('events', [])
    return (summary.get('applied') == 0 and summary.get('skipped') == 1
            and summary.get('failed') == 0
            and sum(e.get('errorCode') == 'already_vendored' for e in events) == 1
            and not any(e.get('action') == 'failed' for e in events)
            and not set(codes) - INFORMATIONAL - {'already_vendored'})


def ledger_record(project, mode):
    """The patch record the mode's ledger holds for PURL (None when absent).

    Both ledgers embed the record — hosted under `records`, vendored under the
    entry's `record`; vendored mode never writes `.socket/manifest.json`."""
    path = project / ('.socket/vendor/redirect-state.json' if mode == 'hosted'
                      else '.socket/vendor/state.json')
    if not path.is_file():
        return None
    state = json.loads(path.read_text(encoding='utf-8'))
    if mode == 'hosted':
        return state.get('records', {}).get(PURL)
    return state.get('entries', {}).get(PURL, {}).get('record')


def load_json(path):
    return json.loads(path.read_text(encoding='utf-8')) if path.is_file() else None


def wired_fragments(project, mode):
    """The {original, new} bun.lock line pair the mode's ledger recorded for
    PURL: the hosted ledger's `redirect_bun_lock_package` edit, or the
    vendored ledger's `bun_lock_package` wiring."""
    if mode == 'hosted':
        edits = load_json(project / '.socket/vendor/redirect-state.json')['edits']
        return next(e for e in edits if e['path'] in ('bun.lock', 'bun.lockb') and
                    e['kind'] in ('redirect_bun_lock_package', 'redirect_bun_lockb_package'))
    wiring = load_json(project / '.socket/vendor/state.json')['entries'][PURL]['wiring']
    return next(w for w in wiring if w['file'] in ('bun.lock', 'bun.lockb'))


def wired_line(text, recorded_new):
    """The live bun.lock line carrying the recorded wiring `recorded_new`:
    byte-identical, or the digest-less 2-tuple Bun < 1.3.10 re-saves it as
    (same `"key": ["spec", {meta}` head, no trailing `"sha512-…"`). None when
    neither spelling is present."""
    if recorded_new in text:
        return recorded_new
    head = recorded_new[:recorded_new.rfind(', "sha512-')]
    for line in text.splitlines():
        if line.startswith(head) and line[len(head):] in (']', '],'):
            return line
    return None


def crlf_only(data):
    return all(line.endswith(b'\r\n') for line in data.splitlines(keepends=True) if line.strip())


def tamper_digests(lock, marker):
    """Replace the sha512 on every tuple line carrying `marker`."""
    return b''.join(
        re.sub(rb'sha512-[A-Za-z0-9+/=]+(?="\])', b'sha512-' + b'A' * 86 + b'==', line)
        if marker in line else line for line in lock.splitlines(keepends=True))


def remove_node_modules(project):
    for modules in sorted(project.rglob('node_modules'), key=lambda p: len(p.parts)):
        if modules.exists() and not modules.is_symlink():
            shutil.rmtree(modules)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--cli', type=Path, required=True)
    parser.add_argument('--cli-revision', required=True,
                        help='the branch-resolvable commit the rows are about (cliRevision)')
    parser.add_argument('--cli-build-sha', default=os.environ.get('CLI_BUILD_SHA') or None,
                        help='the commit the CLI binary was built from (cliBuildSha; on a pull '
                             'request the refs/pull/N/merge commit, which diverges from the head '
                             'once main advances) — defaults to $CLI_BUILD_SHA, else null')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--tools', type=Path)
    parser.add_argument('--versions', nargs='+', default=VERSIONS)
    parser.add_argument('--shapes', nargs='+', default=SHAPES, choices=SHAPES)
    parser.add_argument('--modes', nargs='+', default=MODES, choices=MODES)
    parser.add_argument('--jobs', type=int, default=4)
    args = parser.parse_args()
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=True)
    cli = root / ('socket-patch.exe' if platform.system() == 'Windows' else 'socket-patch')
    shutil.copy2(args.cli.resolve(), cli)
    toolroot = (args.tools or root / 'tools').resolve()
    provenance = dict(capturedAt=datetime.now(timezone.utc).isoformat(),
                      os=platform.system().lower(), platform=platform.platform(),
                      cliRevision=args.cli_revision, cliBuildSha=args.cli_build_sha,
                      cliSha256=sha256(cli.read_bytes()))
    jobs = [(v, s, m) for v in args.versions for s in args.shapes for m in args.modes
            if cell_applies(v, s, m)]
    if not jobs:
        # Only an explicit --versions/--shapes/--modes narrowing gets here: the
        # default shape list holds `direct`, which applies to every release and
        # mode. Not a failure — but the summary must say that nothing ran, so a
        # consumer can never mistake it for a green matrix.
        reason = ('no (version, shape, mode) cell applies to the requested narrowing: '
                  f'versions={" ".join(args.versions)} shapes={" ".join(args.shapes)} '
                  f'modes={" ".join(args.modes)}')
        save(root / 'summary.json', [dict(noCells=True, bun=' '.join(args.versions), shape='*',
                                          mode='*', passed=False, error=reason, **provenance)])
        print(f'::notice::{reason}', flush=True)
        return 0
    # The legacy-lockb shape baselines every project with the last binary-only
    # release, whatever the matrix version — needed only where such a cell
    # applies (the shape is gated to distinct, newer binary readers).
    legacy_needed = any(shape == 'legacy-lockb' for _, shape, _ in jobs)
    needed = list(dict.fromkeys([*args.versions, *([LEGACY_BUN] if legacy_needed else [])]))
    try:
        tools = {v: install_tool(toolroot, v) for v in needed}
    except Exception as error:  # noqa: BLE001 — the artifact must explain the run
        rows = [dict(bun=v, shape='*', mode='*', passed=False,
                     error=f'tool install failed: {error}', **provenance) for v in args.versions]
        save(root / 'summary.json', rows)
        print('tool install failed:', error, flush=True)
        return 1
    tool_sha = {v: dict(bunSha256=sha256(path.read_bytes()),
                        bunArchiveSha256=archive_sha256(toolroot, v)) for v, path in tools.items()}
    base_env = {k: v for k, v in os.environ.items()
                if not k.startswith(('SOCKET_', 'BUN_', 'npm_config_', 'NPM_CONFIG_'))}
    base_env.update(SOCKET_NO_CONFIG='1', SOCKET_NO_UPDATE_CHECK='1', NO_COLOR='1')

    def backtest(job):
        version, shape, mode = job
        expected = expected_outcome(version, shape, mode)
        case = root / 'captures' / f'{version}-{shape}-{mode}'
        case.mkdir(parents=True, exist_ok=True)
        project = case / ('project space café' if shape == 'space-unicode' else 'project')
        if project.exists():
            shutil.rmtree(project)
        project.mkdir()
        row = dict(bun=version, shape=shape, mode=mode, passed=False, **provenance,
                   **tool_sha[version], supported=expected['supported'],
                   expected=dict(supported=expected['supported'],
                                 refusals=sorted(expected['codes']), exit=expected['exit']))
        checks, exit_codes = {}, {}
        row['checks'] = checks
        row['exitCodes'] = exit_codes
        # The two-mode shapes: `pre_mode` is the mode applied first, `main_mode`
        # the mode of the command the row is about (its ledger, its envelope).
        main_mode = 'hosted' if shape == 'vendored-then-hosted' else mode
        pre_mode = 'hosted' if shape == 'hosted-then-vendored' else mode
        try:
            bun = tools[version]

            def env_for(binary, cache):
                temporary = case / 'tool-tmp'
                temporary.mkdir(exist_ok=True)
                return dict(base_env, PATH=str(binary.parent) + os.pathsep + base_env['PATH'],
                            BUN_INSTALL_CACHE_DIR=str(case / cache),
                            BUN_INSTALL=str(case / 'bun-home'),
                            TMPDIR=str(temporary), TMP=str(temporary), TEMP=str(temporary),
                            BUN_TMPDIR=str(temporary))
            env = env_for(bun, 'cache')

            def cli_command(verb, run_mode):
                return [cli, *verb, '--mode', run_mode,
                        '--cwd', project, '--json', '--yes', '--no-telemetry']

            def install(binary, label, flags=(), cache=None):
                remove_node_modules(project)
                return run([binary, 'install', '--ignore-scripts', *flags], project,
                           env_for(binary, cache or 'cache-' + label), case / (label + '.log'), False)

            files = project_files(shape)
            for name, data in files.items():
                (project / name).parent.mkdir(parents=True, exist_ok=True)
                (project / name).write_bytes(data)
            baseline_bun = tools[LEGACY_BUN] if shape == 'legacy-lockb' else bun
            install_args = ['install', '--ignore-scripts']
            if shape in TEXT_OPT_IN_SHAPES:
                install_args += ['--save-text-lockfile']
            # The legacy writer never shares a cache with the matrix release.
            run([baseline_bun, *install_args], project,
                env_for(baseline_bun, 'cache-legacy' if shape == 'legacy-lockb' else 'cache'),
                case / 'baseline.log')
            lock = project / ('bun.lock' if (project / 'bun.lock').exists() else 'bun.lockb')
            if shape == 'crlf-lock':
                lock.write_bytes(lock.read_bytes().replace(b'\r\n', b'\n').replace(b'\n', b'\r\n'))
                code, _ = install(bun, 'crlf-accepted', ['--frozen-lockfile'])
                checks['crlfLockAccepted'] = code == 0 and crlf_only(lock.read_bytes())
            if shape == 'custom-registry':
                # bun writes "" for its default registry, so `.npmrc` alone never
                # fills the slot: inject the full-URL form bun emits for any other
                # registry and prove bun installs from it before the CLI runs.
                text = lock.read_text(encoding='utf-8')
                injected = text.replace('["minimist@1.2.2", ""', f'["minimist@1.2.2", "{REGISTRY_SLOT}"')
                checks['registrySlotInjected'] = injected != text
                lock.write_text(injected, encoding='utf-8')
                code, _ = install(bun, 'registry-accepted', ['--frozen-lockfile'])
                checks['registrySlotAccepted'] = code == 0 and lock.read_text(encoding='utf-8') == injected
            original = {name: (project / name).read_bytes()
                        for name in [*files, 'bun.lock', 'bun.lockb'] if (project / name).exists()}
            row['originalSha256'] = {n: sha256(b) for n, b in original.items()}
            original_binary_dump = None
            binary_schema_upgraded = False
            if lock.name == 'bun.lockb' and lock.is_file():
                _, original_binary_dump = run([bun, lock.name], project, env,
                                              case / 'original-binary-dump.log')
            if shape in TEXT_OPT_IN_SHAPES:
                checks['textLockWritten'] = 'bun.lock' in original and 'bun.lockb' not in original
            if shape == 'legacy-lockb':
                checks['legacyLockbBaseline'] = 'bun.lockb' in original and 'bun.lock' not in original
            installed = bool(installed_targets(project))
            if version in NO_PEER_OR_OVERRIDE and shape in ('peer', 'transitive'):
                checks['upstreamNotInstalled'] = not installed
            else:
                checks['installedBefore'] = installed
            if 'bun.lock' in original:
                # Registry 4-tuples are digest-verified on every text-lock
                # release: the baseline every rewrite is compared against.
                scratch = case / 'registry-tamper'
                if scratch.exists():
                    shutil.rmtree(scratch)
                shutil.copytree(project, scratch, ignore=shutil.ignore_patterns('node_modules', '.socket'))
                tampered = tamper_digests(original['bun.lock'], b'minimist@1.2.2"')
                (scratch / 'bun.lock').write_bytes(tampered)
                code, output = run([bun, 'install', '--ignore-scripts', '--frozen-lockfile'], scratch,
                                   env_for(bun, 'cache-registry-tamper'), case / 'registry-tamper.log',
                                   False, timeout=60, tolerate_timeout=True)
                checks['registryDigestEnforced'] = (
                    tampered != original['bun.lock'] and code != 0
                    and ('integrity' in output.lower() or 'checksum' in output.lower()))
                if code is None:
                    row.setdefault('notes', []).append(
                        'bun printed the registry integrity error but never exited (killed after 60 s)')
                shutil.rmtree(scratch, ignore_errors=True)
            if shape == 'lockfile-only':
                shutil.rmtree(project / 'node_modules')
            seeded = seed_manifest(project) if shape == 'preexisting-manifest' else None

            if shape in CONVERSION_SHAPES:
                # First mode (or the first vendoring): must land and install.
                code, output = run(cli_command(['scan'], pre_mode), project, env, case / 'conversion.log', False)
                exit_codes['conversion'] = code
                pre_envelope = parse_envelope(output)
                save(case / 'conversion-output.json', pre_envelope)
                pre_record = ledger_record(project, pre_mode)
                checks['conversionApplied'] = (code == 0 and applied_count(pre_envelope, pre_mode) == 1
                                               and pre_record is not None)
                if not checks['conversionApplied']:
                    raise RuntimeError(f'Expected the first mode to apply: {output[-4000:]}')
                code, _ = install(bun, 'conversion-frozen', ['--frozen-lockfile'])
                checks['conversionPatchedBytes'] = code == 0 and oracle(project, pre_record, 'after')[0]
                if shape == 'already-vendored-workspace':
                    # Grow the wired project into a workspace with the SAME bun
                    # (bun re-saves the lock: its version is kept, and the
                    # wired tuple must survive verbatim), so the re-run meets
                    # an already-wired purl inside a workspace lock.
                    files = {**files, **add_workspace_member(project)}
                    code, _ = install(bun, 'member', cache='cache')
                    text = lock.read_text(encoding='utf-8')
                    checks['memberInstall'] = code == 0 and 'workspace:packages/consumer' in text
                    wiring = wired_fragments(project, pre_mode)
                    # Bun < 1.3.10 re-saves URL/local tarball tuples WITHOUT
                    # their sha512 (the 2-tuple `["name@<spec>", {meta}]`);
                    # 1.3.10+ keep the 3-tuple. Either spelling is the CLI's
                    # own wiring (the spec bun installs from is intact): the
                    # re-run heals the digest and rollback unwinds both.
                    live_wired = wired_line(text, wiring['new'])
                    checks['wiringSurvivesInstall'] = live_wired is not None
                    row['digestDroppedOnResave'] = live_wired != wiring['new']
                    if ver(version) >= TARBALL_INTEGRITY_ENFORCED_FROM:
                        checks['resaveKeepsDigest'] = live_wired == wiring['new']
                    # Rollback restores the wired line only: the pristine lock
                    # is the grown lock with the registry line put back.
                    original = {name: (project / name).read_bytes() for name in files}
                    original['bun.lock'] = lock.read_bytes().replace(
                        (live_wired or wiring['new']).encode(), wiring['original'].encode())

            command = cli_command(get_verb(shape), main_mode)
            code, output = run(command, project, env, case / 'cli.log', False)
            exit_codes['main'] = code
            row['exitCode'] = code
            envelope = parse_envelope(output)
            save(case / 'cli-output.json', envelope)
            applied = applied_count(envelope, main_mode)
            codes, other_codes = envelope_codes(envelope)
            # A documented no-op re-run skips its purl as already_vendored;
            # that skip reason is the expected outcome there, not a refusal.
            expected_skips = {'already_vendored'} if expected['rerun'] else set()
            refusals = set(codes) - INFORMATIONAL - expected_skips
            row['codes'] = sorted(set(codes))
            row['otherPurlCodes'] = sorted(set(other_codes))
            row['refusals'] = sorted(refusals)
            row['applied'] = applied
            checks['refusalCodesExact'] = refusals == expected['codes']
            if expected['supported']:
                checks['noRegressionCodes'] = not set(codes) & REGRESSION_CODES
            manifest = project / '.socket/manifest.json'
            if not expected['supported']:
                row['upstreamLimitations'] = [expected['limitation']]
                checks['noPatchApplied'] = applied == 0
                checks['unchanged'] = all((project / n).read_bytes() == b for n, b in original.items())
                checks['unchangedLockPresence'] = all((project / name).exists() == (name in original)
                                                      for name in ['bun.lock', 'bun.lockb'])
                # Hosted refusals exit 0 with redirected 0 (documented posture);
                # vendored / get refusals exit non-zero and never fetch.
                checks['exitCodeContract'] = code == 0 if expected['exit'] == 'zero' else code != 0
                if expected['exit'] == 'nonzero':
                    checks['noDownloadOnRefusal'] = downloaded_count(envelope) == 0
                after = load_json(manifest)
                checks['noStrayManifestRecord'] = after is None or PURL not in after.get('patches', {})
                if seeded is not None:
                    checks['preexistingManifestPreserved'] = (
                        after is not None and after.get('patches', {}).get(OTHER_PURL) == seeded['patches'][OTHER_PURL])
                else:
                    # No mode writes .socket/manifest.json (vendored is manifest-free).
                    checks['noManifest'] = after is None
            else:
                if expected['rerun']:
                    checks['rerunClean'] = rerun_clean(code, envelope, main_mode)
                    if not checks['rerunClean']:
                        raise RuntimeError(f'Expected a clean no-op re-run: {output[-4000:]}')
                else:
                    checks['cliSuccess'] = code == 0 and applied == 1
                    if not checks['cliSuccess']:
                        raise RuntimeError(f'Expected one applied patch: {output[-4000:]}')
                record = ledger_record(project, main_mode)
                if record is None:
                    raise RuntimeError(f'No ledger record for {PURL} in {main_mode} mode')
                row['patchUuid'] = record['uuid']
                checks['publishedPatch'] = record['uuid'] == UUID
                # Neither ledger-backed mode writes .socket/manifest.json: vendored
                # is manifest-free and hosted persists only the redirect ledger.
                checks['noManifest'] = not manifest.exists()
                patched_lock = lock.read_bytes()
                lockb_origin = lock.name == 'bun.lockb'
                lock_text = patched_lock.decode('utf-8', errors='replace')
                if shape == 'hosted-then-vendored':
                    checks['takeoverReported'] = 'vendor_takeover_reverted_redirect' in codes
                    checks['localPathTuple'] = (f'.socket/vendor/npm/{UUID}/minimist-1.2.2.tgz'
                                                if lockb_origin else LOCAL_TUPLE_SPEC) in lock_text
                    redirect_ledger = load_json(project / '.socket/vendor/redirect-state.json')
                    checks['redirectLedgerRecordGone'] = (redirect_ledger is None
                                                          or PURL not in redirect_ledger.get('records', {}))
                    original_wiring = wired_fragments(project, main_mode)['original']
                    if lockb_origin:
                        checks['vendorLedgerOriginalPristine'] = (
                            original_wiring.get('name') == 'minimist' and
                            original_wiring.get('version') == '1.2.2' and
                            UUID not in original_wiring.get('resolution', ''))
                    else:
                        pristine_line = next(line for line in original['bun.lock'].decode('utf-8').split('\n')
                                             if '"minimist@1.2.2"' in line)
                        checks['vendorLedgerOriginalPristine'] = original_wiring == pristine_line
                elif shape == 'vendored-then-hosted':
                    checks['takeoverReported'] = 'redirect_takeover_reverted_vendored' in codes
                    checks['urlTuple'] = ('https://patch.socket.dev/' if lockb_origin
                                          else HOSTED_TUPLE_PREFIX) in lock_text
                    checks['vendorArtifactGone'] = not (project / '.socket/vendor/npm' / UUID).exists()
                    vendor_ledger = load_json(project / '.socket/vendor/state.json')
                    checks['vendorLedgerEntryGone'] = (vendor_ledger is None
                                                       or PURL not in vendor_ledger.get('entries', {}))
                    # The hosted takeover unwinds the vendored wiring, ledger entry
                    # and artifact; neither mode ever wrote a manifest record
                    # (`noManifest` above covers the whole cell).
                if shape == 'custom-registry':
                    checks['registrySlotDropped'] = REGISTRY_SLOT not in lock_text
                if shape == 'crlf-lock':
                    checks['lockEolPreserved'] = crlf_only(patched_lock)
                if lockb_origin:
                    checks['nativeBinaryPreserved'] = (project / 'bun.lockb').is_file() and not (project / 'bun.lock').exists()
                    wiring = wired_fragments(project, main_mode)
                    checks['binaryPackageSnapshot'] = (isinstance(wiring.get('original'), dict) and
                                                       isinstance(wiring.get('new'), dict))
                capture = case / 'tree'
                if capture.exists():
                    shutil.rmtree(capture)
                capture.mkdir()
                for name in [*files, 'bun.lock', 'bun.lockb', '.socket/manifest.json',
                             '.socket/vendor/state.json', '.socket/vendor/redirect-state.json']:
                    source = project / name
                    if source.is_file():
                        destination = capture / name
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copyfile(source, destination)
                row['manifestSha256'] = {p.relative_to(capture).as_posix(): sha256(p.read_bytes())
                                         for p in capture.rglob('*') if p.is_file()}
                patched_binary_dump = None
                if lockb_origin:
                    _, patched_binary_dump = run([bun, lock.name], project, env,
                                                 case / 'patched-binary-dump.log')
                for label, flags, cache in [
                        ('frozen', ['--frozen-lockfile'], None),
                        ('ordinary', [], None),
                        ('warmFrozen', ['--frozen-lockfile'], 'cache-frozen'),
                        ('warmOrdinary', [], 'cache-ordinary')]:
                    if shape == 'production':
                        flags = [*flags, '--production']
                    code, _ = install(bun, label, flags, cache=cache)
                    correct, hashes = oracle(project, record, 'after')
                    checks[label + 'PatchedBytes'] = code == 0 and correct
                    row[label + 'Files'] = hashes
                    installed_lock = lock.read_bytes()
                    if (lockb_origin and label == 'ordinary' and installed_lock != patched_lock
                            and ver(version) >= (1, 2, 23)):
                        # A modern ordinary install upgrades legacy binary
                        # format 2 to format 3 even before any patch. Preserve
                        # this real installer state for rerun and rollback.
                        prefix = b'#!/usr/bin/env bun\nbun-lockfile-format-v0\n'
                        old_revision = int.from_bytes(patched_lock[len(prefix):len(prefix) + 4], 'little')
                        new_revision = int.from_bytes(installed_lock[len(prefix):len(prefix) + 4], 'little')
                        _, installed_dump = run([bun, lock.name], project, env,
                                                case / 'ordinary-binary-dump.log')
                        checks['ordinaryBinarySchemaUpgrade'] = old_revision == 2 and new_revision == 3
                        checks['ordinaryBinaryResolutionStable'] = installed_dump == patched_binary_dump
                        binary_schema_upgraded = True
                        row['binarySchemaUpgrade'] = {'from': old_revision, 'to': new_revision}
                        patched_lock = installed_lock
                    else:
                        checks[label + 'StableLock'] = installed_lock == patched_lock
                code, repeat = run(command, project, env, case / 'repeat.log', False)
                exit_codes['repeat'] = code
                row['repeat'] = parse_envelope(repeat)
                checks['repeatStableLock'] = lock.read_bytes() == patched_lock
                checks['repeatClean'] = rerun_clean(code, row['repeat'], main_mode)
                if main_mode != 'hosted':
                    # The same re-run during a vendoring-service outage (a
                    # closed port: every service call is a transport
                    # failure). The committed artifact is reused, so the
                    # lock stays byte-identical and the run is the same
                    # already_vendored no-op — whichever source built it.
                    outage_env = dict(env, SOCKET_VENDOR_URL='http://127.0.0.1:9')
                    code, outage = run(command, project, outage_env, case / 'repeat-outage.log', False)
                    exit_codes['repeatOutage'] = code
                    row['repeatOutage'] = parse_envelope(outage)
                    checks['repeatOutageStableLock'] = lock.read_bytes() == patched_lock
                    checks['repeatOutageClean'] = rerun_clean(code, row['repeatOutage'], main_mode)
                if shape == 'already-vendored-workspace' and main_mode != 'hosted':
                    # A deleted committed artifact is rebuilt by `repair`
                    # (locally, so its tarball digest may differ from the
                    # service prebuilt one and the lock line is re-pinned) and
                    # a cold frozen install from the repaired lock still yields
                    # the patched bytes. Every later step judges the REPAIRED lock.
                    artifact = project / '.socket/vendor/npm' / UUID / 'minimist-1.2.2.tgz'
                    artifact.unlink()
                    code, output = run([cli, 'repair', '--cwd', project, '--json', '--yes', '--no-telemetry'],
                                       project, env, case / 'repair.log', False)
                    exit_codes['repair'] = code
                    repaired = parse_envelope(output)
                    row['repair'] = repaired
                    checks['repairRebuilt'] = (
                        code == 0 and artifact.is_file()
                        and any(e.get('action') == 'rebuilt' and e.get('purl') == PURL
                                for e in repaired.get('events', [])))
                    patched_lock = lock.read_bytes()
                    checks['repairKeepsLocalTuple'] = LOCAL_TUPLE_SPEC in patched_lock.decode('utf-8')
                    code, _ = install(bun, 'repair-frozen', ['--frozen-lockfile'])
                    checks['repairFrozenPatchedBytes'] = code == 0 and oracle(project, record, 'after')[0]
                    checks['repairStableLock'] = lock.read_bytes() == patched_lock
                if lockb_origin:
                    digest = wired_fragments(project, main_mode)['new']['integrity']
                    raw_digest = base64.b64decode(digest.removeprefix('sha512-'))
                    tampered = patched_lock.replace(raw_digest, bytes(len(raw_digest)))
                else:
                    tampered = tamper_digests(patched_lock, UUID.encode())
                checks['tamperedDigest'] = tampered != patched_lock
                lock.write_bytes(tampered)
                remove_node_modules(project)
                code, output = run([bun, 'install', '--ignore-scripts', '--frozen-lockfile'], project,
                                   env_for(bun, 'cache-corrupt'), case / 'corrupt.log', False,
                                   timeout=60, tolerate_timeout=True)
                row['rejectsCorruptDigest'] = code != 0 and ('integrity' in output.lower()
                                                              or 'checksum' in output.lower())
                if code is None:
                    row.setdefault('notes', []).append(
                        'bun printed the tarball integrity error but never exited (killed after 60 s)')
                if ver(version) >= TARBALL_INTEGRITY_ENFORCED_FROM:
                    checks['rejectCorruptDigest'] = row['rejectsCorruptDigest']
                else:
                    # Below the boundary bun's behaviour is RECORDED, not asserted:
                    # the rewrite trades a verified registry tuple for an unverified
                    # tarball tuple on these releases.
                    checks['legacyDigestBehavior'] = True
                    row.setdefault('upstreamLimitations', []).append(
                        'Bun %s %s a tampered digest on the patched tarball tuple (enforcement '
                        'documented from %s); registry tuples are verified' % (
                            version, 'rejected' if row['rejectsCorruptDigest'] else 'accepted',
                            '.'.join(map(str, TARBALL_INTEGRITY_ENFORCED_FROM))))
                lock.write_bytes(patched_lock)
                code, output = run([cli, 'rollback', '--cwd', project, '--json', '--yes', '--no-telemetry'],
                                   project, env, case / 'rollback.log', False)
                exit_codes['rollback'] = code
                rolled = parse_envelope(output)
                rollback_codes = [w.get('code') for w in rolled.get('warnings', [])]
                row['rollbackWarnings'] = rollback_codes
                checks['rollbackSucceeded'] = code == 0 and rolled.get('status') == 'success'
                checks['rollbackOriginalFiles'] = all(
                    (project / n).exists() and (project / n).read_bytes() == b
                    for n, b in original.items() if not (binary_schema_upgraded and n == 'bun.lockb'))
                if binary_schema_upgraded:
                    _, restored_dump = run([bun, lock.name], project, env,
                                           case / 'rollback-binary-dump.log')
                    checks['rollbackOriginalBinaryResolution'] = restored_dump == original_binary_dump
                checks['rollbackLockPresence'] = all(
                    (project / name).exists() == (name in original) for name in ['bun.lock', 'bun.lockb'])
                checks['rollbackWarningsClean'] = not set(rollback_codes) - INFORMATIONAL
                if shape == 'crlf-lock':
                    checks['rollbackEolPreserved'] = crlf_only(lock.read_bytes())
                code, _ = install(bun, 'reinstall', cache='cache-rollback')
                checks['rollbackOriginalBytes'], row['rollbackFiles'] = oracle(project, record, 'before')
                checks['rollbackOriginalBytes'] = code == 0 and checks['rollbackOriginalBytes']
            row['passed'] = all(checks.values())
        except Exception as error:  # noqa: BLE001 — every cell must produce a row
            row['error'] = str(error)
        save(case / 'result.json', row)
        print(version, shape, mode, 'PASS' if row['passed'] else 'FAIL',
              [k for k, v in checks.items() if not v], row.get('error', '')[:200], flush=True)
        return row

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        rows = list(pool.map(lambda job: retry_network_cell(backtest, job, root), jobs))
    save(root / 'summary.json', rows)
    for version in args.versions:
        mine = [r for r in rows if r['bun'] == version]
        print(f'bun {version}: {sum(r["passed"] for r in mine)}/{len(mine)} passed, '
              f'{sum(bool(r.get("supported")) for r in mine)} supported, '
              f'{sum(not r.get("supported") for r in mine)} unsupported', flush=True)
    return 0 if rows and all(row['passed'] for row in rows) else 1


if __name__ == '__main__':
    raise SystemExit(main())
