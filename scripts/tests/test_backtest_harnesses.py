"""Offline regression tests for shared native-installer harness setup."""

import concurrent.futures
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parents[1] / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pipenv = load_script("backtest-pipenv")
pdm = load_script("backtest-pdm")
bun = load_script("backtest-bun")
vlt = load_script("backtest-vlt")


class BunTransportRetryTests(unittest.TestCase):
    def test_retry_uses_clean_tree_and_keeps_failed_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            job = ('1.1.38', 'direct', 'vendored')
            case = root / 'captures' / '-'.join(job)
            calls = []

            def run_case(_job):
                self.assertFalse(case.exists(), 'retry must discard partial state and caches')
                case.mkdir(parents=True)
                (case / 'cache').mkdir()
                (case / 'cli.log').write_text('failed request evidence')
                calls.append(True)
                row = dict(passed=len(calls) > 1, checks={'repeatStableLock': len(calls) > 1})
                if len(calls) == 1:
                    row['repeat'] = {'vendor': {'events': [{'reason':
                        'Network error: error sending request for url (https://patch.socket.dev/example)'}]}}
                bun.save(case / 'result.json', row)
                return row

            with patch.object(bun.time, 'sleep'):
                row = bun.retry_network_cell(run_case, job, root)
            self.assertTrue(row['passed'])
            self.assertEqual(len(calls), 2)
            evidence = root / row['networkRetryAttempts'][0]['evidence']
            self.assertEqual((evidence / 'cli.log').read_text(), 'failed request evidence')
            self.assertFalse((evidence / 'cache').exists())

    def test_functional_failure_is_never_retried(self):
        with tempfile.TemporaryDirectory() as temp:
            row = dict(passed=False, checks={'frozenPatchedBytes': False}, error='installed bytes differ')
            calls = []
            result = bun.retry_network_cell(lambda job: calls.append(job) or row,
                                           ('1.0.0', 'production', 'hosted'), Path(temp))
            self.assertIs(result, row)
            self.assertEqual(len(calls), 1)

    def test_persistent_transport_failure_remains_failed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            job = ('1.1.38', 'direct', 'hosted')
            case = root / 'captures' / '-'.join(job)
            calls = []

            def run_case(_job):
                case.mkdir(parents=True)
                calls.append(True)
                row = dict(passed=False, error='error sending request for url (https://patches-api.socket.dev/patch/batch)')
                bun.save(case / 'result.json', row)
                return row

            with patch.object(bun.time, 'sleep'):
                row = bun.retry_network_cell(run_case, job, root)
            self.assertFalse(row['passed'])
            self.assertEqual(len(calls), 3)
            self.assertEqual(len(row['networkRetryAttempts']), 2)


class BunManifestlessVexHelperTests(unittest.TestCase):
    UUID = '80630680-4da6-45f9-bba8-b888e0ffd58c'
    VULNS = {'GHSA-xvch-5gv4-984h': ['CVE-2021-44906']}

    def statement(self, purl=bun.PURL, name='GHSA-xvch-5gv4-984h', aliases=('CVE-2021-44906',),
                  marker='redirected', status='not_affected'):
        return {'vulnerability': {'name': name, 'aliases': list(aliases)},
                'products': [{'@id': bun.VEX_PRODUCT, 'subcomponents': [{'@id': purl}]}],
                'status': status,
                'impact_statement': f'Patched via Socket patch {self.UUID} ({marker})'}

    def test_attested_needs_exact_ids_aliases_status_and_marker(self):
        ok = {'statements': [self.statement()]}
        self.assertTrue(bun.vex_attested(ok, bun.PURL, self.UUID, 'redirected', self.VULNS))
        qualified = {'statements': [self.statement(purl=bun.PURL + '?x=1')]}
        self.assertTrue(bun.vex_attested(qualified, bun.PURL, self.UUID, 'redirected', self.VULNS))
        for doc, why in [
                (None, 'no document'),
                ({'statements': []}, 'no statement'),
                ({'statements': [self.statement(marker='vendored')]}, 'wrong marker'),
                ({'statements': [self.statement(aliases=())]}, 'alias missing'),
                ({'statements': [self.statement(status='affected')]}, 'status'),
                ({'statements': [self.statement(), self.statement(name='GHSA-extra')]}, 'extra id'),
                ({'statements': [self.statement(purl='pkg:npm/minimist@1.2.8')]}, 'other purl')]:
            with self.subTest(why):
                self.assertFalse(bun.vex_attested(doc, bun.PURL, self.UUID, 'redirected', self.VULNS))
        self.assertFalse(bun.vex_attested(ok, bun.PURL, self.UUID, 'redirected', {}),
                         'a record without vulnerabilities can never pass')

    def test_skip_reason_reads_the_purl_event_and_scope_spellings(self):
        envelope = {'events': [{'action': 'skipped', 'purl': 'pkg:npm/@s/p@1.0.0',
                                'errorCode': 'record_unavailable'},
                               {'action': 'skipped', 'purl': bun.PURL, 'errorCode': 'vendor_unwired'}]}
        self.assertEqual(bun.vex_skip_reason(envelope, bun.PURL), 'vendor_unwired')
        self.assertEqual(bun.vex_skip_reason(envelope, 'pkg:npm/%40s/p@1.0.0'), 'record_unavailable')
        verified = {'events': [{'action': 'verified', 'purl': bun.PURL}]}
        self.assertIsNone(bun.vex_skip_reason(verified, bun.PURL))
        self.assertIsNone(bun.vex_skip_reason({}, bun.PURL))

    def test_checkout_drops_manifest_node_modules_and_old_output(self):
        with tempfile.TemporaryDirectory() as temp:
            project, dest = Path(temp) / 'p', Path(temp) / 'c'
            for rel in ['package.json', 'bun.lock', '.socket/manifest.json', '.socket/apply.lock',
                        '.socket/vendor/state.json', f'.socket/vendor/npm/{self.UUID}/minimist-1.2.2.tgz',
                        'node_modules/minimist/index.js', 'packages/c/node_modules/x/index.js',
                        'packages/c/package.json', bun.VEX_OUTPUT]:
                (project / rel).parent.mkdir(parents=True, exist_ok=True)
                (project / rel).write_text(rel)
            (dest / 'stale').mkdir(parents=True)
            bun.manifestless_checkout(project, dest)
            got = sorted(p.relative_to(dest).as_posix() for p in dest.rglob('*') if p.is_file())
            self.assertEqual(got, ['.socket/vendor/npm/%s/minimist-1.2.2.tgz' % self.UUID,
                                   '.socket/vendor/state.json', 'bun.lock', 'package.json',
                                   'packages/c/package.json'])


class PipenvShimTests(unittest.TestCase):
    def test_parallel_first_use(self):
        # Force every worker to reach symlink creation before any can create
        # it. A check-then-create implementation deterministically fails here.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            tool = root / "tool"
            executable = tool / "bin/pipenv"
            executable.parent.mkdir(parents=True)
            executable.write_text("the selected pipenv")
            barrier = threading.Barrier(8)
            symlink_to = Path.symlink_to

            def simultaneous_create(link, target, *args, **kwargs):
                barrier.wait(timeout=10)
                return symlink_to(link, target, *args, **kwargs)

            with patch.object(Path, "symlink_to", simultaneous_create):
                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                    directories = list(pool.map(lambda _: pipenv.pipenv_shim_dir(root, "2022.12.19", tool), range(8)))
            self.assertEqual(len(set(directories)), 1)
            self.assertEqual((directories[0] / "pipenv").read_text(), "the selected pipenv")
            self.assertEqual(list(directories[0].iterdir()), [directories[0] / "pipenv"])
            self.assertEqual(pipenv.pipenv_shim_dir(root, "2022.12.19", tool), directories[0])

    def test_conflicting_shim_is_not_accepted_or_overwritten(self):
        for symlink in (False, True):
            with self.subTest(symlink=symlink), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                directory = root / "pipenv-bin/2022.12.19"
                directory.mkdir(parents=True)
                link = directory / "pipenv"
                if symlink:
                    link.symlink_to(root / "different-tool")
                else:
                    link.write_text("existing file")
                with self.assertRaises(FileExistsError):
                    pipenv.pipenv_shim_dir(root, "2022.12.19", root / "tool")
                if symlink:
                    self.assertEqual(os.readlink(link), str(root / "different-tool"))
                else:
                    self.assertEqual(link.read_text(), "existing file")

    def test_legacy_docker_wrapper_is_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            wrapper = root / "legacy-bin/11.10.4"
            wrapper.mkdir(parents=True)
            (wrapper / "pipenv").write_text("docker wrapper")
            self.assertEqual(pipenv.pipenv_shim_dir(root, "11.10.4", root / "tool"), wrapper)
            self.assertEqual((wrapper / "pipenv").read_text(), "docker wrapper")


class PipenvManifestlessVexVerdictTests(unittest.TestCase):
    UUID = "e828efa5-5c6d-43f3-9909-03f5ac232b98"
    PURL = "pkg:pypi/urllib3@1.26.18"

    def doc(self, marker="redirected", purl=None, status="not_affected"):
        return {"statements": [{
            "status": status,
            "products": [{"@id": "pkg:pypi/app@0.1.0", "subcomponents": [{"@id": purl or self.PURL + "?artifact_id=x"}]}],
            "impact_statement": f"Patched via Socket patch {self.UUID} ({marker})",
        }]}

    def test_attests_needs_exit_zero_marker_uuid_and_status(self):
        self.assertTrue(pipenv.vex_attests(0, self.doc(), self.PURL, self.UUID, "redirected"))
        self.assertFalse(pipenv.vex_attests(1, self.doc(), self.PURL, self.UUID, "redirected"))
        self.assertFalse(pipenv.vex_attests(0, self.doc("vendored"), self.PURL, self.UUID, "redirected"))
        self.assertFalse(pipenv.vex_attests(0, self.doc(), self.PURL, "0" * 8, "redirected"))
        self.assertFalse(pipenv.vex_attests(0, self.doc(status="affected"), self.PURL, self.UUID, "redirected"))
        self.assertFalse(pipenv.vex_attests(0, self.doc(purl="pkg:pypi/six@1.16.0"), self.PURL, self.UUID, "redirected"))
        self.assertFalse(pipenv.vex_attests(0, None, self.PURL, self.UUID, "redirected"))

    def test_omits_needs_the_reason_no_statement_and_no_verified_event(self):
        skipped = {"events": [{"action": "skipped", "purl": self.PURL, "errorCode": "redirect_unwired"}]}
        self.assertTrue(pipenv.vex_omits(1, skipped, None, self.PURL, "redirect_unwired"))
        self.assertFalse(pipenv.vex_omits(1, skipped, None, self.PURL, "record_unavailable"))
        self.assertFalse(pipenv.vex_omits(0, skipped, None, self.PURL, "redirect_unwired"))
        self.assertFalse(pipenv.vex_omits(1, skipped, self.doc(), self.PURL, "redirect_unwired"))
        verified = {"events": skipped["events"] + [{"action": "verified", "purl": self.PURL}]}
        self.assertFalse(pipenv.vex_omits(1, verified, None, self.PURL, "redirect_unwired"))
        self.assertFalse(pipenv.vex_omits(1, {}, None, self.PURL, "redirect_unwired"))


class PdmEnvironmentTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "linux", "glibc thread unwinder")
    def test_thread_exit_with_exhausted_file_descriptors(self):
        # Python 3.8's pthread_exit lazily dlopens libgcc_s. Loading it before
        # worker startup avoids the fatal dlopen failure under FD pressure.
        code = """
import errno, os, resource, threading
with open('/proc/self/maps') as maps:
    assert 'libgcc_s.so.1' in maps.read(), 'unwinder was not preloaded'
_, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
resource.setrlimit(resource.RLIMIT_NOFILE, (64, hard))
fds = []
try:
    while True:
        fds.append(os.open(os.devnull, os.O_RDONLY))
except OSError as error:
    assert error.errno == errno.EMFILE
worker = threading.Thread(target=lambda: None)
worker.start()
worker.join()
for fd in fds:
    os.close(fd)
"""
        result = subprocess.run([sys.executable, "-c", code], env=pdm.base_env(), capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_linux_preloads_unwinder_and_preserves_existing_preloads(self):
        for previous in ("", "/custom/library.so"):
            with self.subTest(previous=previous), patch.dict(os.environ, {"LD_PRELOAD": previous}, clear=True):
                with patch.object(pdm.platform, "system", return_value="Linux"):
                    env = pdm.base_env()
                self.assertEqual(env["LD_PRELOAD"].split(), ["libgcc_s.so.1"] + ([previous] if previous else []))
                self.assertEqual(os.environ["LD_PRELOAD"], previous)

    def test_other_platforms_do_not_preload_linux_library(self):
        for system in ("Darwin", "Windows"):
            with self.subTest(system=system), patch.dict(os.environ, {}, clear=True):
                with patch.object(pdm.platform, "system", return_value=system):
                    self.assertNotIn("LD_PRELOAD", pdm.base_env())


class VltOracleTests(unittest.TestCase):
    """The oracle is the documented boundaries, never the CLI's codes."""

    def test_every_mode_must_patch_the_plain_shapes_on_every_era(self):
        for version in vlt.VERSIONS:
            for mode in vlt.MODES:
                with self.subTest(version=version, mode=mode):
                    want = 'safe-refusal' if mode == 'vendored' and vlt.era_of(version) == 'A0' \
                        else 'patched'
                    self.assertEqual(vlt.expected_verdict(version, mode, 'direct'), want)

    def test_refusals_follow_the_support_matrix(self):
        self.assertEqual(vlt.expected_verdict('1.2.0', 'hosted', 'custom-registry'), 'safe-refusal')
        self.assertEqual(vlt.expected_verdict('1.2.0', 'vendored', 'custom-registry'),
                         'safe-refusal')
        self.assertEqual(vlt.expected_verdict('1.2.0', 'agent', 'custom-registry'), 'patched')
        self.assertEqual(vlt.expected_verdict('1.2.0', 'agent', 'lockfile-only'), 'safe-refusal')
        self.assertEqual(vlt.expected_verdict('1.2.0', 'hosted', 'lockfile-only'), 'patched')
        self.assertEqual(vlt.expected_verdict('0.0.0-16', 'vendored', 'direct'), 'safe-refusal')

    def test_cells_a_shape_cannot_express_are_not_in_the_matrix(self):
        self.assertIsNone(vlt.expected_verdict('1.2.0', 'hosted', 'workspace-member-vendored'))
        self.assertIsNone(vlt.expected_verdict('1.2.0', 'hosted', 'hosted-then-vendored'))
        self.assertIsNone(vlt.expected_verdict('1.2.0', 'vendored', 'vendored-then-hosted'))
        self.assertIsNone(vlt.expected_verdict('0.0.0-16', 'vendored', 'hosted-then-vendored'))
        self.assertIsNone(vlt.expected_verdict('0.0.0-12', 'hosted', 'custom-registry'))
        for version in ('0.0.0-24', '0.0.0-29'):
            self.assertIsNone(vlt.expected_verdict(version, 'hosted', 'optional'),
                              'these releases write no lock for an optional-only project')
        self.assertEqual(vlt.expected_verdict('0.0.0-30', 'hosted', 'optional'), 'patched')

    def test_expected_codes_come_from_the_lock_the_cell_writes(self):
        self.assertEqual(vlt.expected_codes('0.0.0-16', 'hosted', 'direct'),
                         ['redirect_vlt_lockfile_version_missing'])
        self.assertEqual(vlt.expected_codes('0.0.0-32', 'hosted', 'direct'),
                         ['redirect_vlt_old_lockfile_ignored'])
        self.assertEqual(vlt.expected_codes('0.0.0-20', 'hosted', 'direct'), [],
                         'vlt.json declares "modifiers" on 0.0.0-16 … 0.0.0-24')
        self.assertEqual(vlt.expected_codes('0.0.0-32', 'hosted', 'alias'), [],
                         'an alias-only era-A lock has no `··` id')
        self.assertEqual(vlt.expected_codes('1.2.0', 'hosted', 'custom-registry'),
                         ['redirect_vlt_custom_registry_skipped'])
        self.assertEqual(vlt.expected_codes('0.0.0-16', 'vendored', 'direct'),
                         ['vendor_lockfile_version_unsupported'])
        self.assertEqual(vlt.expected_codes('0.0.0-32', 'vendored', 'direct'),
                         ['vendor_vlt_legacy_lockfile'])
        self.assertEqual(vlt.expected_codes('0.0.0-32', 'vendored', 'alias'), [])
        self.assertEqual(vlt.expected_codes('1.2.0', 'vendored', 'custom-registry'),
                         ['vendor_lock_entry_unsupported'])
        self.assertEqual(vlt.expected_codes('1.2.0', 'agent', 'lockfile-only'),
                         ['package_not_installed'])
        self.assertEqual(vlt.expected_codes('1.0.0-rc.14', 'hosted', 'direct'), [])

    def test_the_optional_only_limitation_is_bounded(self):
        for version, limited in (('0.0.0-23', False), ('0.0.0-30', True), ('1.0.0-rc.14', True),
                                 ('1.0.4', True), ('1.0.5', False), ('1.2.0', False)):
            with self.subTest(version=version):
                self.assertEqual(bool(vlt.known_vlt_limitation(version, 'hosted', 'optional')),
                                 limited)
        self.assertIsNone(vlt.known_vlt_limitation('1.0.4', 'hosted', 'optional-mixed'))
        self.assertIsNone(vlt.known_vlt_limitation('1.0.4', 'agent', 'optional'))

    def row(self, **fields):
        base = dict(expectedVerdict='patched', expectedCodes=[], codes=[], verdict='patched')
        base.update(fields)
        return base

    def test_matches_expectation(self):
        self.assertTrue(vlt.matches_expectation(self.row()))
        self.assertFalse(vlt.matches_expectation(self.row(verdict='safe-refusal')),
                         'a spurious refusal of a must-patch cell fails')
        self.assertFalse(vlt.matches_expectation(self.row(expectedCodes=['x'])),
                         'a missing documented code fails')
        self.assertTrue(vlt.matches_expectation(self.row(verdict=vlt.BLOCKED,
                                                         blockedByProbe='gzip')))
        self.assertFalse(vlt.matches_expectation(self.row(verdict=vlt.BLOCKED)),
                         'blocked needs the probe to have seen a content-encoding')
        self.assertFalse(vlt.matches_expectation(self.row(
            verdict=vlt.BLOCKED, blockedByProbe='gzip', expectedVerdict='safe-refusal')))
        limited = self.row(verdict='unsupported', vltLimitations=['x'], expectedLimitation='x')
        self.assertTrue(vlt.matches_expectation(limited))
        self.assertFalse(vlt.matches_expectation(dict(limited, expectedLimitation=None)),
                         'only a documented limitation may leave a cell unproven')
        self.assertFalse(vlt.matches_expectation(dict(limited, failingChecks=['freshCi'])))

    def test_observed_verdict(self):
        self.assertEqual(vlt.observed_verdict({'error': 'x'}), 'error')
        self.assertEqual(vlt.observed_verdict({'blocked': True}), vlt.BLOCKED)
        self.assertEqual(vlt.observed_verdict({'safeRefusal': True}), 'safe-refusal')
        self.assertEqual(vlt.observed_verdict({'passed': True}), 'patched')
        self.assertEqual(vlt.observed_verdict({'vltLimitations': ['x']}), 'unsupported')
        self.assertEqual(vlt.observed_verdict({'failingChecks': ['freshCi']}), 'unsafe')

    def test_shapes_are_depscan_capture_shapes(self):
        # The depscan audit (capture-vlt.py SHAPES) reads these rows by shape name.
        capture_names = {'direct', 'dev', 'optional', 'optional-mixed', 'alias', 'scoped',
                         'transitive', 'two-versions', 'workspace', 'workspace-member-vendored',
                         'self-referencing-member-vendored', 'peer-variants', 'crlf-lock',
                         'custom-registry', 'mirror', 'scalar-registry', 'lockfile-only',
                         'hosted-then-vendored', 'vendored-then-hosted', 'get-uuid'}
        self.assertLessEqual(set(vlt.SHAPES), capture_names)


class VltConfigTests(unittest.TestCase):
    """write_vlt_json follows the DESIGN §8.3 per-era registry table."""

    def config(self, version, registry=vlt.NPM_REGISTRY, **spec):
        text = vlt.write_vlt_json(version, spec, registry)
        return None if text is None else json.loads(text)

    def test_public_registry(self):
        self.assertEqual(self.config('1.2.0'),
                         {'config': {'registries': {'npm': vlt.NPM_REGISTRY}}})
        self.assertEqual(self.config('1.0.4'), {'config': {
            'registry': vlt.NPM_REGISTRY, 'registries': {'npm': vlt.NPM_REGISTRY}}})
        self.assertEqual(self.config('1.0.0-rc.33'), {'config': {
            'registry': vlt.NPM_REGISTRY, 'registries': {'npm': vlt.NPM_REGISTRY}}})
        self.assertIsNone(self.config('1.0.0-rc.32'),
                          'vlt strips a registry equal to its npmjs default')
        self.assertIsNone(self.config('1.0.0-rc.14'))
        self.assertEqual(self.config('0.0.0-20'), {'modifiers': {}})
        self.assertIsNone(self.config('0.0.0-25'))
        self.assertIsNone(self.config('0.0.0-1'))

    def test_mirror_registry_per_era(self):
        r = 'http://127.0.0.1:4873/'
        self.assertEqual(self.config('0.0.0-13', r), {'registry': r}, 'flat keys ≤ 0.0.0-13')
        self.assertEqual(self.config('0.0.0-14', r), {'config': {'registry': r}})
        self.assertEqual(self.config('0.0.0-16', r),
                         {'config': {'registry': r}, 'modifiers': {}})
        self.assertEqual(self.config('1.0.0-rc.6', r), {'config': {'registry': r}})
        for version in ('1.0.0-rc.7', '1.0.0-rc.14', '1.0.0-rc.29'):
            self.assertEqual(self.config(version, r), {'config': {'registry': vlt.NPM_REGISTRY}},
                             'rc.7 … rc.29 are not hermetic')
        self.assertEqual(self.config('1.0.0-rc.30', r), {'config': {'registry': r}})
        self.assertEqual(self.config('1.0.0-rc.33', r),
                         {'config': {'registry': r, 'registries': {'npm': r}}})
        self.assertEqual(self.config('1.0.5', r), {'config': {'registries': {'npm': r}}})

    def test_workspaces_and_named_registries(self):
        self.assertEqual(self.config('1.2.0', members=['packages/a'])['workspaces'], 'packages/*')
        self.assertEqual(self.config('0.0.0-13', members=['packages/a']),
                         {'workspaces': 'packages/*'})
        files = vlt.project_files('0.0.0-12', vlt.SHAPES['workspace'])
        self.assertEqual(json.loads(files['vlt-workspaces.json']), {'packages': 'packages/*'})
        self.assertNotIn('vlt.json', files)
        custom = self.config('1.2.0', registries={'acme': vlt.ACME_REGISTRY})
        self.assertEqual(custom['config']['registries'],
                         {'acme': vlt.ACME_REGISTRY, 'npm': vlt.NPM_REGISTRY})


class VltReleaseTests(unittest.TestCase):
    supported, excluded = vlt.release_lists()

    def test_exclusions(self):
        for version in ('0.0.0-0', '0.0.0-2', '0.0.0-10', '0.0.0-22', '1.0.0-rc.19',
                        '1.0.0-rc.21', '0.0.1', '1.0.0', '0.0.0-0.1733957343934'):
            with self.subTest(version=version):
                self.assertEqual(vlt.release_status(version, self.supported, self.excluded),
                                 'excluded')
        for version in vlt.VERSIONS:
            self.assertEqual(vlt.release_status(version, self.supported, self.excluded),
                             'supported')
        self.assertEqual(vlt.release_status('1.3.0', self.supported, self.excluded), 'unlisted')
        self.assertEqual(vlt.unlisted_releases(['1.2.0', '0.0.0-22', '1.3.0', '0.0.0-0.17'],
                                               self.supported, self.excluded), ['1.3.0'])

    def test_main_refuses_an_excluded_release(self):
        with self.assertRaises(SystemExit), patch('sys.stderr'):
            vlt.main(['--cli', 'x', '--out', 'y', '--versions', '0.0.0-22'])
        with self.assertRaises(SystemExit), patch('sys.stderr'):
            vlt.main(['--cli', 'x', '--out', 'y', '--versions', '9.9.9'])

    def test_versions_order_and_eras(self):
        ordered = sorted(['1.2.0', '1.0.0-rc.14', '0.0.0-32', '1.0.10', '1.0.0-rc.9', '1.0.4'],
                         key=vlt.version_key)
        self.assertEqual(ordered, ['0.0.0-32', '1.0.0-rc.9', '1.0.0-rc.14', '1.0.4', '1.0.10',
                                   '1.2.0'])
        eras = {v: vlt.era_of(v) for v in ('0.0.0-18', '0.0.0-19', '1.0.0-rc.8', '1.0.0-rc.9',
                                           '1.0.0-rc.14', '1.0.0-rc.15', '1.0.0-rc.32',
                                           '1.0.0-rc.33', '1.0.7', '1.0.8', '1.1.1', '1.2.0')}
        self.assertEqual(list(eras.values()),
                         ['A0', 'A', 'A', 'B', 'B', 'C', 'C', 'D', 'D', 'E', 'E', 'F'])

    def test_pinned_integrity_covers_every_supported_release(self):
        pinned = json.loads(vlt.HISTORICAL_INTEGRITY.read_text())
        self.assertEqual(sorted(pinned, key=vlt.version_key),
                         sorted(self.supported, key=vlt.version_key))
        self.assertTrue(all(v.startswith('sha512-') for v in pinned.values()))
        self.assertEqual(pinned['1.2.0'], 'sha512-t7ONkM8YgRlY0g+6l+OU4oS2WS/dp7DK/vmFwNqxA0D+'
                         'ehPWprNOTTH3uUYURAnCg5lr9vzJSmX9nNCcG5xGXA==')


class VltLockHelperTests(unittest.TestCase):
    LOCK = ('{\n  "lockfileVersion": 1,\n  "options": {},\n  "nodes": {\n'
            '    "~npm~minimist@1.2.2": [0,"minimist","sha512-AAAA==","https://r/m.tgz"],\n'
            '    "~npm~minimist@1.2.2~peer.1": [0,"minimist","sha512-AAAA=="],\n'
            '    "~acme~minimist@1.2.2": [0,"minimist","sha512-BBBB=="],\n'
            '    "~npm~minimist@1.2.8": [0,"minimist","sha512-CCCC=="],\n'
            '    "·npm·minimist@1.2.2": [0,"minimist","sha512-DDDD=="],\n'
            '    "··minimist@1.2.2": [0,"minimist","sha512-EEEE=="],\n'
            '    "file~.socket+vendor": [0,"minimist",null,".socket/vendor"]\n'
            '  },\n  "edges": {}\n}\n')

    def test_split_dep_id_both_grammars(self):
        self.assertEqual(vlt.split_dep_id('~npm~minimist@1.2.2'), ('npm', 'minimist', '1.2.2', None))
        self.assertEqual(vlt.split_dep_id('~~minimist@1.2.2~peer.1'),
                         ('', 'minimist', '1.2.2', 'peer.1'))
        self.assertEqual(vlt.split_dep_id('··minimist@1.2.2'), ('', 'minimist', '1.2.2', None))
        self.assertEqual(vlt.split_dep_id('~npm~@s+p@1.0.0'), ('npm', '@s/p', '1.0.0', None))
        self.assertEqual(vlt.split_dep_id('·npm·@s§p@1.0.0'), ('npm', '@s/p', '1.0.0', None))
        self.assertIsNone(vlt.split_dep_id('file~_d'))
        self.assertIsNone(vlt.split_dep_id('file·.'))

    def test_target_instances_are_default_registry_nodes(self):
        self.assertEqual(vlt.target_instances(self.LOCK), [
            '~npm~minimist@1.2.2', '~npm~minimist@1.2.2~peer.1', '·npm·minimist@1.2.2',
            '··minimist@1.2.2'])
        self.assertIn('~acme~minimist@1.2.2', vlt.target_instances(self.LOCK, any_registry=True))

    def test_tamper_lock_rewrites_only_the_named_lines(self):
        crlf = self.LOCK.replace('\n', '\r\n').encode()
        out = vlt.tamper_lock(crlf, ['~npm~minimist@1.2.2', '·npm·minimist@1.2.2'])
        wrong = vlt.sri_sha512(b'tampered by backtest-vlt.py')
        lines = out.decode().split('\r\n')
        self.assertIn(f'"~npm~minimist@1.2.2": [0,"minimist","{wrong}","https://r/m.tgz"],',
                      lines[4])
        self.assertIn(wrong, lines[8])
        self.assertEqual([l for i, l in enumerate(lines) if i not in (4, 8)],
                         [l for i, l in enumerate(crlf.decode().split('\r\n')) if i not in (4, 8)])

    def test_snapshot_keeps_the_vendored_payload_and_drops_node_modules(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            payload = f'.socket/vendor/npm/{vlt.UUID}/minimist-1.2.2/node_modules/minimist'
            for rel in ['package.json', 'vlt-lock.json', 'vlt.json', 'node_modules/.vlt-lock.json',
                        'packages/a/node_modules/minimist/index.js', 'packages/a/package.json',
                        f'{payload}/package.json', f'{payload}/index.js',
                        f'{payload}/node_modules/dep/index.js', '.socket/vendor/state.json',
                        f'.socket/vendor/npm/{vlt.UUID}/.gitignore']:
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_text(rel)
            files = vlt.snapshot(root)
            self.assertEqual(sorted(files), sorted([
                'package.json', 'vlt-lock.json', 'vlt.json', 'packages/a/package.json',
                f'{payload}/package.json', f'{payload}/index.js', '.socket/vendor/state.json',
                f'.socket/vendor/npm/{vlt.UUID}/.gitignore']))
            digests = vlt.capture_tree(root, root / 'tree-out')
            self.assertEqual(sorted(digests), sorted([
                'package.json', 'vlt-lock.json', 'vlt.json', 'packages/a/package.json',
                f'{payload}/package.json', '.socket/vendor/state.json']))

    def test_remove_node_modules_keeps_the_vendored_payload(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            payload = f'.socket/vendor/npm/{vlt.UUID}/minimist-1.2.2/node_modules/minimist'
            for rel in ['node_modules/.vlt/x/index.js', 'packages/a/node_modules/m/index.js',
                        f'{payload}/index.js', 'package.json']:
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_text(rel)
            vlt.remove_node_modules(root)
            left = sorted(p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file())
            self.assertEqual(left, [f'{payload}/index.js', 'package.json'])

    @unittest.skipIf(os.name == 'nt', 'symlinks need privileges on Windows')
    def test_snapshot_never_follows_a_link(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'p'
            outside = Path(temp) / 'outside'
            outside.mkdir()
            (outside / 'secret.json').write_text('{}')
            root.mkdir()
            (root / 'package.json').write_text('{}')
            (root / 'linked').symlink_to(outside, target_is_directory=True)
            self.assertEqual(list(vlt.snapshot(root)), ['package.json'])


class VltRetryTests(unittest.TestCase):
    def test_only_transport_failures_retry(self):
        self.assertFalse(vlt.transient({'matchesExpectation': True, 'serveProbe': {'curlExit': 7}}))
        self.assertTrue(vlt.transient({'serveProbe': {'curlExit': 7}}))
        self.assertTrue(vlt.transient({'serveProbe': {'curlExit': 0, 'status': 503}}))
        self.assertTrue(vlt.transient({'error': 'error sending request for url (https://x)'}))
        self.assertFalse(vlt.transient({'serveProbe': {'curlExit': 0, 'status': 200},
                                        'failingChecks': ['freshCi']}))

    def test_a_transport_failure_reruns_from_scratch(self):
        with tempfile.TemporaryDirectory() as temp:
            rows = [{'cell': 'c', 'error': 'error sending request for url (https://x)'},
                    {'cell': 'c', 'matchesExpectation': True}]

            class Fake:
                case = Path(temp)

                def __init__(self, *_):
                    pass

                def run_cell(self):
                    return rows.pop(0)

            with patch.object(vlt.time, 'sleep'), patch('sys.stdout'):
                row = vlt.run_with_retries(Fake, ('1.2.0', 'hosted', 'direct'))
            self.assertTrue(row['matchesExpectation'])
            self.assertEqual(len(row['transportRetries']), 1)
            self.assertTrue((Path(temp) / 'result.json').is_file())


class VltProbeTests(unittest.TestCase):
    def test_header_blocks_take_the_last_response(self):
        dump = ('HTTP/1.1 302 Found\r\nLocation: /x\r\n\r\n'
                'HTTP/2 200\r\ncontent-encoding: gzip\r\ncache-control: public\r\n\r\n')
        self.assertEqual(vlt.parse_header_blocks(dump),
                         (200, {'content-encoding': 'gzip', 'cache-control': 'public'}))
        self.assertEqual(vlt.parse_header_blocks(''), (None, {}))

    def test_identity_encodings(self):
        for value in (None, '', ' ', 'identity', 'IDENTITY'):
            self.assertTrue(vlt.encoding_is_identity(value), value)
        for value in ('gzip', 'br', 'gzip, identity'):
            self.assertFalse(vlt.encoding_is_identity(value), value)

    def test_grant_selection_fails_closed(self):
        ok = {'results': {vlt.UUID: {'status': 'reused', 'url': 'u', 'artifacts': [
            {'kind': 'yarn-berry-zip', 'url': 'z', 'integrity': {'sha512': None}},
            {'kind': 'tarball', 'url': 't', 'integrity': {'sha512': 'sha512-x'}}]}}}
        self.assertEqual(vlt.select_tarball(ok), ('t', 'sha512-x'))
        for broken in ({'results': {}},
                       {'results': {vlt.UUID: {'status': 'withdrawn'}}},
                       {'results': {vlt.UUID: {'status': 'granted', 'artifacts': [
                           {'kind': 'tarball', 'integrity': {}}]}}}):
            with self.assertRaises(RuntimeError):
                vlt.select_tarball(broken)

    def test_envelope_codes_read_every_channel(self):
        envelope = {'redirect': {'warnings': [{'code': 'a'}],
                                 'skipped': [{'reason': 'redirect_vlt_artifact_unverifiable'}]},
                    'vendor': {'events': [{'errorCode': 'b', 'reason': 'prose with spaces'}]}}
        self.assertEqual(sorted(vlt.envelope_codes(envelope)),
                         ['a', 'b', 'redirect_vlt_artifact_unverifiable'])


if __name__ == "__main__":
    unittest.main()
