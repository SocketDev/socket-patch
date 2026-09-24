"""Offline regression tests for shared native-installer harness setup."""

import concurrent.futures
import importlib.util
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


if __name__ == "__main__":
    unittest.main()
