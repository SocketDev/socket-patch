"""Offline regression tests for shared native-installer harness setup."""

import concurrent.futures
import importlib.util
import io
import json
import os
import platform
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from contextlib import redirect_stdout


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parents[1] / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pipenv = load_script("backtest-pipenv")
pdm = load_script("backtest-pdm")
bun = load_script("backtest-bun")
poetry = load_script("backtest-poetry")
with patch.object(sys, "argv", ["backtest-uv", "--render-doc-table", "unused.json"]):
    uv = load_script("backtest-uv")


class UvSummaryTests(unittest.TestCase):
    def test_variant_needs_install_evidence(self):
        prefix = "variant-tool-uv-dev-hosted-"
        observations = [
            {"command": prefix + "lock", "exitCode": 0, "formatSupported": True},
            {"command": prefix + "socket-patch", "exitCode": 0, "patchInLock": True},
        ]
        self.assertEqual(uv.variant_status(observations, "tool-uv-dev", "hosted"),
                         ("fail", ["missing installs"]))
        # Old releases may not provide --frozen or --locked; a successful
        # plain install still provides evidence without inventing missing flags.
        observations.append({"command": prefix + "plain-sync", "exitCode": 0,
                             "installedPatch": True})
        self.assertEqual(uv.variant_status(observations, "tool-uv-dev", "hosted"), "pass")

    def test_summary_preserves_failed_and_malformed_cli_output(self):
        cases = [(2, "panic output", True), (0, "not JSON", True),
                 (0, "[]", True), (0, '{"redirect": ["broken"]}', True),
                 (1, '{"error": "request failed"}', False)]
        for exit_code, stdout, malformed in cases:
            with self.subTest(exit_code=exit_code, stdout=stdout), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                cli, wheel = root / "socket-patch", root / "original.whl"
                cli.write_bytes(b"binary")
                wheel.write_bytes(b"wheel")
                base = root / "matrix/0.12.15"
                (base / "original").mkdir(parents=True)
                (base / "original/uv.lock").write_text("[[package]]\n")
                prefix = "variant-tool-uv-dev-hosted-"
                rows = [{"key": prefix + "lock", "exitCode": 0,
                         "command": ["/mock/uv", "lock"], "formatSupported": True}]
                for key in (prefix + "socket-patch", "project-hosted-socket-patch"):
                    rows.append({"key": key, "command": [str(cli), "scan"],
                                 "exitCode": exit_code, "stdout": stdout,
                                 "stderr": "original CLI diagnostic", "patchInLock": False})
                rows.append({"key": "project-hosted-lock-sync", "exitCode": 0,
                             "command": ["/mock/uv", "sync"],
                             "installedResponseSha256": uv.PATCHED_RESPONSE})
                (base / "variant-backtest.json").write_text(json.dumps({"commands": rows}))
                settings = SimpleNamespace(versions=["0.12.15"], python="/mock/python",
                                           socket_patch_revision="test")
                with patch.object(uv, "ROOT", root), patch.object(uv, "CLI", cli), \
                     patch.object(uv, "WHEEL", wheel), patch.object(uv, "args", settings), \
                     patch.object(platform, "platform", return_value="test-platform"), \
                     patch.object(subprocess, "check_output", return_value="mock 1.0"):
                    uv.write_summary()
                result = json.loads((root / "results.json").read_text())
                observations = result["versions"][0]["observations"]
                scans = [row for row in observations if row["command"].endswith("socket-patch")]
                for scan in scans:
                    self.assertEqual(scan["exitCode"], exit_code)
                    self.assertEqual(scan["diagnostic"], "original CLI diagnostic")
                    self.assertEqual("outputError" in scan, malformed)
                    if malformed:
                        self.assertEqual(scan["stdout"], stdout)
                self.assertEqual(uv.variant_status(observations, "tool-uv-dev", "hosted"),
                                 ("fail", ["scan"]))
                self.assertIn("| 0.12.15 | `package`, v1 | Fail / — |", uv.render_doc_table(result))


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


class BootstrapFailureTests(unittest.TestCase):
    def test_failed_bootstrap_is_persisted_and_exits_nonzero(self):
        for module, version in ((pipenv, "2025.1.3"), (pdm, "2.29.2"), (poetry, "2.4.3")):
            with self.subTest(script=module.__name__), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                cli = root / "socket-patch"
                cli.write_text("mock binary for provenance")
                output = root / "output"
                cli_flags = ("--cli", "--cli-revision") if module is poetry else ("--socket-patch", "--socket-patch-revision")
                argv = [module.__file__, cli_flags[0], str(cli),
                        cli_flags[1], "test", "--output", str(output),
                        "--versions", version, "--shapes", "direct", "--modes", "hosted"]
                with patch.object(sys, "argv", argv), \
                     patch.object(platform, "platform", return_value="test-platform"), \
                     patch.object(module, "Run", side_effect=RuntimeError("offline bootstrap failure")), \
                     patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, stdout="mock version", stderr="")), \
                     redirect_stdout(io.StringIO()):
                    with self.assertRaises(SystemExit) as raised:
                        module.main()
                self.assertEqual(raised.exception.code, 1)
                summary = json.loads((output / "summary.json").read_text())
                self.assertEqual(summary["errors"][0]["phase"], "bootstrap")
                self.assertIn("offline bootstrap failure", summary["errors"][0]["error"])


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
