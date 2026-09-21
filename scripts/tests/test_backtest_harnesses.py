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
