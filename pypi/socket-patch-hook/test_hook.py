"""Tests for the socket-patch startup hook.

Run with: ``python -m unittest test_hook`` (no third-party deps required).

The overriding contract under test is *safety*: the hook must never raise, must
no-op cheaply when there is nothing to do, and must invoke ``socket-patch
apply`` with the right offline arguments only when the installed distributions
have changed.
"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import socket_patch_hook as hook  # noqa: E402


class HookTestBase(unittest.TestCase):
    def setUp(self):
        self._cwd = os.getcwd()
        # Isolate env: clear switches + reentrancy + cache redirect.
        self._saved_env = dict(os.environ)
        for k in ("SOCKET_PATCH_HOOK", "SOCKET_NO_HOOK", hook._REENTRANCY_ENV):
            os.environ.pop(k, None)
        self._tmp = self._mkdtemp()
        os.environ["XDG_CACHE_HOME"] = os.path.join(self._tmp, "cache")
        os.environ["LOCALAPPDATA"] = os.path.join(self._tmp, "cache")

    def tearDown(self):
        os.chdir(self._cwd)
        os.environ.clear()
        os.environ.update(self._saved_env)

    def _mkdtemp(self):
        import tempfile

        d = tempfile.mkdtemp()
        self.addCleanup(self._rmtree, d)
        return d

    @staticmethod
    def _rmtree(path):
        import shutil

        shutil.rmtree(path, ignore_errors=True)

    def _make_project(self):
        """A temp dir that looks like a socket-patch project (has a manifest)."""
        root = self._mkdtemp()
        os.makedirs(os.path.join(root, ".socket"))
        with open(os.path.join(root, ".socket", "manifest.json"), "w") as f:
            f.write('{"patches": {}}')
        return root


class TestRunSpawning(HookTestBase):
    def test_applies_when_manifest_present_and_state_changed(self):
        root = self._make_project()
        os.chdir(root)
        with mock.patch.object(hook, "_resolve_binary", return_value="/fake/socket-patch"), \
                mock.patch("subprocess.run", return_value=mock.Mock(returncode=0)) as run:
            hook.run()
        self.assertEqual(run.call_count, 1)
        argv = run.call_args[0][0]
        self.assertEqual(argv[0], "/fake/socket-patch")
        self.assertIn("apply", argv)
        self.assertIn("--offline", argv)
        self.assertIn("--silent", argv)
        # --ecosystems pypi
        self.assertEqual(argv[argv.index("--ecosystems") + 1], "pypi")
        # --cwd <project root>
        self.assertEqual(
            os.path.realpath(argv[argv.index("--cwd") + 1]),
            os.path.realpath(root),
        )
        # --lock-timeout 0 (skip instantly if another apply holds the lock)
        self.assertEqual(argv[argv.index("--lock-timeout") + 1], "0")
        # Re-entrancy guard set in the child env.
        env = run.call_args[1]["env"]
        self.assertEqual(env[hook._REENTRANCY_ENV], "1")

    def test_second_run_is_a_noop_when_state_unchanged(self):
        root = self._make_project()
        os.chdir(root)
        with mock.patch.object(hook, "_resolve_binary", return_value="/fake/socket-patch"), \
                mock.patch("subprocess.run", return_value=mock.Mock(returncode=0)) as run:
            hook.run()  # first run applies + writes the stamp (success)
            hook.run()  # second run: fingerprint matches stamp -> skip
        self.assertEqual(run.call_count, 1)

    def test_failed_apply_does_not_stamp_so_it_retries(self):
        # A non-zero apply (e.g. lost the lock) must NOT be recorded as handled.
        root = self._make_project()
        os.chdir(root)
        with mock.patch.object(hook, "_resolve_binary", return_value="/fake/socket-patch"), \
                mock.patch("subprocess.run", return_value=mock.Mock(returncode=1)) as run:
            hook.run()
            hook.run()
        self.assertEqual(run.call_count, 2, "a failed apply must be retried next start")

    def test_noop_without_manifest(self):
        root = self._mkdtemp()  # no .socket/manifest.json
        os.chdir(root)
        with mock.patch.object(hook, "_resolve_binary", return_value="/fake/socket-patch"), \
                mock.patch("subprocess.run") as run:
            hook.run()
        run.assert_not_called()

    def test_noop_when_binary_missing(self):
        root = self._make_project()
        os.chdir(root)
        with mock.patch.object(hook, "_resolve_binary", return_value=None), \
                mock.patch("subprocess.run") as run:
            hook.run()
        run.assert_not_called()


class TestDisableSwitches(HookTestBase):
    def test_socket_patch_hook_off(self):
        root = self._make_project()
        os.chdir(root)
        os.environ["SOCKET_PATCH_HOOK"] = "off"
        with mock.patch.object(hook, "_resolve_binary", return_value="/fake/socket-patch"), \
                mock.patch("subprocess.run") as run:
            hook.run()
        run.assert_not_called()

    def test_socket_no_hook(self):
        root = self._make_project()
        os.chdir(root)
        os.environ["SOCKET_NO_HOOK"] = "1"
        with mock.patch.object(hook, "_resolve_binary", return_value="/fake/socket-patch"), \
                mock.patch("subprocess.run") as run:
            hook.run()
        run.assert_not_called()

    def test_reentrancy_guard(self):
        root = self._make_project()
        os.chdir(root)
        os.environ[hook._REENTRANCY_ENV] = "1"
        with mock.patch.object(hook, "_resolve_binary", return_value="/fake/socket-patch"), \
                mock.patch("subprocess.run") as run:
            hook.run()
        run.assert_not_called()


class TestNeverRaises(HookTestBase):
    def test_run_swallows_resolver_errors(self):
        root = self._make_project()
        os.chdir(root)
        with mock.patch.object(hook, "_resolve_binary", side_effect=RuntimeError("boom")):
            # Must not propagate.
            hook.run()

    def test_run_swallows_subprocess_errors(self):
        root = self._make_project()
        os.chdir(root)
        with mock.patch.object(hook, "_resolve_binary", return_value="/fake/socket-patch"), \
                mock.patch("subprocess.run", side_effect=OSError("no such binary")):
            hook.run()  # must not raise

    def test_apply_timeout_is_swallowed(self):
        import subprocess

        root = self._make_project()
        os.chdir(root)
        with mock.patch.object(hook, "_resolve_binary", return_value="/fake/socket-patch"), \
                mock.patch(
                    "subprocess.run",
                    side_effect=subprocess.TimeoutExpired(cmd="x", timeout=1),
                ):
            hook.run()  # must not raise


class TestPthLine(unittest.TestCase):
    """The .pth one-liner must be valid Python and obey the kill switch."""

    def _pth_line(self):
        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(here, "socket_patch_hook.pth")) as f:
            return f.read().strip()

    def test_pth_line_executes_and_calls_run(self):
        line = self._pth_line()
        with mock.patch.object(hook, "run") as run:
            os.environ.pop("SOCKET_PATCH_HOOK", None)
            os.environ.pop("SOCKET_NO_HOOK", None)
            exec(compile(line, "socket_patch_hook.pth", "exec"), {})
        run.assert_called_once()

    def test_pth_line_respects_off_switch(self):
        line = self._pth_line()
        with mock.patch.object(hook, "run") as run:
            os.environ["SOCKET_PATCH_HOOK"] = "off"
            try:
                exec(compile(line, "socket_patch_hook.pth", "exec"), {})
            finally:
                os.environ.pop("SOCKET_PATCH_HOOK", None)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
