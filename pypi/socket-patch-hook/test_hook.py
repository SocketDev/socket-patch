"""Tests for the socket-patch startup hook.

Run with: ``python -m unittest test_hook`` (no third-party deps required).

The overriding contract under test is *safety*: the hook must never raise, must
no-op cheaply when there is nothing to do, must invoke ``socket-patch apply``
with the right offline arguments only when the installed distributions have
changed, and must only ever apply the manifest of the project that owns this
environment (never a foreign one above the cwd).
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
        # Isolate env: clear switches + reentrancy + venv + cache redirect.
        self._saved_env = dict(os.environ)
        for k in ("SOCKET_PATCH_HOOK", "SOCKET_NO_HOOK", "VIRTUAL_ENV", hook._REENTRANCY_ENV):
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
    # These exercise the spawn/guard/stamp logic; project discovery is mocked
    # (it has its own tests in TestProjectRootDiscovery).
    def test_applies_when_manifest_present_and_state_changed(self):
        root = self._make_project()
        with mock.patch.object(hook, "_find_project_root", return_value=root), \
                mock.patch.object(hook, "_resolve_binary", return_value="/fake/socket-patch"), \
                mock.patch("subprocess.run", return_value=mock.Mock(returncode=0)) as run:
            hook.run()
        self.assertEqual(run.call_count, 1)
        argv = run.call_args[0][0]
        self.assertEqual(argv[0], "/fake/socket-patch")
        self.assertIn("apply", argv)
        self.assertIn("--offline", argv)
        self.assertIn("--silent", argv)
        self.assertEqual(argv[argv.index("--ecosystems") + 1], "pypi")
        self.assertEqual(
            os.path.realpath(argv[argv.index("--cwd") + 1]),
            os.path.realpath(root),
        )
        self.assertEqual(argv[argv.index("--lock-timeout") + 1], "0")
        env = run.call_args[1]["env"]
        self.assertEqual(env[hook._REENTRANCY_ENV], "1")

    def test_second_run_is_a_noop_when_state_unchanged(self):
        root = self._make_project()
        with mock.patch.object(hook, "_find_project_root", return_value=root), \
                mock.patch.object(hook, "_resolve_binary", return_value="/fake/socket-patch"), \
                mock.patch("subprocess.run", return_value=mock.Mock(returncode=0)) as run:
            hook.run()  # first run applies + writes the stamp (success)
            hook.run()  # second run: fingerprint matches stamp -> skip
        self.assertEqual(run.call_count, 1)

    def test_failed_apply_does_not_stamp_so_it_retries(self):
        root = self._make_project()
        with mock.patch.object(hook, "_find_project_root", return_value=root), \
                mock.patch.object(hook, "_resolve_binary", return_value="/fake/socket-patch"), \
                mock.patch("subprocess.run", return_value=mock.Mock(returncode=1)) as run:
            hook.run()
            hook.run()
        self.assertEqual(run.call_count, 2, "a failed apply must be retried next start")

    def test_noop_without_manifest(self):
        with mock.patch.object(hook, "_find_project_root", return_value=None), \
                mock.patch.object(hook, "_resolve_binary", return_value="/fake/socket-patch"), \
                mock.patch("subprocess.run") as run:
            hook.run()
        run.assert_not_called()

    def test_noop_when_binary_missing(self):
        root = self._make_project()
        with mock.patch.object(hook, "_find_project_root", return_value=root), \
                mock.patch.object(hook, "_resolve_binary", return_value=None), \
                mock.patch("subprocess.run") as run:
            hook.run()
        run.assert_not_called()


class TestDisableSwitches(HookTestBase):
    def _run_disabled(self):
        root = self._make_project()
        with mock.patch.object(hook, "_find_project_root", return_value=root), \
                mock.patch.object(hook, "_resolve_binary", return_value="/fake/socket-patch"), \
                mock.patch("subprocess.run") as run:
            hook.run()
        return run

    def test_socket_patch_hook_off(self):
        os.environ["SOCKET_PATCH_HOOK"] = "off"
        self._run_disabled().assert_not_called()

    def test_socket_no_hook(self):
        os.environ["SOCKET_NO_HOOK"] = "1"
        self._run_disabled().assert_not_called()

    def test_reentrancy_guard(self):
        os.environ[hook._REENTRANCY_ENV] = "1"
        self._run_disabled().assert_not_called()


class TestNeverRaises(HookTestBase):
    def test_run_swallows_resolver_errors(self):
        root = self._make_project()
        with mock.patch.object(hook, "_find_project_root", return_value=root), \
                mock.patch.object(hook, "_resolve_binary", side_effect=RuntimeError("boom")):
            hook.run()  # must not propagate

    def test_run_swallows_subprocess_errors(self):
        root = self._make_project()
        with mock.patch.object(hook, "_find_project_root", return_value=root), \
                mock.patch.object(hook, "_resolve_binary", return_value="/fake/socket-patch"), \
                mock.patch("subprocess.run", side_effect=OSError("no such binary")):
            hook.run()  # must not raise

    def test_apply_timeout_is_swallowed(self):
        import subprocess

        root = self._make_project()
        with mock.patch.object(hook, "_find_project_root", return_value=root), \
                mock.patch.object(hook, "_resolve_binary", return_value="/fake/socket-patch"), \
                mock.patch(
                    "subprocess.run",
                    side_effect=subprocess.TimeoutExpired(cmd="x", timeout=1),
                ):
            hook.run()  # must not raise

    def test_run_swallows_discovery_errors(self):
        with mock.patch.object(hook, "_find_project_root", side_effect=RuntimeError("boom")), \
                mock.patch("subprocess.run") as run:
            hook.run()  # must not raise
        run.assert_not_called()


class TestProjectRootDiscovery(HookTestBase):
    """The hook must apply only the manifest of the project that OWNS this
    environment — anchored to the venv, not whatever .socket/ sits above cwd."""

    def _socket(self, d):
        os.makedirs(os.path.join(d, ".socket"))
        with open(os.path.join(d, ".socket", "manifest.json"), "w") as f:
            f.write('{"patches": {}}')

    def test_anchors_to_venv_not_cwd(self):
        # venv at <proj>/.venv; manifest at <proj>; cwd is elsewhere.
        proj = os.path.join(self._tmp, "proj")
        self._socket(proj)
        venv = os.path.join(proj, ".venv")
        elsewhere = os.path.join(self._tmp, "elsewhere")
        os.makedirs(elsewhere)
        os.chdir(elsewhere)
        with mock.patch.object(sys, "prefix", venv), \
                mock.patch.object(sys, "base_prefix", self._tmp):  # in_venv = True
            got = hook._find_project_root()
        self.assertEqual(os.path.realpath(got), os.path.realpath(proj))

    def test_in_venv_ignores_unrelated_cwd_manifest(self):
        # SECURITY: a hostile .socket/ above the cwd must NOT be picked up when
        # running inside a venv whose project committed no manifest.
        proj = os.path.join(self._tmp, "proj")  # venv's project: NO .socket
        os.makedirs(proj)
        venv = os.path.join(proj, ".venv")
        attacker = os.path.join(self._tmp, "attacker")
        self._socket(attacker)
        os.chdir(attacker)
        with mock.patch.object(sys, "prefix", venv), \
                mock.patch.object(sys, "base_prefix", self._tmp):  # in_venv = True
            got = hook._find_project_root()
        self.assertIsNone(got, "must not apply a foreign manifest found above cwd")

    def test_system_python_falls_back_to_cwd(self):
        # No venv (sys.prefix == base_prefix): the container/system case, where
        # the project is wherever the process runs from.
        proj = os.path.join(self._tmp, "proj")
        self._socket(proj)
        os.chdir(proj)
        with mock.patch.object(sys, "prefix", "/usr"), \
                mock.patch.object(sys, "base_prefix", "/usr"):  # in_venv = False
            got = hook._find_project_root()
        self.assertEqual(os.path.realpath(got), os.path.realpath(proj))


class TestPthLine(unittest.TestCase):
    """The .pth must be valid: comment lines are ignored by site.py, the import
    line execs, and the kill switch short-circuits before importing."""

    def _pth_import_line(self):
        # site.py execs only lines starting with `import`; `#` lines are
        # comments. Mirror that: run the import line(s) the way site would.
        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(here, "socket_patch_hook.pth")) as f:
            lines = [
                ln.rstrip("\n")
                for ln in f
                if ln.strip() and not ln.lstrip().startswith("#")
            ]
        # Exactly one executable (import) line.
        assert len(lines) == 1, f"expected one import line, got {lines!r}"
        assert lines[0].startswith("import "), lines[0]
        return lines[0]

    def test_pth_line_executes_and_calls_run(self):
        line = self._pth_import_line()
        with mock.patch.object(hook, "run") as run:
            os.environ.pop("SOCKET_PATCH_HOOK", None)
            os.environ.pop("SOCKET_NO_HOOK", None)
            exec(compile(line, "socket_patch_hook.pth", "exec"), {})
        run.assert_called_once()

    def test_pth_line_respects_off_switch(self):
        line = self._pth_import_line()
        with mock.patch.object(hook, "run") as run:
            os.environ["SOCKET_PATCH_HOOK"] = "off"
            try:
                exec(compile(line, "socket_patch_hook.pth", "exec"), {})
            finally:
                os.environ.pop("SOCKET_PATCH_HOOK", None)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
