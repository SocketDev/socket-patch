import ast
import os
import stat
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

# Import the module source for inspection
INIT_PATH = Path(__file__).parent / "socket_patch" / "__init__.py"
INIT_SRC = INIT_PATH.read_text()


class TestInitModule(unittest.TestCase):
    """Test that __init__.py correctly finds and runs the single binary."""

    def test_source_parses(self):
        """Verify __init__.py is valid Python."""
        ast.parse(INIT_SRC)

    def test_main_defined(self):
        """Verify main() function exists."""
        tree = ast.parse(INIT_SRC)
        func_names = [
            node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
        ]
        self.assertIn("main", func_names)

    def test_dispatches_single_binary(self):
        """main() should find the single binary in bin/ and call it."""
        with tempfile.TemporaryDirectory() as tmpdir:
            bin_dir = os.path.join(tmpdir, "bin")
            os.makedirs(bin_dir)
            fake_bin = os.path.join(bin_dir, "socket-patch-test")
            Path(fake_bin).write_text("#!/bin/sh\nexit 0\n")
            os.chmod(fake_bin, os.stat(fake_bin).st_mode | stat.S_IEXEC)

            with mock.patch("socket_patch.os.path.dirname", return_value=tmpdir):
                with mock.patch("socket_patch.subprocess.call", return_value=42) as mock_call:
                    with self.assertRaises(SystemExit) as cm:
                        import socket_patch

                        socket_patch.main()
                    self.assertEqual(cm.exception.code, 42)
                    mock_call.assert_called_once()
                    called_args = mock_call.call_args[0][0]
                    self.assertEqual(called_args[0], fake_bin)

    def test_errors_on_no_binary(self):
        """main() should exit with error if no binary found."""
        with tempfile.TemporaryDirectory() as tmpdir:
            bin_dir = os.path.join(tmpdir, "bin")
            os.makedirs(bin_dir)

            with mock.patch("socket_patch.os.path.dirname", return_value=tmpdir):
                with self.assertRaises(SystemExit) as cm:
                    import socket_patch

                    socket_patch.main()
                self.assertEqual(cm.exception.code, 1)

    def test_errors_on_multiple_binaries(self):
        """main() should exit with error if multiple binaries found."""
        with tempfile.TemporaryDirectory() as tmpdir:
            bin_dir = os.path.join(tmpdir, "bin")
            os.makedirs(bin_dir)
            Path(os.path.join(bin_dir, "socket-patch-a")).touch()
            Path(os.path.join(bin_dir, "socket-patch-b")).touch()

            with mock.patch("socket_patch.os.path.dirname", return_value=tmpdir):
                with self.assertRaises(SystemExit) as cm:
                    import socket_patch

                    socket_patch.main()
                self.assertEqual(cm.exception.code, 1)

    def test_errors_on_missing_bin_dir(self):
        """main() should exit with error if bin/ dir doesn't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Don't create bin_dir
            with mock.patch("socket_patch.os.path.dirname", return_value=tmpdir):
                with self.assertRaises(SystemExit) as cm:
                    import socket_patch

                    socket_patch.main()
                self.assertEqual(cm.exception.code, 1)


class TestWheelBuilder(unittest.TestCase):
    """Test the wheel builder script configuration."""

    def test_wheel_builder_exists(self):
        """Verify the wheel builder script exists."""
        script_path = Path(__file__).parent.parent.parent / "scripts" / "build-pypi-wheels.py"
        self.assertTrue(script_path.exists(), f"Wheel builder script not found at {script_path}")

    def test_wheel_builder_parses(self):
        """Verify the wheel builder script is valid Python."""
        script_path = Path(__file__).parent.parent.parent / "scripts" / "build-pypi-wheels.py"
        ast.parse(script_path.read_text())

    def test_wheel_builder_targets(self):
        """Verify the wheel builder covers all expected targets."""
        script_path = Path(__file__).parent.parent.parent / "scripts" / "build-pypi-wheels.py"
        src = script_path.read_text()

        expected_targets = [
            "aarch64-apple-darwin",
            "x86_64-apple-darwin",
            "x86_64-unknown-linux-musl",
            "aarch64-unknown-linux-gnu",
            "arm-unknown-linux-gnueabihf",
            "i686-unknown-linux-gnu",
            "x86_64-pc-windows-msvc",
            "i686-pc-windows-msvc",
            "aarch64-pc-windows-msvc",
        ]
        for target in expected_targets:
            self.assertIn(target, src, f"Target {target} missing from wheel builder")

        # Android should NOT be in the targets
        self.assertNotIn('"aarch64-linux-android"', src)


if __name__ == "__main__":
    unittest.main()
