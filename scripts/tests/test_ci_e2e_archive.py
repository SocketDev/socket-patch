"""Run CI's real archive commands and check binary/permission round trips."""

import importlib.util
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest
import zipfile

ROOT = Path(__file__).parents[2]
spec = importlib.util.spec_from_file_location("archive_rows", Path(__file__).with_name("test_ci_vlt_rows.py"))
rows = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rows)
JOBS = rows.jobs((ROOT / ".github/workflows/ci.yml").read_text())


def commands(name):
    scripts = []
    for job in JOBS.values():
        for step_name, step in rows.steps(job):
            if step_name == name:
                match = re.search(r"(?m)^        run: \|\n((?:          .*\n|\n)+)", step + "\n")
                scripts.append(textwrap.dedent(match[1]))
    return scripts


def run(script, work):
    return subprocess.run(["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", script],
                          cwd=work, capture_output=True, text=True, timeout=30)


@unittest.skipUnless(shutil.which("zstd"), "zstd is required for the CI archive round trip")
class E2eArchive(unittest.TestCase):
    def test_all_consumers_restore_every_binary_and_its_permissions(self):
        pack = commands("Compress the e2e binaries")
        unpack = commands("Unpack the e2e binaries")
        self.assertTrue(pack)
        self.assertTrue(unpack)
        for compressor in pack:
            for consumer in unpack:
                with self.subTest(consumer=consumer), tempfile.TemporaryDirectory(prefix="e2e-archive-") as directory:
                    work = Path(directory)
                    bundle = work / "target/e2e-bin"
                    bundle.mkdir(parents=True)
                    # Both native Unix and Windows names must survive unchanged.
                    files = {
                        "socket-patch": (b"\x7fELF\x00cli fixture\xff", 0o755),
                        "socket-patch.exe": (b"MZ\x00windows fixture\xff", 0o755),
                        "e2e_redirect_gradle_build": (bytes(range(256)) * 4096, 0o555),
                        "e2e_vendor_jvm_build.exe": (b"MZ\x00test fixture\x80", 0o755),
                    }
                    for name, (payload, mode) in files.items():
                        path = bundle / name
                        path.write_bytes(payload)
                        path.chmod(mode)
                    result = run(compressor, work)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    archive = work / "target/e2e-bin.tar.zst"
                    # upload-artifact stores the compressed tar in a ZIP, then
                    # download-artifact extracts it into target/e2e-archive.
                    transport = work / "artifact.zip"
                    with zipfile.ZipFile(transport, "w", compression=zipfile.ZIP_STORED) as uploaded:
                        uploaded.write(archive, arcname=archive.name)
                    shutil.rmtree(bundle)
                    archive.unlink()
                    with zipfile.ZipFile(transport) as downloaded:
                        downloaded.extractall(work / "target/e2e-archive")
                    result = run(consumer, work)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual({path.name for path in bundle.iterdir()}, set(files))
                    for name, (payload, mode) in files.items():
                        path = bundle / name
                        self.assertEqual(path.read_bytes(), payload, name)
                        if os.name != "nt":
                            self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode, name)

    def test_missing_bundle_fails_even_when_compressor_accepts_empty_input(self):
        for compressor in commands("Compress the e2e binaries"):
            with tempfile.TemporaryDirectory(prefix="e2e-no-bundle-") as directory:
                work = Path(directory)
                (work / "target").mkdir()
                self.assertNotEqual(run(compressor, work).returncode, 0)

    def test_corrupt_archive_fails_the_consumer_step(self):
        for consumer in commands("Unpack the e2e binaries"):
            with tempfile.TemporaryDirectory(prefix="e2e-bad-archive-") as directory:
                work = Path(directory)
                archive_dir = work / "target/e2e-archive"
                archive_dir.mkdir(parents=True)
                (archive_dir / "e2e-bin.tar.zst").write_bytes(b"not a zstd archive")
                self.assertNotEqual(run(consumer, work).returncode, 0)


if __name__ == "__main__":
    unittest.main()
