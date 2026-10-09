"""Exercise the workflow installers against a fake CDN and Apache archive.

The archive bytes must match the committed pin before extraction, even if
the download origin serves a matching checksum for substituted bytes.
"""

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).parents[2]
WORKFLOWS = ("ci.yml", "gradle-compatibility.yml")
VERSION = "3.9.16"
spec = importlib.util.spec_from_file_location("ci_maven_rows", Path(__file__).with_name("test_ci_vlt_rows.py"))
rows = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rows)


def installer(workflow):
    jobs = rows.jobs((ROOT / ".github/workflows" / workflow).read_text())
    step = next(text for job in jobs.values() for name, text in rows.steps(job)
                if name.startswith("Install Maven"))
    match = re.search(r"(?m)^        run: \|\n((?:          .*\n|\n)+)", step + "\n")
    return textwrap.dedent(match[1])


def archive_bytes(contents):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        for name in ("mvn", "mvn.cmd"):
            info = tarfile.TarInfo(f"apache-maven-{VERSION}/bin/{name}")
            info.size = len(contents)
            info.mode = 0o755
            archive.addfile(info, io.BytesIO(contents))
    return data.getvalue()


CURL = r'''
import hashlib, os, pathlib, sys
root = pathlib.Path(os.environ["FIXTURE_ROOT"])
mode = os.environ["FIXTURE_MODE"]
url = next(a for a in sys.argv if a.startswith("https://"))
dest = pathlib.Path(sys.argv[sys.argv.index("-o") + 1])
with (root / "requests").open("a") as log:
    log.write(url + "\n")
if mode == "both-fail" or ("repo.maven.apache.org" in url and mode in ("fallback", "corrupt-fallback")):
    dest.write_bytes(b"partial download")
    sys.exit(22)
payload = (root / ("tampered.tgz" if mode.startswith("corrupt-") else "fixture.tgz")).read_bytes()
if url.endswith(".sha512"):
    # An origin can replace both its tarball and its online digest.
    payload = hashlib.sha512(payload).hexdigest().encode()
dest.write_bytes(payload)
'''


class MavenDownload(unittest.TestCase):
    def test_every_matrix_version_has_a_sha512_pin(self):
        pins = json.loads((ROOT / "scripts/maven-sha512.json").read_text())
        for workflow in WORKFLOWS:
            text = (ROOT / ".github/workflows" / workflow).read_text()
            versions = re.findall(r"(?:maven|MAVEN_VERSION): '([^']+)'", text)
            self.assertTrue(versions)
            self.assertFalse(set(versions) - pins.keys(), f"unpinned Maven version in {workflow}")
        for version, digest in pins.items():
            self.assertRegex(digest, r"^[0-9a-f]{128}$", version)

    def test_workflow_downloads_fail_closed_before_extraction(self):
        for workflow in WORKFLOWS:
            script = installer(workflow)
            for runner_os in ("Linux", "Windows"):
                for mode in ("primary", "fallback", "corrupt-primary", "corrupt-fallback", "both-fail", "unpinned"):
                    with self.subTest(workflow=workflow, runner_os=runner_os, mode=mode):
                        self.check_installer(script, workflow, runner_os, mode)

    def check_installer(self, script, workflow, runner_os, mode):
        with tempfile.TemporaryDirectory(prefix="maven-download-") as directory:
            work = Path(directory)
            trusted = archive_bytes(b"trusted launcher\n")
            (work / "fixture.tgz").write_bytes(trusted)
            (work / "tampered.tgz").write_bytes(archive_bytes(b"substituted launcher\n"))
            (work / "scripts").mkdir()
            pins = {} if mode == "unpinned" else {VERSION: hashlib.sha512(trusted).hexdigest()}
            (work / "scripts/maven-sha512.json").write_text(json.dumps(pins))
            (work / "curl").write_text("#!" + sys.executable + "\n" + CURL)
            (work / "curl").chmod(0o755)
            (work / "python").symlink_to(sys.executable)
            github_env = work / "github-env"
            github_env.touch()
            env = dict(os.environ, PATH=str(work) + os.pathsep + os.environ["PATH"],
                       FIXTURE_ROOT=str(work), FIXTURE_MODE=mode, RUNNER_TEMP=str(work),
                       RUNNER_OS=runner_os, MAVEN_VERSION=VERSION, GITHUB_ENV=str(github_env),
                       PYTHONOPTIMIZE="1")  # Verification must not rely on assert.
            result = subprocess.run(["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", script],
                                    cwd=work, env=env, capture_output=True, text=True, timeout=30)
            requests = (work / "requests").read_text().splitlines()
            self.assertTrue(requests[0].startswith("https://repo.maven.apache.org/"))
            self.assertFalse(any(url.endswith(".sha512") for url in requests), requests)
            fallback = mode in ("fallback", "corrupt-fallback", "both-fail")
            self.assertEqual(len(requests), 2 if fallback else 1, requests)
            if fallback:
                self.assertEqual(requests[1], f"https://archive.apache.org/dist/maven/maven-3/{VERSION}/binaries/apache-maven-{VERSION}-bin.tar.gz")
            if mode in ("primary", "fallback"):
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                launcher = work / f"apache-maven-{VERSION}/bin" / ("mvn.cmd" if runner_os == "Windows" else "mvn")
                self.assertEqual(launcher.read_bytes(), b"trusted launcher\n")
                self.assertIn(f"SOCKET_PATCH_MAVEN_E2E_MVN={launcher}\n", github_env.read_text())
                if workflow == "gradle-compatibility.yml":
                    self.assertIn(f"SOCKET_PATCH_MAVEN_E2E_VERSION={VERSION}\n", github_env.read_text())
                    self.assertIn("SOCKET_PATCH_MAVEN_E2E_REQUIRED=1\n", github_env.read_text())
            else:
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertFalse((work / f"apache-maven-{VERSION}").exists())
                self.assertFalse(github_env.read_text())
                if mode.startswith("corrupt-"):
                    self.assertIn("SHA512 mismatch", result.stderr)


if __name__ == "__main__":
    unittest.main()
