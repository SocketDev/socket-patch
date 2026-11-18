"""scripts/container-jdk.sh against a fake docker, and its wiring in ci.yml.

The script gives the Maven production legs a Java 6 `java` and `javac` that
run in a pinned container image. It must never fail the job when the image
is unavailable (exit 3 tells the step to leave Java 6 out), and the tools it
generates must run bounded, offline and with only the legs' temp directory
mounted.
"""

import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).parents[2]
SCRIPT = ROOT / "scripts/container-jdk.sh"
IMAGE = "example/jdk@sha256:" + "ab" * 32
spec = importlib.util.spec_from_file_location("ci_rows", Path(__file__).with_name("test_ci_vlt_rows.py"))
rows = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rows)

# Logs each call; `FIXTURE_MODE` names the docker subcommand that fails.
DOCKER = r'''
import os, pathlib, sys
with (pathlib.Path(os.environ["FIXTURE_ROOT"]) / "docker.log").open("a") as log:
    log.write("\t".join(sys.argv[1:]) + "\n")
verb = " ".join(sys.argv[1:3]) if sys.argv[1] == "image" else sys.argv[1]
fails = os.environ["FIXTURE_MODE"].split(",")
if verb in fails:
    sys.exit(1)
if verb == "run":
    sys.stderr.write('openjdk version "1.6.0-119"\n')
'''
# What the script and the tools it writes need on PATH, besides docker.
TOOLS = ("bash", "cat", "chmod", "grep", "id", "mkdir", "perl", "sed")


class ContainerJdk(unittest.TestCase):
    def run_script(self, mode, image=IMAGE, docker=True):
        directory = tempfile.TemporaryDirectory(prefix="container-jdk-")
        self.addCleanup(directory.cleanup)
        self.work = Path(directory.name).resolve()
        tools = self.work / "tools"
        tools.mkdir()
        for tool in TOOLS:
            (tools / tool).symlink_to(shutil.which(tool))
        if docker:
            (tools / "docker").write_text("#!" + sys.executable + "\n" + DOCKER)
            (tools / "docker").chmod(0o755)
        self.env = dict(os.environ, PATH=str(tools), FIXTURE_ROOT=str(self.work), FIXTURE_MODE=mode)
        self.mount = self.work / "legs tmp"
        return subprocess.run([str(SCRIPT), image, str(self.work / "jdk"), str(self.mount)],
                              env=self.env, capture_output=True, text=True, timeout=60)

    def calls(self):
        log = self.work / "docker.log"
        return [line.split("\t") for line in log.read_text().splitlines()] if log.exists() else []

    def test_a_present_image_is_not_pulled_and_the_tools_run_in_it(self):
        result = self.run_script("")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "", "stdout stays empty: steps redirect installers into $GITHUB_ENV")
        self.assertEqual([call[0] for call in self.calls()], ["image", "run"])
        self.assertIn('openjdk version "1.6.0-119"', result.stderr)
        cwd = self.mount / "drop-in"
        cwd.mkdir()
        (self.work / "docker.log").unlink()
        tool = subprocess.run([str(self.work / "jdk/bin/javac"), "-d", "classes 6", "DropIn.java"],
                              cwd=cwd, env=self.env, capture_output=True, text=True, timeout=60)
        self.assertEqual(tool.returncode, 0, tool.stderr)
        self.assertEqual(self.calls(), [[
            "run", "--rm", "--pull=never", "--network", "none", "--platform", "linux/amd64",
            "--user", f"{os.getuid()}:{os.getgid()}", "-v", f"{self.mount}:{self.mount}", "-w", str(cwd),
            IMAGE, "timeout", "300", "javac", "-d", "classes 6", "DropIn.java",
        ]])
        for name in ("java", "javac"):
            self.assertTrue(os.access(self.work / "jdk/bin" / name, os.X_OK), name)

    def test_a_missing_image_is_pulled_by_digest(self):
        result = self.run_script("image inspect")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls()[1], ["pull", "--quiet", "--platform", "linux/amd64", IMAGE])

    def test_an_unavailable_image_is_a_soft_skip(self):
        for mode, said in (("image inspect,pull", "could not pull"), ("run", "does not run here")):
            with self.subTest(mode=mode):
                result = self.run_script(mode)
                self.assertEqual(result.returncode, 3, result.stderr)
                self.assertIn(said, result.stderr)
        result = self.run_script("", docker=False)
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertIn("docker is not installed", result.stderr)

    def test_an_image_without_a_digest_is_refused_before_docker_runs(self):
        for image in ("azul/zulu-openjdk:6", "azul/zulu-openjdk@sha256:abc", IMAGE + "0"):
            with self.subTest(image=image):
                result = self.run_script("", image=image)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(self.calls(), [])


class MavenLegsWiring(unittest.TestCase):
    hosted = rows.jobs((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))["hosted-e2e"]

    def test_java_6_is_pinned_and_never_fails_the_job(self):
        step = rows.step(self.hosted, "Add Java 6 in a container (Maven legs)")
        self.assertRegex(step, r"JAVA_6_IMAGE: \S+@sha256:[0-9a-f]{64}\n")
        self.assertIn('scripts/container-jdk.sh "$JAVA_6_IMAGE" "$RUNNER_TEMP/jdk-6" "$RUNNER_TEMP/maven-e2e" '
                      "|| status=$?", step)
        soft_skip = step[step.index("            3)"):step.index("            *)")]
        self.assertIn("::warning ", soft_skip)
        self.assertNotIn("exit", soft_skip)
        self.assertNotIn("GITHUB_ENV", soft_skip)

    def test_the_three_legs_run_in_their_own_step(self):
        main = rows.step(self.hosted, "Run hosted-mode production e2e")
        self.assertIn("--skip maven_", main)
        maven = rows.step(self.hosted, "Run Maven production e2e (hosted, vendored, agent)")
        self.assertIn("if: steps.gate.outputs.run == 'true'", maven)
        self.assertIn("--test e2e_hosted_production --test e2e_vendored_production", maven)
        self.assertIn("--ignored maven_", maven)
        for flag in ("SOCKET_PATCH_HOSTED_E2E_STRICT: '1'", "SOCKET_PATCH_VENDORED_E2E_STRICT: '1'"):
            self.assertIn(flag, maven)
        # The legs' temp directory is the directory the Java 6 container mounts.
        self.assertIn('export TMPDIR="$RUNNER_TEMP/maven-e2e"', maven)
        # Every leg must have run, and the check must not depend on where
        # libtest put its own `test <name> ... ` prefix.
        self.assertIn("for mode in hosted vendored agent; do", maven)
        self.assertIn('grep -q "MAVEN-PROD mode=$mode .* step=remove pass"', maven)
        fixture = (ROOT / "crates/socket-patch-cli/tests/maven_production/mod.rs").read_text(encoding="utf-8")
        self.assertIn('"MAVEN-PROD mode={} maven={} step={step} pass ({detail})"', fixture)
        self.assertIn('&original_class, "remove");', fixture)


if __name__ == "__main__":
    unittest.main()
