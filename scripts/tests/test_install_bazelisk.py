"""scripts/bazel-pins.txt and scripts/install-bazelisk.sh: every pinned
version has a pin for each platform CI runs it on (so a cell on an unpinned
version fails here before it fails in CI), and the installer fails closed.
The installer cases run a copy of the script beside a synthetic pins file,
with a stub `curl` first on PATH: no test touches the network."""

import hashlib
import os
import platform
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).parents[1]
PINS = SCRIPTS / "bazel-pins.txt"
INSTALLER = SCRIPTS / "install-bazelisk.sh"

# The platforms the CI cells run on, in Bazel's release-file spelling.
PLATFORMS = {"linux-x86_64", "darwin-arm64", "windows-x86_64"}
# The lines the plan runs cells on (DESIGN 9.4).
BAZEL_VERSIONS = {
    "5.4.1", "6.6.0", "7.0.2", "7.1.2", "7.7.2", "8.4.2", "8.8.2", "9.3.2", "10.0.0rc3",
}

FAKE_CURL = r"""#!/usr/bin/env bash
url=""; dest=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) dest="$2"; shift 2 ;;
    --retry) shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
echo "$url" >>"$FAKE_CURL_LOG"
body="$FAKE_CURL_DIR/$(printf %s "$url" | tr ':/' '__')"
[ -f "$body" ] || exit 22
cp "$body" "$dest"
"""

# `uname` as another machine reports it: the installer then looks for that
# platform's pins, whatever host the test runs on.
FAKE_UNAME = r"""#!/usr/bin/env bash
case "${1:-}" in
  -s) echo "$FAKE_UNAME_S" ;;
  -m) echo "$FAKE_UNAME_M" ;;
  *) echo "unexpected uname $*" >&2; exit 64 ;;
esac
"""


def read_pins(path=PINS):
    pins = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.startswith("#"):
            pins.append(line.split())
    return pins


def host_platform():
    system = {"Linux": "linux", "Darwin": "darwin"}.get(platform.system(), platform.system())
    machine = platform.machine().lower()
    arch = {"amd64": "x86_64", "aarch64": "arm64"}.get(machine, machine)
    return f"{system}-{arch}"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


class PinsFileTest(unittest.TestCase):
    def test_every_line_is_tool_version_platform_sha256(self):
        seen = set()
        for pin in read_pins():
            self.assertEqual(len(pin), 4, pin)
            tool, version, plat, digest = pin
            self.assertIn(tool, {"bazel", "bazelisk"}, pin)
            self.assertIn(plat, PLATFORMS, pin)
            self.assertRegex(digest, r"^[0-9a-f]{64}$", pin)
            self.assertNotIn((tool, version, plat), seen, f"duplicate pin {pin}")
            seen.add((tool, version, plat))

    def test_every_version_has_all_its_platform_pins(self):
        by_version = {}
        for tool, version, plat, _ in read_pins():
            by_version.setdefault((tool, version), set()).add(plat)
        for (tool, version), plats in sorted(by_version.items()):
            # A pre-release runs record-only cells on ubuntu alone.
            want = {"linux-x86_64"} if "rc" in version else PLATFORMS
            self.assertEqual(plats, want, f"{tool} {version} is pinned for {sorted(plats)}")

    def test_the_planned_lines_and_the_installers_bazelisk_are_pinned(self):
        pins = read_pins()
        self.assertEqual({v for t, v, _, _ in pins if t == "bazel"}, BAZEL_VERSIONS)
        # 7.7.0 alone writes absolute file:/// registry keys into the lock.
        self.assertNotIn("7.7.0", BAZEL_VERSIONS)
        wanted = re.search(r"^BAZELISK_VERSION=(\S+)$", INSTALLER.read_text(encoding="utf-8"), re.M)
        self.assertEqual({v for t, v, _, _ in pins if t == "bazelisk"}, {wanted.group(1)})

    def test_no_two_pins_share_a_digest(self):
        digests = [pin[3] for pin in read_pins()]
        self.assertEqual(len(digests), len(set(digests)), "a digest was pasted twice")


@unittest.skipIf(os.name == "nt" or shutil.which("bash") is None, "needs a POSIX bash")
class InstallerTest(unittest.TestCase):
    BAZEL = b"synthetic bazel release binary\n"
    BAZELISK = b"synthetic bazelisk release binary\n"

    def setUp(self):
        # Resolved: the installer prints `pwd` of the target directory.
        self.tmp = Path(tempfile.mkdtemp(prefix="install-bazelisk-test-")).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        (self.tmp / "scripts").mkdir()
        self.script = self.tmp / "scripts" / "install-bazelisk.sh"
        shutil.copy(INSTALLER, self.script)
        self.bodies = self.tmp / "bodies"
        self.bodies.mkdir()
        self.log = self.tmp / "curl.log"
        self.log.write_text("")
        bin_dir = self.tmp / "bin"
        bin_dir.mkdir()
        curl = bin_dir / "curl"
        curl.write_text(FAKE_CURL)
        curl.chmod(curl.stat().st_mode | stat.S_IXUSR)
        self.env = dict(os.environ, PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
                        FAKE_CURL_LOG=str(self.log), FAKE_CURL_DIR=str(self.bodies))
        self.plat = host_platform()
        self.dest = self.tmp / "dest"
        self.write_pins([
            ("bazelisk", "v1.30.0", self.plat, sha256(self.BAZELISK)),
            ("bazel", "9.3.2", self.plat, sha256(self.BAZEL)),
            ("bazel", "10.0.0rc3", self.plat, sha256(self.BAZEL)),
        ])

    def write_pins(self, pins, newline="\n"):
        text = "# synthetic\n" + "".join(" ".join(pin) + "\n" for pin in pins)
        (self.tmp / "scripts" / "bazel-pins.txt").write_bytes(text.replace("\n", newline).encode())

    def serve(self, url, body):
        (self.bodies / url.replace(":", "_").replace("/", "_")).write_bytes(body)

    def run_installer(self, version="9.3.2", script=None, uname=None):
        env = self.env
        if uname:
            # A `uname` stub first on PATH: (`uname -s`, `uname -m`).
            bin_dir = self.tmp / "uname-bin"
            bin_dir.mkdir(exist_ok=True)
            stub = bin_dir / "uname"
            stub.write_text(FAKE_UNAME)
            stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
            env = dict(env, PATH=f"{bin_dir}{os.pathsep}{env['PATH']}",
                       FAKE_UNAME_S=uname[0], FAKE_UNAME_M=uname[1])
        return subprocess.run(["bash", str(script or self.script), version, str(self.dest)],
                              env=env, capture_output=True, text=True, check=False)

    def requests(self):
        return self.log.read_text().split()

    def urls(self, version="9.3.2"):
        arch = "amd64" if self.plat.endswith("x86_64") else "arm64"
        name = f"bazel-{version}-{self.plat}"
        return (
            f"https://github.com/bazelbuild/bazelisk/releases/download/v1.30.0/bazelisk-{self.plat.split('-')[0]}-{arch}",
            f"https://github.com/bazelbuild/bazel/releases/download/{version}/{name}",
            f"https://releases.bazel.build/{version}/release/{name}",
        )

    def expected_stdout(self, version="9.3.2"):
        dest = self.dest
        bazel = dest / f"bazel-{version}-{self.plat}"
        return (f"SOCKET_PATCH_BAZEL_E2E_BAZEL={bazel}\nSOCKET_PATCH_BAZEL_E2E_BINARY={bazel}\n"
                f"SOCKET_PATCH_BAZEL_E2E_BAZELISK={dest / f'bazelisk-v1.30.0-{self.plat}'}\n"
                f"SOCKET_PATCH_BAZEL_E2E_VERSION={version}\n")

    def test_downloads_verifies_and_prints_the_four_variables(self):
        bazelisk_url, bazel_url, _ = self.urls()
        self.serve(bazelisk_url, self.BAZELISK)
        self.serve(bazel_url, self.BAZEL)
        done = self.run_installer()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout, self.expected_stdout())
        self.assertEqual(self.requests(), [bazelisk_url, bazel_url])
        for name in (f"bazel-9.3.2-{self.plat}", f"bazelisk-v1.30.0-{self.plat}"):
            self.assertTrue(os.access(self.dest / name, os.X_OK), name)
        self.assertEqual(sorted(p.name for p in self.dest.iterdir()),
                         [f"bazel-9.3.2-{self.plat}", f"bazelisk-v1.30.0-{self.plat}"])

    def test_files_that_match_their_pins_are_reused_without_a_download(self):
        self.dest.mkdir()
        (self.dest / f"bazelisk-v1.30.0-{self.plat}").write_bytes(self.BAZELISK)
        (self.dest / f"bazel-9.3.2-{self.plat}").write_bytes(self.BAZEL)
        # A CRLF checkout of the pins file must still resolve.
        self.write_pins(read_pins(self.tmp / "scripts" / "bazel-pins.txt"), newline="\r\n")
        done = self.run_installer()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout, self.expected_stdout())
        self.assertEqual(self.requests(), [])

    def test_a_cached_file_that_does_not_match_is_replaced(self):
        bazelisk_url, bazel_url, _ = self.urls()
        self.serve(bazelisk_url, self.BAZELISK)
        self.serve(bazel_url, self.BAZEL)
        self.dest.mkdir()
        stale = self.dest / f"bazel-9.3.2-{self.plat}"
        stale.write_bytes(b"truncated")
        self.assertEqual(self.run_installer().returncode, 0)
        self.assertEqual(stale.read_bytes(), self.BAZEL)

    def test_a_download_that_does_not_match_its_pin_is_never_installed(self):
        bazelisk_url, bazel_url, mirror_url = self.urls()
        self.serve(bazelisk_url, self.BAZELISK)
        self.serve(bazel_url, self.BAZEL + b"tampered")
        self.serve(mirror_url, b"")
        done = self.run_installer()
        self.assertNotEqual(done.returncode, 0)
        self.assertEqual(done.stdout, "")
        self.assertIn("sha256 mismatch", done.stderr)
        # Both origins were tried, GitHub first, and nothing was left behind.
        self.assertEqual(self.requests(), [bazelisk_url, bazel_url, mirror_url])
        self.assertEqual([p.name for p in self.dest.iterdir()], [f"bazelisk-v1.30.0-{self.plat}"])

    def test_the_second_origin_serves_when_github_fails(self):
        bazelisk_url, bazel_url, mirror_url = self.urls()
        self.serve(bazelisk_url, self.BAZELISK)
        self.serve(mirror_url, self.BAZEL)
        done = self.run_installer()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(self.requests(), [bazelisk_url, bazel_url, mirror_url])

    def test_a_release_candidate_uses_the_rc_directory_of_the_mirror(self):
        bazelisk_url, _, _ = self.urls()
        self.serve(bazelisk_url, self.BAZELISK)
        mirror = f"https://releases.bazel.build/10.0.0/rc3/bazel-10.0.0rc3-{self.plat}"
        self.serve(mirror, self.BAZEL)
        done = self.run_installer("10.0.0rc3")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout, self.expected_stdout("10.0.0rc3"))
        self.assertEqual(self.requests()[-1], mirror)

    def test_an_unpinned_version_fails_closed_before_any_download(self):
        # The committed script and pins file, as CI runs them. On every
        # platform the message names the Bazel version that was asked for:
        # on one with all its pins (as a CI runner reports itself), and on
        # one with no pin at all, not even for bazelisk (a developer's
        # linux-arm64 or darwin-x86_64 machine).
        machines = {"linux-x86_64": ("Linux", "x86_64"), "darwin-arm64": ("Darwin", "arm64"),
                    "windows-x86_64": ("MINGW64_NT-10.0-20348", "x86_64"),
                    "linux-arm64": ("Linux", "aarch64"), "darwin-x86_64": ("Darwin", "x86_64")}
        self.assertLessEqual(PLATFORMS, set(machines))
        pinned = {plat for tool, _, plat, _ in read_pins() if tool == "bazelisk"}
        self.assertFalse({"linux-arm64", "darwin-x86_64"} & pinned, "pick platforms with no pin")
        for plat, uname in [(self.plat, None), *sorted(machines.items())]:
            for version in ("0.0.0", "7.7.0"):
                with self.subTest(platform=plat, version=version):
                    done = self.run_installer(version, script=INSTALLER, uname=uname)
                    self.assertNotEqual(done.returncode, 0)
                    self.assertEqual(done.stdout, "")
                    self.assertIn(f"no pinned sha256 for bazel {version} on {plat}", done.stderr)
        self.assertEqual(self.requests(), [])
        self.assertFalse(self.dest.exists(), "the target directory must not be created")

    def test_an_unpinned_platform_or_an_ambiguous_pin_fails_closed(self):
        other = next(iter(PLATFORMS - {self.plat}))
        ambiguous = [("bazelisk", "v1.30.0", self.plat, sha256(self.BAZELISK)),
                     ("bazel", "9.3.2", self.plat, sha256(self.BAZEL)),
                     ("bazel", "9.3.2", self.plat, sha256(b"another"))]
        for pins in ([("bazelisk", "v1.30.0", other, sha256(self.BAZELISK)),
                      ("bazel", "9.3.2", other, sha256(self.BAZEL))], ambiguous):
            self.write_pins(pins)
            done = self.run_installer()
            self.assertNotEqual(done.returncode, 0, pins)
            self.assertIn("no pinned sha256", done.stderr)
        self.assertEqual(self.requests(), [])

    def test_a_malformed_version_is_refused(self):
        for version in ("9.3", "latest", "9.3.2 ", "9.3.2/../x", "v9.3.2"):
            done = self.run_installer(version)
            self.assertNotEqual(done.returncode, 0, version)
            self.assertIn("is not a Bazel version", done.stderr)
        self.assertEqual(self.requests(), [])


if __name__ == "__main__":
    unittest.main()
