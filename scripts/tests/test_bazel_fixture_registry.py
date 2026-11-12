"""scripts/bazel-fixture-registry.py and the tree it keeps
(crates/socket-patch-cli/tests/fixtures/bazel/registry): the committed
registry subset is exactly what each Bazel version's committed lock pins,
the zero-network cells have their archives, and the check notices every
kind of drift. No test here runs Bazel or touches the network."""

import base64
import hashlib
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


tool = load("bazel_fixture_registry", SCRIPTS / "bazel-fixture-registry.py")
FIXTURES = tool.FIXTURES
MANIFEST = json.loads((FIXTURES / "registry/MANIFEST.json").read_text(encoding="utf-8"))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sri(data):
    return "sha256-" + base64.b64encode(hashlib.sha256(data).digest()).decode()


class CommittedTree(unittest.TestCase):
    def test_the_committed_tree_is_sound(self):
        self.assertEqual(tool.check(), [])

    def test_every_file_a_lock_pins_is_mirrored_with_that_digest(self):
        """Read straight from the locks, not through the tool's own table."""
        registry = FIXTURES / "registry"
        for version, entry in MANIFEST["versions"].items():
            lock = json.loads((FIXTURES / entry["lock"]).read_text(encoding="utf-8"))
            pins = lock["registryFileHashes"]
            self.assertGreater(len(pins), 50, f"Bazel {version}")
            for url, pinned in pins.items():
                rel = url.removeprefix("https://bcr.bazel.build/")
                self.assertNotEqual(rel, url, url)
                self.assertEqual(digest((registry / rel).read_bytes()), pinned, f"Bazel {version}: {rel}")

    def test_a_version_is_pinned_and_its_lock_is_the_fixtures_own(self):
        pins = (SCRIPTS / "bazel-pins.txt").read_text(encoding="utf-8")
        for version, entry in MANIFEST["versions"].items():
            self.assertIn(f"bazel {version} ", pins)
            era = f"e{version.split('.')[0]}"
            self.assertRegex(entry["lock"], rf"^core/bzlmod/{era}/locks/v\d+/MODULE\.bazel\.lock$")
            lock = json.loads((FIXTURES / entry["lock"]).read_text(encoding="utf-8"))
            self.assertEqual(entry["lock"].split("/")[4], f"v{lock['lockFileVersion']}")
            # A lock made against a file:// registry or a loopback server
            # would pin nothing a production registry serves.
            self.assertNotRegex(json.dumps(lock), r"file://|127\.0\.0\.1|localhost")

    def test_a_cell_without_network_has_its_archives_committed(self):
        matrix = json.loads((FIXTURES / "core/MATRIX.json").read_text(encoding="utf-8"))
        for cell in matrix["cells"]:
            entry = MANIFEST["versions"].get(cell["bazel"])
            self.assertIsNotNone(entry, f"Bazel {cell['bazel']} has a core cell and no registry files")
            self.assertEqual(cell["network"] == "none", entry["distdir"], cell["bazel"])
            for archive in entry["archives"] if entry["distdir"] else []:
                path = FIXTURES / "registry/distdir" / cell["bazel"] / archive["file"]
                self.assertEqual(digest(path.read_bytes()), archive["sha256"])
                self.assertEqual(path.stat().st_size, archive["bytes"])


class Drift(unittest.TestCase):
    """`check` over a copy of the committed tree with one thing wrong."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        shutil.copytree(FIXTURES / "registry", self.tmp / "registry")
        for entry in MANIFEST["versions"].values():
            (self.tmp / entry["lock"]).parent.mkdir(parents=True)
            shutil.copyfile(FIXTURES / entry["lock"], self.tmp / entry["lock"])
        self.registry = self.tmp / "registry"
        self.assertEqual(tool.check(self.tmp), [])

    def problems(self):
        return "\n".join(tool.check(self.tmp))

    def test_a_changed_registry_file(self):
        target = self.registry / "modules/platforms/1.0.0/MODULE.bazel"
        target.write_bytes(target.read_bytes() + b"\n")
        self.assertRegex(self.problems(), r"modules/platforms/1\.0\.0/MODULE\.bazel: sha256 \w+, expected")

    def test_a_missing_registry_file(self):
        (self.registry / "bazel_registry.json").unlink()
        self.assertIn("bazel_registry.json: missing", self.problems())

    def test_a_file_nothing_accounts_for(self):
        (self.registry / "modules/platforms/1.0.0/extra.bzl").write_text("x = 1\n")
        self.assertIn("modules/platforms/1.0.0/extra.bzl: no lock or source.json", self.problems())

    def test_a_changed_archive(self):
        archive = self.registry / "distdir/9.3.2/platforms-1.0.0.tar.gz"
        data = archive.read_bytes()
        archive.write_bytes(data[:-1] + bytes([data[-1] ^ 0xFF]))
        self.assertIn("distdir/9.3.2/platforms-1.0.0.tar.gz: sha256", self.problems())

    def test_a_lock_that_pins_other_bytes(self):
        lock_path = self.tmp / MANIFEST["versions"]["7.7.2"]["lock"]
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        url = "https://bcr.bazel.build/modules/platforms/0.0.10/MODULE.bazel"
        lock["registryFileHashes"][url] = "0" * 64
        lock_path.write_text(json.dumps(lock))
        self.assertIn("modules/platforms/0.0.10/MODULE.bazel: sha256", self.problems())

    def test_a_lock_made_without_the_central_registry(self):
        lock_path = self.tmp / MANIFEST["versions"]["7.7.2"]["lock"]
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        lock["registryFileHashes"] = {}
        lock_path.write_text(json.dumps(lock))
        self.assertIn("Bazel 7.7.2", self.problems())
        self.assertIn("no registryFileHashes", self.problems())

    def test_sums_that_do_not_list_the_tree(self):
        sums = self.registry / "SHA256SUMS"
        sums.write_text(sums.read_text().replace("bazel_registry.json", "bazel_registry.json.bak"))
        self.assertEqual(tool.check(self.tmp), ["SHA256SUMS does not list the tree as it is"])


class Add(unittest.TestCase):
    """`add` over a synthetic registry clone, lock and repository cache."""

    ARCHIVE = b"an archive\n"
    PATCH = b"--- a\n+++ b\n"

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.fixtures = self.tmp / "fixtures"
        self.bcr = self.tmp / "bcr"
        self.cache = self.tmp / "cache"
        source = {
            "url": "https://example.invalid/releases/lib-1.0.tar.gz",
            "integrity": sri(self.ARCHIVE),
            "patches": {"fix.patch": sri(self.PATCH)},
        }
        files = {
            "bazel_registry.json": b"{}\n",
            "modules/lib/1.0/MODULE.bazel": b'module(name = "lib", version = "1.0")\n',
            "modules/lib/1.0/source.json": json.dumps(source).encode(),
            "modules/lib/1.0/patches/fix.patch": self.PATCH,
            "modules/unused/2.0/MODULE.bazel": b'module(name = "unused", version = "2.0")\n',
        }
        for rel, data in files.items():
            (self.bcr / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.bcr / rel).write_bytes(data)
        pinned = ["bazel_registry.json", "modules/lib/1.0/MODULE.bazel", "modules/lib/1.0/source.json"]
        hashes = {tool.BCR + rel: digest(files[rel]) for rel in pinned}
        self.lock = self.fixtures / "core/bzlmod/e9/locks/v28/MODULE.bazel.lock"
        self.lock.parent.mkdir(parents=True)
        self.lock.write_text(json.dumps({"lockFileVersion": 28, "registryFileHashes": hashes}))
        fetched = self.cache / "content_addressable/sha256" / digest(self.ARCHIVE)
        fetched.mkdir(parents=True)
        (fetched / "file").write_bytes(self.ARCHIVE)
        (self.fixtures / "registry").mkdir()

    def add(self, distdir=True):
        tool.add(self.fixtures, "9.3.2", self.lock, self.bcr, self.cache, distdir)

    def tree(self):
        return sorted(tool.tree(self.fixtures / "registry"))

    def test_mirrors_what_the_lock_pins_and_a_build_fetched(self):
        self.add()
        self.assertEqual(tool.check(self.fixtures), [])
        self.assertEqual(self.tree(), [
            "MANIFEST.json",
            "bazel_registry.json",
            "distdir/9.3.2/lib-1.0.tar.gz",
            "modules/lib/1.0/MODULE.bazel",
            "modules/lib/1.0/patches/fix.patch",
            "modules/lib/1.0/source.json",
        ])
        manifest = json.loads((self.fixtures / "registry/MANIFEST.json").read_text())
        self.assertEqual(manifest["versions"]["9.3.2"], {
            "lock": "core/bzlmod/e9/locks/v28/MODULE.bazel.lock",
            "distdir": True,
            "archives": [{
                "module": "lib@1.0",
                "file": "lib-1.0.tar.gz",
                "sha256": digest(self.ARCHIVE),
                "bytes": len(self.ARCHIVE),
            }],
        })

    def test_without_a_distdir_the_archive_is_recorded_and_not_copied(self):
        self.add()
        self.add(distdir=False)
        self.assertEqual(tool.check(self.fixtures), [])
        self.assertNotIn("distdir/9.3.2/lib-1.0.tar.gz", self.tree())
        self.assertIn("modules/lib/1.0/patches/fix.patch", self.tree())

    def test_an_archive_no_build_fetched_brings_no_patch(self):
        shutil.rmtree(self.cache)
        self.add()
        self.assertEqual(tool.check(self.fixtures), [])
        self.assertEqual(self.tree(), [
            "MANIFEST.json",
            "bazel_registry.json",
            "modules/lib/1.0/MODULE.bazel",
            "modules/lib/1.0/source.json",
        ])

    def test_a_clone_that_differs_from_the_lock_is_refused(self):
        (self.bcr / "modules/lib/1.0/MODULE.bazel").write_text("# edited upstream\n")
        with self.assertRaises(SystemExit) as refused:
            self.add()
        self.assertIn("is not the file the lock or source.json pins", str(refused.exception))

    def test_a_recorded_miss_is_refused(self):
        lock = json.loads(self.lock.read_text())
        lock["registryFileHashes"][tool.BCR + "modules/lib/1.0/source.json"] = None
        self.lock.write_text(json.dumps(lock))
        with self.assertRaisesRegex(ValueError, "has no sha256"):
            self.add()


if __name__ == "__main__":
    unittest.main()
