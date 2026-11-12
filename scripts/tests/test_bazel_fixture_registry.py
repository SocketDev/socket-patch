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


    def test_a_cell_whose_archives_are_not_committed_lists_them_per_system(self):
        """The harness gives a cell exactly the listed entries of a
        repository cache, so a line without a distdir names every archive
        of every dependency system it has a fixture for."""
        matrix = json.loads((FIXTURES / "core/MATRIX.json").read_text(encoding="utf-8"))
        toys = tool.payload_digests(FIXTURES)
        self.assertTrue(toys, "no toy package under core/payloads")
        listed = 0
        for cell in matrix["cells"]:
            entry = MANIFEST["versions"][cell["bazel"]]
            if entry["distdir"]:
                continue
            listed += 1
            self.assertTrue(entry["archives"], cell["bazel"])
            workspace = entry.get("workspace_archives", [])
            self.assertEqual(bool(workspace), "workspace" in cell["fixtures"], cell["bazel"])
            for archive in entry["archives"] + workspace:
                self.assertRegex(archive["sha256"], r"^[0-9a-f]{64}$")
                self.assertNotIn(archive["sha256"], toys)
        self.assertGreater(listed, 0, "no line without a distdir: is 8.8.2 gone?")
        # Bazel 8's WORKSPACE suffix brings its own rules_cc, which no
        # module of the Bzlmod build is.
        workspace = {a["file"]: a["sha256"] for a in MANIFEST["versions"]["8.8.2"]["workspace_archives"]}
        modules = {a["file"]: a["sha256"] for a in MANIFEST["versions"]["8.8.2"]["archives"]}
        self.assertIn("rules_cc-0.0.16.tar.gz", workspace)
        self.assertNotIn("rules_cc-0.0.16.tar.gz", modules)
        self.assertEqual(workspace["rules_python-0.40.0.tar.gz"], modules["rules_python-0.40.0.tar.gz"])


class Drift(unittest.TestCase):
    """`check` over a copy of the committed tree with one thing wrong."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        shutil.copytree(FIXTURES / "registry", self.tmp / "registry")
        for entry in MANIFEST["versions"].values():
            (self.tmp / entry["lock"]).parent.mkdir(parents=True)
            shutil.copyfile(FIXTURES / entry["lock"], self.tmp / entry["lock"])
        shutil.copytree(FIXTURES / "core/payloads", self.tmp / "core/payloads")
        self.registry = self.tmp / "registry"
        self.assertEqual(tool.check(self.tmp), [])

    def problems(self):
        return "\n".join(tool.check(self.tmp))

    def edit_workspace_archives(self, edit):
        """Apply `edit` to the 8.8.2 list of a manifest copy."""
        path = self.registry / "MANIFEST.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        edit(manifest["versions"]["8.8.2"]["workspace_archives"])
        path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        sums = tool.render_sums(tool.tree(self.registry))
        (self.registry / "SHA256SUMS").write_text(sums, encoding="utf-8")

    def test_a_workspace_archive_that_is_a_toy_package(self):
        payload = FIXTURES / "core/payloads/patched/dep-1.0.0.sh"
        toy = {"file": "dep-1.0.0.sh", "sha256": digest(payload.read_bytes()), "bytes": payload.stat().st_size}
        self.edit_workspace_archives(lambda archives: archives.insert(1, toy))
        self.assertEqual(
            tool.check(self.tmp),
            ["Bazel 8.8.2: workspace archive dep-1.0.0.sh is a toy package, not an archive of Bazel's"],
        )

    def test_a_workspace_archive_without_a_digest(self):
        self.edit_workspace_archives(lambda archives: archives[0].update(sha256="9f38"))
        self.assertEqual(
            tool.check(self.tmp),
            ["Bazel 8.8.2: workspace archive bazel-skylib-1.6.1.tar.gz has no sha256"],
        )

    def test_a_workspace_archive_that_renames_a_module_archive(self):
        def rename(archives):
            for archive in archives:
                if archive["file"] == "rules_python-0.40.0.tar.gz":
                    archive["file"] = "rules_python.tar.gz"

        self.edit_workspace_archives(rename)
        self.assertIn("is the module archive rules_python-0.40.0.tar.gz under another name", self.problems())

    def test_workspace_archives_out_of_order(self):
        self.edit_workspace_archives(lambda archives: archives.reverse())
        self.assertEqual(
            tool.check(self.tmp),
            ["Bazel 8.8.2: workspace archives are not sorted by file name, each listed once"],
        )

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

    def snapshot(self):
        """Every file under the fixtures copy, with its bytes."""
        files = (p for p in self.fixtures.rglob("*") if p.is_file())
        return {p.relative_to(self.fixtures).as_posix(): p.read_bytes() for p in files}

    def add_second_version(self):
        """Bazel 8.8.2, whose lock pins one more module than 9.3.2's."""
        extra = "modules/unused/2.0/MODULE.bazel"
        lock = json.loads(self.lock.read_text())
        lock["registryFileHashes"][tool.BCR + extra] = digest((self.bcr / extra).read_bytes())
        second = self.fixtures / "core/bzlmod/e8/locks/v28/MODULE.bazel.lock"
        second.parent.mkdir(parents=True)
        second.write_text(json.dumps(lock))
        tool.add(self.fixtures, "8.8.2", second, self.bcr, self.cache, False)
        self.assertEqual(tool.check(self.fixtures), [])
        self.assertIn(extra, self.tree())
        return second

    def test_another_versions_unreadable_lock_refuses_before_any_write(self):
        """`add` ends by removing what no lock accounts for. A version whose
        lock cannot be read accounts for nothing: its files must survive."""
        self.add()
        second = self.add_second_version()
        for broken in ('{"lockFileVersion": 28, "registryFileHashes": {}}', "not JSON", None):
            with self.subTest(lock=broken):
                if broken is None:
                    second.unlink()
                else:
                    second.write_text(broken)
                before = self.snapshot()
                with self.assertRaises(SystemExit) as refused:
                    self.add()
                self.assertIn("nothing was changed", str(refused.exception))
                self.assertIn("Bazel 8.8.2", str(refused.exception))
                self.assertEqual(self.snapshot(), before)
                self.assertIn("modules/unused/2.0/MODULE.bazel", self.tree())

    def test_a_file_list_with_a_problem_removes_nothing(self):
        """The same guard for any other reason the list of expected files
        is not whole: here another version's entry is not well formed."""
        self.add()
        self.add_second_version()
        manifest_path = self.fixtures / "registry/MANIFEST.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["versions"]["8.8.2"]["workspace_archives"] = [{"file": "x.tar.gz"}]
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaises(SystemExit) as refused:
            self.add()
        self.assertIn("no file was removed", str(refused.exception))
        self.assertIn("modules/unused/2.0/MODULE.bazel", self.tree())

    def test_an_integrity_the_tool_cannot_read_is_refused(self):
        """Not skipped as an archive no build fetched."""
        source_path = self.bcr / "modules/lib/1.0/source.json"
        source = json.loads(source_path.read_text())
        source["integrity"] = "sha512-" + base64.b64encode(hashlib.sha512(self.ARCHIVE).digest()).decode()
        source_path.write_text(json.dumps(source))
        lock = json.loads(self.lock.read_text())
        lock["registryFileHashes"][tool.BCR + "modules/lib/1.0/source.json"] = digest(source_path.read_bytes())
        self.lock.write_text(json.dumps(lock))
        with self.assertRaises(SystemExit) as refused:
            self.add()
        self.assertIn("is not a sha256", str(refused.exception))
        self.assertEqual(self.tree(), [])

    WORKSPACE_ONLY = b"an archive of the WORKSPACE suffix\n"
    TOY = b"#!/bin/sh\necho toy\n"

    def workspace_cache(self):
        """The repository cache of a cold build with Bzlmod off: the module
        archive again, an archive only WORKSPACE fetches, and a toy package."""
        (self.fixtures / "core/payloads/upstream").mkdir(parents=True)
        (self.fixtures / "core/payloads/upstream/dep-1.0.0.sh").write_bytes(self.TOY)
        cache = self.tmp / "workspace-cache"
        for data in (self.ARCHIVE, self.WORKSPACE_ONLY, self.TOY):
            entry = cache / "content_addressable/sha256" / digest(data)
            entry.mkdir(parents=True)
            (entry / "file").write_bytes(data)
        return cache

    def add_workspace(self, cache, distdir=True, names=None):
        tool.add(self.fixtures, "9.3.2", self.lock, self.bcr, self.cache, distdir, cache, names)

    def entry(self):
        manifest = json.loads((self.fixtures / "registry/MANIFEST.json").read_text())
        return manifest["versions"]["9.3.2"]

    def test_workspace_archives_are_recorded_by_name_without_the_toy_packages(self):
        cache = self.workspace_cache()
        named = {digest(self.WORKSPACE_ONLY): "suffix-1.0.tar.gz"}
        self.add_workspace(cache, names=named)
        self.assertEqual(tool.check(self.fixtures), [])
        self.assertEqual(self.entry()["workspace_archives"], [
            {"file": "lib-1.0.tar.gz", "sha256": digest(self.ARCHIVE), "bytes": len(self.ARCHIVE)},
            {"file": "suffix-1.0.tar.gz", "sha256": digest(self.WORKSPACE_ONLY), "bytes": len(self.WORKSPACE_ONLY)},
        ])
        # A version with a distdir commits them, so its cells need no cache.
        self.assertIn("distdir/9.3.2/suffix-1.0.tar.gz", self.tree())
        committed = self.fixtures / "registry/distdir/9.3.2/suffix-1.0.tar.gz"
        self.assertEqual(committed.read_bytes(), self.WORKSPACE_ONLY)

        # A refresh reuses the recorded name; without the cache it cannot
        # commit the archives again, and without a distdir the list stays.
        self.add_workspace(cache)
        self.assertEqual(len(self.entry()["workspace_archives"]), 2)
        with self.assertRaisesRegex(SystemExit, "pass --workspace-cache"):
            self.add()
        self.add(distdir=False)
        self.assertEqual(tool.check(self.fixtures), [])
        self.assertEqual(len(self.entry()["workspace_archives"]), 2)
        self.assertNotIn("distdir/9.3.2/suffix-1.0.tar.gz", self.tree())

    def test_a_workspace_archive_nobody_named_is_refused_before_any_write(self):
        cache = self.workspace_cache()
        with self.assertRaises(SystemExit) as refused:
            self.add_workspace(cache)
        self.assertIn(f"--name {digest(self.WORKSPACE_ONLY)}=<file>", str(refused.exception))
        self.assertEqual(self.tree(), [])

    def test_a_module_archive_under_another_name_is_refused_before_any_write(self):
        cache = self.workspace_cache()
        named = {digest(self.WORKSPACE_ONLY): "suffix-1.0.tar.gz", digest(self.ARCHIVE): "renamed.tar.gz"}
        with self.assertRaises(SystemExit) as refused:
            self.add_workspace(cache, names=named)
        self.assertIn("nothing was changed", str(refused.exception))
        self.assertIn("is the module archive lib-1.0.tar.gz under another name", str(refused.exception))
        self.assertEqual(self.tree(), [])

    def test_a_lock_outside_the_fixtures_is_refused_before_any_write(self):
        outside = self.tmp / "MODULE.bazel.lock"
        shutil.copyfile(self.lock, outside)
        with self.assertRaisesRegex(SystemExit, "is not under"):
            tool.add(self.fixtures, "9.3.2", outside, self.bcr, self.cache, True)
        self.assertEqual(self.tree(), [])

    def test_a_cache_entry_that_is_not_its_key_is_refused(self):
        cache = self.workspace_cache()
        entry = cache / "content_addressable/sha256" / digest(self.WORKSPACE_ONLY) / "file"
        entry.write_bytes(b"other bytes\n")
        with self.assertRaisesRegex(SystemExit, "is not the file its cache key names"):
            self.add_workspace(cache, names={digest(self.WORKSPACE_ONLY): "suffix-1.0.tar.gz"})
        self.assertEqual(self.tree(), [])

    def test_names_are_sha256_and_file_pairs(self):
        key = digest(self.WORKSPACE_ONLY)
        self.assertEqual(tool.parse_names([f"{key}=suffix-1.0.tar.gz"]), {key: "suffix-1.0.tar.gz"})
        for bad in ("suffix-1.0.tar.gz", f"{key}=", "abc=suffix-1.0.tar.gz"):
            with self.assertRaisesRegex(SystemExit, "expected <sha256>=<file name>"):
                tool.parse_names([bad])


if __name__ == "__main__":
    unittest.main()
