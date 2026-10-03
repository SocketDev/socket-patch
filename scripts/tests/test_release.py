"""scripts/release.py: the release train's version, stamp, CHANGELOG and
release-blocker logic (docs/release-train/DESIGN.md §7 PR 1 acceptance)."""

import contextlib
import copy
import importlib.util
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "release"

spec = importlib.util.spec_from_file_location("release", ROOT / "scripts" / "release.py")
rel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rel)

V = rel.Version.parse
MAIN_SNAPSHOT = (FIXTURES / "CHANGELOG.main-045d7ec7.md").read_text(encoding="utf-8")
TRAIN = (FIXTURES / "CHANGELOG.train.md").read_text(encoding="utf-8")
LEGACY_TAGS = ["1.1.0", "1.2.0", "2.1.4", "3.1.0", "3.2.0", "3.3.0", "4.0.0"]


def packaging_files():
    files = ["Cargo.toml", "Cargo.lock", "CHANGELOG.md", "npm/socket-patch/package-lock.json"]
    files += [p.relative_to(ROOT).as_posix() for p in ROOT.glob("crates/*/Cargo.toml")]
    files += [p.relative_to(ROOT).as_posix() for p in ROOT.glob("npm/*/package.json")]
    return files


def copy_packaging(dest, scripts=False):
    for rel_path in packaging_files() + (
            ["scripts/release.py", "scripts/release-lint.sh", "scripts/version-sync.sh"] if scripts else []):
        (dest / rel_path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / rel_path, dest / rel_path)


def snapshot(root):
    return {p: (Path(root) / p).read_bytes() for p in packaging_files()}


def quiet(fn, *args, **kwargs):
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return fn(*args, **kwargs)


class FakeTags:
    """The three tag facts sync-main needs, without git."""

    def __init__(self, versions, changelogs=None, promoted=None):
        self.versions = sorted(V(v) for v in versions)
        self._changelogs = {V(k): t for k, t in (changelogs or {}).items()}
        self._promoted = {V(k): (V(r) if r else None) for k, r in (promoted or {}).items()}

    def changelog(self, v):
        return self._changelogs[v]

    def promoted_from(self, stable):
        return self._promoted.get(stable)


class TrainRepo:
    """A temp git repo with main + release branches + tags, cut the way the
    train cuts them (release branch = base + one CHANGELOG commit, tagged)."""

    def __init__(self, changelog=TRAIN):
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)
        self.git("init", "-q", "-b", "main")
        self.write(changelog)
        self.commit("main: initial")
        self.git("tag", "v4.0.0")
        self.git_api = rel.Git(self.root)

    def close(self):
        self.dir.cleanup()

    def git(self, *args):
        env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.com",
                   GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.com")
        return subprocess.run(["git", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", *args],
                              cwd=self.root, check=True, capture_output=True, text=True, env=env).stdout

    def write(self, text):
        (self.root / "CHANGELOG.md").write_text(text, encoding="utf-8")

    def read(self, ref="main"):
        return self.git("show", f"{ref}:CHANGELOG.md")

    def commit(self, msg):
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", msg)

    def tags(self):
        return rel.TagSource(self.git_api)

    def add_unreleased(self, heading, bullet):
        """A PR to main adding one entry under [Unreleased]."""
        cl = rel.Changelog.parse(self.read())
        cl.unreleased().append_items([(heading, rel.Block([bullet]))])
        self.git("checkout", "-q", "main")
        self.write(cl.render())
        self.commit(f"main: {bullet}")

    def cut(self, version, date, base="main", tag=True):
        text = rel.cut_changelog(self.read(base), version, date, self.tags())
        self.git("checkout", "-q", "-b", f"release/v{version}", base)
        self.write(text)
        self.commit(f"chore(release): {version}")
        if tag:
            self.git("tag", f"v{version}")
        self.git("checkout", "-q", "main")
        return text

    def promote(self, rc, date):
        core = str(V(rc).core)
        text = rel.promote_changelog(self.read(f"v{rc}"), rc, date)
        self.git("checkout", "-q", "-b", f"release/v{core}", f"v{rc}")
        self.write(text)
        self.commit(f"chore(release): {core}")
        self.git("tag", f"v{core}")
        self.git("checkout", "-q", "main")
        return text

    def merge_sync(self):
        """The release-sync PR merges: main := sync-main(main)."""
        text, _ = rel.sync_main_changelog(self.read(), self.tags())
        self.write(text)
        self.commit("main: release-sync")
        return text

    def next_version(self):
        return rel.next_version(self.git_api, "main")["version"]


# ── semver ──────────────────────────────────────────────────────────────────

class SemverTests(unittest.TestCase):
    def test_rc_precedes_its_release(self):
        self.assertLess(V("5.0.0-rc.1"), V("5.0.0"))
        self.assertLess(V("5.0.0-rc.2"), V("5.0.0-rc.10"))
        self.assertLess(V("4.0.0"), V("5.0.0-rc.1"))
        self.assertLess(V("5.0.0"), V("5.0.1-rc.1"))
        self.assertEqual(sorted(map(V, ["5.0.0", "5.0.0-rc.10", "5.0.0-rc.2", "4.9.9"])),
                         list(map(V, ["4.9.9", "5.0.0-rc.2", "5.0.0-rc.10", "5.0.0"])))

    def test_other_prerelease_and_malformed_forms_are_rejected(self):
        for bad in ["5.0.0-beta.1", "5.0.0-rc.0", "5.0.0-rc.01", "5.0.0-rc", "5.0.0-RC.1",
                    "5.0.0-rc.1.1", "05.0.0", "5.0", "v5.0.0", "5.0.0+build.1", " 5.0.0", ""]:
            with self.subTest(bad=bad), self.assertRaises(rel.ReleaseError):
                V(bad)

    def test_core_and_bump(self):
        self.assertEqual(str(V("5.0.0-rc.3").core), "5.0.0")
        self.assertEqual(str(V("4.2.3").bump("major")), "5.0.0")
        self.assertEqual(str(V("4.2.3").bump("minor")), "4.3.0")
        self.assertEqual(str(V("4.2.3").bump("patch")), "4.2.4")

    def test_cli(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(rel.main(["semver", "compare", "5.0.0-rc.1", "5.0.0"]), 0)
        self.assertEqual(out.getvalue().strip(), "-1")
        self.assertEqual(quiet(rel.main, ["semver", "validate", "--kind", "stable", "5.0.0-rc.1"]), 1)
        self.assertEqual(quiet(rel.main, ["semver", "validate", "--kind", "rc", "5.0.0-rc.1"]), 0)

    def test_tag_and_branch_names(self):
        self.assertEqual(rel.parse_tag("v5.0.0-rc.1"), V("5.0.0-rc.1"))
        self.assertIsNone(rel.parse_tag("v5.0.0-beta"))
        self.assertIsNone(rel.parse_tag("5.0.0"))
        self.assertEqual(rel.parse_release_branch("refs/remotes/origin/release/v5.0.0-rc.2"), V("5.0.0-rc.2"))
        self.assertIsNone(rel.parse_release_branch("refs/heads/release/v5-prerelease"))


# ── stamp ───────────────────────────────────────────────────────────────────

class StampTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        copy_packaging(self.root, scripts=True)
        self.current = rel._read(ROOT / "Cargo.toml").split('version = "', 1)[1].split('"', 1)[0]

    def tearDown(self):
        self.tmp.cleanup()

    def test_stamping_the_current_version_is_a_byte_noop(self):
        self.assertEqual(rel.stamp_files(ROOT, self.current), {})

    def test_version_sync_wrapper_keeps_its_contract_and_is_a_noop(self):
        before = snapshot(self.root)
        proc = subprocess.run(["bash", "scripts/version-sync.sh", self.current], cwd=self.root,
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), f"Synced version to {self.current}")
        self.assertEqual(snapshot(self.root), before)
        usage = subprocess.run(["bash", "scripts/version-sync.sh"], cwd=self.root, capture_output=True, text=True)
        self.assertNotEqual(usage.returncode, 0)
        self.assertIn("Usage: version-sync.sh <version>", usage.stderr)

    def test_rc_stamp_is_offline_and_byte_deterministic(self):
        env = dict(os.environ, npm_config_registry="http://127.0.0.1:1")
        outs = []
        for _ in range(2):
            proc = subprocess.run(["bash", "scripts/version-sync.sh", "5.0.0-rc.1"], cwd=self.root,
                                  capture_output=True, text=True, env=env)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            outs.append(snapshot(self.root))
        self.assertEqual(outs[0], outs[1])
        self.assertEqual(rel.stamp_files(self.root, "5.0.0-rc.1"), {})

    def test_rc_stamp_touches_every_site(self):
        rel.stamp(self.root, "5.0.0-rc.1")
        toml = rel._read(self.root / "Cargo.toml")
        self.assertIn('[workspace.package]\nversion = "5.0.0-rc.1"', toml)
        self.assertIn('socket-patch-core = { path = "crates/socket-patch-core", version = "=5.0.0-rc.1" }', toml)
        lock = rel._read(self.root / "Cargo.lock")
        for name in ["socket-patch-core", "socket-patch-cli", "socket-patch-node", "socket-patch-bench"]:
            self.assertIn(f'name = "{name}"\nversion = "5.0.0-rc.1"\n', lock)
        old_lock = rel._read(ROOT / "Cargo.lock")
        self.assertEqual(len(old_lock.splitlines()), len(lock.splitlines()))
        changed = [a for a, b in zip(old_lock.splitlines(), lock.splitlines()) if a != b]
        self.assertEqual(changed, [f'version = "{self.current}"'] * 4)
        manifests = sorted(self.root.glob("npm/*/package.json"))
        self.assertEqual(len(manifests), 15)
        for m in manifests:
            self.assertEqual(json.loads(rel._read(m))["version"], "5.0.0-rc.1", m)
        main = json.loads(rel._read(self.root / "npm/socket-patch/package.json"))
        self.assertEqual(len(main["optionalDependencies"]), 14)
        self.assertEqual(set(main["optionalDependencies"].values()), {"5.0.0-rc.1"})
        npm_lock = json.loads(rel._read(self.root / "npm/socket-patch/package-lock.json"))
        self.assertEqual(npm_lock["version"], "5.0.0-rc.1")
        self.assertEqual(npm_lock["packages"][""]["version"], "5.0.0-rc.1")
        self.assertEqual(set(npm_lock["packages"][""]["optionalDependencies"].values()), {"5.0.0-rc.1"})
        self.assertFalse([k for k in npm_lock["packages"] if "@socketsecurity/socket-patch-" in k])
        self.assertIn("node_modules/zod", npm_lock["packages"])

    def test_platform_lock_entries_at_the_target_version_are_kept(self):
        self.assertIn("node_modules/@socketsecurity/socket-patch-win32-x64", json.loads(
            rel._read(ROOT / "npm/socket-patch/package-lock.json"))["packages"])
        self.assertFalse(rel.stamp_files(self.root, self.current))

    def test_check_mode_writes_nothing(self):
        before = snapshot(self.root)
        self.assertEqual(quiet(rel.main, ["--root", str(self.root), "stamp", "--check", "5.0.0-rc.1"]), 1)
        self.assertEqual(snapshot(self.root), before)
        self.assertEqual(quiet(rel.main, ["--root", str(self.root), "stamp", "--check", self.current]), 0)

    def test_invalid_versions_are_refused(self):
        self.assertEqual(quiet(rel.main, ["--root", str(self.root), "stamp", "5.0.0-beta.1"]), 1)

    def test_release_lint_accepts_main_at_an_rc(self):
        rel.stamp(self.root, "5.0.0-rc.1")
        path = self.root / "CHANGELOG.md"
        rel._write(path, rel.cut_changelog(rel._read(path), "5.0.0-rc.1", "2026-10-12"))
        lint = lambda *a: subprocess.run(["bash", "scripts/release-lint.sh", *a], cwd=self.root,
                                         capture_output=True, text=True)
        ok = lint()
        self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
        self.assertIn("all checks passed for 5.0.0-rc.1", ok.stdout)
        self.assertNotEqual(lint("--stable-only").returncode, 0)
        rel._write(self.root / "npm/socket-patch-win32-x64/package.json",
                   rel._read(self.root / "npm/socket-patch-win32-x64/package.json").replace("5.0.0-rc.1", "4.0.0"))
        drift = lint("--sync-only")
        self.assertNotEqual(drift.returncode, 0)
        self.assertIn("npm/socket-patch-win32-x64/package.json", drift.stderr)


# ── CHANGELOG ───────────────────────────────────────────────────────────────

class ChangelogTests(unittest.TestCase):
    def test_round_trip_is_byte_identical(self):
        for text in (MAIN_SNAPSHOT, TRAIN, rel._read(ROOT / "CHANGELOG.md"), "# x\n\n## [Unreleased]\n"):
            self.assertEqual(rel.Changelog.parse(text).render(), text)

    def test_blocks(self):
        unrel = rel.Changelog.parse(TRAIN).unreleased()
        self.assertEqual([(n, b.lines[0][:20]) for n, b in unrel.items()], [
            (None, "v5 centers the workf"), ("Breaking changes", "- `scan` and `get` d"),
            ("Breaking changes", "- `setup` and its pu"), ("Added", "- Vendored Maven rea"),
            ("Fixed", "- Bound patch API co"), ("Fixed", "- Stop npm oracle tr")])
        nested = unrel.items()[-1][1]
        self.assertEqual(len(nested.lines), 3)  # the indented paragraph belongs to the bullet

    def test_cut_moves_unreleased_verbatim_and_empties_it(self):
        out = rel.cut_changelog(TRAIN, "5.0.0-rc.1", "2026-10-12")
        self.assertEqual(out, TRAIN.replace("## [Unreleased]\n\n", "## [Unreleased]\n\n## [5.0.0-rc.1] — 2026-10-12\n\n", 1))
        with self.assertRaisesRegex(rel.ReleaseError, "empty"):
            rel.cut_changelog(out, "5.0.0-rc.2", "2026-10-19")
        with self.assertRaisesRegex(rel.ReleaseError, ">= 4.0.0"):
            rel.cut_changelog(TRAIN, "4.0.0", "2026-10-19")
        with self.assertRaisesRegex(rel.ReleaseError, "YYYY-MM-DD"):
            rel.cut_changelog(TRAIN, "5.0.0-rc.1", "10/12/2026")

    def test_cut_of_the_real_main_snapshot(self):
        out = rel.cut_changelog(MAIN_SNAPSHOT, "5.0.0-rc.1", "2026-10-12")
        cl = rel.Changelog.parse(out)
        self.assertEqual([s.heading for s in cl.sections[:3]],
                         ["## [Unreleased]", "## [5.0.0-rc.1] — 2026-10-12", "## [4.0.0] — 2026-08-20"])
        self.assertEqual(len(cl.section(V("5.0.0-rc.1")).items()), 49)
        self.assertEqual(rel.check_section(out, "5.0.0-rc.1"), 49)
        self.assertFalse(cl.unreleased().items())

    def test_promote_single_rc_is_a_heading_rename(self):
        rc1 = rel.cut_changelog(TRAIN, "5.0.0-rc.1", "2026-10-12")
        stable = rel.promote_changelog(rc1, "5.0.0-rc.1", "2026-10-20")
        self.assertEqual(stable, rc1.replace("## [5.0.0-rc.1] — 2026-10-12", "## [5.0.0] — 2026-10-20"))
        self.assertEqual(rel.check_section(stable, "5.0.0"), 6)

    def test_promote_folds_every_rc_up_to_k_and_returns_later_ones(self):
        rc1 = rel.cut_changelog(TRAIN, "5.0.0-rc.1", "2026-10-12")
        cl = rel.Changelog.parse(rc1)
        cl.unreleased().append_items([("Fixed", rel.Block(["- rc.2 fix (#600)."])),
                                      ("Fixed", rel.Block(["- Bound patch API connects and stalled reads (#581)."]))])
        rc2 = rel.cut_changelog(cl.render(), "5.0.0-rc.2", "2026-10-19")
        cl = rel.Changelog.parse(rc2)
        cl.unreleased().append_items([("Added", rel.Block(["- rc.3 feature (#610)."]))])
        rc3 = rel.cut_changelog(cl.render(), "5.0.0-rc.3", "2026-10-26")
        self.assertIn("## [5.0.0-rc.1]", rc3)
        with self.assertRaisesRegex(rel.ReleaseError, "unfolded rc sections"):
            rel.check_section(rc3.replace("## [5.0.0-rc.3]", "## [5.0.0]"), "5.0.0")

        stable = rel.promote_changelog(rc3, "5.0.0-rc.2", "2026-10-27")
        cl = rel.Changelog.parse(stable)
        self.assertEqual([str(s.version) for s in cl.versioned()], ["5.0.0", "4.0.0", "3.2.0"])
        folded = cl.section(V("5.0.0"))
        texts = [b.text for _, b in folded.items()]
        self.assertEqual(texts.count("- Bound patch API connects and stalled reads (#581)."), 1)
        self.assertEqual(texts[-1], "- rc.2 fix (#600).")
        self.assertEqual(len(texts), 7)
        # rc.3 was never promoted: its block returns to [Unreleased].
        self.assertEqual([b.text for _, b in cl.unreleased().items()], ["- rc.3 feature (#610)."])
        self.assertEqual(rel.check_section(stable, "5.0.0"), 7)
        with self.assertRaises(rel.ReleaseError):
            rel.promote_changelog(stable, "5.0.0-rc.2", "2026-10-27")

    def test_notes_link_p1s_never_titles(self):
        rc1 = rel.cut_changelog(TRAIN, "5.0.0-rc.1", "2026-10-12")
        notes = rel.render_notes(rc1, "5.0.0-rc.1", "SocketDev/socket-patch", unlogged=3)
        self.assertTrue(notes.startswith("> **Prerelease.**"))
        self.assertIn("### Breaking changes", notes)
        self.assertNotIn("## [5.0.0-rc.1]", notes)
        self.assertIn("https://github.com/SocketDev/socket-patch/issues?q=is%3Aissue%20is%3Aopen%20label%3Apriority%3Ap1", notes)
        self.assertIn("_3 product commit(s)", notes)
        stable = rel.render_notes(rel.promote_changelog(rc1, "5.0.0-rc.1", "2026-10-20"), "5.0.0")
        self.assertNotIn("Prerelease", stable)
        self.assertTrue(stable.startswith("v5 centers"))


# ── version selection ───────────────────────────────────────────────────────

class VersionSelectionTests(unittest.TestCase):
    def select(self, text, tags, branches=(), fake=None):
        fake = fake or FakeTags(tags)
        synced, _ = rel.sync_main_changelog(text, fake)
        return rel.select_version(fake.versions, [V(b) for b in branches],
                                  rel.Changelog.parse(synced).unreleased())

    def test_first_train_on_the_main_snapshot_is_5_0_0_rc_1(self):
        got = self.select(MAIN_SNAPSHOT, LEGACY_TAGS)
        self.assertEqual((got["version"], got["level"], got["latestStable"]), ("5.0.0-rc.1", "major", "4.0.0"))

    def test_levels(self):
        cl = rel.Changelog.parse(TRAIN)
        self.assertEqual(rel.bump_level(cl.unreleased()), "major")
        for heading, level in [("Added", "minor"), ("Changed", "minor"), ("Deprecated", "minor"),
                               ("Removed", "major"), ("Removed (BREAKING)", "major"), ("Fixed", "patch"),
                               ("Security", "patch"), ("Maintenance", "patch"),
                               ("Fixed — filesystem safety", "patch")]:
            self.assertEqual(rel.heading_level(heading), level, heading)
        empty = rel.Changelog.parse("## [Unreleased]\n\n### Breaking changes\n\n### Fixed\n\n- x\n").unreleased()
        self.assertEqual(rel.bump_level(empty), "patch")  # an empty heading does not count

    def test_burned_branches_and_numbering(self):
        self.assertEqual(self.select(TRAIN, ["4.0.0"], ["5.0.0-rc.1", "5.0.0-rc.2"])["version"], "5.0.0-rc.3")
        got = self.select(TRAIN, ["4.0.0", "5.0.0-rc.1"], ["5.0.0-rc.1", "5.0.0-rc.4", "4.0.1-rc.9"],
                          FakeTags(["4.0.0", "5.0.0-rc.1"],
                                   {"5.0.0-rc.1": rel.cut_changelog(TRAIN, "5.0.0-rc.1", "2026-10-12")}))
        self.assertEqual(got["version"], "5.0.0-rc.5")

    def test_new_major_needs_approval(self):
        with patch.object(rel, "APPROVED_MAJORS", ()):
            with self.assertRaisesRegex(rel.ReleaseError, "Breaking changes.*APPROVED_MAJORS"):
                self.select(TRAIN, ["4.0.0"])
        # A pending minor train does not let a breaking entry open a major unapproved...
        pending = FakeTags(["4.0.0", "4.1.0-rc.1"],
                           {"4.1.0-rc.1": "## [Unreleased]\n\n## [4.1.0-rc.1] — 2026-10-05\n\n### Added\n\n- y\n"})
        with patch.object(rel, "APPROVED_MAJORS", ()):
            with self.assertRaises(rel.ReleaseError):
                self.select(TRAIN, None, fake=pending)
        # ...but an approved one opens it, above the pending minor.
        self.assertEqual(self.select(TRAIN, None, fake=pending)["version"], "5.0.0-rc.1")

    def test_a_major_is_never_skipped(self):
        fake = FakeTags(["4.0.0", "6.0.0-rc.1"], {"6.0.0-rc.1": "## [Unreleased]\n\n## [6.0.0-rc.1] — 2026-10-05\n\n- y\n"})
        with patch.object(rel, "APPROVED_MAJORS", (5, 6)):
            with self.assertRaisesRegex(rel.ReleaseError, "skip a major"):
                self.select(TRAIN, None, fake=fake)

    def test_no_stable_tag_is_an_error(self):
        with self.assertRaisesRegex(rel.ReleaseError, "fetch tags"):
            self.select(TRAIN, [])


class TrainScenarioTests(unittest.TestCase):
    """Temp git repos driven through the §1 timeline, with the release-sync
    PR merged and not merged."""

    def setUp(self):
        self.repo = TrainRepo()
        self.addCleanup(self.repo.close)

    def test_first_cut_and_cli(self):
        self.assertEqual(self.repo.next_version(), "5.0.0-rc.1")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(rel.main(["--root", str(self.repo.root), "next-version", "--ref", "main"]), 0)
        self.assertEqual(out.getvalue().strip(), "5.0.0-rc.1")

    def test_rc2_while_rc1_pending_with_and_without_the_sync_pr(self):
        self.repo.cut("5.0.0-rc.1", "2026-10-12")
        self.repo.add_unreleased("Fixed", "- Week-two fix (#600).")
        unsynced_main = self.repo.read()
        self.assertEqual(self.repo.next_version(), "5.0.0-rc.2")
        cut_unsynced = rel.cut_changelog(unsynced_main, "5.0.0-rc.2", "2026-10-19", self.repo.tags())

        self.repo.merge_sync()
        self.assertEqual(self.repo.next_version(), "5.0.0-rc.2")
        cut_synced = rel.cut_changelog(self.repo.read(), "5.0.0-rc.2", "2026-10-19", self.repo.tags())
        self.assertEqual(cut_unsynced, cut_synced)
        rc2 = rel.Changelog.parse(cut_synced).section(V("5.0.0-rc.2"))
        self.assertEqual([b.text for _, b in rc2.items()], ["- Week-two fix (#600)."])

    def test_burned_branch_is_skipped(self):
        self.repo.cut("5.0.0-rc.1", "2026-10-12")
        self.repo.add_unreleased("Fixed", "- Week-two fix (#600).")
        self.repo.cut("5.0.0-rc.2", "2026-10-19", tag=False)  # QA red: branch exists, never tagged
        self.assertEqual(self.repo.next_version(), "5.0.0-rc.3")

    def test_after_stable_with_the_sync_pr_unmerged(self):
        self.repo.cut("5.0.0-rc.1", "2026-10-12")
        self.repo.add_unreleased("Fixed", "- Week-two fix (#600).")
        self.repo.cut("5.0.0-rc.2", "2026-10-19")
        self.repo.promote("5.0.0-rc.1", "2026-10-20")
        self.assertEqual(self.repo.next_version(), "5.0.1-rc.1")
        self.repo.add_unreleased("Added", "- Week-three feature (#610).")
        self.assertEqual(self.repo.next_version(), "5.1.0-rc.1")
        synced = rel.Changelog.parse(rel.sync_main_changelog(self.repo.read(), self.repo.tags())[0])
        self.assertEqual([(n, b.text) for n, b in synced.unreleased().items()],
                         [("Added", "- Week-three feature (#610)."), ("Fixed", "- Week-two fix (#600).")])
        self.repo.add_unreleased("Breaking changes", "- Drop a flag (#620).")
        with self.assertRaisesRegex(rel.ReleaseError, "open major 6 .* not in APPROVED_MAJORS"):
            self.repo.next_version()

    def test_rc_sync_to_main(self):
        self.repo.cut("5.0.0-rc.1", "2026-10-12")
        self.repo.add_unreleased("Fixed", "- Landed after the cut (#600).")
        before = self.repo.read()
        after = self.repo.merge_sync()
        cl = rel.Changelog.parse(after)
        tag_section = rel.Changelog.parse(self.repo.read("v5.0.0-rc.1")).section(V("5.0.0-rc.1"))
        self.assertEqual(cl.section(V("5.0.0-rc.1")).render(), tag_section.render())
        self.assertEqual([b.text for _, b in cl.unreleased().items()], ["- Landed after the cut (#600)."])
        # Byte-exact: only the shipped blocks left [Unreleased]; the entry
        # that landed after the cut stays where it was.
        self.assertEqual(after, TRAIN.replace("## [Unreleased]\n\n", "## [Unreleased]\n\n### Fixed\n\n"
                                              "- Landed after the cut (#600).\n\n## [5.0.0-rc.1] — 2026-10-12\n\n", 1))
        self.assertNotEqual(before, after)
        self.assertEqual(rel.sync_main_changelog(after, self.repo.tags())[0], after)  # idempotent

    def test_stable_fold_with_an_abandoned_later_rc(self):
        self.repo.cut("5.0.0-rc.1", "2026-10-12")
        self.repo.merge_sync()
        self.repo.add_unreleased("Fixed", "- Week-two fix (#600).")
        self.repo.cut("5.0.0-rc.2", "2026-10-19")
        self.repo.merge_sync()
        self.repo.add_unreleased("Added", "- Newer entry (#610).")
        main_before = self.repo.read()
        self.assertIn("## [5.0.0-rc.2]", main_before)
        self.repo.promote("5.0.0-rc.1", "2026-10-20")

        synced, report = rel.sync_main_changelog(main_before, self.repo.tags())
        self.assertEqual(report["inserted"], ["5.0.0"])
        self.assertEqual(report["folded"], ["5.0.0-rc.1"])
        self.assertEqual(report["abandoned"], ["5.0.0-rc.2"])
        cl = rel.Changelog.parse(synced)
        self.assertEqual([str(s.version) for s in cl.versioned()], ["5.0.0", "4.0.0", "3.2.0"])
        self.assertNotIn("-rc.", synced)
        self.assertEqual(cl.section(V("5.0.0")).render(),
                         rel.Changelog.parse(self.repo.read("v5.0.0")).section(V("5.0.0")).render())
        self.assertEqual(cl.section(V("5.0.0")).heading, "## [5.0.0] — 2026-10-20")
        # The newer [Unreleased] entry is untouched and still first; rc.2's
        # entry is back for the next train.
        self.assertIn("## [Unreleased]\n\n### Added\n\n- Newer entry (#610).\n\n## [5.0.0-rc.2]", main_before)
        self.assertIn("## [Unreleased]\n\n### Added\n\n- Newer entry (#610).\n\n### Fixed\n\n"
                      "- Week-two fix (#600).\n\n## [5.0.0] — 2026-10-20\n", synced)
        self.assertEqual([(n, b.text) for n, b in cl.unreleased().items()],
                         [("Added", "- Newer entry (#610)."), ("Fixed", "- Week-two fix (#600).")])
        self.assertEqual(rel.sync_main_changelog(synced, self.repo.tags())[0], synced)

        # The same end state when the sync PR never merged at all.
        fresh = TrainRepo()
        self.addCleanup(fresh.close)
        fresh.cut("5.0.0-rc.1", "2026-10-12")
        fresh.add_unreleased("Fixed", "- Week-two fix (#600).")
        fresh.cut("5.0.0-rc.2", "2026-10-19")
        fresh.add_unreleased("Added", "- Newer entry (#610).")
        fresh.promote("5.0.0-rc.1", "2026-10-20")
        unsynced = rel.Changelog.parse(rel.sync_main_changelog(fresh.read(), fresh.tags())[0])
        self.assertEqual(unsynced.section(V("5.0.0")).render(), cl.section(V("5.0.0")).render())
        self.assertEqual(unsynced.unreleased().keys(), cl.unreleased().keys())
        self.assertEqual(fresh.next_version(), "5.1.0-rc.1")

    def test_promoting_the_later_rc_folds_both(self):
        self.repo.cut("5.0.0-rc.1", "2026-10-12")
        self.repo.add_unreleased("Fixed", "- Week-two fix (#600).")
        self.repo.cut("5.0.0-rc.2", "2026-10-19")
        self.repo.merge_sync()
        stable = self.repo.promote("5.0.0-rc.2", "2026-10-27")
        section = rel.Changelog.parse(stable).section(V("5.0.0"))
        self.assertEqual(len(section.items()), 7)
        synced, report = rel.sync_main_changelog(self.repo.read(), self.repo.tags())
        self.assertEqual(report["folded"], ["5.0.0-rc.2", "5.0.0-rc.1"])
        self.assertEqual(report["abandoned"], [])
        self.assertFalse(rel.Changelog.parse(synced).unreleased().items())

    def test_an_abandoned_lower_core_train_folds_into_the_next_stable(self):
        self.repo.cut("5.0.0-rc.1", "2026-10-12")
        self.repo.promote("5.0.0-rc.1", "2026-10-20")
        self.repo.add_unreleased("Fixed", "- Patch fix (#700).")
        self.assertEqual(self.repo.next_version(), "5.0.1-rc.1")
        self.repo.cut("5.0.1-rc.1", "2026-10-26")
        self.repo.add_unreleased("Added", "- Feature (#710).")
        self.assertEqual(self.repo.next_version(), "5.1.0-rc.1")
        self.repo.cut("5.1.0-rc.1", "2026-11-02")
        self.repo.merge_sync()
        stable = rel.Changelog.parse(self.repo.promote("5.1.0-rc.1", "2026-11-10"))
        self.assertEqual([b.text for _, b in stable.section(V("5.1.0")).items()],
                         ["- Patch fix (#700).", "- Feature (#710)."])
        synced, report = rel.sync_main_changelog(self.repo.read(), self.repo.tags())
        self.assertEqual(sorted(report["folded"]), ["5.0.1-rc.1", "5.1.0-rc.1"])
        self.assertNotIn("-rc.", synced)

    def test_sync_main_on_a_working_tree_stamps_the_newest_tag(self):
        copy_packaging(self.repo.root)
        self.repo.write(TRAIN)
        self.repo.commit("packaging")
        self.repo.git("tag", "-f", "v4.0.0")
        self.assertEqual(rel.sync_main(self.repo.root, check=True)["changed"], [])
        self.repo.cut("5.0.0-rc.1", "2026-10-12")
        report = rel.sync_main(self.repo.root, check=True)
        self.assertEqual(report["version"], "5.0.0-rc.1")
        self.assertIn("CHANGELOG.md", report["changed"])
        self.assertIn("Cargo.toml", report["changed"])
        quiet(rel.main, ["--root", str(self.repo.root), "sync-main"])
        self.assertEqual(rel.sync_main(self.repo.root, check=True)["changed"], [])
        self.assertIn('version = "5.0.0-rc.1"', rel._read(self.repo.root / "Cargo.toml"))


# ── release-blocker gate ────────────────────────────────────────────────────

BLOCKERS = json.loads((FIXTURES / "blockers.json").read_text(encoding="utf-8"))


class FakeGitHub:
    """Serves a blockers.json scenario at the REST paths release.py reads."""

    def __init__(self, scenario):
        self.repo, self.base = BLOCKERS["repo"], BLOCKERS["base"]
        issues = copy.deepcopy(scenario["issues"])
        self.events = {i["number"]: i.pop("events") for i in issues}
        self.issues = {i["number"]: i for i in issues}
        self.compare = scenario.get("compare", {})
        self.fail = scenario.get("fail", [])
        self.calls = []

    def __call__(self, method, url, headers):
        assert method == "GET" and headers["Authorization"] == "Bearer t0ken"
        parsed = rel.urllib.parse.urlparse(url)
        path, query = parsed.path, dict(rel.urllib.parse.parse_qsl(parsed.query))
        self.calls.append(path)
        if any(path.startswith(f) for f in self.fail):
            return 500, {}, b'{"message": "Server Error"}'
        prefix = f"/repos/{self.repo}"
        assert path.startswith(prefix), path
        path = path[len(prefix):]
        labelled = lambda i: any(lbl["name"] == "release-blocker" for lbl in i["labels"])
        if path == f"/commits/{self.base}":
            body = {"sha": self.base, "commit": {"committer": {"date": BLOCKERS["baseTime"]}}}
        elif path == "/issues":
            body = [i for i in self.issues.values() if i["state"] == query["state"] and labelled(i)
                    and (query.get("since") is None or (i["closed_at"] or "") >= query["since"])]
        elif path == "/issues/events":
            body = sorted((dict(e, issue={"number": n}) for n, evs in self.events.items() for e in evs),
                          key=lambda e: rel._ts(e["created_at"]), reverse=True)
        elif path.startswith("/issues/") and path.endswith("/events"):
            body = self.events[int(path.split("/")[2])]
        elif path.startswith("/issues/"):
            body = self.issues[int(path.split("/")[2])]
        elif path.startswith("/compare/"):
            head, base = path[len("/compare/"):].split("...")
            assert base == self.base
            body = {"status": self.compare[head]}
        else:
            return 404, {}, b'{"message": "Not Found"}'
        return 200, {}, json.dumps(body).encode()


class BlockerTests(unittest.TestCase):
    def run_scenario(self, name):
        fake = FakeGitHub(BLOCKERS["scenarios"][name])
        gh = rel.GitHub(BLOCKERS["repo"], "t0ken", fake)
        return rel.evaluate_blockers(gh, BLOCKERS["base"], BLOCKERS["since"],
                                     rel._logins(BLOCKERS["approvers"]),
                                     rel._logins(BLOCKERS["routineActors"]))

    def test_every_fixture_scenario(self):
        for name, scenario in BLOCKERS["scenarios"].items():
            with self.subTest(name):
                result = self.run_scenario(name)
                if scenario["expect"] == "error":
                    self.assertTrue(result["blocked"])
                    self.assertIn("api-error", result["error"])
                else:
                    self.assertIsNone(result["error"])
                    self.assertEqual([b["number"] for b in result["blockers"]], scenario["expect"])
                    self.assertEqual(result["blocked"], bool(scenario["expect"]))

    def test_named_acceptance_cases(self):
        blocked = lambda name: self.run_scenario(name)["blocked"]
        self.assertTrue(blocked("open_untouched_200_days"))
        self.assertTrue(blocked("closed_by_commit_not_in_base"))
        self.assertFalse(blocked("closed_by_ancestor_commit"))
        self.assertTrue(blocked("closed_by_trusted_human_after_t"))
        self.assertFalse(blocked("closed_by_trusted_human_before_t"))
        self.assertTrue(blocked("closed_by_routine_actor"))
        self.assertTrue(blocked("closed_by_mik_in_routine_fallback"))
        self.assertTrue(blocked("unlabelled_by_routine_actor"))
        self.assertTrue(blocked("unlabelled_by_non_approver"))
        self.assertFalse(blocked("unlabelled_by_trusted_approver"))
        self.assertTrue(blocked("api_error"))

    def test_no_untrusted_text_in_the_result(self):
        result = self.run_scenario("open_untouched_200_days")
        self.assertNotIn("Untrusted title", json.dumps(result))

    def test_transport_failures_and_missing_token_block(self):
        def boom(method, url, headers):
            raise OSError("connection reset")
        for gh in (rel.GitHub("o/r", "t0ken", boom), rel.GitHub("o/r", None, boom),
                   rel.GitHub("o/r", "t0ken", lambda m, u, h: (200, {}, b"<html>"))):
            result = rel.evaluate_blockers(gh, "b" * 40, "2026-08-20T00:00:00Z", set(), set())
            self.assertTrue(result["blocked"])
            self.assertIn("api-error", result["error"])

    def test_pagination_follows_link_headers(self):
        pages = {"/repos/o/r/x?per_page=100": ([1, 2], '<https://api.github.com/repos/o/r/x?page=2>; rel="next"'),
                 "/repos/o/r/x?page=2": ([3], "")}

        def transport(method, url, headers):
            body, link = pages[url[len("https://api.github.com"):]]
            return 200, {"Link": link}, json.dumps(body).encode()
        self.assertEqual(rel.GitHub("o/r", "t", transport).pages("/x"), [1, 2, 3])

    def test_cli_uses_env_and_exit_status(self):
        fake = FakeGitHub(BLOCKERS["scenarios"]["unlabelled_by_routine_actor"])
        env = {"GITHUB_TOKEN": "t0ken", "RELEASE_APPROVERS": "alice,mikolalysenko",
               "RELEASE_ROUTINE_ACTORS": "mikolalysenko"}
        args = rel.build_parser().parse_args(["blockers", "--base", BLOCKERS["base"], "--repo", "o/r",
                                              "--since", BLOCKERS["since"]])
        with patch.dict(os.environ, env):
            self.assertEqual(quiet(rel.cmd_blockers, args, fake), 1)
        fake = FakeGitHub(BLOCKERS["scenarios"]["unlabelled_by_trusted_approver"])
        with patch.dict(os.environ, env):
            self.assertEqual(quiet(rel.cmd_blockers, args, fake), 0)


if __name__ == "__main__":
    unittest.main()
