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

# Hermetic git: no GIT_DIR / GIT_WORK_TREE (a git hook's environment would
# redirect the temp repos' init/commit/tag into the hook's repository) and
# no user or system config.
_ENV = patch.dict(os.environ)


def setUpModule():
    _ENV.start()
    for k in [k for k in os.environ if k in rel._GIT_REPO_ENV or k.startswith("GIT_CONFIG")]:
        del os.environ[k]
    os.environ.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")


def tearDownModule():
    _ENV.stop()


MAIN_SNAPSHOT = (FIXTURES / "CHANGELOG.main-045d7ec7.md").read_text(encoding="utf-8")
TRAIN = (FIXTURES / "CHANGELOG.train.md").read_text(encoding="utf-8")
LEGACY_TAGS = ["1.1.0", "1.2.0", "2.1.4", "3.1.0", "3.2.0", "3.3.0", "4.0.0"]


def packaging_files():
    files = ["Cargo.toml", "Cargo.lock", "CHANGELOG.md", "npm/socket-patch/package-lock.json"]
    files += [p.relative_to(ROOT).as_posix() for p in ROOT.glob("crates/*/Cargo.toml")]
    files += [p.relative_to(ROOT).as_posix() for p in ROOT.glob("npm/*/package.json")]
    return files


PLATFORM_PKG = "node_modules/@socketsecurity/socket-patch-win32-x64"


def copy_packaging(dest, scripts=False, baseline=None, changelog=None):
    """Copy the packaging files into `dest`. With `baseline`, stamp them to
    that version (whatever version this checkout is at, e.g. an rc on a
    synced main) and give the npm lock one platform entry at it, so stamp
    tests never depend on the live tree's version."""
    for rel_path in packaging_files() + (
            ["scripts/release.py", "scripts/release-lint.sh", "scripts/version-sync.sh"] if scripts else []):
        (dest / rel_path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / rel_path, dest / rel_path)
    if changelog is not None:
        rel._write(dest / "CHANGELOG.md", changelog)
    if baseline is not None:
        rel.stamp(dest, baseline)
        lock_path = dest / "npm/socket-patch/package-lock.json"
        lock = json.loads(rel._read(lock_path))
        lock["packages"][PLATFORM_PKG] = {
            "version": baseline, "resolved": f"https://registry.npmjs.org/@socketsecurity/"
            f"socket-patch-win32-x64/-/socket-patch-win32-x64-{baseline}.tgz",
            "integrity": "sha512-AAAA", "cpu": ["x64"], "optional": True, "os": ["win32"]}
        lock["packages"] = dict(sorted(lock["packages"].items()))
        rel._write(lock_path, rel._dump_json(lock))


def snapshot(root):
    return {p: (Path(root) / p).read_bytes() for p in packaging_files()}


def quiet(fn, *args, **kwargs):
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return fn(*args, **kwargs)


class FakeTags:
    """The two tag facts sync-main needs, without git."""

    def __init__(self, versions, changelogs=None):
        self.versions = sorted(V(v) for v in versions)
        self._changelogs = {V(k): t for k, t in (changelogs or {}).items()}

    def changelog(self, v):
        return self._changelogs[v]


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
        env = rel.git_env(dict(GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.com",
                               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.com",
                               GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1"))
        return subprocess.run(["git", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false",
                               "-c", "maintenance.auto=false", "-c", "gc.auto=0", *args],
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
        """A PR to main adding one entry at the end of its [Unreleased]
        subsection (verbatim: an identical entry already there is kept)."""
        cl = rel.Changelog.parse(self.read())
        unrel = cl.unreleased()
        unrel.sub(heading, create=True).append(rel.Block([bullet]))
        if unrel.preamble.blocks:
            unrel.preamble.trail = max(unrel.preamble.trail, 1)
        self.git("checkout", "-q", "main")
        self.write(cl.render())
        self.commit(f"main: {bullet}")

    def cut(self, version, date, base="main", tag=True, sync=True):
        text = rel.cut_changelog(self.read(base), version, date, self.tags() if sync else None)
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
    """Every assertion runs on a temp copy stamped to BASELINE first, so the
    suite passes whatever version this checkout carries (main moves to each
    cut rc through the release-sync PR, D2)."""
    BASELINE = "4.0.0"
    TARGET = "5.0.0-rc.1"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        copy_packaging(self.root, scripts=True, baseline=self.BASELINE, changelog=TRAIN)
        self.current = self.BASELINE

    def tearDown(self):
        self.tmp.cleanup()

    def lint(self, *args):
        return subprocess.run(["bash", "scripts/release-lint.sh", *args], cwd=self.root,
                              capture_output=True, text=True)

    def test_stamping_the_current_version_is_a_byte_noop(self):
        self.assertEqual(rel.stamp_files(self.root, self.current), {})

    def test_the_live_checkout_is_coherent(self):
        live = rel._read(ROOT / "Cargo.toml").split('version = "', 1)[1].split('"', 1)[0]
        self.assertEqual(rel.stamp_files(ROOT, live), {})
        self.assertEqual(rel.npm_lock_drift(ROOT), [])

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
            proc = subprocess.run(["bash", "scripts/version-sync.sh", self.TARGET], cwd=self.root,
                                  capture_output=True, text=True, env=env)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            outs.append(snapshot(self.root))
        self.assertEqual(outs[0], outs[1])
        self.assertEqual(rel.stamp_files(self.root, self.TARGET), {})

    def test_rc_stamp_touches_every_site(self):
        old_lock = rel._read(self.root / "Cargo.lock")
        rel.stamp(self.root, self.TARGET)
        toml = rel._read(self.root / "Cargo.toml")
        self.assertIn(f'[workspace.package]\nversion = "{self.TARGET}"', toml)
        self.assertIn(f'socket-patch-core = {{ path = "crates/socket-patch-core", version = "={self.TARGET}" }}', toml)
        lock = rel._read(self.root / "Cargo.lock")
        for name in ["socket-patch-core", "socket-patch-cli", "socket-patch-node", "socket-patch-bench"]:
            self.assertIn(f'name = "{name}"\nversion = "{self.TARGET}"\n', lock)
        self.assertEqual(len(old_lock.splitlines()), len(lock.splitlines()))
        changed = [a for a, b in zip(old_lock.splitlines(), lock.splitlines()) if a != b]
        self.assertEqual(changed, [f'version = "{self.current}"'] * 4)
        manifests = sorted(self.root.glob("npm/*/package.json"))
        self.assertEqual(len(manifests), 15)
        for m in manifests:
            self.assertEqual(json.loads(rel._read(m))["version"], self.TARGET, m)
        main = json.loads(rel._read(self.root / "npm/socket-patch/package.json"))
        self.assertEqual(len(main["optionalDependencies"]), 14)
        self.assertEqual(set(main["optionalDependencies"].values()), {self.TARGET})
        npm_lock = json.loads(rel._read(self.root / "npm/socket-patch/package-lock.json"))
        self.assertEqual(npm_lock["version"], self.TARGET)
        self.assertEqual(npm_lock["packages"][""]["version"], self.TARGET)
        self.assertEqual(set(npm_lock["packages"][""]["optionalDependencies"].values()), {self.TARGET})
        self.assertFalse([k for k in npm_lock["packages"] if "@socketsecurity/socket-patch-" in k])
        self.assertIn("node_modules/zod", npm_lock["packages"])
        self.assertEqual(rel.npm_lock_drift(self.root), [])

    def test_platform_lock_entries_at_the_target_version_are_kept(self):
        self.assertIn(PLATFORM_PKG, json.loads(
            rel._read(self.root / "npm/socket-patch/package-lock.json"))["packages"])
        self.assertFalse(rel.stamp_files(self.root, self.current))

    def test_check_mode_writes_nothing(self):
        before = snapshot(self.root)
        self.assertEqual(quiet(rel.main, ["--root", str(self.root), "stamp", "--check", self.TARGET]), 1)
        self.assertEqual(snapshot(self.root), before)
        self.assertEqual(quiet(rel.main, ["--root", str(self.root), "stamp", "--check", self.current]), 0)

    def test_invalid_versions_are_refused(self):
        self.assertEqual(quiet(rel.main, ["--root", str(self.root), "stamp", "5.0.0-beta.1"]), 1)

    def test_release_lint_accepts_main_at_an_rc(self):
        rel.stamp(self.root, self.TARGET)
        path = self.root / "CHANGELOG.md"
        rel._write(path, rel.cut_changelog(rel._read(path), self.TARGET, "2026-10-12"))
        ok = self.lint()
        self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
        self.assertIn(f"all checks passed for {self.TARGET}", ok.stdout)
        self.assertNotEqual(self.lint("--stable-only").returncode, 0)
        rel._write(self.root / "npm/socket-patch-win32-x64/package.json",
                   rel._read(self.root / "npm/socket-patch-win32-x64/package.json").replace(self.TARGET, "4.0.0"))
        drift = self.lint("--sync-only")
        self.assertNotEqual(drift.returncode, 0)
        self.assertIn("npm/socket-patch-win32-x64/package.json", drift.stdout + drift.stderr)

    def test_release_lint_catches_npm_dependency_drift(self):
        pkg = self.root / "npm/socket-patch/package.json"
        rel._write(pkg, rel._read(pkg).replace('"zod": "3.25.76"', '"zod": "3.25.77"'))
        drift = self.lint("--sync-only")
        self.assertNotEqual(drift.returncode, 0, drift.stdout)
        self.assertIn("dependencies", drift.stdout + drift.stderr)
        self.assertIn("node_modules/zod is 3.25.76", drift.stdout + drift.stderr)
        self.assertEqual(quiet(rel.main, ["--root", str(self.root), "npm-lock-check"]), 1)
        rel._write(pkg, rel._read(pkg).replace('"zod": "3.25.77"', '"zod": "3.25.76"'))
        lock_path = self.root / "npm/socket-patch/package-lock.json"
        lock = json.loads(rel._read(lock_path))
        del lock["packages"]["node_modules/typescript"]
        lock["packages"][""]["engines"] = {"node": ">=20"}
        rel._write(lock_path, rel._dump_json(lock))
        problems = rel.npm_lock_drift(self.root)
        self.assertIn("package-lock.json has no node_modules/typescript (devDependencies)", problems)
        self.assertIn('package-lock.json packages[""].engines != package.json engines', problems)


class StampEolAndAtomicityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        copy_packaging(self.root, baseline="4.0.0", changelog=TRAIN)

    def test_a_crlf_checkout_stamps_and_checks_like_an_lf_one(self):
        # Re-review finding 5: a Windows autocrlf checkout (no `* text=auto`).
        twin = tempfile.TemporaryDirectory()
        self.addCleanup(twin.cleanup)
        copy_packaging(Path(twin.name), baseline="4.0.0", changelog=TRAIN)
        for rel_path in packaging_files():
            f = self.root / rel_path
            f.write_bytes(f.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
        self.assertEqual(rel.stamp(self.root, "4.0.0", check=True), [])
        self.assertEqual(rel.npm_lock_drift(self.root), [])
        changed = rel.stamp(self.root, "5.0.0-rc.1")
        self.assertEqual(changed, rel.stamp(Path(twin.name), "5.0.0-rc.1"))
        for rel_path in packaging_files():
            data = (self.root / rel_path).read_bytes()
            self.assertNotIn(b"\n", data.replace(b"\r\n", b""), rel_path)
            self.assertEqual(data.replace(b"\r\n", b"\n"), (Path(twin.name) / rel_path).read_bytes(), rel_path)
        self.assertEqual(rel.stamp(self.root, "5.0.0-rc.1", check=True), [])

    def test_sync_main_writes_nothing_when_the_stamp_refuses(self):
        # Re-review finding 6: CHANGELOG.md must not be rewritten when the
        # stamp then fails (here: Cargo.lock lost a workspace member entry).
        repo = TrainRepo()
        self.addCleanup(repo.close)
        copy_packaging(repo.root, baseline="4.0.0", changelog=TRAIN)
        lock = repo.root / "Cargo.lock"
        chunks = rel._read(lock).split("[[package]]\n")
        rel._write(lock, "[[package]]\n".join(c for c in chunks if not c.startswith('name = "socket-patch-bench"\n')))
        repo.commit("packaging")
        repo.git("tag", "-f", "v4.0.0")
        repo.cut("5.0.0-rc.1", "2026-10-12")
        before = snapshot(repo.root)
        with self.assertRaisesRegex(rel.ReleaseError, "Cargo.lock"):
            rel.sync_main(repo.root)
        self.assertEqual(snapshot(repo.root), before)
        self.assertEqual(quiet(rel.main, ["--root", str(repo.root), "sync-main"]), 1)
        self.assertEqual(snapshot(repo.root), before)


class StampFromAnRcBaselineTests(StampTests):
    """The same suite on a tree already at an rc (main after a release-sync)."""
    BASELINE = "5.0.0-rc.1"
    TARGET = "5.0.0-rc.2"


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
        # The fold keeps every occurrence (multiset): rc.2 repeated #581.
        self.assertEqual(texts.count("- Bound patch API connects and stalled reads (#581)."), 2)
        self.assertEqual(texts[-2:], ["- rc.2 fix (#600).", "- Bound patch API connects and stalled reads (#581)."])
        self.assertEqual(len(texts), 8)
        # rc.3 was never promoted: its block returns to [Unreleased].
        self.assertEqual([b.text for _, b in cl.unreleased().items()], ["- rc.3 feature (#610)."])
        self.assertEqual(rel.check_section(stable, "5.0.0"), 8)
        with self.assertRaises(rel.ReleaseError):
            rel.promote_changelog(stable, "5.0.0-rc.2", "2026-10-27")

    def test_promote_returns_every_block_of_a_later_rc(self):
        # rc.2 repeats an rc.1 entry and is abandoned when rc.1 is promoted:
        # its copy did not ship, so it returns (sync-main step 2 agrees).
        rc1 = rel.cut_changelog(TRAIN, "5.0.0-rc.1", "2026-10-12")
        cl = rel.Changelog.parse(rc1)
        cl.unreleased().append_items([("Fixed", rel.Block(["- Bound patch API connects and stalled reads (#581)."])),
                                      ("Fixed", rel.Block(["- rc.2 fix (#600)."]))])
        rc2 = rel.cut_changelog(cl.render(), "5.0.0-rc.2", "2026-10-19")
        stable = rel.Changelog.parse(rel.promote_changelog(rc2, "5.0.0-rc.1", "2026-10-20"))
        self.assertEqual([b.text for _, b in stable.unreleased().items()],
                         ["- Bound patch API connects and stalled reads (#581).", "- rc.2 fix (#600)."])
        self.assertEqual(len(stable.section(V("5.0.0")).items()), 6)

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
        self.assertEqual(report["folded"], ["5.0.0-rc.1", "5.0.0-rc.2"])
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

    def __init__(self, scenario, repo=None, base=None, base_time=None):
        self.repo, self.base = repo or BLOCKERS["repo"], base or BLOCKERS["base"]
        self.base_time = base_time or BLOCKERS["baseTime"]
        issues = copy.deepcopy(scenario["issues"])
        self.events = {i["number"]: i.pop("events") for i in issues}
        self.timeline = {i["number"]: i.pop("timeline", []) for i in issues}
        self.issues = {i["number"]: i for i in issues}
        self.compare = scenario.get("compare", {})
        self.pulls = {int(k): v for k, v in scenario.get("pulls", {}).items()}
        self.gone = {int(k): v for k, v in scenario.get("gone", {}).items()}
        self.label = scenario.get("label", "release-blocker")
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
        # GitHub's `labels=` filter is case-insensitive.
        labelled = lambda i: any(lbl["name"].lower() == query["labels"].lower() for lbl in i["labels"])
        if path == f"/commits/{self.base}":
            body = {"sha": self.base, "commit": {"committer": {"date": self.base_time}}}
        elif path.startswith("/labels/"):
            if self.label is None or self.label.lower() != path[len("/labels/"):].lower():
                return 404, {}, b'{"message": "Not Found"}'
            body = {"name": self.label}
        elif path.startswith("/pulls/"):
            body = self.pulls[int(path.split("/")[2])]
        elif path.startswith("/issues/") and path.endswith("/timeline"):
            body = self.timeline[int(path.split("/")[2])]
        elif path.split("/")[-1].isdigit() and path.startswith("/issues/") and int(path.split("/")[2]) in self.gone:
            return self.gone[int(path.split("/")[2])], {}, b'{"message": "gone"}'
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
            result = rel.evaluate_blockers(gh, "b" * 40, "2026-08-20T00:00:00Z", {"alice"}, {"bot"})
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



# ── review fixes: CHANGELOG invariants ──────────────────────────────────────

class ChangelogInvariantTests(unittest.TestCase):
    def test_crlf_round_trips_and_every_transform_keeps_crlf(self):
        crlf = TRAIN.replace("\n", "\r\n")
        self.assertEqual(rel.Changelog.parse(crlf).render(), crlf)
        bare_lf = lambda text: [i for i, c in enumerate(text) if c == "\n" and text[i - 1:i] != "\r"]
        cut = rel.cut_changelog(crlf, "5.0.0-rc.1", "2026-10-12")
        self.assertEqual(cut, rel.cut_changelog(TRAIN, "5.0.0-rc.1", "2026-10-12").replace("\n", "\r\n"))
        promoted = rel.promote_changelog(cut, "5.0.0-rc.1", "2026-10-20")
        self.assertEqual(bare_lf(promoted), [])
        self.assertEqual(promoted, rel.promote_changelog(
            rel.cut_changelog(TRAIN, "5.0.0-rc.1", "2026-10-12"), "5.0.0-rc.1", "2026-10-20").replace("\n", "\r\n"))
        # sync-main: tag CHANGELOGs come from git (LF); main's CRLF wins.
        fake = FakeTags(["4.0.0", "5.0.0-rc.1"], {"5.0.0-rc.1": rel.cut_changelog(TRAIN, "5.0.0-rc.1", "2026-10-12")})
        cl = rel.Changelog.parse(crlf)
        cl.unreleased().sub("Fixed").append(rel.Block(["- Landed after the cut (#600)."]))
        synced, report = rel.sync_main_changelog(cl.render(), fake)
        self.assertEqual(report["inserted"], ["5.0.0-rc.1"])
        self.assertEqual(bare_lf(synced), [])
        self.assertEqual(rel.check_section(synced, "5.0.0-rc.1"), 6)

    def test_cut_orders_subsections_canonically(self):
        text = ("## [Unreleased]\n\nIntro.\n\n### Maintenance\n\n- m\n\n### Fixed\n\n- f1\n- f2\n\n"
                "### Security\n\n- s\n\n### Added\n\n- a\n\n### Breaking changes\n\n- b\n\n## [4.0.0] — 2026-08-20\n\n- x\n")
        cut = rel.cut_changelog(text, "5.0.0-rc.1", "2026-10-12")
        sec = rel.Changelog.parse(cut).section(V("5.0.0-rc.1"))
        self.assertEqual([s.name for s in sec.subs],
                         [None, "Breaking changes", "Added", "Fixed", "Security", "Maintenance"])
        self.assertEqual([b.text for _, b in sec.items()], ["Intro.", "- b", "- a", "- f1", "- f2", "- s", "- m"])
        self.assertIn("## [5.0.0-rc.1] — 2026-10-12\n\nIntro.\n\n### Breaking changes\n\n- b\n\n### Added\n\n- a\n\n"
                      "### Fixed\n\n- f1\n- f2\n\n### Security\n\n- s\n\n### Maintenance\n\n- m\n\n## [4.0.0]", cut)

    def test_remove_takes_one_occurrence_per_shipped_block(self):
        unrel = rel.Changelog.parse("## [Unreleased]\n\n### Changed\n\n- dup\n- other\n- dup\n").unreleased()
        removed = unrel.remove({("Changed", "- dup"): 1})
        self.assertEqual(sum(removed.values()), 1)
        self.assertEqual([b.text for _, b in unrel.items()], ["- other", "- dup"])


class SyncInvarianceTests(unittest.TestCase):
    """An unmerged release-sync PR changes neither the version nor the bytes
    of the next cut (DESIGN.md §3.7), and no CHANGELOG entry is lost."""

    def both(self, script):
        out = []
        for merge in (True, False):
            r = TrainRepo()
            self.addCleanup(r.close)
            script(r, r.merge_sync if merge else (lambda: None))
            nv = r.next_version()
            out.append((nv, rel.cut_changelog(r.read(), nv, "2026-11-30", r.tags()), r))
        self.assertEqual(out[0][:2], out[1][:2])
        return out[0]

    def test_hotfix_beside_a_pending_train_rc_of_the_same_core(self):
        def script(r, sync):
            r.cut("5.0.0-rc.1", "2026-10-12"); sync()
            r.promote("5.0.0-rc.1", "2026-10-20"); sync()
            r.add_unreleased("Fixed", "- Train fix A (#700).")
            self.assertEqual(r.next_version(), "5.0.1-rc.1")
            r.cut("5.0.1-rc.1", "2026-10-26"); sync()
            r.add_unreleased("Fixed", "- Urgent fix B (#710).")  # the pick, on main first
            # Hotfix (§3.4): from v5.0.0, V = patch(L)-rc.N with rc.1 burned,
            # cut without syncing train rcs into it.
            cl = rel.Changelog.parse(r.read("v5.0.0"))
            cl.unreleased().sub("Fixed", create=True).append(rel.Block(["- Urgent fix B (#710)."]))
            r.git("checkout", "-q", "-b", "release/v5.0.1-rc.2", "v5.0.0")
            r.write(rel.roll_unreleased(cl.render(), "5.0.1-rc.2", "2026-10-28"))
            r.commit("hotfix")
            r.git("tag", "v5.0.1-rc.2")
            r.git("checkout", "-q", "main")
            r.promote("5.0.1-rc.2", "2026-10-29")
            synced, report = rel.sync_main_changelog(r.read(), r.tags())
            cl = rel.Changelog.parse(synced)
            self.assertEqual([b.text for _, b in cl.section(V("5.0.1")).items()], ["- Urgent fix B (#710)."])
            self.assertEqual([b.text for _, b in cl.unreleased().items()], ["- Train fix A (#700)."])
            self.assertNotIn("-rc.", synced)
            self.assertIn("5.0.1", report["inserted"])  # (5.0.0 too when never synced)
            sync()
        nv, cut, _ = self.both(script)
        self.assertEqual(nv, "5.0.2-rc.1")
        self.assertEqual([b.text for _, b in rel.Changelog.parse(cut).section(V(nv)).items()],
                         ["- Train fix A (#700)."])

    def test_a_repeated_entry_is_not_swallowed(self):
        def script(r, sync):
            r.add_unreleased("Changed", "- Updated dependencies.")
            r.cut("5.0.0-rc.1", "2026-10-12"); sync()
            r.add_unreleased("Changed", "- Updated dependencies.")  # a new entry for week two
            r.add_unreleased("Fixed", "- Week-two fix (#600).")
        nv, cut, _ = self.both(script)
        self.assertEqual(nv, "5.0.0-rc.2")
        self.assertEqual([b.text for _, b in rel.Changelog.parse(cut).section(V(nv)).items()],
                         ["- Updated dependencies.", "- Week-two fix (#600)."])

    def test_an_entry_repeated_across_folded_rcs_ships_once_per_copy(self):
        # Re-review finding 1: the fold and sync-main count the same way, so
        # neither copy of a repeated entry comes back as unshipped (which
        # would also have raised the next bump from patch to minor).
        def script(r, sync):
            r.add_unreleased("Changed", "- Updated dependencies.")
            r.cut("5.0.0-rc.1", "2026-10-12"); sync()
            r.add_unreleased("Changed", "- Updated dependencies.")
            r.add_unreleased("Fixed", "- Week-two fix (#600).")
            r.cut("5.0.0-rc.2", "2026-10-19"); sync()
            folded = rel.Changelog.parse(r.promote("5.0.0-rc.2", "2026-10-27")).section(V("5.0.0"))
            self.assertEqual([b.text for _, b in folded.items()].count("- Updated dependencies."), 2)
            sync()
            synced = rel.Changelog.parse(rel.sync_main_changelog(r.read(), r.tags())[0])
            self.assertFalse(synced.unreleased().items())
            r.add_unreleased("Fixed", "- Week-four fix (#700).")
        nv, cut, _ = self.both(script)
        self.assertEqual(nv, "5.0.1-rc.1")
        self.assertEqual([(n, b.text) for n, b in rel.Changelog.parse(cut).section(V(nv)).items()],
                         [("Fixed", "- Week-four fix (#700).")])

    def test_a_repeated_entry_after_a_promotion_keeps_its_place(self):
        # Re-review finding 3: the rc section on main is charged before
        # [Unreleased] is touched, so the newer identical copy stays where
        # it was written, synced or not.
        def script(r, sync):
            r.add_unreleased("Fixed", "- R.")
            r.cut("5.0.0-rc.1", "2026-10-12"); sync()
            r.add_unreleased("Fixed", "- W2 (#600).")
            r.add_unreleased("Fixed", "- R.")
            r.promote("5.0.0-rc.1", "2026-10-20"); sync()
        nv, cut, _ = self.both(script)
        self.assertEqual(nv, "5.0.1-rc.1")
        self.assertEqual([b.text for _, b in rel.Changelog.parse(cut).section(V(nv)).items()],
                         ["- W2 (#600).", "- R."])

    def test_a_repeated_heading_entry_keeps_the_bump_level(self):
        def script(r, sync):
            r.cut("5.0.0-rc.1", "2026-10-12"); sync()
            r.promote("5.0.0-rc.1", "2026-10-20"); sync()
            r.add_unreleased("Added", "- Support for more lockfiles.")
            r.cut("5.1.0-rc.1", "2026-10-26"); sync()
            r.promote("5.1.0-rc.1", "2026-11-03"); sync()
            r.add_unreleased("Added", "- Support for more lockfiles.")
        nv, _, _ = self.both(script)
        self.assertEqual(nv, "5.2.0-rc.1")

    def test_returned_blocks_keep_their_chronological_place(self):
        def script(r, sync):
            r.cut("5.0.0-rc.1", "2026-10-12"); sync()
            r.add_unreleased("Fixed", "- Week-two fix (#600).")
            r.cut("5.0.0-rc.2", "2026-10-19"); sync()
            r.add_unreleased("Fixed", "- Week-three fix B (#610).")
            r.promote("5.0.0-rc.1", "2026-10-20")
        nv, cut, _ = self.both(script)
        self.assertEqual(nv, "5.0.1-rc.1")
        self.assertEqual([b.text for _, b in rel.Changelog.parse(cut).section(V(nv)).items()],
                         ["- Week-two fix (#600).", "- Week-three fix B (#610)."])

    def test_subsection_order_does_not_depend_on_shipped_history(self):
        def script(r, sync):
            r.cut("5.0.0-rc.1", "2026-10-12"); sync()  # TRAIN: Breaking, Added, Fixed
            r.add_unreleased("Fixed", "- X (#600).")
            r.add_unreleased("Added", "- Y (#601).")
            r.add_unreleased("Fixed", "- Z (#602).")
            r.cut("5.0.0-rc.2", "2026-10-19"); sync()
            r.add_unreleased("Maintenance", "- M (#603).")
            r.promote("5.0.0-rc.1", "2026-10-20")
        nv, cut, _ = self.both(script)
        self.assertEqual(nv, "5.1.0-rc.1")
        sec = rel.Changelog.parse(cut).section(V(nv))
        self.assertEqual([(n, b.text) for n, b in sec.items()],
                         [("Added", "- Y (#601)."), ("Fixed", "- X (#600)."), ("Fixed", "- Z (#602)."),
                          ("Maintenance", "- M (#603).")])

    def test_synced_main_at_an_rc_passes_release_lint(self):
        r = TrainRepo()
        self.addCleanup(r.close)
        copy_packaging(r.root, scripts=True, baseline="4.0.0", changelog=TRAIN)
        r.commit("packaging")
        r.git("tag", "-f", "v4.0.0")
        r.git("remote", "add", "origin", str(r.root))
        r.cut("5.0.0-rc.1", "2026-10-12")
        r.add_unreleased("Fixed", "- Landed after the cut (#600).")
        report = rel.sync_main(r.root)
        self.assertEqual(report["version"], "5.0.0-rc.1")
        lint = lambda *a: subprocess.run(["bash", "scripts/release-lint.sh", *a], cwd=r.root,
                                         capture_output=True, text=True, env=rel.git_env())
        for args in [(), ("--tag-exists",)]:
            res = lint(*args)
            self.assertEqual(res.returncode, 0, (args, res.stdout, res.stderr))
            self.assertIn("all checks passed for 5.0.0-rc.1", res.stdout)
        self.assertNotEqual(lint("--tag-check").returncode, 0)  # the tag exists elsewhere
        r.git("tag", "-d", "v5.0.0-rc.1")
        gone = lint("--tag-exists")
        self.assertNotEqual(gone.returncode, 0)
        self.assertIn("does not exist", gone.stdout + gone.stderr)

    def test_git_environment_cannot_redirect_the_repos(self):
        victim = tempfile.TemporaryDirectory()
        self.addCleanup(victim.cleanup)
        subprocess.run(["git", "init", "-q", "-b", "main", victim.name], check=True, env=rel.git_env())
        with patch.dict(os.environ, GIT_DIR=os.path.join(victim.name, ".git"), GIT_WORK_TREE=victim.name):
            r = TrainRepo()
            self.addCleanup(r.close)
            r.cut("5.0.0-rc.1", "2026-10-12")
            self.assertEqual(r.next_version(), "5.0.0-rc.2")
            self.assertEqual(sorted(map(str, rel.Git(r.root).tags())), ["4.0.0", "5.0.0-rc.1"])
        refs = subprocess.run(["git", "-C", victim.name, "for-each-ref"], capture_output=True, text=True,
                              env=rel.git_env()).stdout
        self.assertEqual(refs, "")


# ── review fixes: release-blocker gate ──────────────────────────────────────

def _ev(i, kind, login, at, label=None, commit=None):
    e = {"id": i, "event": kind, "actor": {"login": login, "type": "User"}, "commit_id": commit,
         "created_at": at}
    if label:
        e["label"] = {"name": label}
    return e


def _issue(number, labels, state, events, **extra):
    return dict({"number": number, "title": "t", "state": state, "labels": [{"name": n} for n in labels],
                 "closed_at": "2026-10-01T00:00:00Z" if state == "closed" else None, "events": events}, **extra)


class BlockerHardeningTests(unittest.TestCase):
    APPROVERS = rel._logins("alice, bob, mikolalysenko")
    ROUTINE = rel._logins("mikolalysenko, claude-routine-bot")

    def evaluate(self, scenario, since=None):
        fake = FakeGitHub(scenario)
        result = rel.evaluate_blockers(rel.GitHub(BLOCKERS["repo"], "t0ken", fake), BLOCKERS["base"],
                                       since or BLOCKERS["since"], self.APPROVERS, self.ROUTINE)
        return result, fake

    def test_label_names_compare_case_insensitively(self):
        result, _ = self.evaluate({"issues": [_issue(7, ["Release-Blocker"], "open", [
            _ev(1, "labeled", "alice", "2026-09-01T00:00:00Z", "Release-Blocker")])]})
        self.assertEqual([b["number"] for b in result["blockers"]], [7], result)
        result, _ = self.evaluate({"issues": [_issue(8, [], "open", [
            _ev(1, "labeled", "alice", "2026-09-01T00:00:00Z", "release-blocker"),
            _ev(2, "unlabeled", "claude-routine-bot", "2026-09-02T00:00:00Z", "RELEASE-BLOCKER")])]})
        self.assertEqual([b["number"] for b in result["blockers"]], [8], result)

    def test_a_missing_or_renamed_label_blocks(self):
        open_issue = _issue(7, ["release-blocker"], "open", [
            _ev(1, "labeled", "alice", "2026-09-01T00:00:00Z", "release-blocker")])
        for label in (None, "Release-Blocker"):
            with self.subTest(label=label):
                result, fake = self.evaluate({"issues": [open_issue], "label": label})
                self.assertTrue(result["blocked"])
                self.assertTrue(result["error"].startswith("label:"), result)
                self.assertNotIn(f"/repos/{BLOCKERS['repo']}/issues", fake.calls)

    def test_a_label_that_vanished_without_an_unlabel_event_blocks(self):
        result, _ = self.evaluate({"issues": [_issue(9, [], "open", [
            _ev(1, "labeled", "alice", "2026-09-01T00:00:00Z", "release-blocker")])]})
        self.assertEqual(result["blockers"], [{"number": 9, "reason": "open, label removed without an unlabeled event"}])

    def test_deleted_transferred_or_converted_issues_block(self):
        labelled = [_ev(1, "labeled", "alice", "2026-09-01T00:00:00Z", "release-blocker")]
        for status in (404, 410):
            with self.subTest(status=status):
                result, _ = self.evaluate({"issues": [_issue(10, [], "open", labelled)], "gone": {"10": status}})
                self.assertEqual([b["number"] for b in result["blockers"]], [10], result)
                self.assertIn("issue gone", result["blockers"][0]["reason"])
        moved = _issue(11, ["release-blocker"], "open", labelled,
                       repository_url="https://api.github.com/repos/o/elsewhere")
        result, _ = self.evaluate({"issues": [moved]})
        self.assertEqual([b["number"] for b in result["blockers"]], [11], result)
        self.assertIn("transferred", result["blockers"][0]["reason"])

    def test_evaluate_itself_fails_closed_without_both_lists(self):
        scenario = BLOCKERS["scenarios"]["closed_by_mik_in_routine_fallback"]
        for approvers, routine in [(self.APPROVERS, set()), (set(), self.ROUTINE), ({"mikolalysenko"}, self.ROUTINE)]:
            fake = FakeGitHub(scenario)
            result = rel.evaluate_blockers(rel.GitHub(BLOCKERS["repo"], "t0ken", fake), BLOCKERS["base"],
                                           BLOCKERS["since"], approvers, routine)
            self.assertTrue(result["blocked"])
            self.assertTrue(result["error"].startswith("config:"), result)

    def test_malformed_event_shapes_fail_closed(self):
        bad = _issue(7, ["release-blocker"], "open", [_ev(1, "labeled", "alice", "2026-09-01T00:00:00Z")])
        bad["events"][0]["label"] = "release-blocker"  # a string, not an object
        result, _ = self.evaluate({"issues": [bad]})
        self.assertTrue(result["blocked"])
        self.assertIn("api-error", result["error"])

    def test_since_after_the_base_commit_fails_closed(self):
        scenario = BLOCKERS["scenarios"]["closed_by_routine_actor"]
        self.assertTrue(self.evaluate(scenario)[0]["blocked"])
        result, _ = self.evaluate(scenario, since="2099-01-01T00:00:00Z")
        self.assertTrue(result["blocked"])
        self.assertTrue(result["error"].startswith("since:"), result)

    def test_login_lists_parse_strictly(self):
        self.assertEqual(rel._logins("mikolalysenko\nclaude-routine-bot"), {"mikolalysenko", "claude-routine-bot"})
        self.assertEqual(rel._logins(" @MikolaLysenko  claude-routine-bot,\tgithub-actions[bot] "),
                         {"mikolalysenko", "claude-routine-bot", "github-actions[bot]"})
        for bad in ["mikolalysenko;bob", "-bob", "a/b", "bob@example.com"]:
            with self.subTest(bad=bad), self.assertRaises(rel.ReleaseError):
                rel._logins(bad)
        for approvers, routine in [("alice", ""), ("alice", None), ("", "mikolalysenko"),
                                   ("mikolalysenko", "mikolalysenko,bot")]:
            with self.subTest(approvers=approvers, routine=routine), self.assertRaises(rel.ReleaseError):
                rel.blocker_config(approvers, routine)

    def test_cli_fails_closed_on_routine_actor_config(self):
        args = rel.build_parser().parse_args(["blockers", "--base", BLOCKERS["base"], "--repo", "o/r",
                                              "--since", BLOCKERS["since"]])
        scenario = BLOCKERS["scenarios"]["closed_by_mik_in_routine_fallback"]
        for routine, code in [("mikolalysenko\nclaude-routine-bot", 1), ("@mikolalysenko claude-routine-bot", 1),
                              ("", 1), (None, 1), ("mikolalysenko,", 1)]:
            fake = FakeGitHub(scenario)
            env = {"GITHUB_TOKEN": "t0ken", "RELEASE_APPROVERS": "alice,bob,mikolalysenko"}
            if routine is not None:
                env["RELEASE_ROUTINE_ACTORS"] = routine
            out = io.StringIO()
            with patch.dict(os.environ, env), contextlib.redirect_stdout(out), \
                    contextlib.redirect_stderr(io.StringIO()):
                if routine is None:
                    os.environ.pop("RELEASE_ROUTINE_ACTORS", None)
                self.assertEqual(rel.cmd_blockers(args, fake), code, routine)
            result = json.loads(out.getvalue())
            self.assertTrue(result["blocked"], routine)
            if not (routine or "").strip(", "):
                self.assertTrue(result["error"].startswith("config:"), result)
                self.assertEqual(fake.calls, [])
            else:
                self.assertEqual([b["number"] for b in result["blockers"]], [107])

    def test_a_pr_merge_close_resolves_through_the_merge_commit(self):
        fx = json.loads((FIXTURES / "blockers-pr-merge-454.json").read_text(encoding="utf-8"))

        def run(compare=None, timeline=None):
            issue = dict(fx["issue"], events=fx["events"], timeline=fx["timeline"] if timeline is None else timeline)
            fake = FakeGitHub({"issues": [issue], "pulls": fx["pulls"], "compare": compare or {}},
                              repo=fx["repo"], base=fx["base"], base_time=fx["baseTime"])
            return rel.evaluate_blockers(rel.GitHub(fx["repo"], "t0ken", fake), fx["base"], fx["since"],
                                         self.APPROVERS, self.ROUTINE)
        sha = fx["pulls"]["456"]["merge_commit_sha"]
        self.assertFalse(run({sha: "identical"})["blocked"])
        self.assertFalse(run({sha: "ahead"})["blocked"])
        behind = run({sha: "diverged"})
        self.assertTrue(behind["blocked"])
        self.assertIn("closing PR merge a36432ee1ae7 not in base", behind["blockers"][0]["reason"])
        none = run(timeline=[])
        self.assertIn("no fix commit", none["blockers"][0]["reason"])
        # A PR that merged long before the close did not close it.
        late = copy.deepcopy(fx["timeline"])
        late[0]["source"]["issue"]["pull_request"]["merged_at"] = "2026-10-01T10:00:00Z"
        self.assertIn("no fix commit", run({sha: "ahead"}, timeline=late)["blockers"][0]["reason"])

    def test_a_manual_close_after_an_unrelated_mentioning_pr_does_not_resolve(self):
        # Re-review finding 4: a PR that merely mentions the issue and merged
        # just before someone else closed it by hand is not its closing PR.
        fx = json.loads((FIXTURES / "blockers-pr-merge-454.json").read_text(encoding="utf-8"))
        sha = fx["pulls"]["456"]["merge_commit_sha"]
        for closer, merger in [("claude-routine-bot", "mikolalysenko"), ("alice", "mikolalysenko"),
                               ("mikolalysenko", None)]:
            with self.subTest(closer=closer, merger=merger):
                events = copy.deepcopy(fx["events"])
                events[-1]["actor"]["login"] = closer
                pulls = copy.deepcopy(fx["pulls"])
                pulls["456"]["merged_by"] = {"login": merger} if merger else None
                issue = dict(fx["issue"], events=events, timeline=fx["timeline"])
                fake = FakeGitHub({"issues": [issue], "pulls": pulls, "compare": {sha: "ahead"}},
                                  repo=fx["repo"], base=fx["base"], base_time=fx["baseTime"])
                result = rel.evaluate_blockers(rel.GitHub(fx["repo"], "t0ken", fake), fx["base"], fx["since"],
                                               self.APPROVERS, self.ROUTINE)
                # (alice is trusted, but her close is after t: it needs a fix.)
                self.assertTrue(result["blocked"], result)
                self.assertIn("no fix commit", result["blockers"][0]["reason"])

    def test_since_comes_from_mains_history_not_the_tags_date(self):
        repo = TrainRepo()
        self.addCleanup(repo.close)
        repo.commit("main: later work")
        base = repo.git("rev-parse", "HEAD").strip()
        repo.git("checkout", "-q", "-b", "side", "v4.0.0")
        env_date = {"GIT_COMMITTER_DATE": "2099-01-01T00:00:00Z"}
        subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "forged"],
                       cwd=repo.root, check=True, env=rel.git_env(dict(env_date, GIT_AUTHOR_NAME="t",
                       GIT_AUTHOR_EMAIL="t@e", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@e")))
        repo.git("tag", "v4.0.1")
        repo.git("checkout", "-q", "main")
        since = rel.latest_stable_date(repo.git_api, base)
        floor = rel._ts(repo.git_api.commit_date(base)) - rel.SINCE_LOOKBACK
        self.assertEqual(rel._ts(since), min(floor, rel._ts(repo.git_api.commit_date("v4.0.0"))))
        with self.assertRaises(rel.ReleaseError):
            rel.latest_stable_date(repo.git_api, "0" * 40)

    def test_a_forged_stable_tag_cannot_move_since_past_the_lookback(self):
        # Re-review finding 2: a high stable tag pointed at the base itself
        # (no date forgery) makes merge-base(L, base) = base.
        def at(date):
            return rel.git_env(dict(GIT_COMMITTER_DATE=date, GIT_AUTHOR_DATE=date, GIT_AUTHOR_NAME="t",
                                    GIT_AUTHOR_EMAIL="t@e", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@e"))
        repo = TrainRepo()
        self.addCleanup(repo.close)
        for date in ("2026-06-01T00:00:00Z", "2026-09-01T00:00:00Z", "2026-10-01T00:00:00Z"):
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", date],
                           cwd=repo.root, check=True, env=at(date))
            if date.startswith("2026-06"):
                repo.git("tag", "-f", "v4.0.0")  # L, cut long before the lookback
        base = repo.git("rev-parse", "HEAD").strip()
        honest = rel._ts(rel.latest_stable_date(repo.git_api, base))
        self.assertEqual(honest, rel._ts("2026-06-01T00:00:00Z"))
        for tag in ("v4.0.1", "v99.0.0"):
            repo.git("tag", tag, base)
            forged = rel._ts(rel.latest_stable_date(repo.git_api, base))
            self.assertEqual(forged, rel._ts("2026-10-01T00:00:00Z") - rel.SINCE_LOOKBACK, tag)
            repo.git("tag", "-d", tag)


# ── review fixes: the CI release-readiness gate ─────────────────────────────

class CiGateTests(unittest.TestCase):
    """Runs the `Lint release readiness` step of ci.yml with release-lint.sh
    and git stubbed, to check which path each PR shape takes."""

    @classmethod
    def setUpClass(cls):
        lines = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8").splitlines()
        start = lines.index("      - name: Lint release readiness")
        run = next(i for i in range(start, len(lines)) if lines[i].strip() == "run: |")
        body = []
        for line in lines[run + 1:]:
            if line.strip() and not line.startswith(" " * 10):
                break
            body.append(line[10:])
        cls.script = "\n".join(body) + "\n"

    def gate(self, head_ref, head_repo, base_ref="main", bump=False):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "scripts").mkdir()
            (d / "bin").mkdir()
            (d / "scripts/release-lint.sh").write_text('echo "LINT $*"\n')
            (d / "Cargo.toml").write_text('version = "5.0.0-rc.1"\n')
            (d / "bin/git").write_text('#!/bin/sh\n[ "$1" = show ] && echo \'version = "%s"\'\nexit 0\n'
                                       % ("4.0.0" if bump else "5.0.0-rc.1"))
            (d / "bin/git").chmod(0o755)
            env = dict(os.environ, PATH=f"{d / 'bin'}:{os.environ['PATH']}", EVENT_NAME="pull_request",
                       BASE_SHA="b" * 40, HEAD_REF=head_ref, BASE_REF=base_ref, HEAD_REPO=head_repo,
                       REPO="SocketDev/socket-patch")
            proc = subprocess.run(["bash", "-e", "-c", self.script], cwd=d, env=env, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            return proc.stdout.strip().splitlines()[-1]

    def test_only_the_same_repo_sync_branch_into_main_skips_the_bump_gate(self):
        self.assertEqual(self.gate("release-sync", "SocketDev/socket-patch", bump=True), "LINT --tag-exists")
        self.assertEqual(self.gate("release-sync", "mallory/socket-patch", bump=True), "LINT --tag-check")
        self.assertEqual(self.gate("release-sync", "SocketDev/socket-patch", base_ref="release/v5", bump=True),
                         "LINT --tag-check")
        self.assertEqual(self.gate("release-sync", "mallory/socket-patch"), "LINT --sync-only")
        self.assertEqual(self.gate("feature", "SocketDev/socket-patch"), "LINT --sync-only")

if __name__ == "__main__":
    unittest.main()
