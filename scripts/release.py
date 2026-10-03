#!/usr/bin/env python3
"""socket-patch release-train tooling (docs/release-train/DESIGN.md).

Stdlib-only, one file, so every workflow and routine can run it with a bare
`python3`. Subcommands (PR 1 of the train):

  semver validate|compare|core   version grammar: X.Y.Z or X.Y.Z-rc.N only
  stamp <V> [--check]            offline, byte-deterministic version stamp
                                 (Cargo.toml, Cargo.lock, 15 npm manifests,
                                 the npm wrapper lockfile)
  npm-lock-check                 offline: the npm wrapper lockfile agrees with
                                 its package.json beyond the stamped versions
  next-version                   the version the next rc cut would get,
                                 derived from git tags + burned release/*
                                 branches + the [Unreleased] headings
  changelog cut|promote|sync-main|check
                                 CHANGELOG.md transforms (see "CHANGELOG
                                 model" below)
  sync-main [--check]            the rolling release-sync PR's deterministic
                                 part: CHANGELOG sync + stamp of the newest tag
  notes --version V              GitHub release notes for one section
  blockers --base <sha>          the release-blocker gate (DESIGN.md §3.5)

Exit status: 0 ok, 1 refused/blocked/drift, 2 usage error.

Version rules
-------------
* Grammar: `X.Y.Z` (stable) or `X.Y.Z-rc.N` (N >= 1, no leading zeros). No
  other prerelease or build-metadata forms exist in this project.
  Precedence is semver's: X.Y.Z-rc.N < X.Y.Z-rc.(N+1) < X.Y.Z.
* L = the newest stable tag. The bump level comes from the `### ` headings of
  [Unreleased] that still hold entries *after* `changelog sync-main` has been
  applied in memory (so an unmerged release-sync PR changes nothing):
  a heading containing "breaking" or starting "Removed" -> major;
  starting "Added" / "Changed" / "Deprecated" -> minor; anything else -> patch.
* core = max(bump(L, level), every pending rc core above L). N = 1 + the
  highest rc number of that core over tags AND release/v<core>-rc.* branches
  (a number is burned when its branch is created, even if it never ships).
* Major rule: a core whose major is above L's major may only be cut when
  that major is listed in APPROVED_MAJORS below, and only L.major + 1 (a major
  is never skipped). Adding a major there is a reviewed PR on main, i.e. a
  human decision. Once a major's train is in flight (an rc tag M.0.0-rc.N
  exists) further breaking entries are absorbed into M.0.0. A breaking
  heading that would open an unapproved major is refused with an error
  rather than silently shipped as a minor.
* Main's own Cargo/npm version is never read for any of this.

CHANGELOG model
---------------
Sections are `## [Unreleased]` and `## [V] — YYYY-MM-DD`; subsections are
`### Name`. A *block* is a top-level bullet with its continuation lines, a
paragraph, or a fenced code block. Block identity is (subsection name, text
with trailing whitespace stripped); all matching is exact and counts
occurrences (multisets): removing a shipped block removes one occurrence, so
an identical entry written again later is kept. CRLF files stay CRLF.

* cut V: apply sync-main in memory, then move every [Unreleased] block into a
  new `## [V] — date` section directly below an empty [Unreleased]. The new
  section's `###` subsections are put in canonical order (SUBSECTION_ORDER),
  so the cut does not depend on the order main's [Unreleased] happens to have.
* promote rc.K: fold every `[X-rc.N]` section with X-rc.N <= rc.K that is
  newer than the newest stable section into one `## [core] — date` section
  (oldest rc first; within a subsection later rcs append; rc headers
  removed). The fold keeps every occurrence: an entry written in two rcs
  (`- Updated dependencies.` twice) appears twice, so [core] is exactly the
  multiset sum of the folded rcs, the same count sync-main charges them
  against. Later rc sections of the same core (rc.K+1..) are abandoned:
  all of their blocks move back into [Unreleased] (before the blocks already
  there) and their headers are dropped.
* sync-main (main's CHANGELOG := what it would be had every release-sync PR
  merged). For train-era tags (version > TRAIN_FLOOR):
    1. each stable tag S whose section main lacks: insert the tag's own [S]
       section; its blocks form S's budget (a multiset);
    2. each rc section on main whose core already shipped (owner S = the
       smallest stable tag >= its core) is dropped. Its blocks (text from
       its tag) are charged against S's budget, oldest rc first; the ones
       the budget does not cover did not ship and move back into
       [Unreleased], oldest rc first and before the blocks already there. A
       folded rc returns nothing; an abandoned later rc, or a train rc cut
       beside a hotfix of the same core, returns exactly what did not ship.
       No ancestry or rc-number rule is involved;
    3. what is left of each new S's budget (the shipped blocks main never
       got as an rc section, i.e. still in [Unreleased] on an unsynced
       main) is removed from [Unreleased], one occurrence each, oldest
       first. Charging the rc sections before touching [Unreleased] keeps a
       newer identical entry (which did not ship) in place either way;
    4. each pending rc tag (no owner yet) whose section main lacks: insert
       the tag's section and remove those blocks from [Unreleased].
  Only blocks of sections inserted *in this run* are removed from
  [Unreleased], so entries added to [Unreleased] later are never touched and
  a second run is a no-op. Section text always comes from the tag (the bytes
  that shipped); rc-section edits made on main are dropped by the fold.
  With entries appended at the end of their subsection (the convention), the
  next cut is byte-identical whether or not release-sync PRs merged.
"""

from __future__ import annotations

import argparse
import collections
import copy
import datetime
import functools
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# Majors a cut may open. Adding one is the human-reviewed approval of a new
# major line (DESIGN.md D4: 5.0.0 is pre-approved as the train's first release).
APPROVED_MAJORS = (5,)
# Tags at or below this predate the train; their sections are already on main
# and are never synced (v3.3.0, for one, has no CHANGELOG section at all).
TRAIN_FLOOR = "4.0.0"

DEFAULT_REPO = "SocketDev/socket-patch"
BLOCKER_LABEL = "release-blocker"
P1_LABEL = "priority:p1"
API_ROOT = "https://api.github.com"


class ReleaseError(Exception):
    """A refusal: printed as `release.py: error: ...`, exit status 1."""


def _read(path):
    """Exact text (no newline translation), so byte comparisons are exact."""
    with open(path, encoding="utf-8", newline="") as f:
        return f.read()


def _write(path, text):
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(text)


def _is_crlf(text):
    """A CRLF file (a Windows checkout with core.autocrlf: the repo has no
    `* text=auto`, so every text file may arrive CRLF)."""
    return text.count("\r\n") * 2 > text.count("\n")


def _with_eol(text, transform):
    """transform(LF text) applied to `text`, keeping its line endings: a
    CRLF file is normalized to LF, transformed, and written back CRLF."""
    if not _is_crlf(text):
        return transform(text)
    return transform(text.replace("\r\n", "\n")).replace("\n", "\r\n")


# ── semver ──────────────────────────────────────────────────────────────────

_VERSION_RE = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-rc\.([1-9][0-9]*))?$")


@functools.total_ordering
class Version:
    __slots__ = ("major", "minor", "patch", "rc")

    def __init__(self, major, minor, patch, rc=None):
        self.major, self.minor, self.patch, self.rc = major, minor, patch, rc

    @classmethod
    def parse(cls, text):
        m = _VERSION_RE.match(text or "")
        if not m:
            raise ReleaseError(
                f"'{text}' is not a release version (X.Y.Z or X.Y.Z-rc.N, N >= 1, "
                "no leading zeros, no other prerelease or build forms)")
        rc = int(m.group(4)) if m.group(4) else None
        return cls(int(m.group(1)), int(m.group(2)), int(m.group(3)), rc)

    @classmethod
    def try_parse(cls, text):
        try:
            return cls.parse(text)
        except ReleaseError:
            return None

    @property
    def is_rc(self):
        return self.rc is not None

    @property
    def core(self):
        return Version(self.major, self.minor, self.patch)

    def with_rc(self, n):
        return Version(self.major, self.minor, self.patch, n)

    def bump(self, level):
        if level == "major":
            return Version(self.major + 1, 0, 0)
        if level == "minor":
            return Version(self.major, self.minor + 1, 0)
        if level == "patch":
            return Version(self.major, self.minor, self.patch + 1)
        raise ValueError(level)

    def _key(self):
        # A prerelease sorts below its own core; rc numbers compare numerically.
        return (self.major, self.minor, self.patch,
                0 if self.is_rc else 1, self.rc or 0)

    def __eq__(self, other):
        return isinstance(other, Version) and self._key() == other._key()

    def __lt__(self, other):
        return self._key() < other._key()

    def __hash__(self):
        return hash(self._key())

    def __str__(self):
        s = f"{self.major}.{self.minor}.{self.patch}"
        return f"{s}-rc.{self.rc}" if self.is_rc else s

    __repr__ = __str__


def parse_tag(name):
    """`v5.0.0-rc.1` -> Version; anything else (non-release tags) -> None."""
    if not name.startswith("v"):
        return None
    return Version.try_parse(name[1:])


def parse_release_branch(name):
    """`release/v5.0.0-rc.2` (any remote prefix) -> Version, else None."""
    m = re.search(r"(?:^|/)release/v([^/]+)$", name)
    return Version.try_parse(m.group(1)) if m else None


# ── git ─────────────────────────────────────────────────────────────────────

# Variables that make git operate on a repository other than the one at
# `cwd` (a hook's GIT_DIR, for one). Git(root) always means root.
_GIT_REPO_ENV = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
                 "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR", "GIT_NAMESPACE",
                 "GIT_CEILING_DIRECTORIES", "GIT_PREFIX")


def git_env(extra=None):
    env = {k: v for k, v in os.environ.items() if k not in _GIT_REPO_ENV}
    env.update(extra or {})
    return env


class Git:
    def __init__(self, root):
        self.root = Path(root)

    def run(self, *args, ok_codes=(0,)):
        proc = subprocess.run(["git", *args], cwd=self.root, capture_output=True,
                              text=True, encoding="utf-8", env=git_env())
        if proc.returncode not in ok_codes:
            raise ReleaseError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
        return proc

    def tags(self):
        """{Version: tag name} for every v<release-version> tag."""
        out = self.run("tag", "--list", "v*").stdout.split()
        return {v: t for t in out for v in [parse_tag(t)] if v is not None}

    def release_branches(self, remote=None):
        names = self.run("for-each-ref", "--format=%(refname)",
                         "refs/heads/release/", "refs/remotes/").stdout.split()
        if remote:
            ls = self.run("ls-remote", "--heads", remote, "refs/heads/release/*").stdout
            names += [line.split("\t", 1)[1] for line in ls.splitlines() if "\t" in line]
        return sorted({v for n in names for v in [parse_release_branch(n)] if v})

    def show(self, rev, path):
        return self.run("show", f"{rev}:{path}").stdout

    def commit_date(self, rev):
        return self.run("log", "-1", "--format=%cI", f"{rev}^{{commit}}").stdout.strip()


class TagSource:
    """What sync-main needs to know about tags: which exist and the
    CHANGELOG at each. Backed by git here; tests may hand in the same two
    facts without git."""

    def __init__(self, git):
        self.git = git
        self._tags = git.tags()
        self._changelogs = {}

    @property
    def versions(self):
        return sorted(self._tags)

    def changelog(self, v):
        if v not in self._changelogs:
            self._changelogs[v] = self.git.show(f"refs/tags/{self._tags[v]}", "CHANGELOG.md")
        return self._changelogs[v]


# ── stamp ───────────────────────────────────────────────────────────────────

_TOML_HEADER = re.compile(r"^\[\[?([^\]]+)\]\]?\s*(#.*)?$")


def _stamp_cargo_toml(text, version):
    out, table = [], None
    hits = {"version": 0, "pin": 0}
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        m = _TOML_HEADER.match(body)
        if m:
            table = m.group(1).strip()
        elif table == "workspace.package" and re.match(r'^version\s*=\s*"[^"]*"\s*$', body):
            line = re.sub(r'"[^"]*"', f'"{version}"', line, count=1)
            hits["version"] += 1
        elif table == "workspace.dependencies" and re.match(r"^socket-patch-core\s*=", body):
            line, n = re.subn(r'(\bversion\s*=\s*")=?[^"]*(")', rf"\g<1>={version}\g<2>", line)
            hits["pin"] += n
        out.append(line)
    if hits != {"version": 1, "pin": 1}:
        raise ReleaseError(
            "Cargo.toml: expected exactly one [workspace.package] version and one "
            f"socket-patch-core version pin, found {hits}")
    return "".join(out)


def _workspace_members(root, cargo_toml):
    """Package names of workspace members whose version is inherited from
    [workspace.package] (only those move with the release version)."""
    m = re.search(r"^members\s*=\s*\[(.*?)\]", cargo_toml, re.S | re.M)
    if not m:
        raise ReleaseError("Cargo.toml: no [workspace] members list")
    names = []
    for rel in re.findall(r'"([^"]+)"', m.group(1)):
        manifest = _read(root / rel / "Cargo.toml")
        name = re.search(r'^name\s*=\s*"([^"]+)"', manifest, re.M)
        if name and re.search(r"^version\.workspace\s*=\s*true\s*$", manifest, re.M):
            names.append(name.group(1))
    return names


def _stamp_cargo_lock(text, version, members):
    chunks = re.split(r"(?m)^(?=\[\[package\]\]$)", text)
    seen = []
    for i, chunk in enumerate(chunks):
        if not chunk.startswith("[[package]]"):
            continue
        name = re.search(r'^name = "([^"]+)"$', chunk, re.M)
        if not name or name.group(1) not in members or re.search(r"^source = ", chunk, re.M):
            continue
        chunks[i], n = re.subn(r'(?m)^version = "[^"]*"$', f'version = "{version}"', chunk, count=1)
        if n != 1:
            raise ReleaseError(f"Cargo.lock: package {name.group(1)} has no version line")
        seen.append(name.group(1))
    if sorted(seen) != sorted(members):
        raise ReleaseError(
            f"Cargo.lock: expected one source-less entry per workspace member {sorted(members)}, "
            f"found {sorted(seen)} (run `cargo metadata` once to refresh the lock)")
    return "".join(chunks)


def _dump_json(obj):
    return json.dumps(obj, indent=2, ensure_ascii=False) + "\n"


def _npm_manifests(root):
    main = root / "npm" / "socket-patch" / "package.json"
    platforms = sorted(root.glob("npm/socket-patch-*/package.json"))
    if not main.is_file() or not platforms:
        raise ReleaseError("npm/: expected npm/socket-patch and npm/socket-patch-*/ packages")
    return [main] + platforms


_PLATFORM_LOCK_KEY = re.compile(r"^node_modules/@socketsecurity/socket-patch-[^/]+$")


def stamp_files(root, version):
    """{relative path: new bytes} for every stamped file whose bytes change.
    Pure: reads the tree, writes nothing."""
    version = str(Version.parse(str(version)))
    root = Path(root)
    changes = {}

    def put(path, transform):
        # Every file keeps its own line endings (a CRLF checkout stays CRLF,
        # so `stamp --check` on it is a byte no-op).
        old = _read(path)
        new = _with_eol(old, transform)
        if new != old:
            changes[path.relative_to(root).as_posix()] = new

    cargo_toml = root / "Cargo.toml"
    toml_text = _read(cargo_toml).replace("\r\n", "\n")
    put(cargo_toml, lambda text: _stamp_cargo_toml(text, version))
    members = _workspace_members(root, toml_text)
    put(root / "Cargo.lock", lambda text: _stamp_cargo_lock(text, version, members))

    def stamp_manifest(main):
        def transform(text):
            pkg = json.loads(text)
            pkg["version"] = version
            if main:
                for dep in pkg.get("optionalDependencies", {}):
                    pkg["optionalDependencies"][dep] = version
            return _dump_json(pkg)
        return transform

    for i, manifest in enumerate(_npm_manifests(root)):
        put(manifest, stamp_manifest(i == 0))

    def stamp_npm_lock(text):
        obj = json.loads(text)
        obj["version"] = version
        top = obj.get("packages", {}).get("")
        if top is None:
            raise ReleaseError('package-lock.json: no packages[""] entry')
        top["version"] = version
        for dep in top.get("optionalDependencies", {}):
            top["optionalDependencies"][dep] = version
        # Platform entries pin a registry tarball + integrity for one version;
        # an entry for any other version is stale and would make `npm ci`
        # refuse the lock. Dropping it (instead of re-resolving over the
        # network) keeps the stamp offline and deterministic; `npm install`
        # resolves it on demand.
        obj["packages"] = {k: v for k, v in obj["packages"].items()
                           if not (_PLATFORM_LOCK_KEY.match(k) and v.get("version") != version)}
        return _dump_json(obj)

    put(root / "npm" / "socket-patch" / "package-lock.json", stamp_npm_lock)
    return changes


_LOCK_TOP_FIELDS = ("name", "version", "dependencies", "devDependencies", "optionalDependencies",
                    "peerDependencies", "engines", "bin")
_EXACT_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")


def npm_lock_drift(root):
    """Offline coherence of npm/socket-patch/package-lock.json with its
    package.json, beyond the version fields `stamp` owns: packages[""] must
    repeat the manifest's dependency maps, engines, bin and name, and every
    non-optional dependency needs a `node_modules/<name>` entry (at exactly
    that version when the manifest pins one). Returns a list of problems.
    (This is what the networked `npm install --package-lock-only` drift check
    caught before the stamp went offline.)"""
    root = Path(root)
    pkg = json.loads(_read(root / "npm" / "socket-patch" / "package.json"))
    lock = json.loads(_read(root / "npm" / "socket-patch" / "package-lock.json"))
    top = (lock.get("packages") or {}).get("")
    if top is None:
        return ['package-lock.json: no packages[""] entry']
    problems = []
    for field in _LOCK_TOP_FIELDS:
        want, have = pkg.get(field), top.get(field)
        if field == "bin" and isinstance(want, str):
            want = {pkg.get("name", "").split("/")[-1]: want}
        if (want or None) != (have or None):
            problems.append(f'package-lock.json packages[""].{field} != package.json {field}')
    if lock.get("name") != pkg.get("name"):
        problems.append("package-lock.json name != package.json name")
    for field in ("dependencies", "devDependencies"):
        for dep, spec in sorted((pkg.get(field) or {}).items()):
            entry = lock["packages"].get(f"node_modules/{dep}")
            if entry is None:
                problems.append(f"package-lock.json has no node_modules/{dep} ({field})")
            elif _EXACT_VERSION.match(spec) and entry.get("version") != spec:
                problems.append(f"package-lock.json node_modules/{dep} is {entry.get('version')}, "
                                f"package.json {field} pins {spec}")
    return problems


def stamp(root, version, check=False):
    changes = stamp_files(root, version)
    if not check:
        for rel, text in changes.items():
            _write(Path(root) / rel, text)
    return sorted(changes)


# ── CHANGELOG ───────────────────────────────────────────────────────────────

_BULLET = re.compile(r"^(?:[-*+]|[0-9]+[.)])(?:\s|$)")
_FENCE = re.compile(r"^\s*(```|~~~)")
UNRELEASED = "Unreleased"


def _blank(line):
    return not line.strip()


def _indented(line):
    return line[:1] in (" ", "\t")


class Block:
    __slots__ = ("lines", "gap")

    def __init__(self, lines, gap=0):
        self.lines, self.gap = list(lines), gap

    @property
    def is_bullet(self):
        return bool(_BULLET.match(self.lines[0]))

    @property
    def text(self):
        return "\n".join(line.rstrip() for line in self.lines)


class Sub:
    """A subsection (`### Name`), or a section's preamble when heading is None."""
    __slots__ = ("heading", "lead", "blocks", "trail")

    def __init__(self, heading, lead=0, blocks=(), trail=0):
        self.heading, self.lead, self.blocks, self.trail = heading, lead, list(blocks), trail

    @property
    def name(self):
        return None if self.heading is None else self.heading[4:].strip()

    def render(self):
        out = [] if self.heading is None else [self.heading]
        if not self.blocks:
            return out + [""] * max(self.lead, self.trail)
        out += [""] * self.lead
        for i, b in enumerate(self.blocks):
            out += ([""] * b.gap if i else []) + b.lines
        return out + [""] * self.trail

    def append(self, block):
        if not self.blocks:
            self.lead, self.trail = max(self.lead, 1), max(self.trail, 1)
            self.blocks = [Block(block.lines, 0)]
            return
        prev = self.blocks[-1]
        gap = block.gap if block.gap > 0 else (0 if prev.is_bullet and block.is_bullet else 1)
        self.blocks.append(Block(block.lines, gap))


def _parse_blocks(lines):
    n, i, lead = len(lines), 0, 0
    while i < n and _blank(lines[i]):
        lead, i = lead + 1, i + 1
    blocks, gap = [], 0
    while i < n:
        start = i
        fence = _FENCE.match(lines[i])
        if fence and not _indented(lines[i]):
            i += 1
            while i < n and not lines[i].lstrip().startswith(fence.group(1)):
                i += 1
            i = min(i + 1, n)
        else:
            bullet = bool(_BULLET.match(lines[i]))
            in_fence = None
            i += 1
            while i < n:
                line = lines[i]
                if in_fence:
                    if line.lstrip().startswith(in_fence):
                        in_fence = None
                    i += 1
                    continue
                if _blank(line):
                    if not bullet:
                        break
                    j = i
                    while j < n and _blank(lines[j]):
                        j += 1
                    if j < n and _indented(lines[j]):  # nested content of the bullet
                        i = j
                        continue
                    break
                if _BULLET.match(line):
                    break
                f = _FENCE.match(line)
                if f:
                    if not _indented(line):
                        break
                    in_fence = f.group(1)
                i += 1
        blocks.append(Block(lines[start:i], gap))
        gap = 0
        while i < n and _blank(lines[i]):
            gap, i = gap + 1, i + 1
    return lead, blocks, (gap if blocks else 0)


def _section_version(heading):
    m = re.match(r"^## \[([^\]]+)\]", heading) or re.match(r"^## (\S+)", heading)
    if not m:
        return None
    if m.group(1).lower() == "unreleased":
        return UNRELEASED
    return Version.try_parse(m.group(1))


class Section:
    __slots__ = ("heading", "subs", "version")

    def __init__(self, heading, subs):
        self.heading, self.subs = heading, subs
        self.version = _section_version(heading)

    @property
    def preamble(self):
        return self.subs[0]

    def items(self):
        return [(s.name, b) for s in self.subs for b in s.blocks]

    def keys(self):
        return {(name, b.text) for name, b in self.items()}

    def sub(self, name, create=False):
        for s in self.subs:
            if s.name == name:
                return s
        if not create:
            return None
        s = Sub(f"### {name}", 1, [], 1)
        self.subs[-1].trail = max(self.subs[-1].trail, 1)
        self.subs.append(s)
        return s

    def key_counts(self):
        return collections.Counter((name, b.text) for name, b in self.items())

    def remove(self, counts):
        """Drop blocks matching `counts` ({key: n}), at most n occurrences of
        each key, oldest (first) first: a shipped block is removed once, so an
        identical entry added again later stays. Drops emptied subsections."""
        left, removed = collections.Counter(counts), collections.Counter()
        for s in self.subs:
            keep = []
            for b in s.blocks:
                if left[(s.name, b.text)] > 0:
                    left[(s.name, b.text)] -= 1
                    removed[(s.name, b.text)] += 1
                else:
                    keep.append(b)
            if len(keep) != len(s.blocks):
                s.blocks = keep
                if not keep and s.heading is None:
                    s.lead, s.trail = 1, 0
        self.subs = [self.subs[0]] + [s for s in self.subs[1:] if s.blocks]
        return removed

    def append_items(self, items):
        """Append (subsection, block) pairs at the end of their subsections.
        Nothing is de-duplicated (multiset semantics, like remove()): an
        entry written twice is two entries. Returns how many were added."""
        added = 0
        for name, block in items:
            self.sub(name, create=True).append(block)
            added += 1
        # The preamble needs a blank line before a following subsection.
        if self.preamble.blocks and len(self.subs) > 1:
            self.preamble.trail = max(self.preamble.trail, 1)
        return added

    def return_items(self, items):
        """Put blocks of an unshipped rc back: (subsection, block) pairs, in
        their original order, go *before* the blocks already in each
        subsection (they were written earlier than anything there now);
        subsections that do not exist yet are created. Nothing is
        de-duplicated (multiset semantics, like remove()). Returns the count."""
        groups = {}
        for name, block in items:
            groups.setdefault(name, []).append(block)
        for name, blocks in groups.items():
            sub = self.sub(name, create=True)
            old, sub.blocks = sub.blocks, []
            for b in [Block(b.lines, 0) for b in blocks] + [
                    Block(b.lines, b.gap if i else 0) for i, b in enumerate(old)]:
                sub.append(b)
        if self.preamble.blocks and len(self.subs) > 1:
            self.preamble.trail = max(self.preamble.trail, 1)
        return sum(len(b) for b in groups.values())

    def canonicalize(self):
        """Order subsections canonically (SUBSECTION_ORDER); block order
        within a subsection is kept."""
        self.subs = [self.subs[0]] + sorted(self.subs[1:], key=lambda s: subsection_rank(s.name))
        for s in self.subs[1:-1]:
            s.trail = max(s.trail, 1)
        if self.preamble.blocks and len(self.subs) > 1:
            self.preamble.trail = max(self.preamble.trail, 1)

    def render(self):
        out = [self.heading]
        for s in self.subs:
            out += s.render()
        return out


def _parse_section(heading, body):
    groups, cur = [[None, []]], None
    in_fence = None
    for line in body:
        f = _FENCE.match(line)
        if in_fence:
            if f and line.lstrip().startswith(in_fence):
                in_fence = None
        elif f:
            in_fence = f.group(1)
        elif line.startswith("### "):
            groups.append([line, []])
            continue
        groups[-1][1].append(line)
    subs = []
    for h, lines in groups:
        lead, blocks, trail = _parse_blocks(lines)
        subs.append(Sub(h, lead, blocks, trail))
    return Section(heading, subs)


class Changelog:
    def __init__(self, header, sections, ends_nl, eol="\n"):
        self.header, self.sections, self.ends_nl, self.eol = header, sections, ends_nl, eol

    @classmethod
    def parse(cls, text):
        # A CRLF file (a Windows checkout: CHANGELOG.md is plain `text` in
        # .gitattributes) is parsed as LF and rendered back as CRLF, so every
        # generated line gets the file's own line ending.
        eol = "\r\n" if _is_crlf(text) else "\n"
        if eol == "\r\n":
            text = text.replace("\r\n", "\n")
        ends_nl = text.endswith("\n")
        lines = text.split("\n")
        if ends_nl:
            lines = lines[:-1]
        header, raw, in_fence = [], [], None
        for line in lines:
            f = _FENCE.match(line)
            if in_fence:
                if f and line.lstrip().startswith(in_fence):
                    in_fence = None
            elif f:
                in_fence = f.group(1)
            elif line.startswith("## "):
                raw.append((line, []))
                continue
            (raw[-1][1] if raw else header).append(line)
        return cls(header, [_parse_section(h, body) for h, body in raw], ends_nl, eol)

    def render(self):
        out = list(self.header)
        for s in self.sections:
            out += s.render()
        return self.eol.join(out) + (self.eol if self.ends_nl else "")

    def section(self, version):
        for s in self.sections:
            if s.version == version:
                return s
        return None

    def unreleased(self):
        found = [s for s in self.sections if s.version == UNRELEASED]
        if len(found) != 1:
            raise ReleaseError(f"CHANGELOG.md must have exactly one '## [Unreleased]' section, found {len(found)}")
        return found[0]

    def versioned(self):
        return [s for s in self.sections if isinstance(s.version, Version)]

    def newest_stable(self):
        stables = [s.version for s in self.versioned() if not s.version.is_rc]
        return max(stables) if stables else None

    def insert(self, section):
        """Insert in descending precedence below [Unreleased]."""
        if self.section(section.version) is not None:
            raise ReleaseError(f"CHANGELOG.md already has a [{section.version}] section")
        idx = len(self.sections)
        for i, s in enumerate(self.sections):
            if isinstance(s.version, Version) and s.version < section.version:
                idx = i
                break
        else:
            # Older than everything: after the last versioned section (or [Unreleased]).
            for i, s in enumerate(self.sections):
                if isinstance(s.version, Version) or s.version == UNRELEASED:
                    idx = i + 1
        unrel = self.sections.index(self.unreleased())
        idx = max(idx, unrel + 1)
        if idx > 0:
            self.sections[idx - 1].subs[-1].trail = max(self.sections[idx - 1].subs[-1].trail, 1)
        if idx < len(self.sections):
            section.subs[-1].trail = max(section.subs[-1].trail, 1)
        self.sections.insert(idx, section)
        return idx

    def drop(self, section):
        self.sections.remove(section)


def _heading(version, date):
    if not re.match(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$", date or ""):
        raise ReleaseError(f"'{date}' is not a YYYY-MM-DD date")
    return f"## [{version}] — {date}"


# Canonical `###` order of a cut section: breaking headings first, then Keep a
# Changelog's order, then anything else; ties by name. A cut always uses it,
# because the order [Unreleased] happens to have on main depends on whether
# release-sync PRs merged (on an unsynced main, already-shipped subsections
# keep their old positions), and the cut must not.
SUBSECTION_ORDER = ("added", "changed", "deprecated", "removed", "fixed", "security")


def subsection_rank(name):
    low = (name or "").lower()
    kac = next((i for i, k in enumerate(SUBSECTION_ORDER) if low.startswith(k)), len(SUBSECTION_ORDER))
    return (0 if "breaking" in low else 1, kac, low, name or "")


def heading_level(name):
    name = name.lower()
    if "breaking" in name or name.startswith("removed"):
        return "major"
    if name.startswith(("added", "changed", "deprecated")):
        return "minor"
    return "patch"


def bump_level(section):
    """major / minor / patch from the subsection names that hold entries."""
    order = ("patch", "minor", "major")
    levels = [heading_level(s.name) for s in section.subs[1:] if s.blocks]
    return max(levels, key=order.index, default="patch")


def sync_main_changelog(text, tags):
    """See the module docstring. `tags`: a TagSource-like object."""
    cl = Changelog.parse(text)
    unrel = cl.unreleased()
    floor = Version.parse(TRAIN_FLOOR)
    versions = tags.versions
    stables = sorted(v for v in versions if not v.is_rc)
    train = [v for v in versions if v > floor]
    report = {"inserted": [], "folded": [], "abandoned": [], "removedFromUnreleased": 0,
              "returnedToUnreleased": 0}

    def tag_section(v):
        sec = Changelog.parse(tags.changelog(v)).section(v)
        if sec is None:
            raise ReleaseError(f"tag v{v} has no [{v}] section in its CHANGELOG.md")
        return copy.deepcopy(sec)

    def owner(v):
        return next((s for s in stables if s >= v.core), None)

    # 1. Shipped-block budget per stable: [S]'s blocks (a multiset; the fold
    #    keeps every occurrence, so [S] is the sum of its folded rcs).
    budget, new_stables = {}, []
    for v in (v for v in train if not v.is_rc):
        if cl.section(v) is None:
            sec = tag_section(v)
            cl.insert(sec)
            budget[v] = sec.key_counts()
            new_stables.append(v)
            report["inserted"].append(str(v))

    # 2. Every rc section whose core has shipped is replaced by what did not
    #    ship: its blocks (text from its tag, the bytes that were cut) are
    #    charged against [S]'s budget, oldest rc first, and the rest return.
    #    A folded rc returns nothing; a later rc abandoned at promotion, or
    #    a train rc cut beside a hotfix of the same core, returns exactly
    #    what [S] lacks.
    returned = []
    for sec in sorted((s for s in cl.versioned() if s.version.is_rc), key=lambda s: s.version):
        stable = owner(sec.version)
        if stable is None:
            continue
        if stable not in budget:
            shipped = cl.section(stable)
            budget[stable] = shipped.key_counts() if shipped else collections.Counter()
        left = budget[stable]
        source = tag_section(sec.version) if sec.version in versions else sec
        back = []
        for name, block in source.items():
            if left[(name, block.text)] > 0:
                left[(name, block.text)] -= 1
            else:
                back.append((name, block))
        returned += back
        report["abandoned" if back else "folded"].append(str(sec.version))
        cl.drop(sec)

    # 3. What the rc sections on main did not cover shipped from blocks that
    #    are still in [Unreleased] (an unsynced main): remove those, oldest
    #    occurrence first. Charging the rc sections first means a newer
    #    identical entry in [Unreleased] (which did not ship) is never
    #    taken in place of an rc's copy, so the result, block order
    #    included, does not depend on which release-sync PRs merged.
    for v in new_stables:
        report["removedFromUnreleased"] += sum(unrel.remove(budget[v]).values())
    report["returnedToUnreleased"] += unrel.return_items(returned)

    # 4. Pending rc tags.

    for v in (v for v in train if v.is_rc and owner(v) is None):
        if cl.section(v) is None:
            sec = tag_section(v)
            cl.insert(sec)
            report["removedFromUnreleased"] += sum(unrel.remove(sec.key_counts()).values())
            report["inserted"].append(str(v))
    return cl.render(), report


def roll_unreleased(text, version, date):
    """[Unreleased] -> `## [V] — date`, leaving an empty [Unreleased] above."""
    version = Version.parse(str(version))
    cl = Changelog.parse(text)
    unrel = cl.unreleased()
    if not unrel.items():
        raise ReleaseError("CHANGELOG.md's [Unreleased] section is empty — nothing to release")
    newer = [s.version for s in cl.versioned() if s.version >= version]
    if newer:
        raise ReleaseError(f"CHANGELOG.md already has a section >= {version}: [{max(newer)}]")
    sec = Section(_heading(version, date), unrel.subs)
    sec.canonicalize()
    unrel.subs = [Sub(None, 1, [], 0)]
    cl.insert(sec)
    return cl.render()


def cut_changelog(text, version, date, tags=None):
    if tags is not None:
        text, _ = sync_main_changelog(text, tags)
    return roll_unreleased(text, version, date)


def promote_changelog(text, rc, date):
    """Fold the rc sections into `## [core(rc)] — date` (module docstring)."""
    rc = Version.parse(str(rc))
    if not rc.is_rc:
        raise ReleaseError(f"promote needs an rc version, got {rc}")
    cl = Changelog.parse(text)
    if cl.section(rc.core) is not None:
        raise ReleaseError(f"CHANGELOG.md already has a [{rc.core}] section")
    floor = cl.newest_stable()
    rcs = [s for s in cl.versioned() if s.version.is_rc]
    fold = sorted((s for s in rcs if s.version <= rc and (floor is None or s.version > floor)),
                  key=lambda s: s.version)
    if not fold or fold[-1].version != rc:
        raise ReleaseError(f"CHANGELOG.md has no [{rc}] section to promote")
    merged = copy.deepcopy(fold[0])
    merged.heading, merged.version = _heading(rc.core, date), rc.core
    for s in fold[1:]:
        merged.append_items(s.items())
    unrel = cl.unreleased()
    later = sorted((s for s in rcs if s.version.core == rc.core and s.version > rc),
                   key=lambda s: s.version)
    # [core] is exactly the multiset sum of the folded rcs, so none of a
    # later rc's blocks shipped through it: all of them return (the same
    # count sync-main step 2 charges, which leaves no budget for later rcs).
    unrel.return_items([(n, b) for s in later for n, b in s.items()])
    for s in later:
        cl.drop(s)
    newest = fold[-1]
    merged.subs[-1].trail = newest.subs[-1].trail
    cl.sections[cl.sections.index(newest)] = merged
    for s in fold[:-1]:
        cl.drop(s)
    return cl.render()


def check_section(text, version):
    version = Version.parse(str(version))
    cl = Changelog.parse(text)
    sec = cl.section(version)
    if sec is None:
        raise ReleaseError(f"CHANGELOG.md has no '## [{version}]' section")
    if not sec.items():
        raise ReleaseError(f"CHANGELOG.md's [{version}] section is empty — a release needs written notes")
    if not version.is_rc:
        left = [str(s.version) for s in cl.versioned() if s.version.is_rc and s.version.core == version]
        if left:
            raise ReleaseError(f"CHANGELOG.md still has unfolded rc sections for {version}: {left}")
    return len(sec.items())


# ── version selection ───────────────────────────────────────────────────────

def select_version(tag_versions, branch_versions, unreleased_section):
    """The next rc version (module docstring, "Version rules")."""
    tags = sorted(tag_versions)
    stables = [v for v in tags if not v.is_rc]
    if not stables:
        raise ReleaseError("no stable v<X.Y.Z> tag found — fetch tags first")
    latest = stables[-1]
    level = bump_level(unreleased_section)
    pending = sorted({v.core for v in tags if v.is_rc and v.core > latest})
    core = max([latest.bump(level)] + pending)
    if core.major > latest.major:
        if core.major != latest.major + 1:
            raise ReleaseError(f"refusing to skip a major: latest stable is {latest}, candidate core {core}")
        if core.major not in APPROVED_MAJORS:
            heading = next((s.name for s in unreleased_section.subs[1:]
                            if s.blocks and heading_level(s.name) == "major"), "?")
            raise ReleaseError(
                f"[Unreleased] has '### {heading}' entries, which would open major {core.major} "
                f"(latest stable {latest}), but {core.major} is not in APPROVED_MAJORS in "
                "scripts/release.py. A new major needs a reviewed PR adding it there; otherwise "
                "move those entries under a non-breaking heading.")
    used = [v.rc for v in list(tags) + list(branch_versions) if v.is_rc and v.core == core]
    version = core.with_rc(max(used, default=0) + 1)
    if tags and version <= tags[-1]:
        raise ReleaseError(f"{version} would not be above the newest tag v{tags[-1]}")
    return {"version": str(version), "core": str(core), "level": level,
            "latestStable": str(latest), "pendingCores": [str(p) for p in pending],
            "burnedRcNumbers": sorted(set(used)),
            "unreleasedEntries": len(unreleased_section.items())}


def next_version(git, ref="HEAD", remote=None):
    tags = TagSource(git)
    synced, _ = sync_main_changelog(git.show(ref, "CHANGELOG.md"), tags)
    unrel = Changelog.parse(synced).unreleased()
    return select_version(tags.versions, git.release_branches(remote), unrel)


# ── release notes ───────────────────────────────────────────────────────────

def _query_url(repo, query):
    return f"https://github.com/{repo}/issues?q=" + urllib.parse.quote(query, safe="")


def render_notes(text, version, repo=DEFAULT_REPO, unlogged=None):
    version = Version.parse(str(version))
    sec = Changelog.parse(text).section(version)
    if sec is None:
        raise ReleaseError(f"CHANGELOG.md has no [{version}] section")
    body = [line for s in sec.subs for line in s.render()]
    while body and _blank(body[0]):
        body.pop(0)
    while body and _blank(body[-1]):
        body.pop()
    out = []
    if version.is_rc:
        out += [f"> **Prerelease.** Not served by `install.socket.dev/patch`, `socket-patch --update`, "
                "`npm i @socketsecurity/socket-patch` (latest) or `cargo install` without `--version`. "
                f"Try it with `npm i -g @socketsecurity/socket-patch@{version}` or "
                f"`cargo install socket-patch-cli --locked --version {version}`.", ""]
    out += body + ["", "---", ""]
    # A link, never issue titles: no untrusted text reaches the notes.
    out.append(f"Known issues: [open P1 issues]({_query_url(repo, f'is:issue is:open label:{P1_LABEL}')}) "
               f"· [open release blockers]({_query_url(repo, f'is:open label:{BLOCKER_LABEL}')})")
    if unlogged:
        out += ["", f"_{unlogged} product commit(s) in this release have no CHANGELOG entry._"]
    return "\n".join(out) + "\n"


# ── release-blocker gate (DESIGN.md §3.5) ───────────────────────────────────

class ApiError(Exception):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


def urllib_transport(method, url, headers):
    req = urllib.request.Request(url, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read()


class GitHub:
    """Minimal REST client; `transport(method, url, headers) -> (status,
    headers, body bytes)` is injectable for tests."""

    def __init__(self, repo, token, transport=urllib_transport, api_root=API_ROOT):
        self.repo, self.token, self.transport, self.api_root = repo, token, transport, api_root

    def _get(self, url):
        if not self.token:
            raise ApiError("no GITHUB_TOKEN")
        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/vnd.github+json",
                   "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "socket-patch-release"}
        try:
            status, resp_headers, body = self.transport("GET", url, headers)
        except Exception as e:  # network, TLS, timeouts: all fail closed
            raise ApiError(f"GET {url}: {e}") from e
        if not 200 <= status < 300:
            raise ApiError(f"GET {url}: HTTP {status}", status)
        try:
            data = json.loads(body)
        except ValueError as e:
            raise ApiError(f"GET {url}: invalid JSON") from e
        link = {k.lower(): v for k, v in (resp_headers or {}).items()}.get("link", "")
        nxt = re.search(r'<([^>]+)>;\s*rel="next"', link)
        return data, nxt.group(1) if nxt else None

    def url(self, path, **params):
        q = urllib.parse.urlencode(sorted((k, v) for k, v in params.items() if v is not None))
        return f"{self.api_root}/repos/{self.repo}{path}" + (f"?{q}" if q else "")

    def get(self, path, **params):
        return self._get(self.url(path, **params))[0]

    def pages(self, path, max_pages=50, stop=None, **params):
        url, items = self.url(path, per_page=100, **params), []
        for _ in range(max_pages):
            data, url = self._get(url)
            if not isinstance(data, list):
                raise ApiError(f"{path}: expected a list")
            items += data
            if url is None or (stop and stop(data)):
                return items
        raise ApiError(f"{path}: more than {max_pages} pages")


def _ts(value):
    """ISO-8601 (`Z` or any offset) -> aware UTC datetime; None stays None."""
    if not value:
        return None
    dt = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError(f"timestamp without a zone: {value}")
    return dt.astimezone(datetime.timezone.utc)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


_LOGIN_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,38})(?:\[bot\])?$")


def _logins(env_value):
    """A login list from a repo variable: comma- and/or whitespace-separated,
    an optional leading `@`, case-insensitive. Anything that is not a GitHub
    login is a config error (ReleaseError), never silently dropped."""
    out = set()
    for token in re.split(r"[\s,]+", env_value or ""):
        login = token.strip().lstrip("@").lower()
        if not token.strip():
            continue
        if not _LOGIN_RE.match(login):
            raise ReleaseError(f"'{token}' is not a GitHub login")
        out.add(login)
    return out


def _actor(event):
    return ((event.get("actor") or {}).get("login") or "").lower()


def _is_blocker_label(name):
    # GitHub label names are case-insensitive (`labels=` filters that way and
    # a label can be renamed by case alone), so the gate compares that way.
    return (name or "").lower() == BLOCKER_LABEL


def _is_blocker_event(e, kind):
    return e.get("event") == kind and _is_blocker_label((e.get("label") or {}).get("name"))


# A close whose event has no commit_id (GitHub's auto-close on a PR merge) is
# matched to the merged PR(s) that cross-reference the issue and merged at
# most this long before the close.
PR_CLOSE_WINDOW = datetime.timedelta(seconds=120)


def _closing_pr_merges(gh, number, close):
    """Merge commit SHAs of the same-repo PRs that merged within
    PR_CLOSE_WINDOW before `close`, cross-reference issue `number`, and were
    merged by the close event's own actor (GitHub attributes a merge
    auto-close to the merger). A manual close by anyone else right after an
    unrelated PR that merely mentions the issue therefore matches nothing."""
    closed_at = _ts(close["created_at"])
    closer = _actor(close)
    shas = []
    for e in gh.pages(f"/issues/{number}/timeline"):
        if e.get("event") != "cross-referenced":
            continue
        src = (e.get("source") or {}).get("issue") or {}
        merged_at = _ts((src.get("pull_request") or {}).get("merged_at"))
        repo = ((src.get("repository") or {}).get("full_name") or "").lower()
        if merged_at is None or repo != gh.repo.lower():
            continue
        if datetime.timedelta(0) <= closed_at - merged_at <= PR_CLOSE_WINDOW:
            pr = gh.get(f"/pulls/{src['number']}")
            if not pr.get("merged") or not pr.get("merge_commit_sha"):
                raise ApiError(f"PR #{src['number']}: merged_at set but no merge commit")
            merger = ((pr.get("merged_by") or {}).get("login") or "").lower()
            if not closer or merger != closer:
                continue
            shas.append(pr["merge_commit_sha"])
    return shas


def evaluate_blockers(gh, base, since, approvers, routine_actors):
    """{'blocked': bool, 'blockers': [...], 'error': str|None}. Any API error
    blocks (fail closed)."""
    def trusted(login):
        return bool(login) and login in approvers and login not in routine_actors

    def in_base(sha):
        return gh.get(f"/compare/{sha}...{base}").get("status") in ("ahead", "identical")

    if not approvers or not routine_actors or not approvers - routine_actors:
        return {"blocked": True, "blockers": [], "base": base, "since": since,
                "error": "config: RELEASE_APPROVERS and RELEASE_ROUTINE_ACTORS must both be set "
                         "and leave at least one trusted approver"}
    try:
        since_dt = _ts(since)
        t = _ts(gh.get(f"/commits/{base}")["commit"]["committer"]["date"])
        if since_dt > t:
            return {"blocked": True, "blockers": [], "base": base, "since": since,
                    "error": f"since: {since} is after the base commit time {_iso(t)}"}
        # The label must exist under its exact name: a deleted or renamed
        # label drops off every issue without an `unlabeled` event.
        try:
            label = gh.get(f"/labels/{BLOCKER_LABEL}")
        except ApiError as e:
            if e.status != 404:
                raise
            label = {}
        if label.get("name") != BLOCKER_LABEL:
            return {"blocked": True, "blockers": [], "base": base, "since": since,
                    "error": f"label: the '{BLOCKER_LABEL}' label does not exist under that exact "
                             f"name (found {label.get('name')!r}); create it (DESIGN.md setup S5)"}
        candidates = set()
        for issue in gh.pages("/issues", state="open", labels=BLOCKER_LABEL):
            candidates.add(issue["number"])
        # `since` filters on updated_at, a superset of "closed since L".
        for issue in gh.pages("/issues", state="closed", labels=BLOCKER_LABEL, since=_iso(since_dt)):
            candidates.add(issue["number"])
        # Unlabelled issues no longer match a label query, and labelled ones
        # whose label vanished without an event do not either; find both in
        # the repo-wide event feed (newest first), back to `since`.
        stop = lambda page: any(_ts(e["created_at"]) < since_dt for e in page)
        for e in gh.pages("/issues/events", stop=stop):
            if _ts(e["created_at"]) >= since_dt and (
                    _is_blocker_event(e, "unlabeled") or _is_blocker_event(e, "labeled")):
                candidates.add(e["issue"]["number"])

        blockers = []
        for number in sorted(candidates):
            try:
                issue = gh.get(f"/issues/{number}")
            except ApiError as e:
                if e.status not in (404, 410):
                    raise
                blockers.append({"number": number, "reason": f"issue gone (HTTP {e.status}): "
                                 "deleted, transferred or converted"})
                continue
            repo_url = (issue.get("repository_url") or "").lower()
            if issue.get("number") != number or (
                    repo_url and not repo_url.endswith(f"/repos/{gh.repo.lower()}")):
                blockers.append({"number": number, "reason": "issue moved to another repository "
                                 "or number (transferred)"})
                continue
            events = sorted(gh.pages(f"/issues/{number}/events"),
                            key=lambda e: (_ts(e["created_at"]), e.get("id") or 0))
            labelled = any(_is_blocker_label(lbl.get("name")) for lbl in issue.get("labels") or [])
            marks = [e for e in events if _is_blocker_event(e, "labeled") or _is_blocker_event(e, "unlabeled")]
            last = marks[-1] if marks else None
            if labelled:
                why = "labelled"
            elif last is not None and last["event"] == "labeled":
                why = "label removed without an unlabeled event"
            elif last is not None and not trusted(_actor(last)):
                why = f"unlabelled by untrusted @{_actor(last)}"
            else:
                continue  # never a blocker, or a trusted human unlabelled it last
            if issue.get("state") != "closed":
                blockers.append({"number": number, "reason": f"open, {why}"})
                continue
            closes = [e for e in events if e.get("event") == "closed"]
            if not closes:
                blockers.append({"number": number, "reason": f"closed without a close event, {why}"})
                continue
            close = closes[-1]
            if close.get("commit_id"):
                if in_base(close["commit_id"]):
                    continue  # the fix is in this tree
                fix = f"fix {close['commit_id'][:12]} not in base"
            else:
                # A PR merge auto-close carries no commit_id: use the merge
                # commit of the PR that closed it. Ambiguous -> all must be in.
                merges = _closing_pr_merges(gh, number, close)
                if merges and all(in_base(sha) for sha in merges):
                    continue  # the closing PR's merge is in this tree
                fix = (f"closing PR merge {merges[0][:12]} not in base" if merges
                       else "no fix commit")
            if trusted(_actor(close)) and _ts(close["created_at"]) <= t:
                continue  # a trusted human closed it before the base commit
            blockers.append({"number": number,
                             "reason": f"closed by @{_actor(close) or '?'} ({fix}), {why}"})
        return {"blocked": bool(blockers), "blockers": blockers, "error": None,
                "base": base, "baseTime": _iso(t), "since": _iso(since_dt)}
    except (ApiError, AttributeError, KeyError, TypeError, ValueError) as e:
        return {"blocked": True, "blockers": [], "error": f"api-error: {e}", "base": base,
                "since": since}


# `since` is never later than this long before the base commit. Until the
# refs/tags/v* ruleset (DESIGN.md S9) is live, any account that can push a
# tag can point a high stable tag (v99.0.0) at `base` itself, which makes
# merge-base(L, base) = base and would drop every older close or unlabel
# out of the candidate set. The lookback bounds what such a tag can hide to
# events older than this; it covers a stable's 8-day soak plus several
# skipped weeks, and an earlier bound only adds candidates.
SINCE_LOOKBACK = datetime.timedelta(days=35)


def latest_stable_date(git, base):
    """The lower time bound for closed/unlabelled candidates: the earlier of
    the committer date of merge-base(L, base) (L = the newest stable tag,
    so this is L's cut point on main) and base's date minus SINCE_LOOKBACK.
    Nothing a tag can do moves it later than the lookback: a tag's own date
    is never read (it could point at an off-main commit with a forged
    future date), and a forged high tag at `base` only reaches the
    lookback bound. An older bound only adds candidates, each still judged
    on its events."""
    stables = [v for v in git.tags() if not v.is_rc]
    if not stables:
        raise ReleaseError("no stable tag found — fetch tags or pass --since")
    mb = git.run("merge-base", f"refs/tags/v{max(stables)}", base).stdout.strip()
    floor = _ts(git.commit_date(base)) - SINCE_LOOKBACK
    return _iso(min(_ts(git.commit_date(mb)), floor))


# ── sync-main ───────────────────────────────────────────────────────────────

def sync_main(root, check=False):
    """CHANGELOG sync + stamp of the newest tag version, on a working tree."""
    git = Git(root)
    tags = TagSource(git)
    if not tags.versions:
        raise ReleaseError("no release tags found — fetch tags first")
    target = max(tags.versions)
    path = Path(root) / "CHANGELOG.md"
    old = _read(path)
    # Compute everything before writing anything: a stamp refusal (a lock
    # missing a member entry, say) must not leave a half-synced tree.
    new, report = sync_main_changelog(old, tags)
    changes = stamp_files(root, target)
    changed = (["CHANGELOG.md"] if new != old else []) + sorted(changes)
    if not check:
        if new != old:
            _write(path, new)
        for rel_path, text in changes.items():
            _write(Path(root) / rel_path, text)
    report.update({"version": str(target), "changed": changed})
    return report


# ── CLI ─────────────────────────────────────────────────────────────────────

def cmd_semver(args):
    if args.op == "validate":
        v = Version.parse(args.versions[0])
        if args.kind == "stable" and v.is_rc:
            raise ReleaseError(f"{v} is a prerelease; a stable X.Y.Z is required here")
        if args.kind == "rc" and not v.is_rc:
            raise ReleaseError(f"{v} is not an X.Y.Z-rc.N version")
        print(v)
    elif args.op == "compare":
        a, b = (Version.parse(x) for x in args.versions[:2])
        print((a > b) - (a < b))
    elif args.op == "core":
        print(Version.parse(args.versions[0]).core)
    return 0


def cmd_stamp(args):
    changed = stamp(Path(args.root), args.version, check=args.check)
    if args.check:
        if changed:
            print(f"stamp {args.version} is not a no-op — these files carry a different "
                  f"version: {' '.join(changed)}", file=sys.stderr)
            return 1
        print(f"every stamped site already carries {args.version}")
        return 0
    print(f"Synced version to {args.version}")
    return 0


def cmd_npm_lock_check(args):
    problems = npm_lock_drift(Path(args.root))
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        print("run `npm install --package-lock-only` in npm/socket-patch with npm 10", file=sys.stderr)
        return 1
    print("npm/socket-patch/package-lock.json matches package.json")
    return 0


def cmd_next_version(args):
    result = next_version(Git(args.root), args.ref, args.remote)
    print(json.dumps(result, indent=2) if args.json else result["version"])
    return 0


def cmd_changelog(args):
    path = Path(args.file or Path(args.root) / "CHANGELOG.md")
    text = _read(path)
    if args.op == "check":
        n = check_section(text, args.version)
        print(f"[{args.version}] section present with {n} entries")
        return 0
    if args.op == "cut":
        tags = None if args.no_sync else TagSource(Git(args.root))
        new = cut_changelog(text, args.version, args.date, tags)
    elif args.op == "promote":
        new = promote_changelog(text, args.rc, args.date)
    else:
        new, report = sync_main_changelog(text, TagSource(Git(args.root)))
        print(json.dumps(report, indent=2), file=sys.stderr)
    _write(path, new)
    return 0


def cmd_sync_main(args):
    report = sync_main(Path(args.root), check=args.check)
    print(json.dumps(report, indent=2))
    return 1 if args.check and report["changed"] else 0


def cmd_notes(args):
    text = Git(args.root).show(args.ref, "CHANGELOG.md") if args.ref else _read(
        args.file or Path(args.root) / "CHANGELOG.md")
    sys.stdout.write(render_notes(text, args.version, args.repo, args.unlogged))
    return 0


def blocker_config(approvers_env, routine_env):
    """(approvers, routine_actors) from the repo variables, or ReleaseError.
    Both must be set: an empty routine list would silently make a routine
    identity that is also an approver (D3: mikolalysenko) trusted."""
    approvers, routine = _logins(approvers_env), _logins(routine_env)
    if not approvers:
        raise ReleaseError("RELEASE_APPROVERS is empty")
    if not routine:
        raise ReleaseError("RELEASE_ROUTINE_ACTORS is empty (it must list every routine identity)")
    if not approvers - routine:
        raise ReleaseError("every RELEASE_APPROVERS login is also a routine actor; nobody is trusted")
    return approvers, routine


def cmd_blockers(args, transport=urllib_transport):
    def refuse(error):
        print(json.dumps({"blocked": True, "blockers": [], "error": error}, indent=2))
        print(f"blocked: {error}", file=sys.stderr)
        return 1

    try:
        approvers, routine = blocker_config(os.environ.get("RELEASE_APPROVERS"),
                                            os.environ.get("RELEASE_ROUTINE_ACTORS"))
    except ReleaseError as e:
        return refuse(f"config: {e}")
    since = args.since
    if not since:
        try:
            since = latest_stable_date(Git(args.root), args.base)
        except ReleaseError as e:
            return refuse(f"since: {e}")
    gh = GitHub(args.repo, os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"), transport)
    result = evaluate_blockers(gh, args.base, since, approvers, routine)
    print(json.dumps(result, indent=2))
    for b in result["blockers"]:
        print(f"release-blocker #{b['number']}: {b['reason']}", file=sys.stderr)
    if result["error"]:
        print(f"blocked: {result['error']}", file=sys.stderr)
    return 1 if result["blocked"] else 0


def build_parser():
    p = argparse.ArgumentParser(prog="release.py", description=__doc__.split("\n\n")[0])
    p.add_argument("--root", default=str(REPO_ROOT), help="repository root (default: this checkout)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("semver", help="validate / compare release versions")
    s.add_argument("op", choices=["validate", "compare", "core"])
    s.add_argument("versions", nargs="+")
    s.add_argument("--kind", choices=["any", "stable", "rc"], default="any")
    s.set_defaults(fn=cmd_semver)

    s = sub.add_parser("stamp", help="stamp a version into every packaging site (offline)")
    s.add_argument("version")
    s.add_argument("--check", action="store_true", help="write nothing; exit 1 if the stamp would change a file")
    s.set_defaults(fn=cmd_stamp)

    s = sub.add_parser("npm-lock-check", help="offline: the npm wrapper lock matches its package.json")
    s.set_defaults(fn=cmd_npm_lock_check)

    s = sub.add_parser("next-version", help="the version the next rc cut gets")
    s.add_argument("--ref", default="HEAD", help="candidate commit whose CHANGELOG is read")
    s.add_argument("--remote", help="also count release/* branches on this remote (git ls-remote)")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_next_version)

    s = sub.add_parser("changelog", help="CHANGELOG.md transforms")
    s.add_argument("op", choices=["cut", "promote", "sync-main", "check"])
    s.add_argument("--file", help="CHANGELOG path (default: <root>/CHANGELOG.md)")
    s.add_argument("--version", help="cut/check: the section version")
    s.add_argument("--rc", help="promote: the rc being promoted (X.Y.Z-rc.N)")
    s.add_argument("--date", help="cut/promote: YYYY-MM-DD (UTC)")
    s.add_argument("--no-sync", action="store_true", help="cut: skip the in-memory sync-main step")
    s.set_defaults(fn=cmd_changelog)

    s = sub.add_parser("sync-main", help="sync CHANGELOG + version on main to the newest tag")
    s.add_argument("--check", action="store_true", help="write nothing; exit 1 if main is behind")
    s.set_defaults(fn=cmd_sync_main)

    s = sub.add_parser("notes", help="render GitHub release notes for one version")
    s.add_argument("--version", required=True)
    s.add_argument("--file")
    s.add_argument("--ref", help="read CHANGELOG.md at this git ref instead of a file")
    s.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY") or DEFAULT_REPO)
    s.add_argument("--unlogged", type=int, help="product commits without a CHANGELOG entry")
    s.set_defaults(fn=cmd_notes)

    s = sub.add_parser("blockers", help="the release-blocker gate; exit 1 when blocked")
    s.add_argument("--base", required=True, help="the candidate tree's base commit")
    s.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY") or DEFAULT_REPO)
    s.add_argument("--since", help="ISO time bound for closed/unlabelled candidates (default: the "
                                   "earlier of merge-base(newest stable tag, --base)'s date and "
                                   "--base's date minus 35 days)")
    s.set_defaults(fn=cmd_blockers)
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.cmd == "changelog":
        need = {"cut": ("version", "date"), "promote": ("rc", "date"), "check": ("version",)}
        for name in need.get(args.op, ()):
            if not getattr(args, name):
                parser.error(f"changelog {args.op} needs --{name}")
    try:
        return args.fn(args)
    except ReleaseError as e:
        print(f"release.py: error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
