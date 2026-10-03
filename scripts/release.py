#!/usr/bin/env python3
"""socket-patch release-train tooling (docs/release-train/DESIGN.md).

Stdlib-only, one file, so every workflow and routine can run it with a bare
`python3`. Subcommands (PR 1 of the train):

  semver validate|compare|core   version grammar: X.Y.Z or X.Y.Z-rc.N only
  stamp <V> [--check]            offline, byte-deterministic version stamp
                                 (Cargo.toml, Cargo.lock, 15 npm manifests,
                                 the npm wrapper lockfile)
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
with trailing whitespace stripped); all matching is exact.

* cut V: apply sync-main in memory, then move every [Unreleased] block into a
  new `## [V] — date` section directly below an empty [Unreleased].
* promote rc.K: fold every `[X-rc.N]` section with X-rc.N <= rc.K that is
  newer than the newest stable section into one `## [core] — date` section
  (oldest rc first; within a subsection later rcs append, exact duplicates
  dropped; rc headers removed). Later rc sections of the same core (rc.K+1..)
  are abandoned: their blocks move back into [Unreleased] (appended to the
  matching subsection, exact duplicates skipped) and their headers dropped.
* sync-main (main's CHANGELOG := what it would be had every release-sync PR
  merged). For train-era tags (version > TRAIN_FLOOR):
    1. each stable tag S whose section main lacks: insert the tag's own [S]
       section and remove exactly those blocks from [Unreleased];
    2. each rc section on main whose core already shipped (owner S = the
       smallest stable tag >= its core): if it is <= the rc S was promoted
       from (the newest same-core rc tag that is an ancestor of tag S) it
       was folded into [S] and is deleted; otherwise it was abandoned, and
       its blocks move back into [Unreleased] (skipping blocks already there
       or in [S]);
    3. each pending rc tag (no owner yet) whose section main lacks: insert
       the tag's section and remove exactly those blocks from [Unreleased].
  Only blocks of sections inserted *in this run* are removed from
  [Unreleased], so entries added to [Unreleased] later are never touched and
  a second run is a no-op. Section text always comes from the tag (the bytes
  that shipped); rc-section edits made on main are dropped by the fold.
"""

from __future__ import annotations

import argparse
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

class Git:
    def __init__(self, root):
        self.root = Path(root)

    def run(self, *args, ok_codes=(0,)):
        proc = subprocess.run(["git", *args], cwd=self.root, capture_output=True,
                              text=True, encoding="utf-8")
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

    def is_ancestor(self, a, b):
        return self.run("merge-base", "--is-ancestor", a, b, ok_codes=(0, 1)).returncode == 0

    def commit_date(self, rev):
        return self.run("log", "-1", "--format=%cI", f"{rev}^{{commit}}").stdout.strip()


class TagSource:
    """What sync-main needs to know about tags: which exist, the CHANGELOG at
    each, and which rc each stable was promoted from. Backed by git here; the
    tests hand in the same three facts from temp repos."""

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

    def promoted_from(self, stable):
        """The newest same-core rc tag that is an ancestor of tag `stable`."""
        cands = sorted((v for v in self._tags if v.is_rc and v.core == stable), reverse=True)
        for rc in cands:
            if self.git.is_ancestor(f"refs/tags/{self._tags[rc]}",
                                    f"refs/tags/{self._tags[stable]}"):
                return rc
        return None


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

    def put(path, new):
        old = _read(path)
        if new != old:
            changes[path.relative_to(root).as_posix()] = new

    cargo_toml = root / "Cargo.toml"
    toml_text = _read(cargo_toml)
    put(cargo_toml, _stamp_cargo_toml(toml_text, version))
    lock = root / "Cargo.lock"
    put(lock, _stamp_cargo_lock(_read(lock), version,
                                _workspace_members(root, toml_text)))

    for i, manifest in enumerate(_npm_manifests(root)):
        pkg = json.loads(_read(manifest))
        pkg["version"] = version
        if i == 0:
            for dep in pkg.get("optionalDependencies", {}):
                pkg["optionalDependencies"][dep] = version
        put(manifest, _dump_json(pkg))

    npm_lock = root / "npm" / "socket-patch" / "package-lock.json"
    obj = json.loads(_read(npm_lock))
    obj["version"] = version
    top = obj.get("packages", {}).get("")
    if top is None:
        raise ReleaseError('package-lock.json: no packages[""] entry')
    top["version"] = version
    for dep in top.get("optionalDependencies", {}):
        top["optionalDependencies"][dep] = version
    # Platform entries pin a registry tarball + integrity for one version; an
    # entry for any other version is stale and would make `npm ci` refuse the
    # lock. Dropping it (instead of re-resolving over the network) keeps the
    # stamp offline and deterministic; `npm install` resolves it on demand.
    obj["packages"] = {k: v for k, v in obj["packages"].items()
                       if not (_PLATFORM_LOCK_KEY.match(k) and v.get("version") != version)}
    put(npm_lock, _dump_json(obj))
    return changes


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

    def remove(self, keys):
        """Drop blocks whose key is in `keys`; drop emptied subsections."""
        removed = 0
        for s in self.subs:
            keep = [b for b in s.blocks if (s.name, b.text) not in keys]
            removed += len(s.blocks) - len(keep)
            if len(keep) != len(s.blocks):
                s.blocks = keep
                if not keep and s.heading is None:
                    s.lead, s.trail = 1, 0
        self.subs = [self.subs[0]] + [s for s in self.subs[1:] if s.blocks]
        return removed

    def append_items(self, items, skip=frozenset()):
        """Append (subsection, block) pairs, skipping exact duplicates of
        `skip` or of blocks already here. Returns how many were added."""
        seen, added = set(skip) | self.keys(), 0
        for name, block in items:
            if (name, block.text) in seen:
                continue
            seen.add((name, block.text))
            self.sub(name, create=True).append(block)
            added += 1
        # The preamble needs a blank line before a following subsection.
        if self.preamble.blocks and len(self.subs) > 1:
            self.preamble.trail = max(self.preamble.trail, 1)
        return added

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
    def __init__(self, header, sections, ends_nl):
        self.header, self.sections, self.ends_nl = header, sections, ends_nl

    @classmethod
    def parse(cls, text):
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
        return cls(header, [_parse_section(h, body) for h, body in raw], ends_nl)

    def render(self):
        out = list(self.header)
        for s in self.sections:
            out += s.render()
        return "\n".join(out) + ("\n" if self.ends_nl else "")

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

    for v in (v for v in train if not v.is_rc):
        if cl.section(v) is None:
            sec = tag_section(v)
            cl.insert(sec)
            report["removedFromUnreleased"] += unrel.remove(sec.keys())
            report["inserted"].append(str(v))

    promoted = {}
    for sec in [s for s in cl.versioned() if s.version.is_rc]:
        stable = owner(sec.version)
        if stable is None:
            continue
        if stable not in promoted:
            promoted[stable] = tags.promoted_from(stable)
        rc = promoted[stable]
        if rc is not None and sec.version <= rc:
            report["folded"].append(str(sec.version))
        else:
            shipped = cl.section(stable)
            report["returnedToUnreleased"] += unrel.append_items(
                sec.items(), skip=shipped.keys() if shipped else ())
            report["abandoned"].append(str(sec.version))
        cl.drop(sec)

    for v in (v for v in train if v.is_rc and owner(v) is None):
        if cl.section(v) is None:
            sec = tag_section(v)
            cl.insert(sec)
            report["removedFromUnreleased"] += unrel.remove(sec.keys())
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
    for s in sorted((s for s in rcs if s.version.core == rc.core and s.version > rc),
                    key=lambda s: s.version):
        unrel.append_items(s.items(), skip=merged.keys())
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
    pass


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
            raise ApiError(f"GET {url}: HTTP {status}")
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


def _logins(env_value):
    return {x.strip().lower() for x in (env_value or "").split(",") if x.strip()}


def _actor(event):
    return ((event.get("actor") or {}).get("login") or "").lower()


def _is_blocker_event(e, kind):
    return e.get("event") == kind and (e.get("label") or {}).get("name") == BLOCKER_LABEL


def evaluate_blockers(gh, base, since, approvers, routine_actors):
    """{'blocked': bool, 'blockers': [...], 'error': str|None}. Any API error
    blocks (fail closed)."""
    def trusted(login):
        return bool(login) and login in approvers and login not in routine_actors

    try:
        since_dt = _ts(since)
        t = _ts(gh.get(f"/commits/{base}")["commit"]["committer"]["date"])
        candidates = set()
        for issue in gh.pages("/issues", state="open", labels=BLOCKER_LABEL):
            candidates.add(issue["number"])
        # `since` filters on updated_at, a superset of "closed since L".
        for issue in gh.pages("/issues", state="closed", labels=BLOCKER_LABEL, since=_iso(since_dt)):
            candidates.add(issue["number"])
        # Unlabelled issues no longer match a label query; find them in the
        # repo-wide event feed (newest first), back to the newest stable.
        stop = lambda page: any(_ts(e["created_at"]) < since_dt for e in page)
        for e in gh.pages("/issues/events", stop=stop):
            if _ts(e["created_at"]) >= since_dt and _is_blocker_event(e, "unlabeled"):
                candidates.add(e["issue"]["number"])

        blockers = []
        for number in sorted(candidates):
            issue = gh.get(f"/issues/{number}")
            events = sorted(gh.pages(f"/issues/{number}/events"),
                            key=lambda e: (_ts(e["created_at"]), e.get("id") or 0))
            labelled = any(lbl.get("name") == BLOCKER_LABEL for lbl in issue.get("labels") or [])
            unlabels = [e for e in events if _is_blocker_event(e, "unlabeled")]
            if not labelled and not (unlabels and not trusted(_actor(unlabels[-1]))):
                continue  # never a blocker, or a trusted human unlabelled it last
            why = "labelled" if labelled else f"unlabelled by untrusted @{_actor(unlabels[-1])}"
            if issue.get("state") != "closed":
                blockers.append({"number": number, "reason": f"open, {why}"})
                continue
            closes = [e for e in events if e.get("event") == "closed"]
            if not closes:
                blockers.append({"number": number, "reason": f"closed without a close event, {why}"})
                continue
            close = closes[-1]
            if close.get("commit_id"):
                status = gh.get(f"/compare/{close['commit_id']}...{base}").get("status")
                if status in ("ahead", "identical"):
                    continue  # the fix is in this tree
            if trusted(_actor(close)) and _ts(close["created_at"]) <= t:
                continue  # a trusted human closed it before the base commit
            fix = f"fix {close['commit_id'][:12]} not in base" if close.get("commit_id") else "no fix commit"
            blockers.append({"number": number,
                             "reason": f"closed by @{_actor(close) or '?'} ({fix}), {why}"})
        return {"blocked": bool(blockers), "blockers": blockers, "error": None,
                "base": base, "baseTime": _iso(t), "since": _iso(since_dt)}
    except (ApiError, KeyError, TypeError, ValueError) as e:
        return {"blocked": True, "blockers": [], "error": f"api-error: {e}", "base": base,
                "since": since}


def latest_stable_date(git):
    stables = [v for v in git.tags() if not v.is_rc]
    if not stables:
        raise ReleaseError("no stable tag found — fetch tags or pass --since")
    return git.commit_date(f"refs/tags/v{max(stables)}")


# ── sync-main ───────────────────────────────────────────────────────────────

def sync_main(root, check=False):
    """CHANGELOG sync + stamp of the newest tag version, on a working tree."""
    git = Git(root)
    tags = TagSource(git)
    path = Path(root) / "CHANGELOG.md"
    old = _read(path)
    new, report = sync_main_changelog(old, tags)
    if not tags.versions:
        raise ReleaseError("no release tags found — fetch tags first")
    target = max(tags.versions)
    changed = []
    if new != old:
        changed.append("CHANGELOG.md")
        if not check:
            _write(path, new)
    changed += stamp(root, target, check=check)
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


def cmd_blockers(args, transport=urllib_transport):
    since = args.since
    if not since:
        try:
            since = latest_stable_date(Git(args.root))
        except ReleaseError as e:
            result = {"blocked": True, "blockers": [], "error": f"since: {e}"}
            print(json.dumps(result, indent=2))
            return 1
    gh = GitHub(args.repo, os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"), transport)
    result = evaluate_blockers(gh, args.base, since,
                               _logins(os.environ.get("RELEASE_APPROVERS")),
                               _logins(os.environ.get("RELEASE_ROUTINE_ACTORS")))
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
    s.add_argument("--since", help="ISO time bound for closed/unlabelled candidates "
                                   "(default: the newest stable tag's commit date)")
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
