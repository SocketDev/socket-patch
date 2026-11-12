#!/usr/bin/env python3
"""Build and check the committed Bazel registry subset of the real-Bazel suite.

A Bzlmod workspace with no dependency of its own still resolves the modules
Bazel brings (156 module versions on 9.3.2), and its first build fetches a
few of their source archives. The `bazel_core_` tests run with no network,
so everything they resolve is committed under
crates/socket-patch-cli/tests/fixtures/bazel/registry/:

  bazel_registry.json, modules/**   the registry files, for --registry=file://.
                                    One tree: the union over the Bazel versions
                                    of MANIFEST.json.
  distdir/<bazel version>/<file>    the archives a cold build of the toy
                                    fixture fetches, for --distdir. Only where
                                    they are small: 8.8.2 fetches 12.4 MB, so
                                    its entry says `"distdir": false` and its
                                    cells take them from a repository cache
                                    (tests/bazel_build_common/toy.rs).
  MANIFEST.json                     per Bazel version: the lock the file list
                                    comes from, and the archives.
  SHA256SUMS                        every file above.

A manifest entry lists two kinds of archive:

  archives             the module archives a Bzlmod build fetches, each tied
                       to a registry module.
  workspace_archives   what a build with Bzlmod off fetches where that is
                       anything (Bazel 8: the repositories of Bazel's own
                       WORKSPACE suffix, `workspace_deps.bzl` in its source).
                       A hybrid build fetches both lists.

Nothing here is trusted on its own word. A registry file must have the
sha256 that version's committed MODULE.bazel.lock pins for it
(`registryFileHashes`; the lock is made by `bazel mod deps` against
https://bcr.bazel.build/), and a patch or a module archive the digest its
module's `source.json` states. Nothing vouches for a `workspace_archives`
entry, and nothing needs to: where the archive is not committed the list
only says which entries of a repository cache a cell is given, and Bazel
takes a cache entry by the checksum its own WORKSPACE suffix states.

  bazel-fixture-registry.py check
      Verify the committed tree. Offline; run by
      scripts/tests/test_bazel_fixture_registry.py.

  bazel-fixture-registry.py add --bazel V --lock LOCK --bcr CLONE
                                --repository-cache DIR [--no-distdir]
                                [--workspace-cache DIR [--name SHA256=FILE]...]
      Add or refresh one Bazel version. LOCK is the committed lock (under the
      fixtures directory). CLONE is a checkout of bazel-central-registry.
      DIR is the repository cache of one cold build, which tells which
      archives a build fetches. To make both, in a copy of
      core/bzlmod/<era> with common/probe.bzl beside it, under Bazel V:

        bazel mod deps --lockfile_mode=update        # then copy MODULE.bazel.lock to LOCK
        bazel shutdown && rm MODULE.bazel.lock
        bazel --output_user_root=<new> build //... --repository_cache=<DIR, empty> \\
            --distdir=<fixtures>/core/payloads/upstream

      --workspace-cache is the repository cache of the same cold build of
      core/workspace/<era> with Bzlmod off (`--noenable_bzlmod`, on Bazel 8
      also `--enable_workspace`). Every file in it but a toy package is
      recorded. Its name is the module archive's when the digest is one, the
      name an earlier run recorded, or the one --name gives (the `archive`
      that Bazel's `workspace_deps.bzl` states for the sha256). Without the
      option the version's list stays as it is.

      Everything is read and verified before the first write. `add` refuses
      to run while the lock of another version in the manifest cannot be
      read: the files only that lock accounts for would be removed as
      unaccounted.

      After a change to toy.bzl or a toy lock, only the `//:toy.bzl%toy`
      entry of each committed lock is stale (for an edit of toy.bzl, its
      `bzlTransitiveDigest` alone). Build once with that lock in place and
      --lockfile_mode=update against https://bcr.bazel.build/, and copy the
      lock back. Not under --registry=file://: Bazel then rewrites the lock
      with an empty `registryFileHashes` (seen on 7.7.2, 8.8.2 and 9.3.2),
      which `check` refuses. Offline, build a copy that way and move only
      the changed value of the `//:toy.bzl%toy` entry into the committed lock.
"""

import argparse
import base64
import hashlib
import json
import re
import shutil
import sys
from pathlib import Path

FIXTURES = Path(__file__).resolve().parents[1] / "crates/socket-patch-cli/tests/fixtures/bazel"
BCR = "https://bcr.bazel.build/"
# Files of the tree that no lock or source.json vouches for.
OWN = ("MANIFEST.json", "SHA256SUMS")


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sri_sha256(integrity):
    """The hex sha256 of an SRI string, or None for another algorithm."""
    algorithm, _, encoded = integrity.partition("-")
    return base64.b64decode(encoded).hex() if algorithm == "sha256" else None


def lock_pins(lock_path):
    """Registry-relative path -> sha256, for every registry file a lock pins."""
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    pins = {}
    for url, digest in lock.get("registryFileHashes", {}).items():
        if not url.startswith(BCR):
            raise ValueError(f"{lock_path}: {url} is not a file of {BCR}")
        if not isinstance(digest, str) or len(digest) != 64:
            # A recorded miss ("not found") cannot be mirrored: a file://
            # registry would have to prove the absence.
            raise ValueError(f"{lock_path}: {url} has no sha256")
        pins[url[len(BCR):]] = digest
    if not pins:
        raise ValueError(f"{lock_path}: no registryFileHashes (a lock made under --registry=file://?)")
    return pins


def module_files(source, base):
    """Path -> sha256 of the patch and overlay files a source.json names."""
    files = {}
    for kind in ("patches", "overlay"):
        for name, integrity in source.get(kind, {}).items():
            files[f"{base}/{kind}/{name}"] = sri_sha256(integrity)
    return files


def payload_digests(fixtures):
    """sha256 of every toy package file (core/payloads). None is ever a
    module archive: a cache seeded from a manifest list must hold no package."""
    payloads = fixtures / "core/payloads"
    return {sha256(path) for path in payloads.rglob("*") if path.is_file()}


def workspace_problems(archives, module_archives, toys):
    """What is wrong with a version's `workspace_archives` list."""
    problems = []
    modules = {archive["sha256"]: archive for archive in module_archives}
    for archive in archives:
        if set(archive) != {"file", "sha256", "bytes"}:
            problems.append(f"workspace archive {archive!r} is not a file, a sha256 and a size")
            continue
        name, digest, size = archive["file"], archive["sha256"], archive["bytes"]
        if not isinstance(name, str) or not name or "/" in name or "\\" in name:
            problems.append(f"workspace archive {name!r} is not a file name")
        elif not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            problems.append(f"workspace archive {name} has no sha256")
        elif not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            problems.append(f"workspace archive {name} has no size")
        elif digest in toys:
            problems.append(f"workspace archive {name} is a toy package, not an archive of Bazel's")
        elif digest in modules and (modules[digest]["file"], modules[digest]["bytes"]) != (name, size):
            module = modules[digest]["file"]
            problems.append(f"workspace archive {name} is the module archive {module} under another name or size")
    if not problems:
        names = [archive["file"] for archive in archives]
        if names != sorted(set(names)) or len({archive["sha256"] for archive in archives}) != len(archives):
            problems.append("workspace archives are not sorted by file name, each listed once")
    return problems


def expected(fixtures):
    """(path under registry/ -> sha256, problems) from the manifest, the
    locks it names and the mirrored source.json of each archive's module."""
    registry = fixtures / "registry"
    manifest = json.loads((registry / "MANIFEST.json").read_text(encoding="utf-8"))
    files, problems = {}, []
    toys = payload_digests(fixtures)

    def want(rel, digest, why):
        if digest is None:
            problems.append(f"{rel}: {why} states no sha256")
        elif files.setdefault(rel, digest) != digest:
            problems.append(f"{rel}: {why} wants {digest}, another version {files[rel]}")

    for version, entry in sorted(manifest["versions"].items()):
        try:
            pins = lock_pins(fixtures / entry["lock"])
        except (OSError, ValueError) as error:
            problems.append(f"Bazel {version}: {error}")
            continue
        for rel, digest in pins.items():
            want(rel, digest, f"the Bazel {version} lock")
        for archive in entry["archives"]:
            name, _, module_version = archive["module"].partition("@")
            base = f"modules/{name}/{module_version}"
            if f"{base}/source.json" not in pins:
                problems.append(f"Bazel {version}: the lock pins no {base}/source.json")
                continue
            try:
                source = json.loads((registry / base / "source.json").read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue  # reported as missing or mismatched below
            if sri_sha256(source.get("integrity", "")) != archive["sha256"]:
                problems.append(f"Bazel {version}: {archive['file']} is not the archive of {base}/source.json")
            if source.get("url", "").rsplit("/", 1)[-1] != archive["file"]:
                problems.append(f"Bazel {version}: --distdir finds {base} by another name than {archive['file']}")
            for rel, digest in module_files(source, base).items():
                want(rel, digest, f"{base}/source.json")
            if entry["distdir"]:
                want(f"distdir/{version}/{archive['file']}", archive["sha256"], f"the Bazel {version} manifest entry")
        workspace = entry.get("workspace_archives", [])
        wrong = workspace_problems(workspace, entry["archives"], toys)
        problems.extend(f"Bazel {version}: {problem}" for problem in wrong)
        if entry["distdir"] and not wrong:
            for archive in workspace:
                want(f"distdir/{version}/{archive['file']}", archive["sha256"], f"the Bazel {version} manifest entry")
    return files, problems


def tree(registry):
    """Path -> sha256 of every file under registry/ but SHA256SUMS."""
    paths = (p for p in registry.rglob("*") if p.is_file() and p.name != "SHA256SUMS")
    return {p.relative_to(registry).as_posix(): sha256(p) for p in paths}


def render_sums(digests):
    return "".join(f"{digest}  {rel}\n" for rel, digest in sorted(digests.items()))


def check(fixtures=FIXTURES):
    """Every problem with the committed tree; empty when it is sound."""
    registry = fixtures / "registry"
    try:
        files, problems = expected(fixtures)
    except (OSError, ValueError, KeyError, TypeError) as error:
        return [f"MANIFEST.json: {error!r}"]
    actual = tree(registry)
    for rel, digest in sorted(files.items()):
        if rel not in actual:
            problems.append(f"{rel}: missing")
        elif actual[rel] != digest:
            problems.append(f"{rel}: sha256 {actual[rel]}, expected {digest}")
    for rel in sorted(set(actual) - set(files) - set(OWN)):
        problems.append(f"{rel}: no lock or source.json of MANIFEST.json accounts for this file")
    sums = registry / "SHA256SUMS"
    if not sums.is_file() or sums.read_text(encoding="utf-8") != render_sums(actual):
        problems.append("SHA256SUMS does not list the tree as it is")
    return problems


def cached_files(cache):
    """sha256 -> file, for every download a --repository_cache directory holds."""
    entries = cache / "content_addressable" / "sha256"
    found = {}
    for entry in sorted(entries.iterdir()) if entries.is_dir() else []:
        if (entry / "file").is_file():
            found[entry.name] = entry / "file"
    return found


def workspace_archives(cache, version, names, toys):
    """The `workspace_archives` list for the repository cache of a cold
    WORKSPACE build, and file name -> cached file. `names` is sha256 -> file
    name for every archive that can be named."""
    archives, sources = [], {}
    for digest, fetched in cached_files(cache).items():
        if digest in toys:
            continue
        if sha256(fetched) != digest:
            raise SystemExit(f"{fetched} is not the file its cache key names")
        size = fetched.stat().st_size
        if digest not in names:
            raise SystemExit(
                f"{digest} ({size} bytes) in {cache} is not a module archive of Bazel {version}: name it with "
                f"--name {digest}=<file>, the `archive` of that sha256 in Bazel's workspace_deps.bzl. "
                "(Many unnamed files: is this the cache of a build with Bzlmod off?)"
            )
        if names[digest] in sources:
            raise SystemExit(f"two archives named {names[digest]}: --distdir finds a file by its name alone")
        archives.append({"file": names[digest], "sha256": digest, "bytes": size})
        sources[names[digest]] = fetched
    return sorted(archives, key=lambda archive: archive["file"]), sources


def add(fixtures, version, lock, bcr, cache, distdir, workspace_cache=None, names=None):
    """Mirror what `version`'s lock pins, verified, and record its archives.
    Everything this version brings is read and checked before the first
    write, so a refusal up to there leaves the tree as it was. The one
    refusal after it (the manifest as written does not account for every
    file) removes nothing."""
    registry = fixtures / "registry"
    manifest_path = registry / "MANIFEST.json"
    manifest = {"registry": BCR, "versions": {}}
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    previous = manifest["versions"].get(version, {})
    try:
        lock_name = lock.resolve().relative_to(fixtures.resolve()).as_posix()
    except ValueError:
        raise SystemExit(f"{lock} is not under {fixtures}: the manifest names a committed lock") from None

    # The last step removes every file no lock of the manifest accounts for.
    # A version whose lock cannot be read accounts for nothing, so its files
    # would go: refuse before anything is written.
    unreadable = []
    for other, entry in sorted(manifest["versions"].items()):
        if other == version:
            continue
        try:
            lock_pins(fixtures / entry["lock"])
        except (OSError, ValueError) as error:
            unreadable.append(f"Bazel {other}: {error}")
    if unreadable:
        raise SystemExit("\n".join(["nothing was changed; the lock of another version cannot be read:"] + unreadable))

    copies = {}  # path under registry/ -> the verified file to copy there

    def mirror(rel, digest):
        source = bcr / rel
        if not source.is_file() or sha256(source) != digest:
            raise SystemExit(f"{source} is not the file the lock or source.json pins ({digest})")
        copies[rel] = source

    pins = lock_pins(lock)
    for rel, digest in pins.items():
        mirror(rel, digest)
    fetched_files = cached_files(cache)
    archives = []
    for rel in sorted(pins):
        if not rel.endswith("/source.json"):
            continue
        source = json.loads((bcr / rel).read_text(encoding="utf-8"))
        integrity = source.get("integrity", "")
        digest = sri_sha256(integrity)
        if integrity and digest is None:
            # Searching the sha256 cache for it would find nothing, and the
            # archive would be dropped as one no build fetched.
            raise SystemExit(f"{rel}: integrity {integrity!r} is not a sha256, which is all this tool reads")
        if digest not in fetched_files:
            continue  # no build fetched this module
        fetched = fetched_files[digest]
        base = rel.rsplit("/", 1)[0]
        for extra, extra_digest in module_files(source, base).items():
            mirror(extra, extra_digest)
        name = source["url"].rsplit("/", 1)[-1]
        if any(archive["file"] == name for archive in archives):
            raise SystemExit(f"two archives named {name}: --distdir finds a file by its name alone")
        _, module, module_version, _ = rel.split("/")
        archives.append({
            "module": f"{module}@{module_version}",
            "file": name,
            "sha256": digest,
            "bytes": fetched.stat().st_size,
        })
        if distdir:
            copies[f"distdir/{version}/{name}"] = fetched

    workspace = previous.get("workspace_archives", [])
    if workspace_cache is not None:
        known = {archive["sha256"]: archive["file"] for archive in workspace}
        known.update({archive["sha256"]: archive["file"] for archive in archives})
        known.update(names or {})
        workspace, sources = workspace_archives(workspace_cache, version, known, payload_digests(fixtures))
        if distdir:
            for name, fetched in sources.items():
                copies[f"distdir/{version}/{name}"] = fetched
    elif workspace and distdir:
        raise SystemExit(
            f"Bazel {version} lists WORKSPACE archives: pass --workspace-cache, so that --distdir gets them too"
        )
    wrong = workspace_problems(workspace, archives, payload_digests(fixtures))
    if wrong:
        raise SystemExit("\n".join([f"nothing was changed; the WORKSPACE archives of Bazel {version}:"] + wrong))

    shutil.rmtree(registry / "distdir" / version, ignore_errors=True)
    for rel, source in copies.items():
        (registry / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, registry / rel)
    manifest["versions"][version] = {
        "lock": lock_name,
        "distdir": distdir,
        "archives": archives,
    }
    if workspace:
        manifest["versions"][version]["workspace_archives"] = workspace
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    # Drop what a refreshed version no longer needs. Only with a file list
    # that is whole: a problem here means some file's owner is unknown.
    files, problems = expected(fixtures)
    if problems:
        raise SystemExit("\n".join(["no file was removed and SHA256SUMS was not rewritten:"] + problems))
    for rel in set(tree(registry)) - set(files) - set(OWN):
        (registry / rel).unlink()
    for directory in sorted((p for p in registry.rglob("*") if p.is_dir()), reverse=True):
        if not any(directory.iterdir()):
            directory.rmdir()
    (registry / "SHA256SUMS").write_text(render_sums(tree(registry)), encoding="utf-8")


def parse_names(pairs):
    """`SHA256=FILE` arguments as sha256 -> file name."""
    names = {}
    for pair in pairs:
        digest, _, name = pair.partition("=")
        if not re.fullmatch(r"[0-9a-f]{64}", digest) or not name:
            raise SystemExit(f"--name {pair}: expected <sha256>=<file name>")
        names[digest] = name
    return names


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("check")
    adding = commands.add_parser("add")
    adding.add_argument("--bazel", required=True)
    adding.add_argument("--lock", required=True, type=Path)
    adding.add_argument("--bcr", required=True, type=Path)
    adding.add_argument("--repository-cache", required=True, type=Path)
    adding.add_argument("--no-distdir", action="store_true")
    adding.add_argument("--workspace-cache", type=Path)
    adding.add_argument("--name", action="append", default=[], metavar="SHA256=FILE")
    args = parser.parse_args(argv)
    if args.command == "add":
        add(
            FIXTURES, args.bazel, args.lock, args.bcr, args.repository_cache, not args.no_distdir,
            args.workspace_cache, parse_names(args.name),
        )
    problems = check()
    for problem in problems:
        print(problem, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
