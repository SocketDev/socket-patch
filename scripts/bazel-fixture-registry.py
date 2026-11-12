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
  distdir/<bazel version>/<file>    the module archives a cold build of the toy
                                    fixture fetches, for --distdir. Only where
                                    they are small: 8.8.2 fetches 12.4 MB, so
                                    its cells fetch them from the network once
                                    and its entry says `"distdir": false`.
  MANIFEST.json                     per Bazel version: the lock the file list
                                    comes from, and the archives.
  SHA256SUMS                        every file above.

Nothing here is trusted on its own word. A registry file must have the
sha256 that version's committed MODULE.bazel.lock pins for it
(`registryFileHashes`; the lock is made by `bazel mod deps` against
https://bcr.bazel.build/), and a patch or an archive the digest its module's
`source.json` states.

  bazel-fixture-registry.py check
      Verify the committed tree. Offline; run by
      scripts/tests/test_bazel_fixture_registry.py.

  bazel-fixture-registry.py add --bazel V --lock LOCK --bcr CLONE
                                --repository-cache DIR [--no-distdir]
      Add or refresh one Bazel version. LOCK is the committed lock (under the
      fixtures directory). CLONE is a checkout of bazel-central-registry.
      DIR is the repository cache of one cold build, which tells which
      archives a build fetches. To make both, in a copy of
      core/bzlmod/<era> with common/probe.bzl beside it, under Bazel V:

        bazel mod deps --lockfile_mode=update        # then copy MODULE.bazel.lock to LOCK
        bazel shutdown && rm MODULE.bazel.lock
        bazel --output_user_root=<new> build //... --repository_cache=<DIR, empty> \\
            --distdir=<fixtures>/core/payloads/upstream

      After a change to toy.bzl or a toy lock, only the extension entry of
      each committed lock is stale: build once with that lock in place and
      --lockfile_mode=update, and copy the lock back.
"""

import argparse
import base64
import hashlib
import json
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


def expected(fixtures):
    """(path under registry/ -> sha256, problems) from the manifest, the
    locks it names and the mirrored source.json of each archive's module."""
    registry = fixtures / "registry"
    manifest = json.loads((registry / "MANIFEST.json").read_text(encoding="utf-8"))
    files, problems = {}, []

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
    except (OSError, ValueError, KeyError) as error:
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


def add(fixtures, version, lock, bcr, cache, distdir):
    """Mirror what `version`'s lock pins, verified, and record its archives."""
    registry = fixtures / "registry"
    manifest_path = registry / "MANIFEST.json"
    manifest = {"registry": BCR, "versions": {}}
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    def mirror(rel, digest):
        source = bcr / rel
        if not source.is_file() or sha256(source) != digest:
            raise SystemExit(f"{source} is not the file the lock or source.json pins ({digest})")
        (registry / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, registry / rel)

    pins = lock_pins(lock)
    for rel, digest in pins.items():
        mirror(rel, digest)
    shutil.rmtree(registry / "distdir" / version, ignore_errors=True)
    archives = []
    for rel in sorted(pins):
        if not rel.endswith("/source.json"):
            continue
        source = json.loads((registry / rel).read_text(encoding="utf-8"))
        digest = sri_sha256(source.get("integrity", ""))
        fetched = cache / "content_addressable" / "sha256" / str(digest) / "file"
        if digest is None or not fetched.is_file():
            continue  # no build fetched this module
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
            (registry / "distdir" / version).mkdir(parents=True, exist_ok=True)
            shutil.copyfile(fetched, registry / "distdir" / version / name)
    manifest["versions"][version] = {
        "lock": lock.resolve().relative_to(fixtures.resolve()).as_posix(),
        "distdir": distdir,
        "archives": archives,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    # Drop what a refreshed version no longer needs.
    files, _ = expected(fixtures)
    for rel in set(tree(registry)) - set(files) - set(OWN):
        (registry / rel).unlink()
    for directory in sorted((p for p in registry.rglob("*") if p.is_dir()), reverse=True):
        if not any(directory.iterdir()):
            directory.rmdir()
    (registry / "SHA256SUMS").write_text(render_sums(tree(registry)), encoding="utf-8")


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
    args = parser.parse_args(argv)
    if args.command == "add":
        add(FIXTURES, args.bazel, args.lock, args.bcr, args.repository_cache, not args.no_distdir)
    problems = check()
    for problem in problems:
        print(problem, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
