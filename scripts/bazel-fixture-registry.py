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
  MANIFEST.json                     per Bazel version: where its file list
                                    comes from (a lock, or a recorded list),
                                    and the archives.
  README.md                         the layout and where each part came from.
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

Bazel 6.6.0, 7.0.x and 7.1.x write a lock with no `registryFileHashes`
(and one that names the registry it was made against, so no committed lock
of theirs passes `--lockfile_mode=error` under --registry=file://: their
cells make the lock in the test). For such a version the manifest entry
holds a `recorded` list instead of a lock: every registry file a cold build
of the toy fixtures asked for, with the sha256 the bazel-central-registry
checkout had for it, and the commit of that checkout. A digest another
version's lock pins for the same file must agree; the rest stand on the
record. `modules/<name>/metadata.json` (the yanked-version list, which
upstream rewrites) is never mirrored: a registry without it yanks nothing.

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

  bazel-fixture-registry.py record --bcr CLONE --log LOG --config CFG [--port N]
  bazel-fixture-registry.py add --bazel V --requests LOG --bcr CLONE
                                --repository-cache DIR [--source TEXT]
      The same for a Bazel version below 7.2.0, which has no lock to name.
      `record` plays https://bcr.bazel.build/ from CLONE on a loopback port
      until it is interrupted (SIGINT or SIGTERM), writes the one-line
      downloader config CFG that sends registry reads to it, and appends
      `<status> TAB <path>` to LOG for each. With it running, build cold
      once per fixture of the version's era that has a MODULE.bazel
      (core/bzlmod/<era> and core/hybrid/<era>, common/probe.bzl beside
      each), every build into the same empty DIR:

        bazel --output_user_root=<new> build //... --repository_cache=<DIR> \\
            --experimental_downloader_config=<CFG> --lockfile_mode=update \\
            --distdir=<fixtures>/core/payloads/upstream   # and --enable_bzlmod on 6.x

      `add --requests` mirrors what LOG lists from CLONE, refuses a request
      the run got no file for, and records the commit of CLONE (--source
      says what CLONE is when it is not a git checkout). The fixtures of
      such a version commit no lock.
"""

import argparse
import base64
import hashlib
import json
import re
import shutil
import signal
import socketserver
import subprocess
import sys
from http.server import BaseHTTPRequestHandler
from pathlib import Path

FIXTURES = Path(__file__).resolve().parents[1] / "crates/socket-patch-cli/tests/fixtures/bazel"
BCR = "https://bcr.bazel.build/"
# Files of the tree that no lock or source.json vouches for.
OWN = ("MANIFEST.json", "README.md", "SHA256SUMS")
# What a recorded list may name: the files module resolution reads. A patch
# comes in through the source.json of an archive a build fetched.
RECORDED_FILE = re.compile(r"bazel_registry\.json|modules/[^/]+/[^/]+/(MODULE\.bazel|source\.json)")
# The first Bazel whose lock pins the registry files it read.
FIRST_WITH_REGISTRY_HASHES = (7, 2, 0)


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


def release(version):
    """`7.1.2` or `10.0.0rc3` as a tuple of its three numbers."""
    numbers = re.match(r"(\d+)\.(\d+)\.(\d+)", version)
    if not numbers:
        raise ValueError(f"{version!r} is not a Bazel version")
    return tuple(int(number) for number in numbers.groups())


def recorded_pins(version, recorded):
    """Registry-relative path -> sha256, for a version whose file list is a
    recorded one (`add --requests`)."""
    if release(version) >= FIRST_WITH_REGISTRY_HASHES:
        raise ValueError(f"Bazel {version} writes registryFileHashes: its file list comes from a lock")
    files = recorded.get("files") if isinstance(recorded, dict) else None
    if not isinstance(files, dict) or "bazel_registry.json" not in files:
        raise ValueError(f"Bazel {version}: the recorded list has no bazel_registry.json")
    if not isinstance(recorded.get("source"), str) or not recorded["source"]:
        raise ValueError(f"Bazel {version}: the recorded list does not say what it was recorded from")
    for rel, digest in files.items():
        if not RECORDED_FILE.fullmatch(rel):
            raise ValueError(f"Bazel {version}: {rel} is not a file module resolution reads")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError(f"Bazel {version}: {rel} has no sha256")
    return dict(files)


def version_pins(fixtures, version, entry):
    """(registry-relative path -> sha256, what vouches for them) for one
    manifest entry: its committed lock, or its recorded list."""
    if ("lock" in entry) == ("recorded" in entry):
        raise ValueError(f"Bazel {version}: the entry names one of `lock` and `recorded`")
    if "lock" in entry:
        return lock_pins(fixtures / entry["lock"]), f"the Bazel {version} lock"
    return recorded_pins(version, entry["recorded"]), f"the Bazel {version} recorded list"


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
            pins, vouched_by = version_pins(fixtures, version, entry)
        except (OSError, ValueError) as error:
            problems.append(f"Bazel {version}: {error}")
            continue
        for rel, digest in pins.items():
            want(rel, digest, vouched_by)
        for archive in entry["archives"]:
            name, _, module_version = archive["module"].partition("@")
            base = f"modules/{name}/{module_version}"
            if f"{base}/source.json" not in pins:
                problems.append(f"{vouched_by} pins no {base}/source.json")
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


def requested_files(log):
    """The registry files a recorded run read: the paths of the log `record`
    wrote, without the yanked-version lists. A request the run got no file
    for is refused, as a miss a lock records is: a file:// registry cannot
    show that a file is absent upstream."""
    files = set()
    for line in log.read_text(encoding="utf-8").splitlines():
        status, tab, rel = line.partition("\t")
        if not tab or not status.isdigit():
            raise SystemExit(f"{log}: {line!r} is not `<status> TAB <path>`")
        if re.fullmatch(r"modules/[^/]+/metadata\.json", rel):
            continue
        if status != "200":
            raise SystemExit(f"{log}: the run asked for {rel} and got {status}; a miss cannot be mirrored")
        if not RECORDED_FILE.fullmatch(rel):
            raise SystemExit(f"{log}: {rel} is not a file module resolution reads")
        files.add(rel)
    if "bazel_registry.json" not in files:
        raise SystemExit(f"{log}: no request for bazel_registry.json: did a build run against the recorder?")
    return files


def checkout_commit(bcr):
    """`bazel-central-registry@<commit>` for a git checkout, else None."""
    try:
        head = subprocess.run(
            ["git", "-C", str(bcr), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None
    return f"bazel-central-registry@{head}" if re.fullmatch(r"[0-9a-f]{40,64}", head) else None


def add(
    fixtures, version, lock, bcr, cache, distdir, workspace_cache=None, names=None, requests=None, recorded_from=None
):
    """Mirror what `version` reads, verified, and record its archives. The
    file list is what the lock pins, or with `requests` (the log of a
    recorded run, for a Bazel whose lock pins no registry file) what that
    run asked for, as `bcr` holds it; `recorded_from` then says what `bcr` is.
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
    if (lock is None) == (requests is None):
        raise SystemExit("name the version's committed lock or the request log of a recorded run, not both")
    if lock is not None:
        try:
            lock_name = lock.resolve().relative_to(fixtures.resolve()).as_posix()
        except ValueError:
            raise SystemExit(f"{lock} is not under {fixtures}: the manifest names a committed lock") from None

    # The last step removes every file no lock of the manifest accounts for.
    # A version whose lock cannot be read accounts for nothing, so its files
    # would go: refuse before anything is written.
    unreadable, others = [], {}
    for other, entry in sorted(manifest["versions"].items()):
        if other == version:
            continue
        try:
            other_pins, _ = version_pins(fixtures, other, entry)
        except (OSError, ValueError) as error:
            unreadable.append(f"Bazel {other}: {error}")
            continue
        for rel, digest in other_pins.items():
            others.setdefault(rel, (digest, other))
    if unreadable:
        raise SystemExit("\n".join(["nothing was changed; the lock of another version cannot be read:"] + unreadable))

    copies = {}  # path under registry/ -> the verified file to copy there

    def mirror(rel, digest):
        source = bcr / rel
        if not source.is_file() or sha256(source) != digest:
            raise SystemExit(f"{source} is not the file the lock or source.json pins ({digest})")
        copies[rel] = source

    if requests is not None:
        if not recorded_from:
            raise SystemExit(f"{bcr} is not a git checkout: say what it is with --source")
        pins = {}
        for rel in sorted(requested_files(requests)):
            if not (bcr / rel).is_file():
                raise SystemExit(f"{bcr / rel}: the recorded run read this file and the checkout does not have it")
            pins[rel] = sha256(bcr / rel)
            pinned, other = others.get(rel, (pins[rel], version))
            if pinned != pins[rel]:
                raise SystemExit(
                    f"nothing was changed; {bcr / rel} has sha256 {pins[rel]}, and Bazel {other} pins {pinned}"
                )
        file_list = {"recorded": {"source": recorded_from, "files": pins}}
        try:
            recorded_pins(version, file_list["recorded"])
        except ValueError as error:
            raise SystemExit(f"nothing was changed; {error}") from None
    else:
        pins = lock_pins(lock)
        file_list = {"lock": lock_name}
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
        **file_list,
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


def recorder(bcr, log, port=0):
    """A loopback server that plays https://bcr.bazel.build/ from the
    checkout `bcr` and appends `<status> TAB <path>` to `log` for every
    request. `server_address[1]` is its port; `serve_forever()` runs it."""
    bcr = bcr.resolve()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            rel = self.path.split("?", 1)[0].lstrip("/")
            target = (bcr / rel).resolve()
            found = bcr in target.parents and target.is_file() and ".git" not in target.parts
            body = target.read_bytes() if found else b""
            status = 200 if found else 404
            with log.open("a", encoding="utf-8") as out:
                out.write(f"{status}\t{rel}\n")
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        do_HEAD = do_GET

    # Not http.server.HTTPServer: its bind looks the host name up, which
    # stalls for half a minute where the resolver is sandboxed.
    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    return Server(("127.0.0.1", port), Handler)


def record(bcr, log, config, port):
    """Run the recorder until interrupted (see the module docstring)."""
    if not (bcr / "bazel_registry.json").is_file():
        raise SystemExit(f"{bcr} is not a checkout of bazel-central-registry")
    log.write_text("", encoding="utf-8")

    def interrupt(*_):
        raise KeyboardInterrupt

    # A recorder started in the background of a script has SIGINT ignored.
    for stop in (signal.SIGINT, signal.SIGTERM):
        signal.signal(stop, interrupt)
    with recorder(bcr, log, port) as server:
        bound = server.server_address[1]
        config.write_text(f"rewrite bcr\\.bazel\\.build/(.*) http://127.0.0.1:{bound}/$1\n", encoding="utf-8")
        print(f"recording on 127.0.0.1:{bound}; pass --experimental_downloader_config={config}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
    return 0


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
    recording = commands.add_parser("record")
    recording.add_argument("--bcr", required=True, type=Path)
    recording.add_argument("--log", required=True, type=Path)
    recording.add_argument("--config", required=True, type=Path)
    recording.add_argument("--port", type=int, default=0)
    adding = commands.add_parser("add")
    adding.add_argument("--bazel", required=True)
    file_list = adding.add_mutually_exclusive_group(required=True)
    file_list.add_argument("--lock", type=Path)
    file_list.add_argument("--requests", type=Path)
    adding.add_argument("--bcr", required=True, type=Path)
    adding.add_argument("--source")
    adding.add_argument("--repository-cache", required=True, type=Path)
    adding.add_argument("--no-distdir", action="store_true")
    adding.add_argument("--workspace-cache", type=Path)
    adding.add_argument("--name", action="append", default=[], metavar="SHA256=FILE")
    args = parser.parse_args(argv)
    if args.command == "record":
        return record(args.bcr, args.log, args.config, args.port)
    if args.command == "add":
        add(
            FIXTURES, args.bazel, args.lock, args.bcr, args.repository_cache, not args.no_distdir,
            args.workspace_cache, parse_names(args.name), args.requests, args.source or checkout_commit(args.bcr),
        )
    problems = check()
    for problem in problems:
        print(problem, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
