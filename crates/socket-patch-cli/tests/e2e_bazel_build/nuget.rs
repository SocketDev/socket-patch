//! Hosted, vendored and agent mode for a NuGet package that comes through
//! rules_csharp's `nuget.from_lock(packages_lock_json = "//:packages.lock.json",
//! nuget_config = "//:nuget.config")` under Bzlmod: the lock that
//! `dotnet restore` writes beside a project, and a `nuget.config` whose one
//! package source is nuget.org.
//!
//! rules_csharp reads both files itself. It asks the sources of
//! `nuget.config`, in their order, for every package of the lock, with
//! Bazel's downloader; it holds the file it gets to the lock's
//! `contentHash`, and `MODULE.bazel.lock` records the file's sha256, which
//! Bazel holds every later fetch to. No `dotnet` runs, and a build reads
//! nothing of NuGet's global packages folder.
//!
//! `socket-patch` does read that folder: `scan` finds a NuGet package only
//! where a restore unpacked it (a folder that an `obj/project.assets.json`
//! of the checkout records, the `packages` folder of a packages.config
//! project, or NuGet's global packages folder), and in no lock. The
//! fixture's checkout holds no record of a restore, so the flow has two
//! kinds of machine. On one the global folder holds the fixture's two
//! packages, staged by hand as a restore leaves them
//! ([`Package::restore_into`]); on the other it holds nothing, as on a
//! runner that only ever ran Bazel.
//!
//! The hosted flow, on the Bazel the run is given ([`FIXTURE`] says which
//! ruleset goes with its release), in a fresh output base:
//!
//! - (a) `bazel build` and `bazel run //:consumer` print the unpatched
//!   marker, and Bazel fetched the upstream package from the stand-in.
//!   Where NuGet's folder holds nothing, `scan --mode hosted --yes` then
//!   finds no package: it exits 0 and writes no file.
//! - (b) Where the folder holds the packages, the same command rewrites
//!   `nuget.config` (the Socket source of the patch, ahead of nuget.org,
//!   and a source mapping, which only NuGet's own restore reads) and
//!   `packages.lock.json` (the `contentHash` of the patched package), and
//!   nothing else. It warns that the folder still holds the unpatched copy,
//!   which is what `dotnet restore` would go on using. That leaves
//!   `MODULE.bazel.lock` stale: a build that may not update it
//!   (`--lockfile_mode=error`, as a CI with a frozen lock runs it) fails
//!   right after the scan, until a build that may update the lock, or
//!   `bazel mod deps --lockfile_mode=update`, has rewritten it and the user
//!   has committed that.
//! - (c) With no other step, the two Bazel commands of (a) print the
//!   patched marker, and the package came from the stand-in patch host. The
//!   hub asked that host for the other package of the lock as well, which
//!   it does not hold: Bazel printed a warning with the URL, the access
//!   token of the grant included, and the package came from nuget.org as
//!   before. That build rewrites `MODULE.bazel.lock` and no other file.
//!   From then on the checkout stands: the next build changes no file, and
//!   a `--lockfile_mode=error` build passes.
//!   Then the scan runs a second time, as it does on every run of a
//!   pipeline: it reports the patch applied again and changes no file. And
//!   `vex` is asked for its document on both machines. Where NuGet's folder
//!   holds the unpatched copy it writes none and exits 1 (`not_applied`):
//!   it reads the package there, which is not the one Bazel built. Where
//!   the folder holds nothing it attests the package, from the pin in the
//!   two files.
//! - (d) `socket-patch rollback --yes` restores `nuget.config` and
//!   `packages.lock.json` byte for byte, at once. Bazel's change to its own
//!   lock stays, so a `--lockfile_mode=error` build fails right after the
//!   rollback as it did right after the scan. The next build that may
//!   update the lock prints the unpatched marker and writes the lock of
//!   before: from then on every file of the checkout is the one of before.
//! - (e) On a second machine (a new output base and, on Bazel 9, a new
//!   contents cache), a patch service grants another patch of the package
//!   and its host serves other bytes than the grant pins. After the same
//!   `scan` the build fails, in both states the checkout can be in. With
//!   the Bazel lock of before, which the scan left stale, the hub asks the
//!   sources again and refuses the file over the `contentHash` of
//!   `packages.lock.json`. With a Bazel lock that pins the granted package,
//!   Bazel's downloader refuses the file over its sha256, and then the copy
//!   on nuget.org, which the hub tries next.
//!
//! Another flow is agent mode ([`agent_from_lock`]), which patches the
//! copy of the package in NuGet's global packages folder, where the user's
//! `dotnet restore` unpacked it. No build of Bazel's reads that folder, so
//! the build is the unpatched one before the command and after it. The flow
//! asserts that, and that every form of `vex` says so meanwhile: the
//! package is affected ([`affected`]), unless `vex` is told that the
//! installed tree is what ships (`--no-bazel`).
//!
//! Both markers are read from what Bazel built, and each holds an id made
//! for the run. Bazel's downloader keeps every file it fetches in the
//! repository cache, under its sha256, and hands it out again without a
//! request; the tests of a leg share that cache, and CI restores it from
//! earlier runs. A package of a run is in no cache, so step (a) has to
//! fetch the upstream one and counts the requests.
//!
//! The names of the two packages end in an id of the run as well ([`RUN`]).
//! nuget.org has no scopes: an id there belongs to whoever pushes it first,
//! and the fixture's files are public. Nobody can have pushed an id that is
//! new for every run, so a build that got past the stand-in would find no
//! package of that name on nuget.org. The fixture's files hold a
//! placeholder where a checkout holds that id, and the fixture's lock holds
//! one for each `contentHash` ([`check_out`]). With the placeholder a name
//! is no package id (NuGet takes no `@` in one), so the committed project
//! and lock name no package that anybody could push either.
//!
//! The Bazel lock of the second build of (e) is not one a build wrote: the
//! build that writes it has to fetch the granted package, and then the
//! repository cache, which the two machines share, would hand it to every
//! later build without a request. It is the lock the patched build of (c)
//! wrote, with the four values of the second patch in place of the first's:
//! its source, the sha256 of its package, and the sha256 of the two files
//! the scan rewrote. The build runs with `--lockfile_mode=error`, so a lock
//! that Bazel did not take as current would fail it another way.
//!
//! One loopback server per checkout (the second machine of (e) has its own)
//! stands in for three hosts, by route prefix: the Socket API (`/v0`),
//! `api.nuget.org` (the flat container with the fixture's two packages,
//! where `rollback` also reads the upstream package, through
//! `SOCKET_NUGET_URL`, to compute its `contentHash` again) and
//! `patch.socket.dev` (the Socket source of a patch: its service index, and
//! a flat container that holds the patched package and no other). Bazel
//! drops a plain `http` URL that comes without a checksum, and the hub asks
//! for a service index and for the packages of a changed lock without one.
//! So `nuget.config` and the grant keep the `https` URLs of production, and
//! a downloader config sends every URL of the two hosts to the stand-in
//! ([`downloads`]). It refuses what is left of them, so no build reaches
//! nuget.org or the patch host. It is there from the first build on, and
//! step (c) changes no flag.
//!
//! A second flow, [`hosted_no_config`], is the workspace of rules_csharp's
//! own examples: the tag names the lock and no `nuget_config`, and the
//! checkout holds no `nuget.config`. The hub then has nuget.org as its one
//! source, so a lock re-pinned to the patched package would fail the build:
//! the hub downloads the upstream package and refuses it over the lock's
//! `contentHash`. `socket-patch` reads the tag in `MODULE.bazel` and
//! writes nothing: the same `scan` exits 0, reports the patch as skipped
//! and warns with the tag's file and line and the attribute to add, and
//! the build passes on the upstream package as before. With that
//! attribute on the tag and no other step, the same `scan` creates
//! `nuget.config` and re-pins the lock, and the build is the patched one.
//! [`only_a_tag_that_reads_the_lock_without_its_config_is_withheld`] holds
//! the other workspaces to what the command does without Bazel, and
//! [`the_pin_is_written_where_the_hub_takes_it`] the hubs of more than one
//! tag: the last tag with sources decides which config the hub reads, and
//! the first lock that names a package gives its `contentHash`.
//!
//! A third flow, [`vendored_from_lock`], runs vendored mode in the
//! fixture's workspace. `scan --mode vendored --yes` downloads the patched
//! package from the patch service once and keeps it under `.socket/vendor`,
//! at the path a feed of the hub has a package. It names that folder as a
//! package source in `nuget.config`, which NuGet takes, re-pins the lock,
//! and appends a block to `MODULE.bazel`: a `nuget.from_lock` of its own,
//! whose feeds are the folder of the patch, as a `file:` URL that Bazel
//! reads from the root of the workspace, and then the sources of the
//! config. The build then takes the committed package and asks no host for
//! it, also on a machine with no host to ask; a changed copy fails the
//! build; and `vendor --revert` puts every file back. Where the checkout
//! does not show that the block works (it names no Bazel release), the
//! command declines the package and writes nothing.
//! [`vendored_mode_keeps_the_block_or_declines`] holds the commands to the
//! same without a Bazel, with the other ways in and out.
//!
//! # Known gaps
//!
//! Three outcomes the flows assert are gaps of the product, not its
//! contract. Each is asserted as the release has it, and marked
//! `KNOWN GAP` there with what a fix would change in this test:
//!
//! - Under Bazel alone `socket-patch` finds no NuGet package: it reads
//!   none out of `packages.lock.json`, so the scan of (a) does nothing and
//!   exits 0. The flow has a patched path only because the test stages the
//!   packages in NuGet's global folder first.
//! - On the machine that ran the scan, `vex` exits 1 with `not_applied`
//!   while Bazel builds the patched package (c).
//! - Bazel prints the access token of the grant, in a warning for each
//!   package of the lock that the Socket source does not hold (c).

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Instant;

use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha512};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;

use crate::envelope::{all_codes as codes_of, codes_in, event_triples};
use crate::harness::{
    cell_without_bazel, changed, fixture_path, rewrite, with_vex, Cell, Claim, Fixture, How, Ran,
    StandIn, Tree, CONSUMER, NOTHING,
};
use crate::hosted_memory_common::{read_tree, Patch, ORG};

/// The workspace the test builds, and the ruleset each Bazel release
/// builds it with.
const FIXTURE: Fixture = Fixture {
    name: "nuget::FIXTURE",
    dir: "rules_csharp/bzlmod",
    workflow: "bazel-nuget.yml",
    eras: &[
        // rules_csharp 0.5.0, whose hub downloads with `block = False`,
        // which Bazel has from 7.1.0. It ran on Bazel 9.3.2, 8.8.2 and
        // 7.7.2, the legs of the workflow: every other release of the range
        // is untested.
        ((7, 1, 0)..(10, 0, 0), "e9"),
    ],
};

/// How the id of the package starts that the fixture's project references
/// and a patch replaces, and how the id of the package beside it starts,
/// which has no patch. Each id ends in the tag of its run ([`RUN`]).
const NAME: &str = "SP.Victim";
const NEIGHBOUR: &str = "SP.Other";
/// The version the lock resolves both packages to.
const VERSION: &str = "1.0.0";
/// What the fixture's files hold where a checkout holds the tag of its
/// run, at the end of both ids. NuGet takes no `@` in a package id, so the
/// committed files name no package that could exist on nuget.org.
const RUN: &str = "@RUN@";
/// The two files hosted mode rewrites, and Bazel's own lock.
const CONFIG: &str = "nuget.config";
const LOCK: &str = "packages.lock.json";
const BAZEL_LOCK: &str = "MODULE.bazel.lock";
/// The file of the tag, and the line of it that names [`CONFIG`] there.
const MODULE: &str = "MODULE.bazel";
const NAMES_CONFIG: &str = "    nuget_config = \"//:nuget.config\",\n";
/// The files of the fixture that name a package.
const NAMING: [&str; 3] = ["App.csproj", "BUILD.bazel", LOCK];
/// nuget.org as the fixture's `nuget.config` names it, and as NuGet records
/// the source of a package it restored.
const SOURCE: &str = "https://api.nuget.org/v3/index.json";
/// The two hosts of a build, which are also the route prefixes of the
/// stand-in that plays them, and the flat container where the ruleset
/// finds the packages of [`SOURCE`].
const NUGET_ORG: &str = "api.nuget.org";
const PATCH_HOST: &str = "patch.socket.dev";
const FLAT_CONTAINER: &str = "api.nuget.org/v3-flatcontainer";
/// The one command of hosted mode.
const SCAN: [&str; 4] = ["scan", "--mode", "hosted", "--yes"];
/// The one command of vendored mode, before the option that names the
/// patch service ([`vendored_scan`]).
const VENDORED: [&str; 4] = ["scan", "--mode", "vendored", "--yes"];

/// The sha256 of `bytes` in lowercase hex, as `MODULE.bazel.lock` and
/// Bazel's downloader spell one.
fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The path of the one assembly in the package `id`.
fn assembly_path(id: &str) -> String {
    format!("lib/netstandard2.0/{id}.dll")
}

/// The manifest of the package `id`.
fn nuspec(id: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
         <package xmlns=\"http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd\">\n\
         \x20 <metadata>\n\
         \x20   <id>{id}</id>\n\
         \x20   <version>{VERSION}</version>\n\
         \x20   <authors>socket-patch</authors>\n\
         \x20   <description>a test fixture</description>\n\
         \x20 </metadata>\n\
         </package>\n"
    )
}

/// One build of a package of the fixture, for one run.
struct Package {
    /// `<name>.<the tag of the run>`.
    id: String,
    /// The text of its one assembly: a placeholder, which holds no code.
    assembly: String,
    /// The `.nupkg` a source serves for it.
    nupkg: Vec<u8>,
}

impl Package {
    /// Version [`VERSION`] of the package `name` of the run `run`, with
    /// `assembly` as the text of its assembly, as a source serves it: a zip
    /// of its manifest and that file, without a signature. Built here, so
    /// no binary is committed, and every sum a test holds a build to is
    /// computed from the bytes it serves.
    fn new(name: &str, run: &str, assembly: &str) -> Package {
        let id = format!("{name}.{run}");
        let files = [
            (format!("{id}.nuspec"), nuspec(&id)),
            (assembly_path(&id), assembly.to_string()),
        ];
        let mut archive = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, text) in &files {
            let options = zip::write::SimpleFileOptions::default();
            archive.start_file(name.as_str(), options).expect("zip");
            archive.write_all(text.as_bytes()).expect("zip");
        }
        Package {
            id,
            assembly: assembly.to_string(),
            nupkg: archive.finish().expect("zip").into_inner(),
        }
    }

    /// The line the consumer prints once Bazel built this package in.
    fn marker(&self) -> String {
        format!("OUT: {}", self.assembly)
    }

    /// Its id in lower case, as NuGet and the ruleset spell it in a path.
    fn lower(&self) -> String {
        self.id.to_lowercase()
    }

    /// Its purl, as `scan` names a package it found in NuGet's folder,
    /// where the directory of a package is its id in lower case.
    fn purl(&self) -> String {
        format!("pkg:nuget/{}@{VERSION}", self.lower())
    }

    /// What a lock holds as its `contentHash`: for a package without a
    /// signature, the sha512 of the file, in base64.
    fn content_hash(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(Sha512::digest(&self.nupkg))
    }

    /// The route of its file in the flat container the stand-in plays
    /// under `/<base>`.
    fn file(&self, base: &str) -> String {
        let lower = self.lower();
        format!("/{base}/{lower}/{VERSION}/{lower}.{VERSION}.nupkg")
    }

    /// Unpack it into NuGet's global packages folder of the machine whose
    /// .NET home is `home`, as `dotnet restore` leaves a package there: its
    /// files, the manifest under the id in lower case, the `.nupkg` itself
    /// with its hash beside it, and the record of the restore. No `dotnet`
    /// ran, and nothing is written into the checkout, where a restore also
    /// leaves the project's `obj` directory.
    fn restore_into(&self, home: &Path) {
        let lower = self.lower();
        let dir = packages_folder(home).join(&lower).join(VERSION);
        let leaf = format!("{lower}.{VERSION}.nupkg");
        let record = json!({
            "version": 2,
            "contentHash": self.content_hash(),
            "source": SOURCE,
        });
        let files = [
            (format!("{lower}.nuspec"), nuspec(&self.id).into_bytes()),
            (assembly_path(&self.id), self.assembly.clone().into_bytes()),
            (leaf.clone(), self.nupkg.clone()),
            (format!("{leaf}.sha512"), self.content_hash().into_bytes()),
            (
                ".nupkg.metadata".to_string(),
                serde_json::to_vec_pretty(&record).expect("a JSON document"),
            ),
        ];
        for (name, bytes) in files {
            let path = dir.join(name);
            std::fs::create_dir_all(path.parent().expect("a file path")).expect("create a folder");
            std::fs::write(&path, bytes).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        }
    }
}

/// NuGet's global packages folder of the machine whose .NET home is `home`,
/// at its default place.
fn packages_folder(home: &Path) -> PathBuf {
    home.join(".nuget").join("packages")
}

/// A file of the fixture's `common` directory, with the tag `run` where it
/// holds [`RUN`].
fn fixture_file(rel: &str, run: &str) -> String {
    let path = fixture_path(FIXTURE.dir).join("common").join(rel);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    assert!(text.contains(RUN), "{}: no {RUN}", path.display());
    text.replace(RUN, run)
}

/// A file of the fixture's `common` directory that names no package.
fn fixture_file_as_is(rel: &str) -> String {
    let path = fixture_path(FIXTURE.dir).join("common").join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The entry of a lock that resolves the package `id` to the file of
/// `content_hash`, laid out as `dotnet restore` writes it.
fn lock_entry(id: &str, content_hash: &str) -> String {
    format!(
        "      \"{id}\": {{\n        \"type\": \"Direct\",\n        \
         \"requested\": \"[{VERSION}, )\",\n        \"resolved\": \"{VERSION}\",\n        \
         \"contentHash\": \"{content_hash}\"\n      }}"
    )
}

/// The `contentHash` of each package in the fixture's own lock, which is
/// the sum of no file: sixty-four zero bytes.
fn placeholder() -> String {
    base64::engine::general_purpose::STANDARD.encode([0; 64])
}

/// The fixture's lock for the run `run`, with the `contentHash` of each of
/// `packages` in place of its placeholder.
fn lock_pinning(run: &str, packages: &[&Package]) -> String {
    let mut lock = fixture_file(LOCK, run);
    for package in packages {
        let unpinned = lock_entry(&package.id, &placeholder());
        let entries = lock.matches(&unpinned).count();
        assert_eq!(entries, 1, "{LOCK} of the fixture: not one\n{unpinned}");
        lock = lock.replace(&unpinned, &lock_entry(&package.id, &package.content_hash()));
    }
    lock
}

/// Make `cell` the checkout of the run `run`: every file that names a
/// package names the packages of the run, and the lock pins `upstream`,
/// the two packages nuget.org has for it.
fn check_out(cell: &Cell, run: &str, upstream: &[&Package]) {
    for rel in NAMING {
        let text = match rel {
            LOCK => lock_pinning(run, upstream),
            _ => fixture_file(rel, run),
        };
        cell.write(rel, text);
    }
}

/// One patch of the package, under an id that is new for every run, on a
/// Socket source of its own.
struct Patched {
    uuid: String,
    package: Package,
    /// The source, as host and path. As in production, the access token of
    /// the grant and the patch id are part of the path.
    feed: String,
}

impl Patched {
    fn new(run: &str) -> Patched {
        let uuid = uuid::Uuid::new_v4().to_string();
        let token = uuid::Uuid::new_v4().to_string();
        Patched {
            package: Package::new(NAME, run, &format!("PATCHED {uuid}")),
            feed: format!("{PATCH_HOST}/patch-registry/nuget/{token}/{uuid}"),
            uuid,
        }
    }

    /// The service index of the source: the URL hosted mode writes into
    /// `nuget.config`.
    fn index(&self) -> String {
        format!("https://{}/index.json", self.feed)
    }

    /// The route of `package` in the flat container of the source.
    fn file(&self, package: &Package) -> String {
        package.file(&format!("{}/flat", self.feed))
    }
}

/// A stand-in that holds `packages` as nuget.org's flat container does.
fn registry(packages: &[&Package]) -> StandIn {
    let standin = StandIn::start();
    for package in packages {
        standin.serve(5, &package.file(FLAT_CONTAINER), &package.nupkg);
    }
    standin
}

/// The Socket API on `standin` for `patch` of `upstream`, free for every
/// caller, and the Socket source of the patch: its service index, and
/// `served` as the file of the package. The grant names the sha512 of the
/// patch's own package, whatever is served. The source holds no other
/// package: a route nobody serves is a 404.
fn grant(standin: &StandIn, upstream: &Package, patch: &Patched, served: &[u8]) {
    grant_recorded(standin, patch, served, &record(upstream, patch));
}

/// The record of `patch`: the assembly of `upstream` becomes the one of the
/// patch.
fn record(upstream: &Package, patch: &Patched) -> Value {
    let package = &patch.package;
    json!({
        "uuid": patch.uuid,
        "purl": package.purl(),
        "publishedAt": "2026-01-01T00:00:00Z",
        "files": { assembly_path(&package.id): {
            "beforeHash": compute_git_sha256_from_bytes(upstream.assembly.as_bytes()),
            "afterHash": compute_git_sha256_from_bytes(package.assembly.as_bytes()),
        }},
        "vulnerabilities": { "GHSA-test-aaaa-bbbb": {
            "cves": ["CVE-2024-0001"], "summary": "s", "severity": "high", "description": "d",
        }},
        "description": "fixture",
        "license": "MIT",
        "tier": "free",
    })
}

/// [`grant`] of the patch's own package, with a record that carries both
/// assemblies: agent mode patches the copy in NuGet's folder from the
/// record and asks for no package.
fn grant_installed(standin: &StandIn, upstream: &Package, patch: &Patched) {
    let b64 = |text: &str| base64::engine::general_purpose::STANDARD.encode(text);
    let mut record = record(upstream, patch);
    let file = &mut record["files"][assembly_path(&patch.package.id)];
    file["blobContent"] = b64(&patch.package.assembly).into();
    file["beforeBlobContent"] = b64(&upstream.assembly).into();
    grant_recorded(standin, patch, &patch.package.nupkg, &record);
}

/// [`grant`] with `record` as the record of the patch.
fn grant_recorded(standin: &StandIn, patch: &Patched, served: &[u8], record: &Value) {
    let package = &patch.package;
    // A route starts with the `/` that ends `https://`.
    let url = format!("https:/{}", patch.file(package));
    let reference = json!({
        "status": "granted",
        "url": url,
        "purl": package.purl(),
        "artifacts": [{
            "kind": "tarball",
            "url": url,
            "integrity": { "sha512": format!("sha512-{}", package.content_hash()) },
        }],
        "registryOverride": {
            "kind": "nuget-v3",
            "indexUrl": patch.index(),
            "identifiers": {
                "name": package.id,
                "version": VERSION,
                "nugetIdLower": package.lower(),
                "nugetVersionNorm": VERSION,
            },
        },
    });
    let granted = Patch {
        purl: package.purl(),
        uuid: patch.uuid.clone(),
        reference,
    };
    standin.api(&[granted]);
    // Priority 1: ahead of the shared API mock's patch record, which names
    // a file no NuGet package has. `vex` holds the package in NuGet's
    // folder to the hashes of this one.
    let record = serde_json::to_vec(record).expect("a JSON document");
    let record_route = format!("/v0/orgs/{ORG}/patches/view/{}", patch.uuid);
    standin.serve(1, &record_route, &record);
    let index = json!({ "version": "3.0.0", "resources": [{
        "@id": format!("https://{}/flat/", patch.feed),
        "@type": "PackageBaseAddress/3.0.0",
    }] });
    let index = serde_json::to_vec(&index).expect("a JSON document");
    standin.serve(5, &format!("/{}/index.json", patch.feed), &index);
    standin.serve(5, &patch.file(package), served);
}

/// The downloader config of the flow, for [`Cell::route_downloads`]: Bazel
/// fetches every URL of nuget.org's API host and of the patch host from the
/// stand-in at `origin`, under the route prefix of the host. A URL of
/// either that no rule rewrote is refused, and so is every other host of
/// nuget.org, so no download of Bazel's reaches the real ones. Every other
/// download is left alone.
fn downloads(origin: &str) -> Vec<String> {
    vec![
        rewrite(&format!("{NUGET_ORG}/"), origin),
        rewrite(&format!("{PATCH_HOST}/"), origin),
        "block nuget.org".to_string(),
        format!("block {PATCH_HOST}"),
    ]
}

/// `socket-patch <args>` in `cell`, on the machine whose .NET home is
/// `home`, with `standin` as the Socket API and as the registry `rollback`
/// reads the upstream package from. Both variables of the .NET home are
/// set, so that neither a `NUGET_PACKAGES` nor a `DOTNET_CLI_HOME` of the
/// caller's shell moves the folder or adds a user-level NuGet config.
fn socket_patch(cell: &Cell, standin: &StandIn, home: &Path, args: &[&str]) -> Ran {
    on_machine(standin, home, |api, env| cell.socket_patch(api, args, env))
}

/// What `run` gives for the Socket API and the environment of
/// [`socket_patch`].
fn on_machine<T>(standin: &StandIn, home: &Path, run: impl Fn(&str, &[(&str, &str)]) -> T) -> T {
    let origin = standin.origin();
    let upstream = format!("{origin}/{NUGET_ORG}");
    let packages = packages_folder(home);
    let (home, packages) = (home.to_string_lossy(), packages.to_string_lossy());
    let env = [
        ("SOCKET_NUGET_URL", upstream.as_str()),
        ("DOTNET_CLI_HOME", home.as_ref()),
        ("NUGET_PACKAGES", packages.as_ref()),
    ];
    run(&origin, &env)
}

/// A text file of a tree.
fn text(tree: &Tree, rel: &str) -> String {
    String::from_utf8(tree[rel].clone()).expect("a text file")
}

/// The build of a CI that holds Bazel's lock frozen, right after the
/// `socket-patch` command `after` and before any build that may update the
/// lock: Bazel must refuse it, because the command changed the two files
/// the hub reads and the lock records what the hub made of them. The
/// harness names `--lockfile_mode=update` on every command; Bazel takes the
/// last one, so the `error` passed here is the one in force.
fn frozen_build_fails(cell: &Cell, after: &str) {
    let build = cell.bazel("build", &["--lockfile_mode=error", CONSUMER]);
    let stale = "MODULE.bazel.lock is no longer up-to-date";
    assert!(
        !build.ok() && build.stderr().contains(stale),
        "{}: right after `{after}`, a `--lockfile_mode=error` build on Bazel {} must fail on the \
         stale lock: {BAZEL_LOCK} records the two files the command rewrote, so a user has to run \
         a build that may update it, or `bazel mod deps --lockfile_mode=update`, and commit the \
         lock before a CI with a frozen lock passes.\n{}",
        cell.test,
        cell.release(),
        build.dump()
    );
}

/// The flow of the module docs.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn hosted_from_lock() {
    let test = "nuget::hosted_from_lock";
    let started = Instant::now();
    let Some(mut cell) = Cell::open(test, &FIXTURE) else {
        return;
    };
    let release = cell.release().to_string();

    // The packages of this run: the two nuget.org has, and one patch of the
    // first. Each id ends in the tag of the run, and the assembly of each
    // build of the package holds an id that is new for every run.
    let run = format!("R{}", uuid::Uuid::new_v4().simple());
    let upstream = Package::new(NAME, &run, &format!("PRISTINE {run}"));
    let neighbour = Package::new(NEIGHBOUR, &run, "NEIGHBOUR");
    let patch = Patched::new(&run);
    let (purl, unpatched, patched) = (upstream.purl(), upstream.marker(), patch.package.marker());
    let one = |action: &str, code: &str| [(purl.clone(), action.to_string(), code.to_string())];

    let standin = registry(&[&neighbour, &upstream]);
    let origin = standin.origin();
    grant(&standin, &upstream, &patch, &patch.package.nupkg);
    cell.route_downloads(&downloads(&origin));
    check_out(&cell, &run, &[&neighbour, &upstream]);
    let (upstream_route, patched_route) =
        (upstream.file(FLAT_CONTAINER), patch.file(&patch.package));

    // The .NET homes of three machines, outside every checkout: one where
    // nobody ran `dotnet restore`, the one that restored the project, and
    // the second machine of (e).
    let machines = tempfile::Builder::new()
        .prefix("sp-bazel-nuget-")
        .tempdir()
        .expect("create the machines");
    let [bare, restored, second_home] =
        ["bare", "restored", "second"].map(|name| machines.path().join(name));

    // (a) The unpatched build, with the upstream package from the stand-in.
    let before = cell.builds_unpatched(&unpatched);
    assert!(
        standin.asked(&upstream_route) > 0,
        "{test}: the build did not fetch the upstream package from the stand-in"
    );
    // KNOWN GAP: where NuGet's folder holds nothing, as on a runner that
    // only ever ran Bazel, hosted mode does nothing: the scan finds no
    // package, says so with exit 0, and writes no file. A scan that read
    // the packages out of `packages.lock.json` would pin here as in (b),
    // and (b) would need no staged folder.
    let scan = socket_patch(&cell, &standin, &bare, &SCAN);
    let said = &scan.dump;
    assert_eq!(scan.code, 0, "{test}: {said}");
    assert_eq!(scan.envelope["status"], "success", "{test}: {said}");
    assert_eq!(scan.envelope["scannedPackages"], 0, "{test}: {said}");
    assert_eq!(scan.envelope["summary"]["applied"], 0, "{test}: {said}");
    assert_eq!(changed(&before, &cell.tree()), NOTHING, "{test}: {said}");

    // (b) The one command of hosted mode, where the folder holds the two
    // packages. It rewrites those two files and no other: the Socket source
    // is the first one the hub asks, and the lock pins the patched package.
    for package in [&neighbour, &upstream] {
        package.restore_into(&restored);
    }
    let scan = socket_patch(&cell, &standin, &restored, &SCAN);
    let said = &scan.dump;
    let pinned = cell.pinned_by(&scan, &purl, &patch.uuid, &before, &[CONFIG, LOCK]);
    assert_eq!(scan.envelope["scannedPackages"], 2, "{test}: {said}");
    let config = text(&pinned, CONFIG);
    let sources = format!(
        "  <packageSources>\n    <clear />\n    <add key=\"socket-patch-{}\" value=\"{}\" />\n    \
         <add key=\"nuget.org\" value=\"{SOURCE}\" />\n  </packageSources>\n",
        patch.uuid,
        patch.index()
    );
    assert!(config.contains(&sources), "{test}: {CONFIG}:\n{config}");
    assert_eq!(
        text(&pinned, LOCK),
        lock_pinning(&run, &[&neighbour, &patch.package]),
        "{test}: {LOCK}"
    );
    // The one warning is about NuGet's folder, which no build here reads.
    assert_eq!(
        codes_in(&scan.envelope["warnings"]),
        ["redirect_nuget_stale_global_package"],
        "{test}: {said}"
    );
    assert_eq!(standin.asked(&patched_route), 0, "{test}: {said}");
    // The scan left Bazel's lock as it was, so a frozen lock fails here.
    frozen_build_fails(&cell, "scan --mode hosted");

    // (c) The build of (a) and no other step: patched, from the patch
    // host. The hub asked that host for the other package as well.
    // KNOWN GAP: Bazel printed the URL it got a 404 for, access token
    // included. A fix (a source without the token in its URL, or no
    // request for a package the source does not hold) would turn the
    // second half of the assertion below around: the build prints no URL
    // of the source.
    let build = cell.bazel("build", &[CONSUMER]);
    assert!(build.ok(), "{test}: {}", build.dump());
    let missed = patch.file(&neighbour);
    assert!(
        standin.asked(&missed) > 0
            && build
                .stderr()
                .contains(&format!("WARNING: Download from {origin}{missed} failed")),
        "{test}: the hub did not ask the Socket source for {}, or Bazel did not warn with its \
         URL:\n{}",
        neighbour.id,
        build.dump()
    );
    assert!(
        standin.asked(&patched_route) > 0,
        "{test}: the patched build did not fetch the package from the stand-in patch host"
    );
    // Bazel changed no file of the checkout but its own lock. From here on
    // the checkout stands: the build prints the patched marker and changes
    // no file, and Bazel's lock holds when Bazel may not update it.
    let built = cell.tree();
    assert_eq!(changed(&pinned, &built), [BAZEL_LOCK], "{test}");
    cell.builds_patched(&built, &patched);

    // The same command once more, as a pipeline runs it: applied again,
    // and no file rewritten.
    let again = socket_patch(&cell, &standin, &restored, &SCAN);
    let said = &again.dump;
    assert_eq!(again.code, 0, "{test}: {said}");
    assert_eq!(again.envelope["status"], "success", "{test}: {said}");
    let applied = one("applied", "");
    assert_eq!(event_triples(&again.envelope), applied, "{test}: {said}");
    let rewritten = &again.envelope["redirect"]["rewrittenFiles"];
    assert_eq!(*rewritten, json!([]), "{test}: {said}");
    // `vex` on the machine that ran the scan. KNOWN GAP: it reads the
    // package in NuGet's folder, finds the unpatched one, attests nothing
    // and writes no document, while the build is the patched one. A fix
    // would make this the `vex` of the next block: exit 0, `verified`,
    // and the document.
    let document = machines.path().join("vex.json");
    let output = document.to_string_lossy();
    let vex = socket_patch(&cell, &standin, &restored, &["vex", "--output", &output]);
    let said = &vex.dump;
    assert_eq!(vex.code, 1, "{test}: {said}");
    let withheld = one("skipped", "not_applied");
    assert_eq!(event_triples(&vex.envelope), withheld, "{test}: {said}");
    assert!(!document.exists(), "{test}: {said}");
    // `vex` where NuGet's folder holds nothing: it attests the package
    // from the pin in the two files.
    let vex = socket_patch(&cell, &standin, &bare, &["vex", "--output", &output]);
    let said = &vex.dump;
    assert_eq!(vex.code, 0, "{test}: {said}");
    let attested = one("verified", "");
    assert_eq!(event_triples(&vex.envelope), attested, "{test}: {said}");
    let written = std::fs::read_to_string(&document).unwrap_or_default();
    // With its closing quote, as the document writes `"@id": "<purl>"`.
    let names = written.contains(&format!("\"{purl}\""));
    assert!(names, "{test}: {said}\n{written}");
    // None of those three commands changed a file, so the build is the
    // one above.
    assert_eq!(changed(&built, &cell.tree()), NOTHING, "{test}");

    // (d) The undo: the two files are the ones of before at once, and
    // Bazel's lock is still the one of the patched build, so a frozen lock
    // fails again. The next build prints the unpatched marker and puts the
    // lock back. The step is written out and not `Cell::undone`, which
    // expects every file back before that build: here it is that build
    // which brings back Bazel's lock.
    let undo = socket_patch(&cell, &standin, &restored, &["rollback", "--yes"]);
    let said = &undo.dump;
    assert_eq!(undo.code, 0, "{test}: {said}");
    assert_eq!(undo.envelope["summary"]["rolledBack"], 1, "{test}: {said}");
    let undone = cell.tree();
    assert_eq!(changed(&built, &undone), [CONFIG, LOCK], "{test}: {said}");
    assert_eq!(changed(&before, &undone), [BAZEL_LOCK], "{test}: {said}");
    frozen_build_fails(&cell, "rollback");
    cell.builds(&unpatched);
    assert_eq!(changed(&before, &cell.tree()), NOTHING, "{test}");

    // (e) A second machine, with a patch whose package no machine has
    // fetched: another service grants it, and its host serves other bytes
    // than the grant pins, still a package of that name and version.
    let mut twin = cell.twin();
    let second = Patched::new(&run);
    let tampered = Package::new(NAME, &run, "TAMPERED");
    let rogue = registry(&[&neighbour, &upstream]);
    grant(&rogue, &upstream, &second, &tampered.nupkg);
    twin.route_downloads(&downloads(&rogue.origin()));
    for package in [&neighbour, &upstream] {
        package.restore_into(&second_home);
    }
    let scan = socket_patch(&twin, &rogue, &second_home, &SCAN);
    let said = &scan.dump;
    assert_eq!(scan.code, 0, "{test}: {said}");
    assert_eq!(scan.envelope["summary"]["applied"], 1, "{test}: {said}");
    let repinned = twin.tree();
    let second_route = second.file(&second.package);

    // With the Bazel lock of before, which the scan left stale: the hub
    // asks the sources again, and holds the file to the lock's
    // `contentHash`. It does not go to nuget.org for the package.
    let build = twin.bazel("build", &[CONSUMER]);
    assert!(
        !build.ok(),
        "{test}: the tampered package built:\n{}",
        build.dump()
    );
    let refusal = format!(
        "{} {VERSION}: the downloaded package does not match its contentHash in {LOCK}",
        upstream.id
    );
    assert!(
        build.stderr().contains(&refusal),
        "{test}: the build did not fail on the contentHash of the granted package:\n{}",
        build.dump()
    );
    let fetches = rogue.asked(&second_route);
    assert!(
        fetches > 0,
        "{test}: the patch host was not asked, so the failed build proves nothing"
    );
    assert_eq!(
        rogue.asked(&upstream_route),
        0,
        "{test}: the build went to the upstream package"
    );

    // With a Bazel lock that pins the granted package: the lock of the
    // patched build of (c), with the values of the second patch in place of
    // the first's. Bazel takes it as current (the `error` named last is the
    // mode in force, as in `frozen_build_fails`), asks for the package,
    // which no cache holds, and refuses the file over its sha256; then the
    // hub's next source, nuget.org, whose copy it refuses the same way.
    let mut lock = text(&built, BAZEL_LOCK);
    for (first, other) in [
        (patch.feed.clone(), second.feed.clone()),
        (
            sha256_hex(&patch.package.nupkg),
            sha256_hex(&second.package.nupkg),
        ),
        (sha256_hex(&pinned[CONFIG]), sha256_hex(&repinned[CONFIG])),
        (sha256_hex(&pinned[LOCK]), sha256_hex(&repinned[LOCK])),
    ] {
        let recorded = lock.contains(&first);
        assert!(recorded, "{test}: {BAZEL_LOCK} does not hold {first}");
        lock = lock.replace(&first, &other);
    }
    twin.write(BAZEL_LOCK, lock);
    let build = twin.bazel("build", &["--lockfile_mode=error", CONSUMER]);
    assert!(
        !build.ok(),
        "{test}: the tampered package built:\n{}",
        build.dump()
    );
    let wanted = sha256_hex(&second.package.nupkg);
    for served in [&tampered, &upstream] {
        let refusal = format!(
            "Checksum was {} but wanted {wanted}",
            sha256_hex(&served.nupkg)
        );
        assert!(
            build.stderr().contains(&refusal),
            "{test}: the build did not fail with {refusal:?}:\n{}",
            build.dump()
        );
    }
    assert!(
        rogue.asked(&second_route) > fetches && rogue.asked(&upstream_route) > 0,
        "{test}: the patch host and nuget.org were not both asked, so the failed build proves \
         nothing"
    );

    println!(
        "{test}: Bazel {release} built {patched:?} from {} after `scan --mode hosted`, and \
         rewrote {BAZEL_LOCK} itself; a `--lockfile_mode=error` build right after the scan, and \
         again right after `rollback`, failed on the stale lock; a scan where NuGet's folder \
         holds nothing found no package; a second scan reported the patch applied again; `vex` \
         attested the package where NuGet's folder holds nothing and withheld it (not_applied) \
         where the folder holds the unpatched copy; `rollback` restored {CONFIG} and {LOCK} at \
         once, and the next build printed {unpatched:?} and left all {} files as before; other \
         bytes at the patch host failed a second machine's build over the contentHash of {LOCK}, \
         and over the sha256 in {BAZEL_LOCK}; the stand-in answered {} requests for the upstream \
         package and {} for the patched one; {:?}",
        patch.index(),
        before.len(),
        standin.asked(&upstream_route),
        standin.asked(&patched_route),
        started.elapsed()
    );
}

/// The codes of the warnings with which hosted mode says that it wrote
/// nothing for a package: the hub does not read `nuget.config`, or it has
/// the package from a lock that the run does not re-pin.
const WITHHELD: &str = "redirect_bazel_nuget_config_undeclared";
const NOT_REPINNED: &str = "redirect_bazel_nuget_lock_not_repinned";

/// For a finished `scan --mode hosted --yes` in a checkout whose tag names
/// no `nuget_config`: it passed and reports the package `purl` as skipped
/// and no file as rewritten, and its one warning is about `package`, under
/// the name the purl has for it. The warning names the tag by its file and
/// line, and says to put on it the attribute that [`NAMES_CONFIG`] is in
/// the fixture; it does not send the user to vendored mode, which no
/// Bazel build of NuGet packages is known to take. Gives the warning's
/// text.
fn withheld(test: &str, scan: &Ran, package: &Package, purl: &str) -> String {
    let said = &scan.dump;
    assert_eq!(scan.code, 0, "{test}: {said}");
    assert_eq!(scan.envelope["status"], "success", "{test}: {said}");
    assert_eq!(scan.envelope["summary"]["applied"], 0, "{test}: {said}");
    let skipped = [(
        purl.to_string(),
        "skipped".to_string(),
        "redirect_unconfirmed".to_string(),
    )];
    assert_eq!(event_triples(&scan.envelope), skipped, "{test}: {said}");
    let rewritten = &scan.envelope["redirect"]["rewrittenFiles"];
    assert_eq!(*rewritten, json!([]), "{test}: {said}");
    let warnings = &scan.envelope["warnings"];
    assert_eq!(codes_in(warnings), [WITHHELD], "{test}: {said}");
    let detail = warnings[0]["detail"].as_str().unwrap_or_default();
    let starts = format!(
        "{}@{VERSION}: {MODULE}:9: this `nuget.from_lock` names no `nuget_config`, so \
         rules_csharp does not read {CONFIG}",
        package.lower()
    );
    assert!(detail.starts_with(&starts), "{test}: {detail}");
    let attribute = NAMES_CONFIG.trim().trim_end_matches(',');
    let way = format!("Put `{attribute}` on that tag and run this command again");
    assert!(detail.contains(&way), "{test}: {detail}");
    assert!(!detail.contains("vendored"), "{test}: {detail}");
    detail.to_string()
}

/// The flow of a tag that names no `nuget_config`, in a checkout without a
/// `nuget.config`, on the machine that restored the project.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn hosted_no_config() {
    let test = "nuget::hosted_no_config";
    let started = Instant::now();
    let Some(mut cell) = Cell::open(test, &FIXTURE) else {
        return;
    };
    let release = cell.release().to_string();

    let run = format!("R{}", uuid::Uuid::new_v4().simple());
    let upstream = Package::new(NAME, &run, &format!("PRISTINE {run}"));
    let neighbour = Package::new(NEIGHBOUR, &run, "NEIGHBOUR");
    let patch = Patched::new(&run);
    let (purl, unpatched, patched) = (upstream.purl(), upstream.marker(), patch.package.marker());
    let standin = registry(&[&neighbour, &upstream]);
    grant(&standin, &upstream, &patch, &patch.package.nupkg);
    cell.route_downloads(&downloads(&standin.origin()));
    check_out(&cell, &run, &[&neighbour, &upstream]);
    // The fixture's tag without the line that names its `nuget.config`,
    // and no such file.
    let module = std::fs::read_to_string(cell.path(MODULE)).expect(MODULE);
    cell.write(MODULE, module.replace(NAMES_CONFIG, ""));
    std::fs::remove_file(cell.path(CONFIG)).expect("remove nuget.config");
    let home = tempfile::Builder::new()
        .prefix("sp-bazel-nuget-")
        .tempdir()
        .expect("create the .NET home");
    for package in [&neighbour, &upstream] {
        package.restore_into(home.path());
    }

    // The unpatched build: the hub has nuget.org alone.
    let before = cell.builds_unpatched(&unpatched);
    assert!(!before.contains_key(CONFIG), "{test}: a {CONFIG} is left");

    // The scan writes nothing: a lock re-pinned to the patched package
    // would fail the next build, because the hub would still download the
    // upstream one. So the build passes as before, and changes no file.
    let scan = socket_patch(&cell, &standin, home.path(), &SCAN);
    withheld(test, &scan, &upstream, &purl);
    assert_eq!(changed(&before, &cell.tree()), NOTHING, "{test}");
    cell.builds(&unpatched);
    assert_eq!(changed(&before, &cell.tree()), NOTHING, "{test}");

    // What the warning says to do, and no other step: the attribute on the
    // tag, and the same command. It creates the file the tag now names and
    // re-pins the lock, and the build is the patched one, from the Socket
    // source.
    cell.write(MODULE, &module);
    let wired = cell.tree();
    let scan = socket_patch(&cell, &standin, home.path(), &SCAN);
    let pinned = cell.pinned_by(&scan, &purl, &patch.uuid, &wired, &[CONFIG, LOCK]);
    assert_eq!(
        text(&pinned, LOCK),
        lock_pinning(&run, &[&neighbour, &patch.package]),
        "{test}: {LOCK}"
    );
    cell.builds(&patched);
    assert_eq!(changed(&pinned, &cell.tree()), [BAZEL_LOCK], "{test}");
    let fetches = standin.asked(&patch.file(&patch.package));
    assert!(fetches > 0, "{test}: the Socket source was not asked");

    println!(
        "{test}: on Bazel {release}, `scan --mode hosted` wrote nothing for a tag that names no \
         nuget_config and warned ({WITHHELD}), and the build still printed {unpatched:?}; with \
         the attribute on the tag the same scan wrote {CONFIG} and {LOCK}, and the build printed \
         {patched:?} from the Socket source ({fetches} requests for the package); {:?}",
        started.elapsed()
    );
}

/// `scan --mode vendored --yes <more>` in `cell`, on the machine whose .NET
/// home is `home`. The grant names the patched package by its URL on the
/// patch host, and vendored mode downloads it itself: `--patch-server-url`
/// sends that one download to `standin`, which serves the package there
/// under the path of that URL (`service` of [`service_route`]).
fn vendored_scan(cell: &Cell, standin: &StandIn, home: &Path, more: &[&str]) -> Ran {
    let origin = standin.origin();
    let args = [&VENDORED[..], &["--patch-server-url", &origin], more].concat();
    socket_patch(cell, standin, home, &args)
}

/// Has `standin` serve the package of `patch` to vendored mode, and gives
/// the route: the path of the URL the grant names, without the prefix of
/// the patch host that a download of Bazel's carries on the stand-in.
fn service_route(standin: &StandIn, patch: &Patched) -> String {
    let route = patch.file(&patch.package);
    let service = route
        .strip_prefix(&format!("/{PATCH_HOST}"))
        .expect("a route of the patch host");
    standin.serve(5, service, &patch.package.nupkg);
    service.to_string()
}

/// Where vendored mode keeps what it wrote for `patch`: the folder of the
/// patch under the checkout's `.socket/vendor`.
fn vendor_dir(patch: &Patched) -> String {
    format!(".socket/vendor/nuget/{}", patch.uuid)
}

/// Where vendored mode keeps the package of `patch` for a hub, below
/// [`vendor_dir`]: the path at which a feed of rules_csharp has a package.
fn hub_copy(patch: &Patched) -> String {
    let lower = patch.package.lower();
    format!(
        "{}/{lower}/{VERSION}/{lower}.{VERSION}.nupkg",
        vendor_dir(patch)
    )
}

/// The block vendored mode keeps at the end of the fixture's `MODULE.bazel`
/// for the folder `dir` of a patch: the hub's own extension and lock, and
/// as feeds that folder, which Bazel reads from the root of the workspace,
/// and then the one source of the fixture's `nuget.config`.
fn block(dir: &str) -> String {
    format!(
        "# >>> socket-patch: NuGet patches for Bazel (managed block: socket-patch writes and \
         removes it) >>>\n\
         socket_patch_nuget = use_extension(\"@rules_csharp//csharp:extensions.bzl\", \"nuget\")\n\
         socket_patch_nuget.from_lock(\n    feeds = [\n        \"file:{dir}\",\n        \
         \"{SOURCE}\",\n    ],\n    packages_lock_json = \"//:{LOCK}\",\n)\n\
         # <<< socket-patch <<<\n"
    )
}

/// The code with which vendored mode declines a package of a hub, where it
/// cannot show that its block works, and the file that names the Bazel
/// release of a checkout.
const DECLINED: &str = "vendor_nuget_bazel_workspace";
const BAZEL_VERSION: &str = ".bazelversion";

/// For a finished vendored command that declined the package `purl`: it
/// failed with exit 1, its one event is the refusal, and the detail says
/// `why`, names hosted mode and the switch.
fn declined(test: &str, ran: &Ran, purl: &str, why: &str) {
    let said = &ran.dump;
    assert_eq!(ran.code, 1, "{test}: {said}");
    assert_eq!(ran.envelope["status"], "partialFailure", "{test}: {said}");
    let refusal = [(purl.to_string(), "failed".to_string(), DECLINED.to_string())];
    assert_eq!(event_triples(&ran.envelope), refusal, "{test}: {said}");
    let event = &ran.envelope["events"][0];
    let detail = event["error"].as_str().or(event["reason"].as_str());
    let detail = detail.unwrap_or_default();
    for part in [why, "`--mode hosted`", "`--allow-vendored-in-bazel`"] {
        assert!(detail.contains(part), "{test}: no {part:?} in {detail:?}");
    }
}

/// Vendored mode in the fixture's workspace, on the machine that restored
/// the project.
///
/// - (a) The unpatched build. The checkout names no Bazel release, so
///   `scan --mode vendored --yes` declines the package: nothing is
///   downloaded or written, and the build stays the one of before.
/// - (b) With the release in `.bazelversion`, the same command downloads
///   the patched package from the patch service once and keeps it where a
///   feed of the hub has a package, names that folder in `nuget.config`,
///   re-pins the lock, and appends its block to `MODULE.bazel`. `vendor
///   --check` passes, `vex` attests the package, and `bazel query //...`
///   lists what it listed. Bazel's own lock is stale, as after a hosted
///   scan: a frozen lock fails until a build has updated it.
/// - (c) The build of (a) prints the patched marker, from the committed
///   copy: Bazel asks no host for the package. Then on a second machine,
///   with the stand-in stopped, a new output base and the package in no
///   repository cache, the build prints it again.
/// - (d) On a third machine, one byte of the committed package is another:
///   `vendor --check` fails, and so does the build, over the sha256 that
///   Bazel's lock pins.
/// - (e) `vendor --revert` puts every file back but Bazel's own lock, and
///   the next build prints the unpatched marker and writes the lock of
///   before.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn vendored_from_lock() {
    let test = "nuget::vendored_from_lock";
    let started = Instant::now();
    let Some(mut cell) = Cell::open(test, &FIXTURE) else {
        return;
    };
    let release = cell.release().to_string();

    let run = format!("R{}", uuid::Uuid::new_v4().simple());
    let upstream = Package::new(NAME, &run, &format!("PRISTINE {run}"));
    let neighbour = Package::new(NEIGHBOUR, &run, "NEIGHBOUR");
    let patch = Patched::new(&run);
    let (purl, unpatched, patched) = (upstream.purl(), upstream.marker(), patch.package.marker());
    let standin = registry(&[&neighbour, &upstream]);
    grant(&standin, &upstream, &patch, &patch.package.nupkg);
    let service = service_route(&standin, &patch);
    cell.route_downloads(&downloads(&standin.origin()));
    check_out(&cell, &run, &[&neighbour, &upstream]);
    let home = tempfile::Builder::new()
        .prefix("sp-bazel-nuget-")
        .tempdir()
        .expect("create the .NET home");
    for package in [&neighbour, &upstream] {
        package.restore_into(home.path());
    }
    let listing = |cell: &Cell| {
        let query = cell.bazel("query", &["//..."]);
        assert!(query.ok(), "{test}: {}", query.dump());
        query.stdout()
    };

    // (a) The unpatched build. No file of the checkout names the Bazel
    // release that builds it, and the block is written for the releases it
    // was built on alone: the command declines, with nothing downloaded
    // and nothing written, and the build passes on the upstream package.
    let unnamed = cell.builds_unpatched(&unpatched);
    let scan = vendored_scan(&cell, &standin, home.path(), &[]);
    let no_release = "no file of the checkout names the Bazel release that builds it";
    declined(test, &scan, &purl, no_release);
    assert_eq!(standin.asked(&service), 0, "{test}: {}", scan.dump);
    assert_eq!(changed(&unnamed, &cell.tree()), NOTHING, "{test}");
    cell.builds_patched(&unnamed, &unpatched);

    // (b) The checkout names its release, as a launcher reads it.
    cell.write(BAZEL_VERSION, format!("{release}\n"));
    let before = cell.tree();
    let targets = listing(&cell);
    let scan = vendored_scan(&cell, &standin, home.path(), &[]);
    let said = &scan.dump;
    assert_eq!(scan.code, 0, "{test}: {said}");
    assert_eq!(scan.envelope["status"], "success", "{test}: {said}");
    assert_eq!(scan.envelope["summary"]["applied"], 1, "{test}: {said}");
    let event = |action: &str, code: &str| (purl.clone(), action.to_string(), code.to_string());
    let events = [
        event("downloaded", ""),
        event("applied", ""),
        event("skipped", "vendor_prebuilt_downloaded"),
        // NuGet's folder holds the unpatched copy, which no build here reads.
        event("skipped", "vendor_nuget_stale_global_package"),
    ];
    assert_eq!(event_triples(&scan.envelope), events, "{test}: {said}");
    assert_eq!(standin.asked(&service), 1, "{test}: {said}");
    let vendored = cell.tree();
    let (dir, copy) = (vendor_dir(&patch), hub_copy(&patch));
    let mut written = vec![
        format!("{dir}/.gitignore"),
        format!("{dir}/socket-patch.vendor.json"),
        copy.clone(),
        ".socket/vendor/state.json".to_string(),
        MODULE.to_string(),
        CONFIG.to_string(),
        LOCK.to_string(),
    ];
    written.sort();
    assert_eq!(changed(&before, &vendored), written, "{test}: {said}");
    assert_eq!(vendored[&copy], patch.package.nupkg, "{test}: {copy}");
    // The config names the folder of the package, where NuGet finds it;
    // the block names the folder of the patch, below which the hub does.
    let folder = copy.rsplit_once('/').expect("a path").0;
    let source = format!(
        "    <add key=\"socket-patch-{}\" value=\"{folder}\" />\n",
        patch.uuid
    );
    let config = text(&vendored, CONFIG);
    assert!(config.contains(&source), "{test}: {CONFIG}:\n{config}");
    assert_eq!(
        text(&vendored, LOCK),
        lock_pinning(&run, &[&neighbour, &patch.package]),
        "{test}: {LOCK}"
    );
    let appended = format!("{}\n{}", text(&before, MODULE), block(&dir));
    assert_eq!(text(&vendored, MODULE), appended, "{test}: {MODULE}");
    // `vendor --check` and `vex` see the package as any vendored one, and
    // Bazel sees no package in the folder.
    let check = socket_patch(&cell, &standin, home.path(), &["vendor", "--check"]);
    assert_eq!(check.code, 0, "{test}: {}", check.dump);
    let verified = [event("verified", "vendor_check_ok")];
    assert_eq!(event_triples(&check.envelope), verified, "{}", check.dump);
    let document = cell.document("vendored");
    let output = document.to_string_lossy();
    let vex = socket_patch(&cell, &standin, home.path(), &["vex", "--output", &output]);
    assert_eq!(vex.code, 0, "{test}: {}", vex.dump);
    let attested = [event("verified", "")];
    assert_eq!(event_triples(&vex.envelope), attested, "{}", vex.dump);
    // With its closing quote, as the document writes `"@id": "<purl>"`.
    let written = std::fs::read_to_string(&document).unwrap_or_default();
    let names = written.contains(&format!("\"{purl}\""));
    assert!(names, "{test}: {}\n{written}", vex.dump);
    assert_eq!(listing(&cell), targets, "{test}: `bazel query //...`");
    assert_eq!(changed(&vendored, &cell.tree()), NOTHING, "{test}");
    frozen_build_fails(&cell, "scan --mode vendored");

    // (c) The build of (a) and no other step: patched, from the committed
    // copy. Bazel asked the folder for the other package of the lock as
    // well, warned that it is not there, and took it from nuget.org as
    // before. It rewrote its own lock and no other file.
    let build = cell.bazel("build", &[CONSUMER]);
    assert!(build.ok(), "{test}: {}", build.dump());
    // A line of Bazel's is compared without white space, here and below:
    // nothing says where a tool breaks a long line.
    let squeezed = |text: &str| text.split_whitespace().collect::<String>();
    let missed = format!("WARNING: Download from file:{dir}/{}/", neighbour.lower());
    assert!(
        squeezed(&build.stderr()).contains(&squeezed(&missed)),
        "{test}: no {missed:?}:\n{}",
        build.dump()
    );
    let built = cell.tree();
    assert_eq!(changed(&vendored, &built), [BAZEL_LOCK], "{test}");
    cell.builds_patched(&built, &patched);
    let patched_route = patch.file(&patch.package);
    let asked = (standin.asked(&service), standin.asked(&patched_route));
    assert_eq!(asked, (1, 0), "{test}: Bazel asked a host for the package");

    // A second machine, with no host to ask: the stand-in is stopped, the
    // output base is new, and the repository cache, which held the package
    // since the build above, holds it no more.
    let sum = sha256_hex(&patch.package.nupkg);
    assert!(cell.uncache(&sum), "{test}: the cache did not hold {sum}");
    drop(standin);
    let offline = cell.twin();
    offline.builds(&patched);
    assert_eq!(changed(&built, &offline.tree()), NOTHING, "{test}");

    // (d) A third machine, where one byte of the committed package is
    // another: `vendor --check` fails, and the build fails over the sha256
    // that Bazel's lock pins. The changed bytes are never built.
    assert!(
        offline.uncache(&sum),
        "{test}: the cache did not hold {sum}"
    );
    let tampered = offline.twin();
    let mut bytes = patch.package.nupkg.clone();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x01;
    tampered.write(&copy, &bytes);
    let check = tampered.socket_patch("http://127.0.0.1:9", &["vendor", "--check"], &[]);
    assert_eq!(check.code, 1, "{test}: {}", check.dump);
    let failed = [event("failed", "vendor_check_failed")];
    assert_eq!(event_triples(&check.envelope), failed, "{}", check.dump);
    let build = tampered.bazel("build", &[CONSUMER]);
    let refusal = format!("Checksum was {} but wanted {sum}", sha256_hex(&bytes));
    assert!(
        !build.ok() && squeezed(&build.stderr()).contains(&squeezed(&refusal)),
        "{test}: the changed package did not fail the build with {refusal:?}:\n{}",
        build.dump()
    );
    drop(tampered);
    drop(offline);

    // (e) The undo, with a registry to ask again: every file of the
    // checkout is the one of before but Bazel's own lock, which the next
    // build puts back with the unpatched marker.
    let standin = registry(&[&neighbour, &upstream]);
    cell.route_downloads(&downloads(&standin.origin()));
    let undo = socket_patch(&cell, &standin, home.path(), &["vendor", "--revert"]);
    let said = &undo.dump;
    assert_eq!(undo.code, 0, "{test}: {said}");
    assert_eq!(undo.envelope["summary"]["removed"], 1, "{test}: {said}");
    assert_eq!(
        changed(&before, &cell.tree()),
        [BAZEL_LOCK],
        "{test}: {said}"
    );
    cell.builds(&unpatched);
    assert_eq!(changed(&before, &cell.tree()), NOTHING, "{test}");

    println!(
        "{test}: on Bazel {release}, `scan --mode vendored` declined the package while no file \
         named the release ({DECLINED}) and the build stayed {unpatched:?}; with {BAZEL_VERSION} \
         it kept the patched package at {copy} and its block in {MODULE}; `vendor --check` passed \
         and `vex` attested the package; the build printed {patched:?} with no request for the \
         package, and again with the stand-in stopped, a new output base and the package in no \
         repository cache; one changed byte failed `vendor --check` and the build ({refusal}); \
         `vendor --revert` restored all {} files but {BAZEL_LOCK}, and the next build printed \
         {unpatched:?} and wrote the lock of before; {:?}",
        before.len(),
        started.elapsed()
    );
}

/// Bazel's lock of a checkout that a build has selected rules_csharp 0.5.0
/// for: the one line of it that vendored mode reads.
const SELECTED: &str = "{\"lockFileVersion\": 28, \"registryFileHashes\": {\
    \"https://bcr.bazel.build/modules/rules_csharp/0.5.0/source.json\": \"sum\"}}\n";

/// Without a Bazel: vendored mode through the binary, in checkouts of the
/// fixture's project on the machine that restored it.
///
/// Where no Bazel workspace is, and where the tag of one reads the lock of
/// another project, the command gives a person and a script what it gives
/// without Bazel, and writes the same files: the package in the folder of
/// the patch, that folder in `nuget.config`, and no line of `MODULE.bazel`.
///
/// In the fixture's workspace it keeps the package where a feed of the hub
/// has it and its block in `MODULE.bazel`; a second run changes nothing;
/// `vendor --check` passes, `list` says what it says without Bazel and
/// `vex` says not affected, through the committed copy; and
/// `vendor --revert`, `rollback` and `remove` each put every file back
/// byte for byte, the block with its one folder, also for a user who
/// switched the Bazel support off (`SOCKET_NO_BAZEL`). Beside a block that
/// was changed by hand no undo changes a file, and each says where the
/// block is; with the block deleted by hand, the undo puts the rest back.
///
/// Where the block cannot be shown to work, `scan` and `get` decline the
/// package with exit 1 and write nothing, a dry run lists it and exits 0,
/// and a person reads the reason. So it is where no tag of the checkout
/// shows the hub: a module file that is not read may hold the tag, and a
/// block without the tag it was written beside still hands the lock to
/// the hub. A pin of hosted mode stays: the scan
/// that would take it over and the `vendor` that would eject it are
/// declined too, and where the block does work `vendor` ejects the pin
/// into it. With `--allow-vendored-in-bazel`, or its variable, the package
/// is vendored as without Bazel, whatever declined it. With
/// `SOCKET_NO_BAZEL=1` the run is the one of the same checkout without its
/// Bazel files, to the byte, where the block works and wherever the
/// package is declined.
#[test]
fn vendored_mode_keeps_the_block_or_declines() {
    let test = "nuget::vendored_mode_keeps_the_block_or_declines";
    let (upstream, neighbour) = (
        Package::new(NAME, "R1", "PRISTINE"),
        Package::new(NEIGHBOUR, "R1", "NEIGHBOUR"),
    );
    let (patch, purl) = (Patched::new("R1"), upstream.purl());
    let standin = registry(&[&neighbour, &upstream]);
    grant(&standin, &upstream, &patch, &patch.package.nupkg);
    let service = service_route(&standin, &patch);
    let home = tempfile::tempdir().expect("create the .NET home");
    for package in [&neighbour, &upstream] {
        package.restore_into(home.path());
    }
    let era = fixture_path(FIXTURE.dir).join(FIXTURE.eras[0].1);
    let module = std::fs::read_to_string(era.join(MODULE)).expect(MODULE);
    // A checkout of the fixture's project and config: with `module` as its
    // MODULE.bazel, beside Bazel's lock, and the release it names.
    let checkout = |module: Option<&str>, release: Option<&str>| {
        let cell = cell_without_bazel("9.3.2");
        check_out(&cell, "R1", &[&neighbour, &upstream]);
        cell.write(CONFIG, fixture_file_as_is(CONFIG));
        cell.write(".git/HEAD", "ref: refs/heads/main\n");
        if let Some(module) = module {
            cell.write(MODULE, module);
            cell.write(BAZEL_LOCK, SELECTED);
        }
        if let Some(release) = release {
            cell.write(BAZEL_VERSION, format!("{release}\n"));
        }
        cell
    };
    let scan = |cell: &Cell, more: &[&str]| vendored_scan(cell, &standin, home.path(), more);
    let (dir, flat) = (
        vendor_dir(&patch),
        format!("{}.{VERSION}.nupkg", upstream.lower()),
    );
    let flat = format!("{dir}/{flat}");
    // What a vendored run wrote of the three files it shares with a hub,
    // and the names of everything it wrote.
    let wrote = |cell: &Cell, before: &Tree| {
        let after = cell.tree();
        let files = [CONFIG, LOCK].map(|file| after[file].clone());
        (changed(before, &after), files)
    };

    // Without Bazel, and beside a tag that reads the lock of another
    // project: the package in the folder of the patch.
    let plain = checkout(None, None);
    let before = plain.tree();
    let without = scan(&plain, &[]);
    assert_eq!(without.code, 0, "{test}: {}", without.dump);
    let as_before = wrote(&plain, &before);
    let mut written = vec![
        format!("{dir}/.gitignore"),
        format!("{dir}/socket-patch.vendor.json"),
        flat.clone(),
        ".socket/vendor/state.json".to_string(),
        CONFIG.to_string(),
        LOCK.to_string(),
    ];
    written.sort();
    assert_eq!(as_before.0, written, "{test}: {}", without.dump);
    let elsewhere = module.replace("//:packages", "//api:packages");
    for (module, release) in [(&elsewhere, None), (&elsewhere, Some("9.3.2"))] {
        let cell = checkout(Some(module), release);
        let before = cell.tree();
        let ran = scan(&cell, &[]);
        assert_eq!(ran.code, 0, "{test}: {}", ran.dump);
        assert_eq!(ran.envelope, without.envelope, "{test}: {}", ran.dump);
        assert_eq!(wrote(&cell, &before), as_before, "{test}: {}", ran.dump);
    }

    // The fixture's workspace: the block, and every way to take it out.
    let hub = checkout(Some(&module), Some("9.3.2"));
    let before = hub.tree();
    let bare = tempfile::tempdir().expect("create a .NET home");
    let undo: [&[&str]; 3] = [
        &["vendor", "--revert"],
        &["rollback", "--yes"],
        &["remove", &purl, "--yes"],
    ];
    for undo in undo {
        let ran = scan(&hub, &[]);
        assert_eq!(ran.code, 0, "{test}: {}", ran.dump);
        let vendored = hub.tree();
        let mut written = vec![
            format!("{dir}/.gitignore"),
            format!("{dir}/socket-patch.vendor.json"),
            hub_copy(&patch),
            ".socket/vendor/state.json".to_string(),
            MODULE.to_string(),
            CONFIG.to_string(),
            LOCK.to_string(),
        ];
        written.sort();
        assert_eq!(changed(&before, &vendored), written, "{test}: {}", ran.dump);
        let appended = format!("{module}\n{}", block(&dir));
        assert_eq!(text(&vendored, MODULE), appended, "{test}");
        // Once more, and the check: nothing is written.
        let again = scan(&hub, &[]);
        assert_eq!(again.code, 0, "{test}: {}", again.dump);
        let check = socket_patch(&hub, &standin, home.path(), &["vendor", "--check"]);
        assert_eq!(check.code, 0, "{test}: {}", check.dump);
        // `list` says of it what it says of the package without Bazel.
        let list = |cell: &Cell| socket_patch(cell, &standin, home.path(), &["list"]);
        let (listed, as_without) = (list(&hub), list(&plain));
        assert_eq!(listed.envelope["events"][0]["details"]["mode"], "vendored");
        assert_eq!(listed.envelope, as_without.envelope, "{}", listed.dump);
        // `vex` says not affected, through the committed copy: the hub
        // builds that copy through the block, so the call that hands the
        // lock to rules_csharp is no reason to say affected. It is asked
        // on a machine that restored nothing, where it has nothing to
        // warn of: NuGet's folder of `home` holds the unpatched copy.
        let run = |cell: &Cell, args: &[&str]| socket_patch(cell, &standin, bare.path(), args);
        hub.stands_alone(run, &Claim::new(&purl, &patch.uuid, How::Vendored), true);
        assert_eq!(changed(&vendored, &hub.tree()), NOTHING, "{test}: {undo:?}");
        let ran = socket_patch(&hub, &standin, home.path(), undo);
        assert_eq!(ran.code, 0, "{test}: {}", ran.dump);
        assert_eq!(
            changed(&before, &hub.tree()),
            NOTHING,
            "{test}: {}",
            ran.dump
        );
    }
    // The switch for a project that Bazel does not build leaves the undo
    // on: with it the folder goes out of the block all the same.
    let ran = scan(&hub, &[]);
    assert_eq!(ran.code, 0, "{test}: {}", ran.dump);
    let ran = on_machine(&standin, home.path(), |api, env| {
        let env = [env, &[("SOCKET_NO_BAZEL", "1")]].concat();
        hub.socket_patch(api, undo[0], &env)
    });
    assert_eq!(ran.code, 0, "{test}: {}", ran.dump);
    assert_eq!(
        changed(&before, &hub.tree()),
        NOTHING,
        "{test}: {}",
        ran.dump
    );

    // A block that was changed by hand keeps the folder of the patch, and
    // with the lock restored beside it the Bazel build would fail on the
    // committed package: no undo changes a file, and each names the line
    // of the block. With the block deleted by hand, the undo puts every
    // other file back.
    let squeezed = |text: &str| text.split_whitespace().collect::<String>();
    let ran = scan(&hub, &[]);
    assert_eq!(ran.code, 0, "{test}: {}", ran.dump);
    let wired = text(&hub.tree(), MODULE);
    hub.write(
        MODULE,
        wired.replace("    feeds = [", "    # mine\n    feeds = ["),
    );
    let edited = hub.tree();
    assert_ne!(text(&edited, MODULE), wired, "{test}");
    let by_hand = format!(
        "{MODULE}:{}: the block that socket-patch keeps there was changed by hand",
        module.lines().count() + 2
    );
    for undo in undo {
        let ran = socket_patch(&hub, &standin, home.path(), undo);
        assert_eq!(ran.code, 1, "{test}: {}", ran.dump);
        assert!(
            squeezed(&ran.dump).contains(&squeezed(&by_hand)),
            "{test}: no {by_hand:?}: {}",
            ran.dump
        );
        assert_eq!(changed(&edited, &hub.tree()), NOTHING, "{test}: {undo:?}");
    }
    hub.write(MODULE, &module);
    let ran = socket_patch(&hub, &standin, home.path(), undo[0]);
    assert_eq!(ran.code, 0, "{test}: {}", ran.dump);
    assert_eq!(
        changed(&before, &hub.tree()),
        NOTHING,
        "{test}: {}",
        ran.dump
    );

    // Where the block cannot be shown to work: declined by every command
    // that would vendor, with nothing asked of the patch service. The
    // fourth row is a tag with `feeds` beside a config without a source:
    // the run would name its folder there, and the next one would take the
    // sources of that file for the hub's in place of those feeds. The last
    // two are hubs that no tag of the checkout shows. The module file is
    // larger than socket-patch reads, so it may hold the tag; and the tag
    // is gone, while the block of an earlier vendored run still hands the
    // lock to the hub.
    let asked = standin.asked(&service);
    let large = format!("{module}{}", "#\n".repeat(1 << 19));
    let unread = "MODULE.bazel: it cannot be read: it is larger than 1 MiB, so socket-patch \
                  cannot tell which `nuget.from_lock` tags the workspace has";
    let tag =
        format!("nuget.from_lock(\n{NAMES_CONFIG}    packages_lock_json = \"//:{LOCK}\",\n)\n");
    let untagged = module.replace(&tag, "");
    assert_ne!(untagged, module, "{test}");
    let earlier = block(".socket/vendor/nuget/7e57ce11-0000-4000-8000-5184602cd3cc");
    let orphaned = format!("{untagged}\n{earlier}");
    let orphan = format!(
        "MODULE.bazel:{}: the block that socket-patch keeps there still reads `//:{LOCK}` for the \
         hub, and the `nuget.from_lock` it was written beside is gone, so a package vendored now \
         would not be among the block's feeds: put that tag back, or take the vendored packages \
         out (`socket-patch vendor --revert`), and run this command again",
        untagged.lines().count() + 2
    );
    let dirs = module.replace(NAMES_CONFIG, "    local_package_dirs = [\"/opt/nuget\"],\n");
    let fed =
        format!("    feeds = [\"https://nuget.private.example/v3/index.json\"],\n{NAMES_CONFIG}");
    let fed = module.replace(NAMES_CONFIG, &fed);
    let sourceless = "<configuration>\n  <packageSources>\n  </packageSources>\n</configuration>\n";
    let rows: [(&str, Option<&str>, Option<&str>, &str); 6] = [
        (
            &module,
            None,
            None,
            "no file of the checkout names the Bazel release",
        ),
        (
            &module,
            Some("8.8.1"),
            None,
            "the checkout names Bazel 8.8.1",
        ),
        (
            &dirs,
            Some("9.3.2"),
            None,
            "MODULE.bazel:9: this `nuget.from_lock` has `local_package_dirs`",
        ),
        (
            &fed,
            Some("9.3.2"),
            Some(sourceless),
            "MODULE.bazel:9: this `nuget.from_lock` has `feeds`, and its `nuget_config` \
             `//:nuget.config` names no package source",
        ),
        (&large, Some("9.3.2"), None, unread),
        (&orphaned, Some("9.3.2"), None, &orphan),
    ];
    for (module, release, config, why) in rows {
        let cell = checkout(Some(module), release);
        if let Some(config) = config {
            cell.write(CONFIG, config);
        }
        let before = cell.tree();
        declined(test, &scan(&cell, &[]), &purl, why);
        let get = ["get", &purl, "--mode", "vendored", "--yes"];
        let get = socket_patch(&cell, &standin, home.path(), &get);
        assert_eq!(get.code, 1, "{test}: {}", get.dump);
        assert!(
            codes_of(&get.envelope).contains(&DECLINED.to_string()),
            "{}",
            get.dump
        );
        // A dry run lists it and passes.
        let dry = scan(&cell, &["--dry-run"]);
        assert_eq!(dry.code, 0, "{test}: {}", dry.dump);
        let listed = [(purl.clone(), "skipped".to_string(), DECLINED.to_string())];
        assert_eq!(event_triples(&dry.envelope), listed, "{test}: {}", dry.dump);
        assert_eq!(changed(&before, &cell.tree()), NOTHING, "{test}: {why}");
        // A person reads the reason after the package, once. The output is
        // compared without white space: nothing says where a long line is
        // broken.
        let run = |api: &str, env: &[(&str, &str)]| {
            let origin = standin.origin();
            let args = [&VENDORED[..], &["--patch-server-url", &origin]].concat();
            cell.socket_patch_person(api, &args, env)
        };
        let person = on_machine(&standin, home.path(), run);
        let told = squeezed(&person.concat());
        let line = squeezed(&format!("{purl} ({DECLINED}): "));
        assert!(
            told.matches(&line).count() == 1 && told.contains(&squeezed(why)),
            "{test}: {person:?}"
        );
        assert_eq!(changed(&before, &cell.tree()), NOTHING, "{test}: {why}");
        assert_eq!(standin.asked(&service), asked, "{test}: {why}");
    }
    // A package that hosted mode pinned: the scan that would take the pin
    // over and the `vendor` that would eject it are declined, and the pin
    // stays. Once the checkout names its release, `vendor` ejects the pin
    // into the block.
    let cell = checkout(Some(&module), None);
    let hosted = socket_patch(&cell, &standin, home.path(), &SCAN);
    assert_eq!(hosted.code, 0, "{test}: {}", hosted.dump);
    let pinned = cell.tree();
    declined(test, &scan(&cell, &[]), &purl, rows[0].3);
    let eject = socket_patch(&cell, &standin, home.path(), &["vendor", "--yes"]);
    assert_eq!(eject.code, 1, "{test}: {}", eject.dump);
    let refused = &eject.envelope["error"]["code"];
    assert_eq!(*refused, "eject_refused", "{test}: {}", eject.dump);
    let kept = eject.envelope["events"][0]["error"].as_str();
    let kept = kept.is_some_and(|why| why.starts_with("kept hosted: ") && why.contains(rows[0].3));
    assert!(kept, "{test}: {}", eject.dump);
    assert_eq!(changed(&pinned, &cell.tree()), NOTHING, "{test}");
    assert_eq!(standin.asked(&service), asked, "{test}");
    cell.write(BAZEL_VERSION, "9.3.2\n");
    let origin = standin.origin();
    let eject = ["vendor", "--yes", "--patch-server-url", &origin];
    let eject = socket_patch(&cell, &standin, home.path(), &eject);
    assert_eq!(eject.code, 0, "{test}: {}", eject.dump);
    let ejected = cell.tree();
    assert_eq!(ejected[&hub_copy(&patch)], patch.package.nupkg, "{test}");
    let appended = format!("{module}\n{}", block(&dir));
    assert_eq!(text(&ejected, MODULE), appended, "{test}: {}", eject.dump);
    assert!(!text(&ejected, CONFIG).contains(PATCH_HOST), "{test}");

    // The user's word, as a flag and as its variable: as without Bazel,
    // also where no tag of the checkout shows the hub.
    let lifted: [(&str, Option<&str>); 3] = [
        (&module, None),
        (&large, Some("9.3.2")),
        (&orphaned, Some("9.3.2")),
    ];
    for ((module, release), flag) in lifted.iter().flat_map(|row| [(*row, true), (*row, false)]) {
        let cell = checkout(Some(module), release);
        let before = cell.tree();
        let ran = match flag {
            true => scan(&cell, &["--allow-vendored-in-bazel"]),
            false => on_machine(&standin, home.path(), |api, env| {
                let origin = standin.origin();
                let args = [&VENDORED[..], &["--patch-server-url", &origin]].concat();
                let env = [env, &[("SOCKET_ALLOW_VENDORED_IN_BAZEL", "1")]].concat();
                cell.socket_patch(api, &args, &env)
            }),
        };
        assert_eq!(ran.code, 0, "{test}: {}", ran.dump);
        assert_eq!(ran.envelope, without.envelope, "{test}: {}", ran.dump);
        assert_eq!(wrote(&cell, &before), as_before, "{test}: {}", ran.dump);
    }

    // The switch for a project that Bazel does not build: the run of the
    // same checkout without its Bazel files, to the byte. Beside those
    // files the run is another one: the block, or the package declined,
    // also where no tag of the checkout shows the hub.
    let bazel = [MODULE, BAZEL_LOCK, BAZEL_VERSION];
    let switched: [(&str, Option<&str>, i32); 4] = [
        (&module, Some("9.3.2"), 0),
        (&module, None, 1),
        (&large, Some("9.3.2"), 1),
        (&orphaned, Some("9.3.2"), 1),
    ];
    for (module, release, code) in switched {
        let cell = checkout(Some(module), release);
        let origin = standin.origin();
        let args = [&VENDORED[..], &["--patch-server-url", &origin]].concat();
        let beside = on_machine(&standin, home.path(), |api, env| {
            cell.off_is_without_bazel(api, &args, env, &bazel)
        });
        assert_eq!(beside[0]["code"], code, "{test}: {beside:#}");
    }
}

/// What a run of agent mode is made of.
struct Restored {
    /// The stand-in of the run: nuget.org with the two packages of the
    /// fixture, and the Socket API with `patch`.
    standin: StandIn,
    /// The package a patch replaces, as nuget.org has it for this run.
    upstream: Package,
    /// One patch of it, granted with a record that agent mode patches
    /// from ([`grant_installed`]).
    patch: Patched,
    /// The .NET home of a machine that restored the project: its NuGet
    /// folder holds the two packages ([`Package::restore_into`]).
    home: tempfile::TempDir,
}

/// Make `cell` the checkout of a new run of agent mode ([`check_out`]),
/// whose builds fetch from the stand-in of the run ([`downloads`]).
fn restored(cell: &mut Cell) -> Restored {
    let run = format!("R{}", uuid::Uuid::new_v4().simple());
    let upstream = Package::new(NAME, &run, &format!("PRISTINE {run}"));
    let neighbour = Package::new(NEIGHBOUR, &run, "NEIGHBOUR");
    let patch = Patched::new(&run);
    let standin = registry(&[&neighbour, &upstream]);
    grant_installed(&standin, &upstream, &patch);
    cell.route_downloads(&downloads(&standin.origin()));
    check_out(cell, &run, &[&neighbour, &upstream]);
    let home = tempfile::Builder::new()
        .prefix("sp-bazel-nuget-")
        .tempdir()
        .expect("create a .NET home");
    for package in [&neighbour, &upstream] {
        package.restore_into(home.path());
    }
    // Bazel has the two variables of that home which `socket-patch` has
    // ([`on_machine`]): a build that read NuGet's folder would find it.
    let folder = packages_folder(home.path());
    let pairs = [
        ("NUGET_PACKAGES", folder.as_path()),
        ("DOTNET_CLI_HOME", home.path()),
    ];
    let owned = |(name, path): (&str, &Path)| (name.to_string(), path.to_string_lossy().into());
    cell.repo_env = pairs.map(owned).to_vec();
    Restored {
        standin,
        upstream,
        patch,
        home,
    }
}

impl Restored {
    /// The assembly of the package in NuGet's folder, where agent mode
    /// patches it.
    fn assembly(&self) -> PathBuf {
        let package = packages_folder(self.home.path()).join(self.upstream.lower());
        package.join(VERSION).join(assembly_path(&self.upstream.id))
    }
}

/// What every form of `vex` has to say of the package while `patch` is in
/// NuGet's folder alone and the hub of the checkout of `cell` builds it
/// from the lock: the whole action statement of the document, which the
/// run warning repeats. It names the lock, the call and its line, hosted
/// mode, which [`hosted_from_lock`] builds patched, with what it needs of
/// the hub, and the option for a repository that ships the installed tree.
fn affected(cell: &Cell, patch: &Patched) -> Vec<String> {
    let module = text(&cell.tree(), MODULE);
    let call = module.lines().position(|line| line == "nuget.from_lock(");
    vec![format!(
        "Bazel builds this package from {LOCK} (`nuget.from_lock`, {MODULE}:{}), which does not \
         name Socket patch {}: the patch is only in the installed copy. Run `socket-patch scan \
         --mode hosted` in the directory of that lock to pin the patch there (the call has to \
         name the project's nuget.config, `nuget_config`). If what you ship is the installed \
         tree and not what Bazel builds, pass `--no-bazel` (`--vex-no-bazel` on scan, apply and \
         vendor).",
        call.expect("a hub") + 1,
        patch.uuid
    )]
}

/// Agent mode beside the hub, which builds the package from the lock.
///
/// - (a) `bazel build` and `bazel run //:consumer` print the unpatched
///   marker, and Bazel fetched the upstream package from the stand-in.
/// - (b) NuGet's folder holds the two packages, as after the user's
///   `dotnet restore` ([`restored`]). `scan --mode agent --yes` patches the
///   assembly of the package there and writes nothing into the checkout
///   but its `.socket` directory, and `apply` passes
///   ([`Cell::patches_outside`]). Both, `vex` and `vex --no-verify` exit 0
///   and write a document that says the package is affected, with what to
///   do about it ([`affected`]).
/// - (c) The same two Bazel commands print the unpatched marker again, as
///   the documents said, and change no file: the hub has Bazel download
///   the package the lock pins, and no build reads NuGet's folder.
///   `vex --no-bazel` says not affected, through the patch: its document
///   then speaks of NuGet's folder, for a repository that ships what
///   `dotnet` built from it, and not of the Bazel build.
/// - (d) A second machine prints the unpatched marker too. Its Bazel has
///   built nothing and evaluates the hub anew, with the patched folder
///   named in its environment ([`Cell::builds_anew`]); the build of (c)
///   is a warm one, which looks at nothing outside the checkout again.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn agent_from_lock() {
    let test = "nuget::agent_from_lock";
    let started = Instant::now();
    let Some(mut cell) = Cell::open(test, &FIXTURE) else {
        return;
    };
    let release = cell.release().to_string();
    let machine = restored(&mut cell);
    let (standin, upstream, patch) = (&machine.standin, &machine.upstream, &machine.patch);
    let (purl, unpatched) = (upstream.purl(), upstream.marker());

    // (a) The unpatched build, with the upstream package from the stand-in.
    cell.builds_unpatched(&unpatched);
    assert!(
        standin.asked(&upstream.file(FLAT_CONTAINER)) > 0,
        "{test}: the build did not fetch the upstream package from the stand-in"
    );

    // (b) Agent mode patches the copy in NuGet's folder, and every
    // document says the package is affected.
    let assembly = machine.assembly();
    let run = |cell: &Cell, args: &[&str]| socket_patch(cell, standin, machine.home.path(), args);
    let names = affected(&cell, patch);
    let claim = Claim::unbuilt(&purl, &patch.uuid, &names);
    let patched = cell.patches_outside(run, &assembly, &patch.package.assembly, &claim);

    // (c) The build is the one of (a): Bazel never reads the patched copy.
    // Told that the installed tree is what ships, `vex` attests that tree.
    cell.builds(&unpatched);
    let shipped = |cell: &Cell, args: &[&str]| run(cell, &[args, &["--no-bazel"]].concat());
    cell.stands_alone(shipped, &Claim::new(&purl, &patch.uuid, How::Agent), true);
    assert_eq!(changed(&patched, &cell.tree()), NOTHING, "{test}");

    // (d) Nor does a Bazel that evaluates the hub anew read it.
    cell.builds_anew(&unpatched);

    println!(
        "{test}: Bazel {release} built {unpatched:?} before and after `scan --mode agent` \
         patched {}, and on a second machine; every form of `vex` said the package is affected, \
         in the words {names:?}, and `vex --no-bazel` said it is not affected in the installed \
         tree; {:?}",
        assembly.display(),
        started.elapsed()
    );
}

/// Without a Bazel: `scan --mode hosted --yes` through the binary, in
/// checkouts of the fixture's project that hold no `nuget.config`. What it
/// gives a person, then a script, and the files it leaves are the same in
/// a checkout that is no Bazel workspace, in one whose tag names the
/// config, and in one whose tag reads the lock of another project. Only
/// the tag that reads this lock and names no config is withheld: nothing
/// is written, a person reads the warning a script gets, and with the
/// attribute on the tag the command gives what it gives without Bazel.
/// Where the two files already hold the pin, it warns and leaves them.
#[test]
fn only_a_tag_that_reads_the_lock_without_its_config_is_withheld() {
    let test = "nuget::only_a_tag_that_reads_the_lock_without_its_config_is_withheld";
    let (upstream, neighbour) = (
        Package::new(NAME, "R1", "PRISTINE"),
        Package::new(NEIGHBOUR, "R1", "NEIGHBOUR"),
    );
    let (patch, purl) = (Patched::new("R1"), upstream.purl());
    let standin = StandIn::start();
    grant(&standin, &upstream, &patch, &patch.package.nupkg);
    let home = tempfile::tempdir().expect("create the .NET home");
    for package in [&neighbour, &upstream] {
        package.restore_into(home.path());
    }
    let era = fixture_path(FIXTURE.dir).join(FIXTURE.eras[0].1);
    let module = std::fs::read_to_string(era.join(MODULE)).expect(MODULE);
    let bare = module.replace(NAMES_CONFIG, "");
    let checkout = |module: Option<&str>| {
        let cell = cell_without_bazel("9.3.2");
        check_out(&cell, "R1", &[&neighbour, &upstream]);
        cell.write(".git/HEAD", "ref: refs/heads/main\n");
        if let Some(module) = module {
            cell.write(MODULE, module);
        }
        cell
    };
    // What the command gives a person, then a script, and the files it
    // leaves beside `MODULE.bazel`.
    let gives = |cell: &Cell| {
        let scan = |api: &str, env: &[(&str, &str)]| cell.socket_patch_person(api, &SCAN, env);
        let person = on_machine(&standin, home.path(), scan);
        let ran = socket_patch(cell, &standin, home.path(), &SCAN);
        let mut files = cell.tree();
        files.remove(MODULE);
        (person, ran, files)
    };
    let said = |(person, ran, files): &([String; 2], Ran, Tree)| {
        (
            person.clone(),
            ran.code,
            ran.envelope.clone(),
            files.clone(),
        )
    };

    // Without Bazel the command pins the package: it creates the config
    // and re-pins the lock.
    let plain = checkout(None);
    let before = plain.tree();
    let without = gives(&plain);
    let pinned = changed(&before, &plain.tree());
    assert_eq!(pinned, [CONFIG, LOCK], "{test}: {}", without.1.dump);
    assert!(
        without.0[0].contains("Switched 1 package"),
        "{:?}",
        without.0
    );
    let elsewhere = bare.replace("//:packages", "//api:packages");
    for same in [&module, &elsewhere] {
        assert_eq!(
            said(&gives(&checkout(Some(same)))),
            said(&without),
            "{same}"
        );
    }

    let cell = checkout(Some(&bare));
    let before = cell.tree();
    let (person, scan, _) = gives(&cell);
    let detail = withheld(test, &scan, &upstream, &purl);
    assert_eq!(changed(&before, &cell.tree()), NOTHING, "{test}");
    let told = [
        "No patches could be switched to hosted:".to_string(),
        format!(
            "  {purl}: no lockfile entry pinning it could be rewritten (see the warning below)"
        ),
        format!("Warning: {detail}"),
    ];
    // The last lines of stderr, after what every scan says there.
    let mut lines: Vec<&str> = person[1].lines().collect();
    let last = lines.split_off(lines.len().saturating_sub(told.len()));
    assert_eq!(last, told, "{test}: {person:?}");
    assert!(person[0].starts_with("Switched 0 packages"), "{person:?}");
    cell.write(MODULE, &module);
    assert_eq!(said(&gives(&cell)), said(&without), "{test}");

    // A checkout that an earlier release pinned under such a tag: the pin
    // stays in the two files and is reported as it is, beside the warning.
    plain.write(MODULE, &bare);
    let before = plain.tree();
    let scan = socket_patch(&plain, &standin, home.path(), &SCAN);
    assert_eq!(changed(&before, &plain.tree()), NOTHING, "{test}");
    let applied = [(purl, "applied".to_string(), String::new())];
    assert_eq!(event_triples(&scan.envelope), applied, "{}", scan.dump);
    let warned = codes_in(&scan.envelope["warnings"]);
    assert_eq!(warned[0], WITHHELD, "{}", scan.dump);
}

/// Without a Bazel: `scan --mode hosted --yes` through the binary in the
/// workspaces of a hub with more than one tag, or with a tag that is not
/// the fixture's. Each is a checkout of the fixture's project, also below
/// the root as `app` and `lib`, with the tags of its row; the scan runs in
/// the directory of the row. It pins the package and rewrites the files
/// named, or it writes nothing and its one warning has the code and the
/// words of the row. What Bazel builds in each was measured on 9.3.2 and
/// is not run here.
#[test]
fn the_pin_is_written_where_the_hub_takes_it() {
    let test = "nuget::the_pin_is_written_where_the_hub_takes_it";
    let (upstream, neighbour) = (
        Package::new(NAME, "R1", "PRISTINE"),
        Package::new(NEIGHBOUR, "R1", "NEIGHBOUR"),
    );
    let (patch, purl) = (Patched::new("R1"), upstream.purl());
    let standin = StandIn::start();
    grant(&standin, &upstream, &patch, &patch.package.nupkg);
    let home = tempfile::tempdir().expect("create the .NET home");
    for package in [&neighbour, &upstream] {
        package.restore_into(home.path());
    }
    let era = fixture_path(FIXTURE.dir).join(FIXTURE.eras[0].1);
    let module = std::fs::read_to_string(era.join(MODULE)).expect(MODULE);
    let (top, _) = module.split_once("nuget.from_lock(").expect("the tag");
    // A file of tags, each the lock it reads and the rest of its lines.
    let with = |tags: &[(&str, &str)]| {
        let tag = |(lock, more): &(&str, &str)| {
            format!("nuget.from_lock(\n{more}    packages_lock_json = \"{lock}\",\n)\n")
        };
        let tags: String = tags.iter().map(tag).collect();
        format!("{top}{tags}use_repo(nuget, \"nuget\")\n")
    };
    let (root, app, lib) = (
        "//:packages.lock.json",
        "//app:packages.lock.json",
        "//lib:packages.lock.json",
    );
    let (own, of_app, of_api) = (
        NAMES_CONFIG,
        "    nuget_config = \"//app:nuget.config\",\n",
        "    nuget_config = \"//api:nuget.config\",\n",
    );
    let feeds = format!("    feeds = [\"{SOURCE}\"],\n");
    let computed = "\"0.5.0\", repo_name = \"rules_\" + \"csharp\")";
    let renamed = module.replacen("\"0.5.0\")", computed, 1);
    assert_ne!(renamed, module);
    let (app_lock, app_config) = ("app/packages.lock.json", "app/nuget.config");
    let empty = "{\n  \"version\": 1,\n  \"dependencies\": {\n    \"net8.0\": {}\n  }\n}\n";
    // The module file, the file added to the checkout, the directory of
    // the scan, and then the files it rewrites, or the code and the words
    // of its warning.
    type Row<'a> = (String, &'a str, &'a str, &'a [&'a str], &'a [&'a str]);
    let rows: [Row; 9] = [
        // The last tag with sources names the config; a line that the
        // reader cannot read is beside the tag, which names the config.
        (
            with(&[("//api:packages.lock.json", of_api), (root, own)]),
            "api/packages.lock.json",
            "",
            &[CONFIG, LOCK],
            &[],
        ),
        (renamed, "", "", &[CONFIG, LOCK], &[]),
        // Feeds and no config; a config that the directory spells its own
        // way.
        (
            with(&[(root, &feeds)]),
            "",
            "",
            &[],
            &[
                WITHHELD,
                "MODULE.bazel:9: this `nuget.from_lock` has `feeds` and no `nuget_config`",
                "name its `feeds` in nuget.config",
            ],
        ),
        (
            with(&[(root, "")]),
            "NuGet.Config",
            "",
            &[],
            &[
                WITHHELD,
                "does not read NuGet.Config, where",
                "Put `nuget_config = \"//:NuGet.Config\"` on that tag",
            ],
        ),
        // Two locks hold the package and the scan re-pins one: the hub
        // has the package from the first.
        (
            with(&[(lib, of_app), (app, of_app)]),
            "",
            "app",
            &[],
            &[
                NOT_REPINNED,
                "MODULE.bazel:9: this `nuget.from_lock` reads lib/packages.lock.json, which holds \
                 the package as well and which this run does not re-pin",
                "Run this command in a directory above both locks",
            ],
        ),
        (
            with(&[(app, of_app), (lib, of_app)]),
            "",
            "app",
            &[app_config, app_lock],
            &[],
        ),
        (
            with(&[(lib, own), (app, own)]),
            "",
            "",
            &[app_lock, "lib/packages.lock.json", CONFIG, LOCK],
            &[],
        ),
        // The tag names a config above the project: the scan writes it
        // where it runs in that directory.
        (
            with(&[(app, own)]),
            "",
            "app",
            &[],
            &[
                WITHHELD,
                "names `//:nuget.config` as its `nuget_config`, not app/nuget.config",
                "Run this command in the directory of that file (`--cwd`)",
            ],
        ),
        (with(&[(app, own)]), "", "", &[app_lock, CONFIG, LOCK], &[]),
    ];
    for (module, added, cwd, rewritten, warned) in rows {
        let cell = cell_without_bazel("9.3.2");
        check_out(&cell, "R1", &[&neighbour, &upstream]);
        cell.write(".git/HEAD", "ref: refs/heads/main\n");
        cell.write(MODULE, &module);
        // The project again, below each directory the tags name.
        let named = |dir: &&str| module.contains(&format!("//{dir}:"));
        for dir in ["app", "lib"].into_iter().filter(named) {
            for file in ["App.csproj", LOCK] {
                let text = std::fs::read(cell.path(file)).expect(file);
                cell.write(&format!("{dir}/{file}"), text);
            }
        }
        match added {
            "" => {}
            "NuGet.Config" => cell.write(added, fixture_file_as_is(CONFIG)),
            _ => cell.write(added, empty),
        }
        let before = cell.tree();
        let args: Vec<&str> = match cwd {
            "" => SCAN.to_vec(),
            _ => SCAN.iter().copied().chain(["--cwd", cwd]).collect(),
        };
        let scan = socket_patch(&cell, &standin, home.path(), &args);
        let said = format!("{test}: {cwd:?} {module}\n{}", scan.dump);
        assert_eq!(scan.code, 0, "{said}");
        assert_eq!(changed(&before, &cell.tree()), rewritten, "{said}");
        let (action, code) = match warned.is_empty() {
            true => ("applied", ""),
            false => ("skipped", "redirect_unconfirmed"),
        };
        let event = [(purl.clone(), action.to_string(), code.to_string())];
        assert_eq!(event_triples(&scan.envelope), event, "{said}");
        let warnings = &scan.envelope["warnings"];
        let Some((code, words)) = warned.split_first() else {
            let codes = codes_in(warnings);
            assert!(!codes.iter().any(|code| code.contains("bazel")), "{said}");
            continue;
        };
        assert_eq!(codes_in(warnings), [*code], "{said}");
        let detail = warnings[0]["detail"].as_str().unwrap_or_default();
        for words in words {
            assert!(detail.contains(words), "{said}");
        }
    }
}

/// Without a Bazel: a checkout of the fixture for a new run of agent mode
/// ([`restored`]), with the `MODULE.bazel` of its era at the root.
fn restored_checkout() -> (Cell, Restored) {
    let mut cell = cell_without_bazel("9.3.2");
    for part in ["common", "e9"] {
        for (rel, bytes) in read_tree(&fixture_path(FIXTURE.dir).join(part)) {
            cell.write(&rel, bytes);
        }
    }
    cell.write(".git/HEAD", "ref: refs/heads/main\n");
    let machine = restored(&mut cell);
    (cell, machine)
}

/// Without a Bazel: step (b) of [`agent_from_lock`] in a checkout of the
/// fixture, where `MODULE.bazel` hands the lock to rules_csharp. Then what
/// the document says to do: `scan --mode hosted --yes` pins the patch in
/// the two files the hub names, and its document and the one of `vex` say
/// not affected, through the pin.
#[test]
fn an_installed_package_is_affected_beside_a_hub_that_reads_the_lock() {
    let (cell, machine) = restored_checkout();
    let (standin, patch) = (&machine.standin, &machine.patch);
    let purl = machine.upstream.purl();
    let run = |cell: &Cell, args: &[&str]| socket_patch(cell, standin, machine.home.path(), args);
    let names = affected(&cell, patch);
    let claim = Claim::unbuilt(&purl, &patch.uuid, &names);
    cell.patches_outside(run, &machine.assembly(), &patch.package.assembly, &claim);

    let document = cell.document("hosted");
    let scan = run(&cell, &[&SCAN[..], &with_vex(&document)].concat());
    assert_eq!(scan.envelope["summary"]["applied"], 1, "{}", scan.dump);
    let claim = Claim::new(&purl, &patch.uuid, How::Hosted);
    cell.wrote_in_run(&scan, &document, &claim);
    cell.stands_alone(run, &claim, true);
}

/// Without a Bazel: what stays the statement of a project without Bazel
/// while the patch is in NuGet's folder alone
/// ([`Cell::keeps_its_statement`]). The hubs that decide nothing: one over
/// a lock that is not in the checkout, one whose `nuget_config` is not written
/// out, one whose call may not run, and one with a second call, for the
/// lock of another project, whose `nuget_config` names the patch:
/// rules_csharp makes one hub of both calls, which may build the patched
/// package through that project's pin.
#[test]
fn an_installed_package_is_attested_where_no_hub_is_shown_to_build_it() {
    let (cell, machine) = restored_checkout();
    let (standin, patch) = (&machine.standin, &machine.patch);
    let (purl, home) = (machine.upstream.purl(), machine.home.path());
    let run = |cell: &Cell, args: &[&str]| socket_patch(cell, standin, home, args);
    let names = affected(&cell, patch);
    let claim = Claim::unbuilt(&purl, &patch.uuid, &names);
    let patched = cell.patches_outside(run, &machine.assembly(), &patch.package.assembly, &claim);

    let gives = |args: &[&str], document: &Path| {
        on_machine(standin, home, |api, env| {
            cell.gives(api, args, env, document)
        })
    };
    // The config of another project, which hosted mode pinned the patch in.
    let pinned = format!("<add key=\"socket-patch\" value=\"{}\" />\n", patch.index());
    cell.write("pinned.config", pinned);
    let module = text(&patched, MODULE);
    let undecided = [
        module.replace("\"//:", "\"//third_party:"),
        module.replace(NAMES_CONFIG, "    nuget_config = CONFIG,\n"),
        module.replace("nuget.from_lock(", "ENABLED and nuget.from_lock("),
        format!(
            "{module}nuget.from_lock(\n    nuget_config = \"//:pinned.config\",\n    \
             packages_lock_json = \"//third_party:{LOCK}\",\n)\n"
        ),
    ];
    let installed = Claim::new(&purl, &patch.uuid, How::Agent);
    cell.keeps_its_statement(run, gives, &installed, &undecided);
}

/// Without a Bazel, what stays fixed now that no id and no sum is
/// committed: the fixture's directories and the legs of its workflow are
/// those of its table; every era names the two files the hub reads; the
/// files that hold the placeholder of an id are the three a checkout
/// rewrites, every id they name ends in it and so is no package id, and the
/// consumer reads the package through the hub; the fixture's lock holds
/// one entry per package, with the placeholder of a `contentHash`, and
/// pinning changes nothing else; two runs serve two packages; and the
/// downloader config is the four rules that keep a build off nuget.org and
/// the patch host.
#[test]
fn a_checkout_names_and_pins_the_packages_of_its_run() {
    FIXTURE.check();
    let root = fixture_path(FIXTURE.dir);
    for (_, era) in FIXTURE.eras {
        let path = root.join(era).join("MODULE.bazel");
        let module = std::fs::read_to_string(&path).expect("the era's MODULE.bazel");
        for named in [
            format!("nuget_config = \"//:{CONFIG}\""),
            format!("packages_lock_json = \"//:{LOCK}\""),
        ] {
            assert!(module.contains(&named), "{}: no {named}", path.display());
        }
        // The one line a flow takes out for a tag without the config.
        assert_eq!(module.matches(NAMES_CONFIG).count(), 1, "{module}");
    }
    let common = root.join("common");
    let read = |rel: &str| std::fs::read_to_string(common.join(rel)).expect(rel);
    // The regular files, at any depth: one that is no text says its name.
    let holds_run = |(rel, bytes): &(String, Vec<u8>)| match std::str::from_utf8(bytes) {
        Ok(text) => text.contains(RUN),
        Err(_) => panic!("{rel} of the fixture is no UTF-8 text"),
    };
    let files = read_tree(&common).into_iter().filter(holds_run);
    let naming: Vec<String> = files.map(|(rel, _)| rel).collect();
    assert_eq!(naming, NAMING);
    // Every id those files name (the references of the project, the label
    // of the consumer, the keys of the lock) ends in the placeholder, whose
    // `@` no package id takes: nobody can push one of them to nuget.org.
    let after = |rel: &str, opener: &str| -> Vec<String> {
        let text = read(rel);
        let ids = text
            .split(opener)
            .skip(1)
            .map(|rest| rest.split('"').next());
        ids.map(|id| id.expect("an id").to_string()).collect()
    };
    let mut ids = after("App.csproj", "<PackageReference Include=\"");
    ids.extend(after("BUILD.bazel", "\"@nuget//:"));
    let committed: Value = serde_json::from_str(&read(LOCK)).expect("a JSON lock");
    for (_, locked) in committed["dependencies"].as_object().expect("frameworks") {
        ids.extend(locked.as_object().expect("ids").keys().cloned());
    }
    assert_eq!(ids.len(), 5, "{ids:?}");
    let pushable = |id: &&String| !id.ends_with(RUN) || !id.contains('@');
    let pushable = ids.iter().find(pushable);
    assert_eq!(pushable, None, "an id anybody could push to nuget.org");
    assert!(read(CONFIG).contains(&format!("<add key=\"nuget.org\" value=\"{SOURCE}\" />")));

    let package = |name, run| Package::new(name, run, "PRISTINE of a run");
    let (neighbour, upstream) = (package(NEIGHBOUR, "R1"), package(NAME, "R1"));
    let label = format!("srcs = [\"@nuget//:{}\"]", upstream.id);
    assert!(fixture_file("BUILD.bazel", "R1").contains(&label));
    let pinned = lock_pinning("R1", &[&neighbour, &upstream]);
    let lock: Value = serde_json::from_str(&pinned).expect("a JSON lock");
    let entries = lock["dependencies"]["net8.0"].as_object().expect("entries");
    assert_eq!(entries.len(), 2, "{pinned}");
    for package in [&neighbour, &upstream] {
        let entry = &entries[&package.id];
        assert_eq!(entry["resolved"], VERSION, "{pinned}");
        assert_eq!(entry["contentHash"], package.content_hash(), "{pinned}");
    }
    // The hashes first: the base64 of one may hold the tag of the run.
    let mut unpinned = pinned;
    for package in [&neighbour, &upstream] {
        unpinned = unpinned.replace(&package.content_hash(), &placeholder());
    }
    assert_eq!(unpinned.replace("R1", RUN), read(LOCK));

    assert_ne!(package(NAME, "R2").nupkg, upstream.nupkg);
    assert_eq!(upstream.purl(), "pkg:nuget/sp.victim.r1@1.0.0");
    assert_eq!(
        upstream.file(FLAT_CONTAINER),
        "/api.nuget.org/v3-flatcontainer/sp.victim.r1/1.0.0/sp.victim.r1.1.0.0.nupkg"
    );
    assert_eq!(
        downloads("http://127.0.0.1:1"),
        [
            r"rewrite (\Qapi.nuget.org/\E.*) http://127.0.0.1:1/$1",
            r"rewrite (\Qpatch.socket.dev/\E.*) http://127.0.0.1:1/$1",
            "block nuget.org",
            "block patch.socket.dev",
        ]
    );
}

/// Without a Bazel: the workflow names the product files of the flow one by
/// one, and a path that names no file, or a pattern under no directory,
/// would start no run. What a pull request starts a run for, a push to main
/// starts one for as well.
#[test]
fn the_workflow_names_files_that_exist() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let workflow = root.join(".github/workflows").join(FIXTURE.workflow);
    let text = std::fs::read_to_string(&workflow).expect("the workflow");
    // The two lists of the file, in its order: `pull_request`, then `push`.
    let (on_pull_request, on_push) = text.split_once("\n  push:\n").expect("a push trigger");
    fn listed(part: &str) -> Vec<&str> {
        let lines = part.lines().map(str::trim);
        lines
            .filter_map(|line| line.strip_prefix("- '")?.strip_suffix('\''))
            .collect()
    }
    let (on_pull_request, on_push) = (listed(on_pull_request), listed(on_push));
    assert!(!on_pull_request.is_empty(), "{}", workflow.display());
    for path in &on_pull_request {
        assert!(on_push.contains(path), "{path} starts no run on main");
    }
    for path in &on_push {
        // A pattern has to name the directory before its first `*`.
        let named = match path.split_once('*') {
            Some((fixed, _)) => root.join(&fixed[..fixed.rfind('/').unwrap_or(0)]).is_dir(),
            None => root.join(path).is_file(),
        };
        assert!(named, "{}: {path}", workflow.display());
    }
}
