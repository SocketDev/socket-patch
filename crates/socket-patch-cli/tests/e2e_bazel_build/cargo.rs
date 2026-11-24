//! Hosted and vendored mode for a crate that rules_rust's crate_universe
//! resolves from a Cargo workspace: `crate.from_cargo(cargo_lockfile =
//! "//:Cargo.lock", manifests = ["//:Cargo.toml"], cargo_config =
//! "//:.cargo/config.toml")` under Bzlmod, with no cargo-bazel lock (the
//! hub's `lockfile`).
//!
//! The hub runs cargo. Its tool, cargo-bazel, copies the manifest, the lock
//! and the config the hub names into a workspace of its own and has the
//! cargo of the Rust toolchain resolve it: that cargo reads the index of
//! every registry the lock names and downloads each crate file, unless its
//! home holds them. A registry crate then becomes one repository, which
//! Bazel's downloader fetches from the registry's download URL and holds to
//! the checksum of `Cargo.lock`. A crate that a `[patch]` table takes from
//! a path becomes a repository that mirrors the directory. With no
//! cargo-bazel lock the hub follows `Cargo.toml` and `Cargo.lock` as they
//! are, and no build needs a repin (`CARGO_BAZEL_REPIN`).
//!
//! Two flows, one test each, on the Bazel the run is given ([`FIXTURE`]
//! says which ruleset goes with its release), each in a fresh output base:
//!
//! - (a) `bazel build` and `bazel run //:consumer` print the unpatched
//!   marker. The stand-in registry was asked for the crate's file of the
//!   index and, at least twice, for the crate file ([`asked_for`]).
//! - (b) The one command of the mode writes its files and no other.
//!   `scan --mode hosted --yes` adds the patch registry to
//!   `.cargo/config.toml` (`[registries.socket-patch-<uuid>]`), names it on
//!   the dependency in `Cargo.toml`, and gives the crate's entry of
//!   `Cargo.lock` that registry as its source and the checksum of the
//!   patched crate file. `scan --mode vendored --yes` unpacks the patched
//!   crate file to `.socket/vendor/cargo/<uuid>/<name>-<version>/`, records
//!   it in the ledger `.socket/vendor/state.json`, points a
//!   `[patch.crates-io]` entry of `Cargo.toml` at the copy, gives the
//!   lock's entry the version of the copy (`<version>+socket.<uuid>`) and
//!   no source, and writes the line of the vendored crates into
//!   `.bazelignore` ([`IGNORED`]): the workspace has a crate hub.
//! - (c) The same two Bazel commands, with no step in between, print the
//!   patched marker. Hosted: the stand-in patch host was asked for its index
//!   file of the crate and, at least twice, for the crate file, and the
//!   upstream one was not asked for again. Vendored: the scan had fetched
//!   it, and the build asked no host for the crate. Then `vex` is asked
//!   for its document. Hosted: it attests the crate, and the command of the
//!   mode, run a second time as on every run of a pipeline, reports the
//!   patch applied again and changes no file. Vendored: `vendor --check`
//!   passes and `vex` attests the crate, `//...` is the user's own target,
//!   and the commands that analyse every target pass (see "The build file
//!   in the copy").
//! - (d) The undo (`rollback --yes`, or `vendor --revert`) puts every file
//!   the command wrote back, byte for byte, and the build prints the
//!   unpatched marker again.
//! - (e) On a second machine (a new output base and, on Bazel 9, a new
//!   contents cache) the command runs against a second patch. The first
//!   machine is removed before the second one builds ([`second_machine`]).
//!   Hosted: the patch host serves another crate file than the one the lock
//!   pins, and the build fails on the checksum, whether the index of that
//!   host names the pinned checksum or the one of the file it serves; the
//!   upstream crate is not asked for in its place. Vendored: the first
//!   build there is the patched one, and the command of the mode, run a
//!   second time, reports the copy `already_vendored`, downloads nothing
//!   and changes no file; `vendor --check` passes and `vex` attests the
//!   crate. Then a build file that cargo-bazel did not write is put into
//!   the copy (see "The build file in the copy"), and then the library of
//!   the copy is changed. Nothing in a build holds the committed copy to a
//!   checksum, as nothing does for any crate a Cargo workspace takes from a
//!   path: the changed library is what Bazel builds next, and it is
//!   `socket-patch vendor --check` that reports the copy
//!   (`vendor_hash_mismatch`).
//!
//! What a build writes into the checkout, and so what (c), (d) and (e)
//! expect beyond that, depends on the ruleset ([`watches`]). rules_rust
//! 0.75.0 has Bazel watch the files the hub reads, and `MODULE.bazel.lock`
//! gets an entry for the hub. Every edit of `Cargo.lock` leaves that lock
//! stale, the command's and the undo's alike: a build that may not update
//! it (`--lockfile_mode=error`, as a CI with a frozen lock runs it) fails
//! until a build that may, or `bazel mod deps --lockfile_mode=update`, has
//! rewritten it and the user has committed that. So the first patched build
//! rewrites Bazel's lock, the undo leaves that lock behind, and the next
//! build writes the one of before.
//!
//! With rules_rust 0.56.0 Bazel's lock has no entry for the hub and a build
//! writes no file: the undo restores the checkout at once. With rules_rust
//! 0.75.0 a build also writes a `BUILD.bazel` into the vendored copy (see
//! "The build file in the copy"). With either, `vendor --check` passes
//! right after the build, `vex` attests the crate, and a second scan
//! reports the copy `already_vendored` and leaves it alone.
//!
//! The two releases also differ in the home of the hub's cargo
//! ([`cargo_env`]). rules_rust 0.75.0 gives it a directory inside the
//! output base that is empty whenever the hub is evaluated, so every
//! evaluation reads the index and downloads the crate file again: in hosted
//! mode the patch host has to answer then. rules_rust 0.56.0 runs cargo
//! with the home it is given, and that cargo asks for nothing its home
//! already holds.
//!
//! A marker is read from what Bazel built. Bazel's downloader keeps every
//! file it fetches in the repository cache, under its checksum, and hands it
//! out again without a request; the tests of a leg share that cache, and CI
//! restores it from earlier runs. So every crate file of a run is new: the
//! library of the upstream crate and of each patch holds an id made for the
//! run, which the marker shows, and the lock of the workspace copy gets the
//! upstream checksum from the bytes the run serves ([`lock_pinning`]); the
//! fixture's own lock holds a placeholder there.
//!
//! One loopback server per checkout (the second machine of (e) has its own)
//! stands in for the Socket API, for the patch host (the sparse index of the
//! patch registry and the crate file) and for crates.io (`index.crates.io`
//! and `static.crates.io`, by route prefix; `rollback` reads the upstream
//! checksum there through `SOCKET_CRATES_INDEX`). No downloader config
//! reaches cargo, so the checkout says where its crates come from the way a
//! project behind a mirror of crates.io does: its `.cargo/config.toml`
//! replaces the `crates-io` source with the stand-in ([`mirror_config`]),
//! and the hub names that file. That is why the hub of the vendored flow
//! names a config too, which vendored mode itself does not need:
//! cargo-bazel leaves the cargo config of a checkout out of the workspace
//! it resolves unless the hub names it, so a hub without one resolves
//! against crates.io itself, where no crate of a test can be. The crate is
//! the tests' own, under a name that crates.io cannot hold ([`NAME`]). What
//! rules_rust downloads for itself still comes from the network: its
//! archives and the cargo-bazel binary (GitHub), the Rust toolchain
//! (static.rust-lang.org), and the crates it builds its own tools from
//! (static.crates.io).
//!
//! # The hub without a cargo config
//!
//! A third flow ([`hosted_from_cargo_without_config`]) runs hosted mode on
//! the hub as the rules_rust README has it, which names no `cargo_config`
//! ([`open_readme_hub`]). cargo-bazel then hands no cargo config of the
//! checkout to its cargo, so the registry that hosted mode defines in
//! `.cargo/config.toml` and names in `Cargo.toml` would be one that cargo
//! has never heard of, and the hub would fail on the manifest (`registry
//! index was not found in any configuration`). The flow holds that
//! `socket-patch` writes no such pin:
//!
//! - (a) The build prints the unpatched marker.
//! - (b) `scan --mode hosted --yes` exits 0, reports the crate as skipped
//!   and warns `redirect_cargo_bazel_config_unread`: the warning names the
//!   hub by its file and line, the config to commit, the attribute the hub
//!   lacks and vendored mode. No file of the checkout changes, and a
//!   person is told the same.
//! - (c) The same build still prints the unpatched marker and changes no
//!   file.
//! - (d) The second way the warning names, on the hub as it is: `scan
//!   --mode vendored --yes`, and the build prints the patched marker, from
//!   the committed copy. `vendor --revert` gives the checkout back.
//! - (e) The first way: the checkout gets `.cargo/config.toml`, with a
//!   comment line in it, and the hub `cargo_config =
//!   "//:.cargo/config.toml"`. The same scan then applies the patch and
//!   rewrites the three files, and the build prints the patched marker,
//!   from the patch host.
//!
//! The tests without a Bazel run the same command in checkouts of the
//! fixture's Cargo files ([`checkout`]): what it writes where no hub reads
//! them is what it writes in no Bazel workspace, byte for byte.
//!
//! # The build file in the copy
//!
//! cargo-bazel renders a build file for every crate of the hub. Since
//! rules_rust 0.59.0 the one of a crate that the workspace takes from a
//! path goes to `<path>/BUILD.bazel`, into the checkout
//! (`crate_universe/src/rendering.rs`, `render_build_files`), each time
//! Bazel evaluates the hub, which a build does when a file the hub reads
//! has changed since the last one. The hub does not build the crate from
//! there: it copies the directory into a repository of its own and renders
//! the `BUILD.bazel` of that repository again, over the copied one
//! (`crate_universe/private/local_crate_mirror.bzl`). What the flow holds
//! of that:
//!
//! - Where the ruleset writes the file, it starts with the banner of every
//!   file cargo-bazel renders ([`BANNER`]), and `socket-patch` takes a
//!   `BUILD.bazel` that starts so, in the copy's own directory of a
//!   project whose Bazel workspace has a crate hub, for no change of the
//!   copy: the scan recorded no such file, and the commands above pass all
//!   the same.
//! - Bazel would read that file as a package of the user's workspace. The
//!   crate has a dependency ([`DEP`]), so the file names a repository of
//!   the hub, which the main repository does not see, and the commands
//!   that analyse every target fail on it: `bazel cquery //...` and
//!   `bazel query 'deps(//...)'` ([`analyses`]). The line that the scan
//!   wrote into `.bazelignore` keeps the copies out of Bazel's packages:
//!   `//...` is the user's own target ([`every_target`]), both commands
//!   pass, and the build is the patched one, because the hub reads the
//!   copy by its path, not as a package. A user who comments the line out
//!   has the package back, and the two commands fail where the ruleset
//!   writes the file.
//! - With either ruleset, a build file that someone else put there under
//!   the same banner does not reach the crate: the build still prints the
//!   patched marker. `vendor --check` passes on it: the banner is all that
//!   `socket-patch` reads of the file. Under the line it is no package.
//!   With the line commented out it is one, and `bazel build //...` builds
//!   its target.
//!
//! What else is a changed copy, and where the line is written, is held
//! without a Bazel
//! ([`only_the_build_file_of_cargo_bazel_is_no_change_of_a_vendored_copy`],
//! [`the_vendored_crates_get_a_bazelignore_line_where_a_crate_hub_builds_them`]).

use std::path::Path;
use std::time::Instant;

use base64::Engine as _;
use serde_json::json;
use sha2::{Digest, Sha256, Sha512};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;

use crate::envelope::{codes_in, event_for, has_event};
use crate::harness::{
    cell_without_bazel, changed, fixture_path, Cell, Fixture, Ran, Release, StandIn, Tree,
    CONSUMER, NOTHING, REPO_CACHE,
};
use crate::hosted_memory_common::{Patch, ORG};

/// The first Bazel release that [`FIXTURE`] builds with rules_rust 0.75.0.
const NEWER_RULESET: Release = (8, 0, 0);

/// The workspace the tests build, and the ruleset each Bazel release builds
/// it with. rules_rust 0.75.0 builds it on Bazel 7.7.2 as well (the hosted
/// flow passed there). Bazel 7 keeps the older release for what that one
/// does differently ([`watches`], [`cargo_env`]).
const FIXTURE: Fixture = Fixture {
    name: "cargo::FIXTURE",
    dir: "rules_rust/bzlmod",
    workflow: "bazel-cargo.yml",
    eras: &[
        // rules_rust 0.56.0, with Rust 1.83.0.
        ((7, 0, 0)..NEWER_RULESET, "e7"),
        // rules_rust 0.75.0, with Rust 1.99.1.
        (NEWER_RULESET..(10, 0, 0), "e9"),
    ],
};

/// The crate the fixture depends on, at the version its lock pins. crates.io
/// takes no name of more than 64 characters (the Cargo Book says so where it
/// describes the `name` field), so nobody can publish this one there: a
/// cargo or a Bazel that gets past the stand-in finds no stranger's crate,
/// and the build fails.
const NAME: &str = "socket-patch-bazel-fixture-with-a-name-that-is-too-long-for-crates-io";
const VERSION: &str = "1.0.0";
const PURL: &str =
    "pkg:cargo/socket-patch-bazel-fixture-with-a-name-that-is-too-long-for-crates-io@1.0.0";
/// The crate that one depends on, at the same version, which the same
/// registry holds under a name crates.io cannot hold either. Its crate
/// file is the same in every run. With a dependency, the build file that
/// cargo-bazel renders for [`NAME`] names a repository of the hub.
const DEP: &str =
    "socket-patch-bazel-fixture-dependency-with-a-name-that-is-too-long-for-crates-io";
/// The `Cargo.toml` of each. The other file of a crate file is `src/lib.rs`.
const CRATE_MANIFEST: &str = "[package]\n\
    name = \"socket-patch-bazel-fixture-with-a-name-that-is-too-long-for-crates-io\"\n\
    version = \"1.0.0\"\n\
    edition = \"2021\"\n\
    \n\
    [dependencies]\n\
    socket-patch-bazel-fixture-dependency-with-a-name-that-is-too-long-for-crates-io = \"1.0.0\"\n";
const DEP_MANIFEST: &str = "[package]\n\
    name = \"socket-patch-bazel-fixture-dependency-with-a-name-that-is-too-long-for-crates-io\"\n\
    version = \"1.0.0\"\n\
    edition = \"2021\"\n";
/// The files of the checkout that cargo and the hub read, and Bazel's lock.
const CONFIG: &str = ".cargo/config.toml";
const LOCK: &str = "Cargo.lock";
const MANIFEST: &str = "Cargo.toml";
const BAZEL_LOCK: &str = "MODULE.bazel.lock";
/// The file that declares the hub, and the line of it that names the cargo
/// config. Every era's hub has that line; without it the hub is the one of
/// the rules_rust README.
const MODULE: &str = "MODULE.bazel";
const HUB_CONFIG: &str = "    cargo_config = \"//:.cargo/config.toml\",\n";
/// How a `Cargo.lock` names crates.io, with or without a mirror, and how
/// the index of another registry names it.
const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";
const CRATES_IO_INDEX: &str = "https://github.com/rust-lang/crates.io-index";
/// Where a cargo home keeps what cargo has read of the sparse index of
/// crates.io: the directory cargo names so before 1.85 and the one from 1.85
/// on (the cargo of rules_rust 0.56.0 is 1.83.0, that of 0.75.0 is 1.99.1).
const CRATES_IO_INDEXES: [&str; 2] = [
    "registry/index/index.crates.io-6f17d22bba15001f",
    "registry/index/index.crates.io-1949cf8c6b5b557f",
];
/// What the fixture's lock holds as the checksum of the crate: the sum of
/// no file.
const PLACEHOLDER: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// The route prefixes under which the stand-in plays the two hosts of
/// crates.io, and the routes of the crate there: its file of the sparse
/// index, and its crate file. The dependency has the same two.
const INDEX: &str = "index.crates.io";
const FILES: &str = "static.crates.io";
const UPSTREAM_ENTRY: &str =
    "/index.crates.io/so/ck/socket-patch-bazel-fixture-with-a-name-that-is-too-long-for-crates-io";
const UPSTREAM_CRATE: &str = "/static.crates.io/crates/socket-patch-bazel-fixture-with-a-name-that-is-too-long-for-crates-io/1.0.0/download";
/// The access-token level of a hosted URL, which `socket-patch` writes as
/// the API hands it out.
const TOKEN: &str = "33333333-3333-4333-8333-333333333333";
/// How every file cargo-bazel renders begins: its banner, up to the name
/// of the tool (`crate_universe/src/rendering/templates/partials/header.j2`,
/// the same since 2022). The command that renders the file again follows.
const BANNER: &str =
    "###############################################################################\n\
    # @generated\n\
    # DO NOT MODIFY: This file is auto-generated by a crate_universe tool.";
/// The two lines `socket-patch` keeps in the `.bazelignore` of a workspace
/// with a crate hub while the project has vendored crates, and the same
/// with the path line commented out: a user's "no" to them.
const IGNORED: &str = "# socket-patch: patched crate copies, not Bazel packages (to opt out, \
    comment out the next line)\n.socket/vendor/cargo\n";
const DECLINED: &str = "# socket-patch: patched crate copies, not Bazel packages (to opt out, \
    comment out the next line)\n# .socket/vendor/cargo\n";
/// The cargo home of every `socket-patch` child: no directory, so a scan
/// finds the crate in the lock alone, as in a checkout only Bazel built.
const NO_CARGO_HOME: &str = "/nonexistent/cargo-home";

/// The sha256 of `bytes` in lowercase hex, as a `Cargo.lock` and a registry
/// index spell a checksum.
fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The crate `name` with `manifest` and with `lib_rs` as its library, as a
/// registry serves it. Every sum a test holds a build to is computed from
/// the bytes it serves, so nothing depends on the exact bytes the archive
/// crates emit.
fn crate_file(name: &str, manifest: &str, lib_rs: &str) -> Vec<u8> {
    let gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut archive = tar::Builder::new(gzip);
    for (file, text) in [("Cargo.toml", manifest), ("src/lib.rs", lib_rs)] {
        let mut header = tar::Header::new_ustar();
        header.set_size(text.len() as u64);
        header.set_mode(0o644);
        let path = format!("{name}-{VERSION}/{file}");
        archive
            .append_data(&mut header, path, text.as_bytes())
            .expect("tar");
    }
    let gzip = archive.into_inner().expect("tar");
    gzip.finish().expect("gzip")
}

/// One build of the crate: a library whose one constant is `<word> <id>`,
/// the crate file of it, and the line the consumer prints once Bazel built
/// that crate in. The id is new for every run, so no cache holds the file.
struct Package {
    lib_rs: String,
    crate_file: Vec<u8>,
    marker: String,
}

impl Package {
    fn new(word: &str, id: &str) -> Package {
        let lib_rs = format!("pub const STATUS: &str = \"{word} {id}\";\n");
        Package {
            crate_file: crate_file(NAME, CRATE_MANIFEST, &lib_rs),
            marker: format!("OUT: {word} {id}"),
            lib_rs,
        }
    }

    /// The crate as the registry of one run has it.
    fn upstream() -> Package {
        Package::new("PRISTINE", &uuid::Uuid::new_v4().to_string())
    }

    /// The checksum of the crate file.
    fn checksum(&self) -> String {
        sha256_hex(&self.crate_file)
    }

    /// The crate's file of a sparse index that lists this crate file: one
    /// line per version. It names the dependency as being in `registry`,
    /// an index: crates.io's own on the patch host, as cargo wants it of a
    /// registry that is not the dependency's, and none on crates.io itself.
    fn index_line(&self, registry: Option<&str>) -> String {
        let dependency = json!({
            "name": DEP, "req": format!("^{VERSION}"), "features": [], "optional": false,
            "default_features": true, "target": null, "kind": "normal", "registry": registry,
        });
        index_line(NAME, &self.checksum(), json!([dependency]))
    }
}

/// One line of a crate's file of a sparse index.
fn index_line(name: &str, checksum: &str, deps: serde_json::Value) -> String {
    let version = json!({
        "name": name, "vers": VERSION, "deps": deps, "features": {}, "yanked": false,
        "cksum": checksum,
    });
    format!("{version}\n")
}

/// The crate file of [`DEP`].
fn dependency_file() -> Vec<u8> {
    let lib_rs = "pub const DEPENDENCY: &str = \"of the fixture\";\n";
    crate_file(DEP, DEP_MANIFEST, lib_rs)
}

/// One patch of the crate, under an id that is new for every run.
struct Patched {
    uuid: String,
    package: Package,
    /// The route of the patch registry's sparse index, the one of the
    /// crate's file there, and the one of the crate file on the patch host.
    index: String,
    entry: String,
    route: String,
}

impl Patched {
    fn new() -> Patched {
        let uuid = uuid::Uuid::new_v4().to_string();
        let index = format!("/patch-registry/cargo/{TOKEN}/{uuid}/index");
        Patched {
            package: Package::new("PATCHED", &uuid),
            entry: format!("{index}/{}", index_path(NAME)),
            route: format!("/patch/cargo/{NAME}/{VERSION}/{TOKEN}/{uuid}/{NAME}-{VERSION}.crate"),
            index,
            uuid,
        }
    }

    /// The name hosted mode gives the patch registry in the cargo config.
    fn registry(&self) -> String {
        format!("socket-patch-{}", self.uuid)
    }

    /// Where vendored mode commits the unpacked crate.
    fn vendored(&self) -> String {
        format!(".socket/vendor/cargo/{}/{NAME}-{VERSION}", self.uuid)
    }
}

/// The path of the file of the crate `name` in a sparse index: cargo's
/// layout for a name of four characters or more.
fn index_path(name: &str) -> String {
    format!("{}/{}/{name}", &name[..2], &name[2..4])
}

/// What the lock's entry of the crate says of its dependency.
fn depends() -> String {
    format!("dependencies = [\n \"{DEP}\",\n]\n")
}

/// The entry of a lock that resolves the crate from `source` and pins its
/// crate file to `checksum`.
fn lock_entry(source: &str, checksum: &str) -> String {
    format!(
        "[[package]]\nname = \"{NAME}\"\nversion = \"{VERSION}\"\n\
         source = \"{source}\"\nchecksum = \"{checksum}\"\n{}",
        depends()
    )
}

/// The entry of a lock that pins the crate file of the dependency to
/// `checksum`.
fn dependency_entry(checksum: &str) -> String {
    format!(
        "[[package]]\nname = \"{DEP}\"\nversion = \"{VERSION}\"\n\
         source = \"{CRATES_IO}\"\nchecksum = \"{checksum}\"\n"
    )
}

/// The fixture's lock with the checksum of `upstream`, and the one of the
/// dependency, in place of the placeholders: the lock a test writes into
/// its workspace copy before the first build.
fn lock_pinning(upstream: &Package) -> String {
    let path = fixture_path(FIXTURE.dir).join("common").join(LOCK);
    let mut lock =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let dependency = dependency_entry(&sha256_hex(&dependency_file()));
    for (unpinned, pinned) in [
        (
            lock_entry(CRATES_IO, PLACEHOLDER),
            lock_entry(CRATES_IO, &upstream.checksum()),
        ),
        (dependency_entry(PLACEHOLDER), dependency),
    ] {
        let entries = lock.matches(&unpinned).count();
        assert_eq!(entries, 1, "{}: not one\n{unpinned}", path.display());
        lock = lock.replace(&unpinned, &pinned);
    }
    lock
}

/// The `.cargo/config.toml` of a checkout whose crates come from a mirror
/// of crates.io, the stand-in at `origin`. The fixture commits none: the
/// port is the run's. The hub names the file, so cargo-bazel's cargo reads
/// it, and cargo-bazel takes the download URL of a crate from the index the
/// replacement names.
fn mirror_config(origin: &str) -> String {
    format!(
        "# This project takes its crates from a mirror of crates.io.\n\
         [source.crates-io]\n\
         replace-with = \"mirror\"\n\
         \n\
         [source.mirror]\n\
         registry = \"sparse+{origin}/{INDEX}/\"\n"
    )
}

/// A stand-in that holds `upstream` as crates.io does: the `config.json` of
/// the sparse index, which names the download host the way the real one
/// does (a base URL, to which cargo adds `/<name>/<version>/download`), the
/// crate's file of the index, and the crate file. And the same two of the
/// dependency.
fn registry(upstream: &Package) -> StandIn {
    let standin = StandIn::start();
    let origin = standin.origin();
    let config = json!({ "dl": format!("{origin}/{FILES}/crates"), "api": origin });
    let config = serde_json::to_vec(&config).expect("a JSON document");
    standin.serve(5, &format!("/{INDEX}/config.json"), &config);
    standin.serve(5, UPSTREAM_ENTRY, upstream.index_line(None).as_bytes());
    standin.serve(5, UPSTREAM_CRATE, &upstream.crate_file);
    let dependency = dependency_file();
    let listed = index_line(DEP, &sha256_hex(&dependency), json!([]));
    let entry = format!("/{INDEX}/{}", index_path(DEP));
    standin.serve(5, &entry, listed.as_bytes());
    let file = format!("/{FILES}/crates/{DEP}/{VERSION}/download");
    standin.serve(5, &file, &dependency);
    standin
}

/// The Socket API on `standin` for `patch` of `upstream`, free for every
/// caller, and the patch host: the sparse index of the patch registry, in
/// the shape of production, and `served` at the URL of the crate file. The
/// API and the index name the checksum of the patch's own crate file,
/// whatever is served.
fn grant(standin: &StandIn, upstream: &Package, patch: &Patched, served: &[u8]) {
    let origin = standin.origin();
    let url = format!("{origin}{}", patch.route);
    let checksum = patch.package.checksum();
    let sha512 = Sha512::digest(&patch.package.crate_file);
    let sha512 = base64::engine::general_purpose::STANDARD.encode(sha512);
    let reference = json!({
        "status": "granted",
        "url": url,
        "purl": PURL,
        "artifacts": [{
            "kind": "tarball",
            "url": url,
            // Vendored mode holds the file it downloads to the sha512.
            "integrity": { "sha256": checksum, "sha512": format!("sha512-{sha512}") },
        }],
        "registryOverride": {
            "kind": "cargo-sparse",
            "indexUrl": format!("sparse+{origin}{}/", patch.index),
            "identifiers": { "name": NAME, "version": VERSION, "cargoCksumSha256": checksum },
        },
    });
    let granted = Patch {
        purl: PURL.to_string(),
        uuid: patch.uuid.clone(),
        reference,
    };
    standin.api(&[granted]);
    // Priority 1: ahead of the shared API mock's patch record, whose hashes
    // are fixed, because vendored mode holds the unpacked library to
    // `afterHash`.
    let record = json!({
        "uuid": patch.uuid,
        "purl": PURL,
        "publishedAt": "2026-01-01T00:00:00Z",
        "files": { "src/lib.rs": {
            "beforeHash": compute_git_sha256_from_bytes(upstream.lib_rs.as_bytes()),
            "afterHash": compute_git_sha256_from_bytes(patch.package.lib_rs.as_bytes()),
        }},
        "vulnerabilities": { "GHSA-test-aaaa-bbbb": {
            "cves": ["CVE-2024-0001"], "summary": "s", "severity": "high", "description": "d",
        }},
        "description": "fixture",
        "license": "MIT",
        "tier": "free",
    });
    let record = serde_json::to_vec(&record).expect("a JSON document");
    let record_route = format!("/v0/orgs/{ORG}/patches/view/{}", patch.uuid);
    standin.serve(1, &record_route, &record);
    let dl = format!(
        "{origin}/patch/cargo/{{crate}}/{{version}}/{TOKEN}/{}/{{crate}}-{{version}}.crate",
        patch.uuid
    );
    let config = serde_json::to_vec(&json!({ "dl": dl, "api": origin })).expect("a JSON document");
    standin.serve(5, &format!("{}/config.json", patch.index), &config);
    let listed = patch.package.index_line(Some(CRATES_IO_INDEX));
    standin.serve(5, &patch.entry, listed.as_bytes());
    standin.serve(5, &patch.route, served);
}

/// What the hub and the cargo that cargo-bazel starts read, for
/// [`Cell::repo_env`]. The harness removes every `CARGO_*` name and `REPIN`
/// of the caller from a Bazel child, so no cargo setting of a shell and no
/// repin switch reaches the hub, and these two are set after that.
/// `CARGO_HOME` is `home`, a directory of the test: under Bzlmod rules_rust
/// 0.56.0 runs its cargo with the cargo home of the environment, and a
/// flow says which one that is. rules_rust 0.75.0 gives its cargo a home
/// inside the output base when `isolated`, which `CARGO_BAZEL_ISOLATED`
/// states, and runs it with `home` as well when not.
fn cargo_env(home: &Path, isolated: bool) -> Vec<(String, String)> {
    let (home, isolated) = (home.to_string_lossy(), isolated.to_string());
    let pins = [("CARGO_HOME", &*home), ("CARGO_BAZEL_ISOLATED", &*isolated)];
    let owned = pins.map(|(name, value)| (name.to_string(), value.to_string()));
    owned.to_vec()
}

/// An empty cargo home, for the Bazel children of one machine.
fn cargo_home() -> tempfile::TempDir {
    tempfile::tempdir().expect("create a cargo home")
}

/// The checkout of the fixture for `test`, the upstream crate of this run,
/// which the lock of the checkout pins, and the stand-in that holds it,
/// which the config of the checkout names. The cargo home comes first: it
/// goes last. `None` after a `SKIP` line when no Bazel runs here.
fn open(test: &str) -> Option<(tempfile::TempDir, Cell, StandIn, Package)> {
    let mut cell = Cell::open(test, &FIXTURE)?;
    let home = cargo_home();
    cell.repo_env = cargo_env(home.path(), true);
    let upstream = Package::upstream();
    let standin = registry(&upstream);
    cell.write(LOCK, lock_pinning(&upstream));
    cell.write(CONFIG, mirror_config(&standin.origin()));
    Some((home, cell, standin, upstream))
}

/// [`open`] for the hub of the rules_rust README: the `MODULE.bazel` of the
/// era without the line that names a cargo config, in a checkout that has
/// none.
///
/// The crate still comes from the stand-in, the way the README says a
/// private registry is reached: `CARGO_BAZEL_ISOLATED=false` has the hub run
/// its cargo with the cargo home of the machine, here the one of the test,
/// and that home's `config.toml` names the mirror. cargo-bazel itself reads
/// no cargo config the hub does not name, so for a crate the lock takes
/// from crates.io it goes by what the cargo home keeps of that index: the
/// `config.json`, for the download URL, and with rules_rust 0.56.0 the
/// files of the index of the crate and of its dependency as well. A cargo behind a mirror fetches
/// neither. The home holds both, as a home does whose cargo has fetched the
/// crate from crates.io itself, with the stand-in as the download host.
fn open_readme_hub(test: &str) -> Option<(tempfile::TempDir, Cell, StandIn, Package)> {
    let mut cell = Cell::open(test, &FIXTURE)?;
    let home = cargo_home();
    cell.repo_env = cargo_env(home.path(), false);
    let upstream = Package::upstream();
    let standin = registry(&upstream);
    let origin = standin.origin();
    cell.write(LOCK, lock_pinning(&upstream));
    let module = std::fs::read_to_string(cell.path(MODULE)).expect(MODULE);
    cell.write(MODULE, module.replace(HUB_CONFIG, ""));
    let keep = |rel: &str, bytes: &[u8]| {
        let path = home.path().join(rel);
        std::fs::create_dir_all(path.parent().expect("a file path")).expect("create the parent");
        std::fs::write(&path, bytes).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    };
    keep("config.toml", mirror_config(&origin).as_bytes());
    let index = json!({ "dl": format!("{origin}/{FILES}/crates"), "api": origin }).to_string();
    // The file of the index of the crate and of its dependency as cargo
    // caches it: the version of the cache format (3) and of the index schema
    // (2), what the server said of the file's age, and per release its
    // version and its line of the file.
    let cached = |line: String| {
        let cached = format!("etag: \"run\"\0{VERSION}\0{}\0", line.trim_end());
        [&[3][..], &2u32.to_le_bytes(), cached.as_bytes()].concat()
    };
    let lines = [
        (NAME, cached(upstream.index_line(None))),
        (
            DEP,
            cached(index_line(DEP, &sha256_hex(&dependency_file()), json!([]))),
        ),
    ];
    for directory in CRATES_IO_INDEXES {
        keep(&format!("{directory}/config.json"), index.as_bytes());
        for (name, cached) in &lines {
            keep(&format!("{directory}/.cache/{}", index_path(name)), cached);
        }
    }
    Some((home, cell, standin, upstream))
}

/// `socket-patch <args>` in `cell`, with `standin` as the Socket API, as
/// the patch server (a hosted pin is recognised by that origin) and as the
/// index `rollback` reads the upstream checksum from.
fn socket_patch(cell: &Cell, standin: &StandIn, args: &[&str]) -> Ran {
    let (origin, index) = hosts(standin);
    cell.socket_patch(&origin, args, &env(&origin, &index))
}

/// [`socket_patch`] as a person runs it: what it printed on stdout and on
/// stderr.
fn person(cell: &Cell, standin: &StandIn, args: &[&str]) -> [String; 2] {
    let (origin, index) = hosts(standin);
    cell.socket_patch_person(&origin, args, &env(&origin, &index))
}

/// The origin of `standin`, and the index of crates.io there.
fn hosts(standin: &StandIn) -> (String, String) {
    let origin = standin.origin();
    let index = format!("{origin}/{INDEX}");
    (origin, index)
}

/// What a `socket-patch` child of a flow is told of its hosts.
fn env<'a>(origin: &'a str, index: &'a str) -> [(&'a str, &'a str); 3] {
    [
        ("SOCKET_PATCH_SERVER_URL", origin),
        ("SOCKET_CRATES_INDEX", index),
        ("CARGO_HOME", NO_CARGO_HOME),
    ]
}

/// A text file of a tree.
fn text(tree: &Tree, rel: &str) -> String {
    String::from_utf8(tree[rel].clone()).expect("a text file")
}

/// Whether the ruleset of `cell` has Bazel watch the files the hub reads,
/// writes into a crate the workspace takes from a path, and gives the hub's
/// cargo an empty home at every evaluation: rules_rust 0.75.0 does all
/// three, 0.56.0 none. Read from the release, as the era is.
fn watches(cell: &Cell) -> bool {
    cell.numbers() >= NEWER_RULESET
}

/// What the first build of `cell` that takes the crate from one registry of
/// `standin` leaves there: the stand-in was asked for `entry`, the crate's
/// file of that index, and at least twice for `file`, the crate file, which
/// no cache holds. That is all this holds. The stand-in records the path of
/// a request and not who sent it, so which of the two came from the hub's
/// cargo and which from Bazel's downloader is not told apart.
fn asked_for(cell: &Cell, standin: &StandIn, entry: &str, file: &str) {
    let (asked, fetches) = (standin.asked(entry), standin.asked(file));
    assert!(
        asked > 0 && fetches >= 2,
        "{}: requests to the stand-in: {asked} for {entry} and {fetches} for {file}. A first \
         build asks for the index file, and at least twice for the crate file",
        cell.test
    );
}

/// Step (a): the build of `cell` prints the marker of `upstream`, and
/// `standin` was asked for the crate's file of the index and, at least
/// twice, for the crate file, which no cache holds ([`asked_for`]). Bazel's
/// lock has an entry for the hub exactly where the ruleset watches its
/// inputs: what the later steps expect of a release follows from it. Gives
/// the files of the checkout.
fn builds_upstream(cell: &Cell, standin: &StandIn, upstream: &Package) -> Tree {
    let before = cell.builds_unpatched(&upstream.marker);
    asked_for(cell, standin, UPSTREAM_ENTRY, UPSTREAM_CRATE);
    let locked = text(&before, BAZEL_LOCK).contains("crate_universe:extensions.bzl%crate");
    assert_eq!(
        locked,
        watches(cell),
        "{}: {BAZEL_LOCK} of Bazel {} must hold an entry for the hub with rules_rust 0.75.0 and \
         none with 0.56.0",
        cell.test,
        cell.release()
    );
    before
}

/// The build of a CI that holds Bazel's lock frozen, right after the
/// `socket-patch` command `after` on a ruleset that [`watches`]: Bazel must
/// refuse it over the lock.
fn refuses_stale_lock(cell: &Cell, after: &str) {
    let build = cell.bazel("build", &["--lockfile_mode=error", CONSUMER]);
    assert!(
        !build.ok()
            && build
                .stderr()
                .contains("MODULE.bazel.lock is no longer up-to-date"),
        "{}: right after `{after}`, a `--lockfile_mode=error` build on Bazel {} must fail on \
         the stale {BAZEL_LOCK}: with rules_rust 0.75.0 a user has to run a build that may \
         update it, or `bazel mod deps --lockfile_mode=update`, and commit the lock before a \
         CI with a frozen lock passes.\n{}",
        cell.test,
        cell.release(),
        build.dump()
    );
}

/// What a build after an edit of `Cargo.lock` rewrites in the checkout of
/// `cell`: Bazel's own lock where the ruleset [`watches`], and nothing else.
fn bazel_rewrites(cell: &Cell) -> &'static [&'static str] {
    if watches(cell) {
        &[BAZEL_LOCK]
    } else {
        &[]
    }
}

/// Step (d), for the finished undo: it counts one package under `counted`
/// of its summary, and every file of the checkout is the one of `before`
/// but Bazel's lock, which is the one of the patched build where the
/// ruleset [`watches`] and stale again. The next build prints `marker` and
/// puts that lock back: from then on every file is the one of `before`.
/// Written out, and not `Cell::undone`, which expects every file back
/// before that build.
fn undone(cell: &Cell, undo: &Ran, counted: &str, before: &Tree, marker: &str) {
    let (test, said) = (&cell.test, &undo.dump);
    assert_eq!(undo.code, 0, "{test}: {said}");
    assert_eq!(undo.envelope["summary"][counted], 1, "{test}: {said}");
    let left = changed(before, &cell.tree());
    assert_eq!(left, bazel_rewrites(cell), "{test}: {said}");
    if watches(cell) {
        refuses_stale_lock(cell, "the undo");
    }
    cell.builds(marker);
    assert_eq!(changed(before, &cell.tree()), NOTHING, "{test}");
}

/// Step (e), up to its build: a second machine with the checkout of `cell`,
/// a cargo home and a stand-in of its own, which its config names and its
/// commands talk to; the patch `second`, whose URL on that patch host
/// answers with `served`; and `scan --mode <mode> --yes` there, which
/// applies it.
///
/// The first machine ends here, before the second one builds: its Bazel
/// server is stopped and its scratch root removed, as at the end of a test.
/// Every workspace copy unpacks the Rust toolchain for itself (1.7 to
/// 1.8 GB), so a test holds one of them at a time and a leg of two tests
/// two, not four. The exception is a run that names no repository cache
/// ([`REPO_CACHE`]): the cache both machines read is then inside the first
/// one's scratch root, so the first machine is handed back, first in the
/// result, and stays until the test ends.
fn second_machine(
    cell: Cell,
    upstream: &Package,
    mode: &str,
    second: &Patched,
    served: &[u8],
) -> (Option<Cell>, tempfile::TempDir, Cell, StandIn) {
    let mut twin = cell.twin();
    let shared = std::env::var_os(REPO_CACHE).is_some_and(|dir| !dir.is_empty());
    let first = if shared {
        drop(cell);
        None
    } else {
        Some(cell)
    };
    let home = cargo_home();
    twin.repo_env = cargo_env(home.path(), true);
    let other = registry(upstream);
    twin.write(CONFIG, mirror_config(&other.origin()));
    grant(&other, upstream, second, served);
    let scan = socket_patch(&twin, &other, &["scan", "--mode", mode, "--yes"]);
    let (test, said) = (&twin.test, &scan.dump);
    assert_eq!(scan.code, 0, "{test}: {said}");
    assert_eq!(scan.envelope["summary"]["applied"], 1, "{test}: {said}");
    (first, home, twin, other)
}

/// The build of `twin` fails, and what cargo says about the crate holds
/// `refusal`.
fn refuses(twin: &Cell, refusal: &str) {
    let build = twin.bazel("build", &[CONSUMER]);
    let stderr = build.stderr();
    let about = format!("`{NAME} v{VERSION} (registry `");
    let said = stderr
        .lines()
        .any(|line| line.contains(&about) && line.contains(refusal));
    assert!(
        !build.ok() && said,
        "{}: the build did not fail with {refusal:?} for {about}:\n{}",
        twin.test,
        build.dump()
    );
}

/// What Bazel takes the checkout of `cell` for: `bazel build //...` passes,
/// and these are the targets `bazel query //...` lists, sorted.
fn every_target(cell: &Cell) -> Vec<String> {
    let build = cell.bazel("build", &["//..."]);
    assert!(build.ok(), "{}: {}", cell.test, build.dump());
    let query = cell.bazel("query", &["//..."]);
    assert!(query.ok(), "{}: {}", cell.test, query.dump());
    let mut targets: Vec<String> = query.stdout().lines().map(str::to_string).collect();
    targets.sort();
    targets
}

/// Whether the commands that analyse every target of the checkout of
/// `cell` pass: `bazel cquery //...` and `bazel query 'deps(//...)'`, which
/// agree. One that fails has met a repository that the build file in the
/// copy names and the main repository does not see: one of the hub, or
/// `platforms`. Bazel names the first one it meets, and which one that is
/// differs from run to run.
fn analyses(cell: &Cell) -> bool {
    let runs = [("cquery", "//..."), ("query", "deps(//...)")];
    let runs = runs.map(|(command, targets)| cell.bazel(command, &[targets]));
    for run in &runs {
        let stderr = run.stderr();
        let unseen = ["@crates__", "@platforms'"]
            .iter()
            .any(|repo| stderr.contains(&format!("No repository visible as '{repo}")));
        assert_ne!(run.ok(), unseen, "{}: {}", cell.test, run.dump());
    }
    assert_eq!(runs[0].ok(), runs[1].ok(), "{}", cell.test);
    runs[0].ok()
}

/// `vex` in the checkout of `cell`, which holds the files of `built`. Its
/// document goes beside the checkout ([`Cell::document`]), and
/// no file of the checkout changes. With `attested` it exits 0 and the
/// document names the crate as patched by `patch`. Without, for a vendored
/// copy that is a changed one, it exits 1 and writes no document: the
/// patch is left out over the inventory of the copy
/// (`vendor_inventory_mismatch`), and nothing else is there to attest.
fn vex(cell: &Cell, standin: &StandIn, patch: &Patched, built: &Tree, attested: bool) {
    let test = &cell.test;
    let document = cell.document("vex");
    let _ = std::fs::remove_file(&document);
    let output = document.to_string_lossy();
    let vex = socket_patch(cell, standin, &["vex", "--output", &output]);
    let said = &vex.dump;
    let written = std::fs::read_to_string(&document).unwrap_or_default();
    if attested {
        assert_eq!(vex.code, 0, "{test}: {said}");
        let action = &event_for(&vex.envelope, PURL)["action"];
        assert_eq!(*action, "verified", "{test}: {said}");
        let by = format!("Patched via Socket patch {}", patch.uuid);
        let names = written.contains(&format!("\"{PURL}\"")) && written.contains(&by);
        assert!(names, "{test}: {said}\n{written}");
    } else {
        assert_eq!(vex.code, 1, "{test}: {said}");
        let left_out = has_event(&vex.envelope, "skipped", "vendor_inventory_mismatch", PURL);
        assert!(left_out, "{test}: {said}");
        let error = &vex.envelope["error"]["code"];
        assert_eq!(*error, "no_applicable_patches", "{test}: {said}");
        assert!(!document.exists(), "{test}: {said}\n{written}");
    }
    assert_eq!(changed(built, &cell.tree()), NOTHING, "{test}");
}

/// The hosted flow of the module docs.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn hosted_from_cargo_with_config() {
    let test = "cargo::hosted_from_cargo_with_config";
    let started = Instant::now();
    let Some((_home, cell, standin, upstream)) = open(test) else {
        return;
    };
    let release = cell.release().to_string();
    let origin = standin.origin();
    let patch = Patched::new();
    grant(&standin, &upstream, &patch, &patch.package.crate_file);

    // (a) The unpatched build, with the upstream crate from the stand-in.
    let before = builds_upstream(&cell, &standin, &upstream);
    let upstream_fetches = standin.asked(UPSTREAM_CRATE);

    // (b) The one command of hosted mode. It rewrites those three files and
    // no other: the config keeps what the project had and gains the patch
    // registry, the dependency names that registry, and the entry of the
    // lock resolves from it, with the checksum of the patched crate file.
    let scan = socket_patch(&cell, &standin, &["scan", "--mode", "hosted", "--yes"]);
    let said = &scan.dump;
    let written = [CONFIG, LOCK, MANIFEST];
    let pinned = cell.pinned_by(&scan, PURL, &patch.uuid, &before, &written);
    let (index, registry) = (format!("sparse+{origin}{}/", patch.index), patch.registry());
    let config = text(&pinned, CONFIG);
    let added = format!("[registries.{registry}]\nindex = \"{index}\"\n");
    assert!(
        config.starts_with(&mirror_config(&origin)) && config.ends_with(&added),
        "{test}: {CONFIG}:\n{config}"
    );
    let manifest = text(&pinned, MANIFEST);
    let dependency = format!("{NAME} = {{ version = \"{VERSION}\", registry = \"{registry}\" }}\n");
    assert!(
        manifest.contains(&dependency),
        "{test}: {MANIFEST}:\n{manifest}"
    );
    let lock = text(&pinned, LOCK);
    let entry = lock_entry(&index, &patch.package.checksum());
    assert!(lock.contains(&entry), "{test}: {LOCK}:\n{lock}");
    assert_eq!(standin.asked(&patch.route), 0, "{test}: {said}");
    if watches(&cell) {
        refuses_stale_lock(&cell, "scan --mode hosted");
    }

    // (c) The same build, no step in between and no repin: patched, from
    // the patch host, which was asked for its index file of the crate and,
    // at least twice, for the crate file.
    cell.builds(&patch.package.marker);
    asked_for(&cell, &standin, &patch.entry, &patch.route);
    assert_eq!(
        standin.asked(UPSTREAM_CRATE),
        upstream_fetches,
        "{test}: the patched build asked for the upstream crate file"
    );
    // Bazel changed no file of the checkout but its own lock, and from here
    // on the checkout stands: the next build changes no file, and that lock
    // holds when Bazel may not update it.
    let built = cell.tree();
    let by_bazel = bazel_rewrites(&cell);
    assert_eq!(changed(&pinned, &built), by_bazel, "{test}");
    // Where that lock has an entry for the hub, it now names the crate file
    // on the patch host, token level included, as `Cargo.lock` names the
    // index there.
    let names_patch_host = text(&built, BAZEL_LOCK).contains(&format!("{origin}{}", patch.route));
    assert_eq!(names_patch_host, watches(&cell), "{test}: {BAZEL_LOCK}");
    cell.builds_patched(&built, &patch.package.marker);
    // `vex` attests the crate. The same command a second time, as every run
    // of a pipeline has it, applies the patch again and changes no file.
    vex(&cell, &standin, &patch, &built, true);
    let again = socket_patch(&cell, &standin, &["scan", "--mode", "hosted", "--yes"]);
    let said = &again.dump;
    assert_eq!(again.code, 0, "{test}: {said}");
    assert_eq!(again.envelope["summary"]["applied"], 1, "{test}: {said}");
    let rewritten = &again.envelope["redirect"]["rewrittenFiles"];
    assert_eq!(*rewritten, json!([]), "{test}: {said}");
    assert_eq!(changed(&built, &cell.tree()), NOTHING, "{test}: {said}");

    // (d) The undo. The three files are the ones of before at once; the
    // config is still there, with what the project had in it.
    let undo = socket_patch(&cell, &standin, &["rollback", "--yes"]);
    undone(&cell, &undo, "rolledBack", &before, &upstream.marker);
    // The build after the undo evaluated the hub again, with the lock of
    // before. Where the ruleset gives the hub's cargo an empty home every
    // time, the stand-in was asked for the upstream crate file once more
    // (Bazel's repository cache holds it, a new cargo home does not).
    // Elsewhere the cargo home of the test held it, and no request was
    // sent.
    let asked_again = standin.asked(UPSTREAM_CRATE) > upstream_fetches;
    assert_eq!(
        asked_again,
        watches(&cell),
        "{test}: requests to the stand-in for the upstream crate file: {} before the undo and \
         {} by the end of its build",
        upstream_fetches,
        standin.asked(UPSTREAM_CRATE)
    );

    // (e) A second machine, a second patch, and a patch host that serves
    // another crate file than the one the lock pins. Its index names the
    // pinned checksum, as the real one does, so cargo refuses the file it
    // downloaded.
    let second = Patched::new();
    let tampered = Package::new("TAMPERED", &second.uuid);
    let (_first, _second_home, mut twin, other) =
        second_machine(cell, &upstream, "hosted", &second, &tampered.crate_file);
    refuses(&twin, "failed to verify the checksum of");
    // The patch host was asked for the file, so the build failed on what it
    // got. The evidence line has the count.
    let refused_fetches = other.asked(&second.route);
    assert!(
        refused_fetches > 0,
        "{test}: the patch host was not asked, so the failed build proves nothing"
    );
    // A patch host that also names the checksum of what it serves gets no
    // further: the checksum of the lock is not the one of its index. That
    // build starts from a cargo home that has not seen the index, as the
    // first build of a machine does. rules_rust 0.56.0 keeps the home it is
    // given from build to build, and cargo does not ask again for the index
    // file of a crate the lock pins while its home holds one.
    let listed = tampered.index_line(Some(CRATES_IO_INDEX));
    other.serve(1, &second.entry, listed.as_bytes());
    let third_home = cargo_home();
    twin.repo_env = cargo_env(third_home.path(), true);
    let asked = other.asked(&second.entry);
    refuses(&twin, "changed between lock files");
    assert!(
        other.asked(&second.entry) > asked,
        "{test}: the index of the patch host was not asked, so the failed build proves nothing"
    );
    assert_eq!(
        other.asked(UPSTREAM_CRATE),
        0,
        "{test}: the build went to the upstream crate"
    );

    println!(
        "{test}: Bazel {release} built {:?} from {index} after `scan --mode hosted`, with no \
         repin, and rewrote {:?} itself; `vex` attested the crate and a second scan applied \
         the patch again without a change; `rollback` restored the three files at once, and the \
         next build printed {:?} and left all {} files as before; another crate file at the \
         patch host failed a second machine's build on the checksum, with the index naming the \
         pinned sum (requests to that patch host for the file: {refused_fetches}) and with it \
         naming the served one; requests to the stand-in for the upstream crate file: {}, {} of \
         them before the undo, and for the patched one: {}; {:?}",
        patch.package.marker,
        by_bazel,
        upstream.marker,
        before.len(),
        standin.asked(UPSTREAM_CRATE),
        upstream_fetches,
        standin.asked(&patch.route),
        started.elapsed()
    );
}

/// The vendored flow of the module docs.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn vendored_from_cargo_with_config() {
    let test = "cargo::vendored_from_cargo_with_config";
    let started = Instant::now();
    let Some((_home, cell, standin, upstream)) = open(test) else {
        return;
    };
    let release = cell.release().to_string();
    let patch = Patched::new();
    grant(&standin, &upstream, &patch, &patch.package.crate_file);

    // (a) The unpatched build, with the upstream crate from the stand-in.
    let before = builds_upstream(&cell, &standin, &upstream);

    // (b) The one command of vendored mode.
    let scan = socket_patch(&cell, &standin, &["scan", "--mode", "vendored", "--yes"]);
    let said = &scan.dump;
    assert_eq!(scan.code, 0, "{test}: {said}");
    assert_eq!(scan.envelope["status"], "success", "{test}: {said}");
    assert_eq!(scan.envelope["summary"]["downloaded"], 1, "{test}: {said}");
    assert_eq!(scan.envelope["summary"]["applied"], 1, "{test}: {said}");
    // The unpacked crate and its ledger under `.socket/vendor`, the two
    // files that wire it in, the line that keeps Bazel out of the copies,
    // and no other.
    let copy = patch.vendored();
    let (copied_manifest, library) = (format!("{copy}/Cargo.toml"), format!("{copy}/src/lib.rs"));
    let written = [
        ".bazelignore".to_string(),
        copied_manifest.clone(),
        library.clone(),
        format!(
            ".socket/vendor/cargo/{}/socket-patch.vendor.json",
            patch.uuid
        ),
        ".socket/vendor/state.json".to_string(),
        LOCK.to_string(),
        MANIFEST.to_string(),
    ];
    let vendored = cell.tree();
    assert_eq!(changed(&before, &vendored), written, "{test}: {said}");
    assert_eq!(text(&vendored, ".bazelignore"), IGNORED, "{test}: {said}");
    // The committed library is the one of the crate file the patch host
    // served. The copy says it is the patched build of the version, a
    // `[patch.crates-io]` entry sends the crate there, and the lock's entry
    // has the copy's version and neither a source nor a checksum.
    assert_eq!(text(&vendored, &library), patch.package.lib_rs, "{test}");
    assert!(standin.asked(&patch.route) > 0, "{test}: {said}");
    let tagged = format!("{VERSION}+socket.{}", patch.uuid);
    let copied_manifest = text(&vendored, &copied_manifest);
    assert!(
        copied_manifest.contains(&format!("version = \"{tagged}\"\n")),
        "{test}: {copy}/Cargo.toml:\n{copied_manifest}"
    );
    let manifest = text(&vendored, MANIFEST);
    let patched_by = format!(
        "[patch.crates-io]\n{NAME}-socket-{} = {{ package = \"{NAME}\", path = \"{copy}\" }}\n",
        &patch.uuid[..8]
    );
    assert!(
        manifest.contains(&patched_by),
        "{test}: {MANIFEST}:\n{manifest}"
    );
    let lock = text(&vendored, LOCK);
    let entry = format!(
        "[[package]]\nname = \"{NAME}\"\nversion = \"{tagged}\"\n{}",
        depends()
    );
    assert!(
        lock.ends_with(&entry) && !lock.contains(&upstream.checksum()),
        "{test}: {LOCK}:\n{lock}"
    );
    if watches(&cell) {
        refuses_stale_lock(&cell, "scan --mode vendored");
    }

    // (c) The same build, no step in between and no repin: patched, from
    // the committed copy. Bazel asks no host for the crate: what the hub's
    // cargo fetches again is the dependency.
    let routes = [UPSTREAM_ENTRY, UPSTREAM_CRATE, patch.route.as_str()];
    let asked = || routes.map(|route| standin.asked(route));
    let requests = asked();
    cell.builds(&patch.package.marker);
    assert_eq!(
        asked(),
        requests,
        "{test}: Bazel asked a host for the crate"
    );
    // Where the ruleset watches, the build rewrote Bazel's lock, and
    // cargo-bazel wrote a `BUILD.bazel` into the committed copy, under its
    // banner. That file is no part of what the scan recorded, and no change
    // of the copy: `vendor --check` passes right after the build, as it
    // does where the build wrote no file.
    let built = cell.tree();
    let build_file = format!("{copy}/BUILD.bazel");
    let by_bazel: &[&str] = if watches(&cell) {
        &[&build_file, BAZEL_LOCK]
    } else {
        &[]
    };
    assert_eq!(changed(&vendored, &built), by_bazel, "{test}");
    if watches(&cell) {
        let rendered = text(&built, &build_file);
        assert!(rendered.starts_with(BANNER), "{test}: {rendered}");
    }
    let check = socket_patch(&cell, &standin, &["vendor", "--check"]);
    assert_eq!(check.code, 0, "{test}: {}", check.dump);
    // From here on the checkout stands: the next build changes no file, and
    // Bazel's lock holds when Bazel may not update it.
    cell.builds_patched(&built, &patch.package.marker);
    vex(&cell, &standin, &patch, &built, true);
    // What Bazel takes the copy for. Under the line the scan wrote it is no
    // package: `//...` is the consumer alone, and the commands that analyse
    // every target pass. A user who comments the line out has the package
    // back, where the ruleset writes the build file: `//...` names targets
    // there, those commands fail on the repository of the dependency, and
    // the file Bazel now reads is a change of the copy again.
    assert_eq!(every_target(&cell), [CONSUMER], "{test}");
    assert!(analyses(&cell), "{test}: under the line of the scan");
    cell.write(".bazelignore", DECLINED);
    let targets = every_target(&cell);
    let package = format!("//{copy}:");
    let (in_copy, own): (Vec<&str>, Vec<&str>) =
        (targets.iter().map(String::as_str)).partition(|target| target.starts_with(&package));
    let in_copy = in_copy.len();
    assert_eq!(own, [CONSUMER], "{test}: {targets:?}");
    assert_eq!(in_copy > 0, watches(&cell), "{test}: {targets:?}");
    assert_eq!(analyses(&cell), !watches(&cell), "{test}: without the line");
    let check = socket_patch(&cell, &standin, &["vendor", "--check"]);
    let read = i32::from(watches(&cell));
    assert_eq!(check.code, read, "{test}: {}", check.dump);
    let declined = ["failed there", "passed"][usize::from(!watches(&cell))];
    cell.write(".bazelignore", IGNORED);
    cell.builds(&patch.package.marker);
    assert_eq!(changed(&built, &cell.tree()), NOTHING, "{test}");

    // (d) The undo. The copy goes, with the `BUILD.bazel` a build wrote
    // into it and with the line in `.bazelignore`, and the two files are
    // the ones of before at once.
    let undo = socket_patch(&cell, &standin, &["vendor", "--revert"]);
    undone(&cell, &undo, "removed", &before, &upstream.marker);

    // (e) A second machine and a second patch, vendored there. Its first
    // build is the patched one, from the committed copy.
    let second = Patched::new();
    let served = &second.package.crate_file;
    let (_first, _second_home, twin, other) =
        second_machine(cell, &upstream, "vendored", &second, served);
    twin.builds(&second.package.marker);
    let second_built = twin.tree();
    // The same command a second time, as every run of a pipeline has it,
    // finds the copy `already_vendored` and leaves it alone, with the
    // `BUILD.bazel` the build wrote into it: nothing is downloaded and no
    // file changes. `vendor --check` passes and `vex` attests the crate.
    let downloads = other.asked(&second.route);
    let again = socket_patch(&twin, &other, &["scan", "--mode", "vendored", "--yes"]);
    let said = &again.dump;
    assert_eq!(again.code, 0, "{test}: {said}");
    let in_sync = has_event(&again.envelope, "skipped", "already_vendored", PURL);
    assert!(in_sync, "{test}: {said}");
    let rebuilt = again.envelope["summary"]["rebuilt"] == 1;
    let downloaded = other.asked(&second.route) > downloads;
    assert_eq!((rebuilt, downloaded), (false, false), "{test}: {said}");
    let second_copy = second.vendored();
    let second_build_file = format!("{second_copy}/BUILD.bazel");
    assert_eq!(
        changed(&second_built, &twin.tree()),
        NOTHING,
        "{test}: {said}"
    );
    twin.builds_patched(&second_built, &second.package.marker);
    let check = socket_patch(&twin, &other, &["vendor", "--check"]);
    assert_eq!(check.code, 0, "{test}: {}", check.dump);
    vex(&twin, &other, &second, &second_built, true);
    // A build file that cargo-bazel did not write, under its banner. It
    // does not reach the crate, which Bazel builds as before, and under
    // the line of the scan it is no package. The banner is all that
    // `socket-patch` reads of such a file, so `vendor --check` passes on
    // this one too. With the line commented out it is a package of the
    // workspace, whose target `//...` builds, and `vendor --check` takes
    // the copy for a changed one.
    let planted = format!(
        "{BANNER}\n\ngenrule(\n    name = \"planted\",\n    outs = [\"planted.txt\"],\n    \
         cmd = \"touch $@\",\n)\n"
    );
    twin.write(&second_build_file, &planted);
    twin.builds(&second.package.marker);
    assert_eq!(every_target(&twin), [CONSUMER], "{test}");
    let check = socket_patch(&twin, &other, &["vendor", "--check"]);
    assert_eq!(check.code, 0, "{test}: {}", check.dump);
    twin.write(".bazelignore", DECLINED);
    let planted_target = format!("//{second_copy}:planted");
    assert_eq!(
        every_target(&twin),
        [planted_target.as_str(), CONSUMER],
        "{test}"
    );
    let check = socket_patch(&twin, &other, &["vendor", "--check"]);
    let said = &check.dump;
    assert_eq!(check.code, 1, "{test}: {said}");
    let reason = event_for(&check.envelope, PURL)["reason"]
        .as_str()
        .unwrap_or_default();
    assert!(
        reason.contains("vendor_inventory_mismatch"),
        "{test}: {said}"
    );
    twin.write(".bazelignore", IGNORED);
    // Then another library in the committed copy. Nothing in a build holds
    // the copy to a checksum: Bazel builds what is there. `vendor --check`
    // is what finds it.
    let tampered = Package::new("TAMPERED", &second.uuid);
    twin.write(&format!("{second_copy}/src/lib.rs"), &tampered.lib_rs);
    twin.builds(&tampered.marker);
    let check = socket_patch(&twin, &other, &["vendor", "--check"]);
    let said = &check.dump;
    assert_eq!(check.code, 1, "{test}: {said}");
    let reason = event_for(&check.envelope, PURL)["reason"]
        .as_str()
        .unwrap_or_default();
    assert!(reason.contains("vendor_hash_mismatch"), "{test}: {said}");

    println!(
        "{test}: Bazel {release} built {:?} from {copy} after `scan --mode vendored`, with no \
         repin and no request for the crate, and wrote {by_bazel:?} itself; right after \
         that build `vendor --check` passed and `vex` attested the crate; under the \
         `.bazelignore` line of the scan `//...` held the consumer alone and `cquery //...` \
         and `query 'deps(//...)'` passed, and with the line commented out `//...` held \
         {in_copy} target(s) in the copy, the two commands {declined} and `vendor --check` \
         exited {read}; `vendor --revert` \
         restored the checkout, and the next build printed {:?} and left all {} files as \
         before; on a second machine, after its first patched build, a second scan reported \
         the copy already_vendored, downloaded nothing and changed no file, `vendor --check` \
         passed and `vex` attested the crate; a BUILD.bazel of someone else's under \
         cargo-bazel's banner left the build patched and `vendor --check` passed, under the \
         line it was no package, and with the line commented out `//...` built its target and \
         `vendor --check` reported vendor_inventory_mismatch; a \
         library then changed in the committed copy was built ({:?}), and `vendor --check` \
         reported vendor_hash_mismatch; {:?}",
        patch.package.marker,
        upstream.marker,
        before.len(),
        tampered.marker,
        started.elapsed()
    );
}

/// The module file of the fixture with rules_rust 0.75.0: one that makes a
/// crate hub.
fn hub() -> String {
    let module = fixture_path(FIXTURE.dir).join("e9/MODULE.bazel");
    std::fs::read_to_string(module).expect("a fixture file")
}

/// Without a Bazel: the fixture's Cargo project in a checkout of its own,
/// with the file `marks` at its root, which holds `module` and makes the
/// checkout a Bazel workspace when it is one of Bazel's names; the
/// stand-in that holds the crate and one patch of it; and that patch,
/// which `scan --mode vendored --yes` has applied there.
fn vendored_checkout(marks: &str, module: &str) -> (Cell, StandIn, Patched) {
    let cell = cell_without_bazel("9.3.2");
    let upstream = Package::upstream();
    let (standin, patch) = (registry(&upstream), Patched::new());
    grant(&standin, &upstream, &patch, &patch.package.crate_file);
    let manifest = fixture_path(FIXTURE.dir).join("common").join(MANIFEST);
    cell.write(MANIFEST, std::fs::read(manifest).expect("a fixture file"));
    cell.write(LOCK, lock_pinning(&upstream));
    cell.write(CONFIG, mirror_config(&standin.origin()));
    cell.write(".git/HEAD", "ref: refs/heads/main\n");
    cell.write(marks, module);
    let scan = socket_patch(&cell, &standin, &["scan", "--mode", "vendored", "--yes"]);
    assert_eq!(scan.code, 0, "{}", scan.dump);
    assert_eq!(scan.envelope["summary"]["applied"], 1, "{}", scan.dump);
    (cell, standin, patch)
}

/// What `socket-patch` does in `cell` with a vendored copy that holds
/// `extra`, a file the scan did not record. A copy it takes for `changed`:
/// `vendor --check` exits 1 over the inventory, `vex` leaves the patch out,
/// and a second scan downloads the crate again and removes the file. The
/// other: the check passes, `vex` attests the crate of `patch`, and a
/// second scan downloads nothing and leaves every file as it is. `repair`
/// after that scan does the same with either.
fn takes_for(cell: &Cell, standin: &StandIn, patch: &Patched, extra: &str, is_changed: bool) {
    let left = cell.tree();
    let check = socket_patch(cell, standin, &["vendor", "--check"]);
    assert_eq!(check.code, i32::from(is_changed), "{extra}: {}", check.dump);
    let reason = event_for(&check.envelope, PURL)["reason"]
        .as_str()
        .unwrap_or_default();
    let mismatch = reason.contains("vendor_inventory_mismatch");
    assert_eq!(mismatch, is_changed, "{extra}: {}", check.dump);
    vex(cell, standin, patch, &left, !is_changed);
    let downloads = standin.asked(&patch.route);
    let again = socket_patch(cell, standin, &["scan", "--mode", "vendored", "--yes"]);
    let said = &again.dump;
    assert_eq!(again.code, 0, "{extra}: {said}");
    let in_sync = has_event(&again.envelope, "skipped", "already_vendored", PURL);
    assert!(in_sync, "{extra}: {said}");
    let rebuilt = again.envelope["summary"]["rebuilt"] == 1;
    let downloaded = standin.asked(&patch.route) - downloads;
    let count = usize::from(is_changed);
    assert_eq!(
        (rebuilt, downloaded),
        (is_changed, count),
        "{extra}: {said}"
    );
    let removed: &[&str] = if is_changed { &[extra] } else { &[] };
    let scanned = cell.tree();
    assert_eq!(changed(&left, &scanned), removed, "{extra}: {said}");
    // `repair` has nothing to restore by now, the file of the other copy
    // included.
    let repair = socket_patch(cell, standin, &["repair"]);
    assert_eq!(repair.code, 0, "{extra}: {}", repair.dump);
    let restored = standin.asked(&patch.route) - downloads - downloaded;
    assert_eq!(restored, 0, "{extra}: {}", repair.dump);
    assert_eq!(changed(&scanned, &cell.tree()), NOTHING, "{extra}");
}

/// The module file of [`hub`] with the Cargo files of another directory of
/// the checkout: a hub of another Cargo workspace.
fn hub_elsewhere() -> String {
    let (hub, ours) = (hub(), "\"//:Cargo");
    assert_eq!(hub.matches(ours).count(), 2, "{hub}");
    hub.replace(ours, "\"//other:Cargo")
}

/// Without a Bazel: a build file in a vendored copy that the scan did not
/// record. The first is where cargo-bazel writes one and starts as its
/// files do, in a Bazel workspace with a hub of the project's crates,
/// under the `.bazelignore` line of the scan: that one is no change of the
/// copy. The others differ from it in one thing each, and are the changed
/// copy they were: a checkout that is no Bazel workspace (a directory
/// named like a workspace file marks none), a workspace whose module file
/// makes no crate hub, or the hub of another Cargo workspace, a path line
/// that the user commented out, no banner, Bazel's other name for a build
/// file, and a directory of the crate ([`takes_for`]).
#[test]
fn only_the_build_file_of_cargo_bazel_is_no_change_of_a_vendored_copy() {
    let rendered = format!("{BANNER} To \n# regenerate this file, run the following:\n");
    let (hub, elsewhere, bazel) = (hub(), hub_elsewhere(), "MODULE.bazel");
    let no_hub = "module(name = \"socket_fixture\", version = \"0.0.0\")\n";
    let (build, mine) = ("BUILD.bazel", "genrule(name = \"x\")\n");
    for (marks, module, lines, file, text, is_changed) in [
        (bazel, hub.as_str(), None, build, rendered.as_str(), false),
        ("WORKSPACE/README", &hub, None, build, &rendered, true),
        (bazel, no_hub, None, build, &rendered, true),
        (bazel, &elsewhere, None, build, &rendered, true),
        (bazel, &hub, Some(DECLINED), build, &rendered, true),
        (bazel, &hub, None, build, mine, true),
        (bazel, &hub, None, "BUILD", &rendered, true),
        (bazel, &hub, None, "src/BUILD.bazel", &rendered, true),
    ] {
        let (cell, standin, patch) = vendored_checkout(marks, module);
        if let Some(lines) = lines {
            cell.write(".bazelignore", lines);
        }
        let extra = format!("{}/{file}", patch.vendored());
        cell.write(&extra, text);
        takes_for(&cell, &standin, &patch, &extra, is_changed);
    }
}

/// Without a Bazel: the `.bazelignore` line of the vendored crates. Where
/// the module files of the workspace make a crate hub, `scan --mode
/// vendored` writes the pair and `vendor --revert` takes it away with the
/// copies, and a person is told of each. A run that leaves Cargo out adds
/// no pair, and a path line that the user commented out stays as it is.
/// In a workspace without such a hub, in one whose hub reads another Cargo
/// workspace, and in no workspace, the scan writes no such file.
#[test]
fn the_vendored_crates_get_a_bazelignore_line_where_a_crate_hub_builds_them() {
    let no_hub = "module(name = \"socket_fixture\", version = \"0.0.0\")\n";
    let elsewhere = hub_elsewhere();
    let none = [
        ("MODULE.bazel", no_hub),
        ("MODULE.bazel", elsewhere.as_str()),
        ("WORKSPACE/README", ""),
    ];
    for (marks, module) in none {
        let (cell, _standin, _patch) = vendored_checkout(marks, module);
        assert!(!cell.tree().contains_key(".bazelignore"), "{marks}");
    }

    let (cell, standin, _patch) = vendored_checkout("MODULE.bazel", &hub());
    let file = || cell.tree().get(".bazelignore").cloned();
    assert_eq!(file().as_deref(), Some(IGNORED.as_bytes()));
    // A run that leaves Cargo out adds none, whatever else it has in scope;
    // the same run without the option does, and says so to a person.
    std::fs::remove_file(cell.path(".bazelignore")).expect("remove the file");
    let repair = socket_patch(&cell, &standin, &["repair", "--ecosystems", "golang"]);
    assert_eq!((repair.code, file()), (0, None), "{}", repair.dump);
    let told = |[stdout, stderr]: [String; 2], verb: &str, what: &str| {
        let line = stdout.lines().find(|line| line.contains(".bazelignore"));
        let said = line.is_some_and(|line| line.starts_with(verb) && line.ends_with(what));
        assert!(said, "{verb} ... {what}:\n{stdout}\n{stderr}");
    };
    let updated = ".bazelignore: the lines that keep patched crate copies under .socket out \
                   of Bazel's packages";
    told(person(&cell, &standin, &["repair"]), "Updated ", updated);
    assert_eq!(file().as_deref(), Some(IGNORED.as_bytes()));
    // The user's "no", over a scan and a repair.
    cell.write(".bazelignore", DECLINED);
    for command in [&["scan", "--mode", "vendored", "--yes"][..], &["repair"]] {
        let ran = socket_patch(&cell, &standin, command);
        assert_eq!(ran.code, 0, "{}", ran.dump);
        let warnings = ran.envelope["warnings"].as_array();
        let warned = |w: &serde_json::Value| w["code"] == "bazelignore_not_updated";
        assert!(
            !warnings.is_some_and(|w| w.iter().any(warned)),
            "{}",
            ran.dump
        );
        assert_eq!(file().as_deref(), Some(DECLINED.as_bytes()), "{command:?}");
    }
    // The pair goes with the copies, out of a file that keeps the user's
    // line, and the file the scan made goes with its last pair.
    cell.write(".bazelignore", format!("node_modules\n{IGNORED}"));
    let undo = socket_patch(&cell, &standin, &["vendor", "--revert"]);
    assert_eq!(undo.code, 0, "{}", undo.dump);
    assert_eq!(file().as_deref(), Some(&b"node_modules\n"[..]));
    std::fs::remove_file(cell.path(".bazelignore")).expect("remove the file");
    let scan = socket_patch(&cell, &standin, &["scan", "--mode", "vendored", "--yes"]);
    assert_eq!(scan.code, 0, "{}", scan.dump);
    assert_eq!(file().as_deref(), Some(IGNORED.as_bytes()));
    let gone = ".bazelignore: no patched crate copy is left under .socket";
    told(
        person(&cell, &standin, &["vendor", "--revert"]),
        "Removed ",
        gone,
    );
    assert_eq!(file(), None);
}

/// The code of the warning for a crate that hosted mode does not pin
/// because a rules_rust hub would not read the cargo config of the pin.
const UNREAD: &str = "redirect_cargo_bazel_config_unread";

/// The attribute a hub names the project's cargo config with, and how the
/// warning says to write it.
const NAMES_CONFIG: &str = "cargo_config = \"//:.cargo/config.toml\"";
const GIVE_THE_HUB: &str = "give the hub `cargo_config = \"//:.cargo/config.toml\"`";

/// What a finished hosted command says when it pins nothing for the crate
/// because of a hub: it exits 0 with the status `success`, the crate is
/// skipped as one no file pins, no file is named as rewritten, and its one
/// warning of [`UNREAD`] names the crate, says that nothing was written
/// and ends with vendored mode. Gives the detail of that warning.
fn unread(test: &str, scan: &Ran) -> String {
    let said = &scan.dump;
    assert_eq!(scan.code, 0, "{test}: {said}");
    assert_eq!(scan.envelope["status"], "success", "{test}: {said}");
    assert_eq!(scan.envelope["summary"]["applied"], 0, "{test}: {said}");
    let skipped = has_event(&scan.envelope, "skipped", "redirect_unconfirmed", PURL);
    assert!(skipped, "{test}: {said}");
    let rewritten = &scan.envelope["redirect"]["rewrittenFiles"];
    assert_eq!(*rewritten, json!([]), "{test}: {said}");
    let warnings = scan.envelope["warnings"].as_array().expect("warnings");
    let ours: Vec<&str> = warnings
        .iter()
        .filter(|warning| warning["code"] == UNREAD)
        .filter_map(|warning| warning["detail"].as_str())
        .collect();
    let [detail] = ours[..] else {
        panic!("{test}: not one {UNREAD} warning: {said}");
    };
    let vendored =
        "; or use `--mode vendored`, which commits the patched crate and needs no registry";
    let about = detail.starts_with(&format!("{NAME}@{VERSION}: "))
        && detail.contains("; dependency skipped (nothing rewritten). ")
        && detail.ends_with(vendored);
    assert!(about, "{test}: {detail}");
    detail.to_string()
}

/// [`unread`] for the hub at `at` (`MODULE.bazel:10`), which names no
/// config: the warning names the hub, the file to commit first, and the
/// attribute to give the hub.
fn withheld(test: &str, scan: &Ran, at: &str) {
    let detail = unread(test, scan);
    let starts = format!(
        "{NAME}@{VERSION}: the rules_rust hub at {at} reads the Cargo files of this project, and \
         it names no `cargo_config`. "
    );
    assert!(detail.starts_with(&starts), "{test}: {detail}");
    let way = format!(
        "Commit {CONFIG} (where the project has none, create it with a comment line in it: \
         `rollback` deletes a config it leaves empty, and a hub that names a missing file fails), \
         {GIVE_THE_HUB}, the label of that file as one string, and run this command again; or \
         use `--mode vendored`"
    );
    assert!(detail.contains(&way), "{test}: no {way:?} in {detail}");
}

/// The line of `module` on which its hub is called, as a warning names it.
fn hub_at(module: &str) -> String {
    let call = module.lines().position(|line| line == "crate.from_cargo(");
    format!("{MODULE}:{}", call.expect("a hub") + 1)
}

/// The flow of the hub without a cargo config (module docs).
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn hosted_from_cargo_without_config() {
    let test = "cargo::hosted_from_cargo_without_config";
    let started = Instant::now();
    let Some((_home, cell, standin, upstream)) = open_readme_hub(test) else {
        return;
    };
    let release = cell.release().to_string();
    let origin = standin.origin();
    let patch = Patched::new();
    grant(&standin, &upstream, &patch, &patch.package.crate_file);

    // (a) The unpatched build, with the upstream crate from the stand-in.
    let before = builds_upstream(&cell, &standin, &upstream);

    // (b) The one command of hosted mode pins nothing: the hub would fail
    // on the pin. It says so, names the hub and the two ways on, and
    // changes no file. A person reads the same warning.
    let command = ["scan", "--mode", "hosted", "--yes"];
    let readme = text(&before, MODULE);
    let scan = socket_patch(&cell, &standin, &command);
    withheld(test, &scan, &hub_at(&readme));
    assert_eq!(changed(&before, &cell.tree()), NOTHING, "{test}");
    let [_, stderr] = person(&cell, &standin, &command);
    let told = stderr
        .lines()
        .any(|line| line.starts_with("Warning: ") && line.contains(GIVE_THE_HUB));
    assert!(told, "{test}: a person is not told:\n{stderr}");
    assert_eq!(changed(&before, &cell.tree()), NOTHING, "{test}");

    // (c) The same build: still the upstream crate, no file changed, and
    // Bazel's lock stands.
    cell.builds_patched(&before, &upstream.marker);

    // (d) The second way the warning names, on the hub as it is: vendored
    // mode needs no registry, and the build is the patched one, from the
    // committed copy. Its undo gives the checkout back.
    let vendored = socket_patch(&cell, &standin, &["scan", "--mode", "vendored", "--yes"]);
    let said = &vendored.dump;
    assert_eq!(vendored.code, 0, "{test}: {said}");
    assert_eq!(vendored.envelope["summary"]["applied"], 1, "{test}: {said}");
    cell.builds(&patch.package.marker);
    let undo = socket_patch(&cell, &standin, &["vendor", "--revert"]);
    undone(&cell, &undo, "removed", &before, &upstream.marker);
    let fetched = standin.asked(&patch.route);

    // (e) The first way: that file in the checkout, with a comment line in
    // it, and the one attribute on the hub. Then the same command applies
    // the patch, and the build is the patched one, from the patch host,
    // which is asked for its index file of the crate and, at least twice,
    // for the crate file.
    let lockfile = "    cargo_lockfile = ";
    let named = readme.replacen(lockfile, &format!("{HUB_CONFIG}{lockfile}"), 1);
    assert!(named.contains(NAMES_CONFIG), "{test}:\n{named}");
    cell.write(MODULE, named);
    let comment = "# The cargo settings of this project.\n";
    cell.write(CONFIG, comment);
    let edited = cell.tree();
    let scan = socket_patch(&cell, &standin, &command);
    let pinned = cell.pinned_by(&scan, PURL, &patch.uuid, &edited, &[CONFIG, LOCK, MANIFEST]);
    let warned = codes_in(&scan.envelope["warnings"]);
    assert!(
        !warned.iter().any(|code| code == UNREAD),
        "{test}: {}",
        scan.dump
    );
    let (index, registry) = (format!("sparse+{origin}{}/", patch.index), patch.registry());
    let defined = format!("{comment}\n[registries.{registry}]\nindex = \"{index}\"\n");
    assert_eq!(text(&pinned, CONFIG), defined, "{test}: {CONFIG}");
    cell.builds(&patch.package.marker);
    let (asked, fetches) = (
        standin.asked(&patch.entry),
        standin.asked(&patch.route) - fetched,
    );
    assert!(
        asked > 0 && fetches >= 2,
        "{test}: requests to the patch host by the hosted build: {asked} for its index file of \
         the crate and {fetches} for the crate file"
    );

    println!(
        "{test}: Bazel {release} built {:?} on the hub of the rules_rust README; `scan --mode \
         hosted` exited 0, warned {UNREAD} and changed no file, and the same build printed the \
         same line; after `scan --mode vendored` on that hub the build printed {:?}, and \
         `vendor --revert` restored the checkout; with {CONFIG} in the checkout and \
         `{NAMES_CONFIG}` on the hub the hosted scan rewrote {:?}, and the build printed the \
         same line from the patch host (requests for the crate file: {fetches}); {:?}",
        upstream.marker,
        patch.package.marker,
        [CONFIG, LOCK, MANIFEST],
        started.elapsed()
    );
}

/// Without a Bazel: the Cargo project of the fixture in a checkout of its
/// own, in the directory `project` of it (`""`: the root, else with a `/`
/// at its end), its lock pinning `upstream`, with `files` beside it, each
/// from the root of the checkout.
fn checkout(project: &str, upstream: &Package, files: &[(&str, &str)]) -> Cell {
    let cell = cell_without_bazel("9.3.2");
    let manifest = std::fs::read(fixture_path(FIXTURE.dir).join("common").join(MANIFEST));
    cell.write(&format!("{project}{MANIFEST}"), manifest.expect(MANIFEST));
    cell.write(&format!("{project}{LOCK}"), lock_pinning(upstream));
    cell.write(".git/HEAD", "ref: refs/heads/main\n");
    for (rel, text) in files {
        cell.write(rel, text);
    }
    cell
}

/// The `MODULE.bazel` of the newer era, whose hub names the cargo config.
fn module_naming_config() -> String {
    let path = fixture_path(FIXTURE.dir).join("e9").join(MODULE);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// An upstream crate, a stand-in that holds it, and a patch of it that the
/// stand-in grants.
fn granted() -> (Package, StandIn, Patched) {
    let (upstream, patch) = (Package::upstream(), Patched::new());
    let standin = registry(&upstream);
    grant(&standin, &upstream, &patch, &patch.package.crate_file);
    (upstream, standin, patch)
}

/// Without a Bazel: on the hub of the README every hosted command pins
/// nothing and changes no file, a dry run and `get` included, and a person
/// reads which package was left out and why. With the config in the
/// checkout and the attribute on the hub a line that may hide a hub still
/// withholds the pin, and the warning names that line and no attribute.
/// Without the line the same scan pins the crate, a scan after it leaves
/// the pin as it is, and `rollback` gives the checkout back, the config
/// with its comment line. A config that holds nothing gets no pin, and the
/// warning asks for the comment line.
#[test]
fn a_hub_without_the_config_gets_no_pin_until_it_names_the_config() {
    let (upstream, standin, patch) = granted();
    let named = module_naming_config();
    let readme = named.replace(HUB_CONFIG, "");
    let cell = checkout("", &upstream, &[(MODULE, &readme)]);
    let before = cell.tree();
    let scan = ["scan", "--mode", "hosted", "--yes"];
    let commands: [&[&str]; 3] = [
        &scan,
        &["scan", "--mode", "hosted", "--yes", "--dry-run"],
        &["get", PURL, "--mode", "hosted", "--yes"],
    ];
    for command in commands {
        let ran = socket_patch(&cell, &standin, command);
        withheld(&format!("{command:?}"), &ran, &hub_at(&readme));
        assert_eq!(changed(&before, &cell.tree()), NOTHING, "{command:?}");
    }
    let [stdout, stderr] = person(&cell, &standin, &scan);
    let left_out = format!(
        "  {PURL}: no lockfile entry pinning it could be rewritten (see the warning below)"
    );
    let lines: Vec<&str> = stderr.lines().collect();
    let warning = format!(
        "Warning: {NAME}@{VERSION}: the rules_rust hub at {}",
        hub_at(&readme)
    );
    let told = lines.contains(&"No patches could be switched to hosted:")
        && lines.contains(&left_out.as_str())
        && lines.iter().any(|line| line.starts_with(&warning));
    assert!(told, "--- stdout\n{stdout}\n--- stderr\n{stderr}");
    assert_eq!(changed(&before, &cell.tree()), NOTHING);

    let comment = "# The cargo settings of this project.\n";
    cell.write(MODULE, &named);
    cell.write(CONFIG, comment);
    let edited = cell.tree();
    // The hub that is seen names the config, and another may be hidden.
    let hidden = format!("{named}make = crate.from_cargo\n");
    cell.write(MODULE, &hidden);
    let detail = unread("a hidden call", &socket_patch(&cell, &standin, &scan));
    let line = format!(
        "{NAME}@{VERSION}: {MODULE}:{}: `crate` is used other than to call a tag, so a rules_rust \
         hub that socket-patch cannot read may take the Cargo files of this project. ",
        hidden.lines().count()
    );
    let way = "Write that line as the call of a tag (`crate.from_cargo(...)`) or as \
               `use_repo(...)` and run this command again: it then pins the crate, or names the \
               hub that is in the way; or use `--mode vendored`";
    let named_line = detail.starts_with(&line) && detail.contains(way);
    assert!(named_line && !detail.contains("ive the hub"), "{detail}");
    cell.write(MODULE, &named);
    assert_eq!(changed(&edited, &cell.tree()), NOTHING);
    let ran = socket_patch(&cell, &standin, &scan);
    let pinned = cell.pinned_by(&ran, PURL, &patch.uuid, &edited, &[CONFIG, LOCK, MANIFEST]);
    // A pin that is in place stays what it was, whatever the hub names by
    // then: applied, with no file to rewrite and no word about the hub.
    cell.write(MODULE, &readme);
    let again = socket_patch(&cell, &standin, &scan);
    assert_eq!(again.envelope["summary"]["applied"], 1, "{}", again.dump);
    assert_eq!(
        codes_in(&again.envelope["warnings"]),
        NOTHING,
        "{}",
        again.dump
    );
    cell.write(MODULE, &named);
    assert_eq!(changed(&pinned, &cell.tree()), NOTHING, "{}", again.dump);
    let undo = socket_patch(&cell, &standin, &["rollback", "--yes"]);
    assert_eq!(undo.code, 0, "{}", undo.dump);
    assert_eq!(undo.envelope["summary"]["rolledBack"], 1, "{}", undo.dump);
    assert_eq!(changed(&edited, &cell.tree()), NOTHING, "{}", undo.dump);

    // A config that holds nothing gets no pin: the `rollback` of the pin
    // would delete the file, and a hub that names a missing file fails.
    cell.write(CONFIG, "");
    let blank = cell.tree();
    let detail = unread("a blank config", &socket_patch(&cell, &standin, &scan));
    let starts = format!(
        "{NAME}@{VERSION}: the rules_rust hub at {} reads the Cargo files of this project and \
         names {CONFIG}, which holds nothing: ",
        hub_at(&named)
    );
    let way = format!(
        "Put a comment line in {CONFIG} and run this command again; or use `--mode vendored`"
    );
    assert!(
        detail.starts_with(&starts) && detail.contains(&way),
        "{detail}"
    );
    assert_eq!(changed(&blank, &cell.tree()), NOTHING);

    // KNOWN GAP, and what the comment line is for: a config that the pin
    // creates is deleted by the `rollback` that empties it, and a hub that
    // names a missing file fails. Once `rollback` keeps the hub's file,
    // the warning needs no such advice and this goes.
    std::fs::remove_file(cell.path(CONFIG)).expect("the blank config");
    let ran = socket_patch(&cell, &standin, &scan);
    assert_eq!(ran.envelope["summary"]["applied"], 1, "{}", ran.dump);
    let undo = socket_patch(&cell, &standin, &["rollback", "--yes"]);
    assert_eq!(changed(&edited, &cell.tree()), [CONFIG], "{}", undo.dump);
    assert!(!cell.tree().contains_key(CONFIG), "{}", undo.dump);
}

/// Without a Bazel: where no hub is seen to read the project's Cargo files
/// the scan is the one of a project in no Bazel workspace: the same
/// envelope, and the same three files, byte for byte. That holds for a
/// workspace without a hub, for a hub that names the config, for one over
/// the Cargo files of another directory, for a project beside the one a
/// hub reads, for a `WORKSPACE` file that Bazel 9 never reads, and for the
/// tag of another ruleset.
#[test]
fn a_project_that_no_hub_is_seen_to_read_is_pinned_as_in_no_bazel_workspace() {
    let (upstream, standin, patch) = granted();
    let scan = ["scan", "--mode", "hosted", "--yes"];
    let written = [CONFIG, LOCK, MANIFEST];
    let plain = checkout("", &upstream, &[]);
    let before = plain.tree();
    let unmarked = socket_patch(&plain, &standin, &scan);
    let pinned = plain.pinned_by(&unmarked, PURL, &patch.uuid, &before, &written);

    let named = module_naming_config();
    let readme = named.replace(HUB_CONFIG, "");
    let hub = readme.find("crate = use_extension(").expect("a hub");
    let (no_hub, elsewhere) = (&readme[..hub], readme.replace("\"//:", "\"//third_party:"));
    let rules_rs = "bazel_dep(name = \"rules_rs\", version = \"0.2.2\")\n\
                    crate = use_extension(\"@rules_rs//rs:extensions.bzl\", \"crate\")\n\
                    crate.from_cargo(\n    name = \"crates\",\n    cargo_lock = \"//:Cargo.lock\",\n    \
                    cargo_toml = \"//:Cargo.toml\",\n)\nuse_repo(crate, \"crates\")\n";
    let stale = "load(\"@rules_rust//crate_universe:defs.bzl\", \"crates_repository\")\n\
                 crates_repository(\n    name = \"crates\",\n    cargo_lockfile = \
                 \"//:Cargo.lock\",\n    manifests = [\"//:Cargo.toml\"],\n)\n";
    let cases: [(&str, &[(&str, &str)]); 6] = [
        ("", &[(MODULE, no_hub)]),
        ("", &[(MODULE, &named)]),
        ("", &[(MODULE, &elsewhere)]),
        ("tool/", &[(MODULE, &readme)]),
        ("", &[("WORKSPACE", stale), (".bazelversion", "9.3.2\n")]),
        ("", &[(MODULE, rules_rs)]),
    ];
    for (project, files) in cases {
        let cell = checkout(project, &upstream, files);
        let before = cell.tree();
        let below = ["--cwd", project.trim_end_matches('/')];
        let command = [&scan[..], &below[..2 * usize::from(!project.is_empty())]].concat();
        let ran = socket_patch(&cell, &standin, &command);
        let said = format!("{project:?} {files:?}: {}", ran.dump);
        assert_eq!(ran.code, 0, "{said}");
        assert_eq!(ran.envelope, unmarked.envelope, "{said}");
        let after = cell.tree();
        let files = written.map(|file| format!("{project}{file}"));
        assert_eq!(changed(&before, &after), files, "{said}");
        for (file, written) in files.iter().zip(written) {
            assert_eq!(after[file], pinned[written], "{file}: {said}");
        }
    }
}

/// Without a Bazel: a crate that vendored mode patched stays vendored when
/// a hosted scan would take it over on the hub of the README: the scan
/// names the hub, keeps every file of the vendored copy and its wiring,
/// and the crate stays patched.
#[test]
fn a_vendored_crate_stays_vendored_on_a_hub_without_the_config() {
    let (upstream, standin, patch) = granted();
    let readme = module_naming_config().replace(HUB_CONFIG, "");
    let cell = checkout("", &upstream, &[(MODULE, &readme)]);
    let vendored = socket_patch(&cell, &standin, &["scan", "--mode", "vendored", "--yes"]);
    assert_eq!(
        vendored.envelope["summary"]["applied"], 1,
        "{}",
        vendored.dump
    );
    let kept = cell.tree();
    assert!(kept.contains_key(&format!("{}/src/lib.rs", patch.vendored())));

    let hosted = socket_patch(&cell, &standin, &["scan", "--mode", "hosted", "--yes"]);
    let said = &hosted.dump;
    assert_eq!(hosted.code, 0, "{said}");
    assert!(
        has_event(&hosted.envelope, "skipped", UNREAD, PURL),
        "{said}"
    );
    let warned = codes_in(&hosted.envelope["warnings"]);
    for code in [UNREAD, "redirect_takeover_kept_vendored"] {
        assert!(
            warned.iter().any(|warned| warned == code),
            "no {code}: {said}"
        );
    }
    assert_eq!(changed(&kept, &cell.tree()), NOTHING, "{said}");
}

/// Without a Bazel, what stays fixed now that no checksum is committed: the
/// fixture's directories and the legs of its workflow are those of its
/// table; the fixture's lock holds the two entries a test pins, the
/// crate's and its dependency's, with the placeholder, and pinning changes
/// nothing else; two runs serve two upstream crate files and one of the
/// dependency; the fixture depends on the crate under the names written
/// out above, and commits no cargo config; every era's hub names the
/// config a test writes, has no cargo-bazel lock, and is the hub of the
/// rules_rust README but for that one line; and crates.io can hold neither
/// name.
#[test]
fn a_test_pins_the_crates_of_the_fixture_lock() {
    FIXTURE.check();
    let root = fixture_path(FIXTURE.dir);
    let read = |rel: &str| std::fs::read_to_string(root.join(rel)).expect(rel);

    let upstream = Package::upstream();
    let pinned = lock_pinning(&upstream);
    let entry = lock_entry(CRATES_IO, &upstream.checksum());
    assert!(pinned.contains(&entry), "no\n{entry}in\n{pinned}");
    let dependency = dependency_entry(&sha256_hex(&dependency_file()));
    assert!(pinned.contains(&dependency), "no\n{dependency}in\n{pinned}");
    let unpinned = pinned
        .replace(&entry, &lock_entry(CRATES_IO, PLACEHOLDER))
        .replace(&dependency, &dependency_entry(PLACEHOLDER));
    assert_eq!(unpinned, read("common/Cargo.lock"));
    assert_ne!(Package::upstream().crate_file, upstream.crate_file);
    assert_eq!(dependency_file(), dependency_file());

    let dependency = format!("\n[dependencies]\n{NAME} = \"{VERSION}\"\n");
    assert!(read("common/Cargo.toml").ends_with(&dependency));
    assert!(read("common/BUILD.bazel").contains(&format!("deps = [\"@crates//:{NAME}\"],")));
    let imported = format!("{}::STATUS", NAME.replace('-', "_"));
    assert!(read("common/src/main.rs").contains(&imported));
    assert!(!root.join("common").join(CONFIG).exists());
    for (_, era) in FIXTURE.eras {
        let module = read(&format!("{era}/MODULE.bazel"));
        let hub = format!(
            "crate.from_cargo(\n    name = \"crates\",\n    cargo_config = \"//:{CONFIG}\",\n    \
             cargo_lockfile = \"//:{LOCK}\",\n    manifests = [\"//:{MANIFEST}\"],\n)\n"
        );
        assert!(module.contains(&hub), "{era}: no\n{hub}in\n{module}");
        // Without that one line it is the hub of the rules_rust README.
        let readme = "crate.from_cargo(\n    name = \"crates\",\n    cargo_lockfile = \
                      \"//:Cargo.lock\",\n    manifests = [\"//:Cargo.toml\"],\n)\n";
        let without = module.replace(HUB_CONFIG, "");
        assert!(without.contains(readme), "{era}: no\n{readme}in\n{without}");
    }

    for (name, manifest) in [(NAME, CRATE_MANIFEST), (DEP, DEP_MANIFEST)] {
        assert!(name.len() > 64, "crates.io can hold {name}");
        assert!(manifest.contains(&format!("name = \"{name}\"\nversion = \"{VERSION}\"\n")));
    }
    let needs = format!("\n[dependencies]\n{DEP} = \"{VERSION}\"\n");
    assert!(CRATE_MANIFEST.ends_with(&needs));
    assert_eq!(PURL, format!("pkg:cargo/{NAME}@{VERSION}"));
    assert_eq!(UPSTREAM_ENTRY, format!("/{INDEX}/{}", index_path(NAME)));
    assert_eq!(
        UPSTREAM_CRATE,
        format!("/{FILES}/crates/{NAME}/{VERSION}/download")
    );
}
