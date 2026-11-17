//! Hosted mode for a gem that comes through rules_ruby's
//! `ruby.bundle_fetch(gemfile = "//:Gemfile", gemfile_lock = "//:Gemfile.lock")`
//! under Bzlmod, where `MODULE.bazel` gives no `gem_checksums` and
//! `Gemfile.lock` has a `CHECKSUMS` section.
//!
//! One flow, on the Bazel the run is given ([`FIXTURE`] says which ruleset
//! goes with its release), in a fresh output base:
//!
//! - (a) `bazel build` and `bazel run //:consumer` print the unpatched
//!   marker.
//! - (b) `socket-patch scan --mode hosted --yes` rewrites `Gemfile` (a
//!   `source:` option on the gem's declaration) and `Gemfile.lock` (a `GEM`
//!   section of the gem's own, whose remote is the patch registry, and the
//!   sha256 of the patched gem in `CHECKSUMS`), and nothing else.
//! - (c) The same two Bazel commands, with no step in between, print the
//!   patched marker; the gem came from the stand-in patch registry, Bazel
//!   changed no file of the checkout, and a `--lockfile_mode=error` build
//!   passes.
//! - (d) `socket-patch rollback --yes`: every file of the checkout is the
//!   one of before, byte for byte, and the build prints the unpatched
//!   marker again.
//! - (e) On a second machine (a new output base and, on Bazel 9, a new
//!   contents cache) with the rewritten `Gemfile` and `Gemfile.lock`, a
//!   patch registry that serves other bytes fails the build, and the
//!   upstream gem is not fetched in its place.
//!
//! The marker is read from what Bazel built, and the patched one holds an
//! id made for the run, so no cache of an earlier run can supply it.
//!
//! What fails the build in (e) is the lock's `CHECKSUMS` section and
//! nothing else. rules_ruby gives Bazel's downloader a sha256 only for a
//! gem that `gem_checksums` names, so here Bazel takes whatever the
//! registry serves, and it is Bundler, in the `bundle install` action of
//! the build, that holds the file to the lock. A lock without the section
//! (Bundler before 2.6 writes none) pins a gem by its source alone and
//! would build the other bytes; this fixture is not that lock.
//!
//! One loopback server stands in for three hosts, by route prefix: the
//! Socket API, `rubygems.org` (the fixture's two gems, and the
//! `info/<gem>` file `rollback` reads through `SOCKET_RUBYGEMS_URL`) and
//! `patch.socket.dev` (the patch registry). rules_ruby reads each gem's
//! remote from the lock and has Bazel download
//! `<remote>gems/<name>-<version>.gem`; Bundler then installs the files
//! with `--local` and asks no registry. Bazel drops a plain `http` URL that
//! comes without a checksum, so the lock and the grant keep the `https`
//! URLs of production and a downloader config ([`Cell::route_downloads`])
//! sends the two gems and the patch host to the stand-in. It is there from
//! the first build on, and step (c) changes no flag. Bundler itself (the
//! `bundler` gem the lock's `BUNDLED WITH` names) is not rewritten and comes
//! from rubygems.org.

use std::io::Write as _;
use std::time::Instant;

use serde_json::json;
use sha2::{Digest, Sha256};

use crate::harness::{fixture_path, rewrite, Cell, Fixture, StandIn, CONSUMER};
use crate::hosted_memory_common::Patch;

/// The sha256 of `bytes` in lowercase hex, as a `Gemfile.lock` and the gem
/// index spell a sum.
fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The workspace the test builds, and the ruleset each Bazel release builds
/// it with.
const FIXTURE: Fixture = Fixture {
    name: "ruby::FIXTURE",
    dir: "rules_ruby/bzlmod",
    workflow: "bazel-ruby.yml",
    eras: &[
        // rules_ruby 1.0.0-rc2 and its prebuilt Ruby 3.4.10, with the
        // Bundler 4.0.15 the lock names.
        ((7, 0, 0)..(10, 0, 0), "e9"),
    ],
};

/// The gem the fixture's `Gemfile` declares and its lock resolves from
/// rubygems.org.
const NAME: &str = "sp-victim";
const VERSION: &str = "1.0.0";
const PURL: &str = "pkg:gem/sp-victim@1.0.0";
/// The gem declared beside it, which has no patch.
const NEIGHBOUR: &str = "sp-other";
const UNPATCHED: &str = "OUT: PRISTINE";
/// The route prefixes of the stand-in, one per host it plays.
const RUBYGEMS: &str = "rubygems.org";
const PATCH_HOST: &str = "patch.socket.dev";

/// gzip of `bytes`, stored and not compressed, with no time and no file
/// name in its header: the same bytes on every run, as the sha256 in the
/// fixture's lock needs.
fn gzip(bytes: &[u8]) -> Vec<u8> {
    let stored = flate2::Compression::none();
    let mut gz = flate2::GzBuilder::new().write(Vec::new(), stored);
    gz.write_all(bytes).expect("gzip");
    gz.finish().expect("gzip")
}

/// A tar of regular files.
fn archive(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut tar = tar::Builder::new(Vec::new());
    for (name, bytes) in files {
        let mut header = tar::Header::new_ustar();
        // RubyGems unpacks only an entry that says it is a file.
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(0o644);
        header.set_size(bytes.len() as u64);
        tar.append_data(&mut header, name, *bytes).expect("tar");
    }
    tar.into_inner().expect("tar")
}

/// Version [`VERSION`] of a pure-Ruby gem, as a registry serves it: a tar
/// of the gzipped specification and of the gzipped tar of its files. Its
/// one file, `lib/<name>.rb` with `_` for `-`, holds `source`. Built here,
/// so no binary is committed; the fixture's lock pins the sha256 of what
/// this gives for the two upstream gems. `real_gem` of
/// `e2e_redirect_gem_stale_install.rs` builds a gem the same way in a test
/// target of its own; the two are not shared yet.
fn gem(name: &str, source: &str) -> Vec<u8> {
    let lib = format!("lib/{}.rb", name.replace('-', "_"));
    let specification = format!(
        "--- !ruby/object:Gem::Specification\n\
         name: {name}\n\
         version: !ruby/object:Gem::Version\n\
         \x20 version: {VERSION}\n\
         platform: ruby\n\
         authors:\n\
         - socket-patch\n\
         files:\n\
         - {lib}\n\
         require_paths:\n\
         - lib\n\
         specification_version: 4\n\
         summary: a test fixture\n"
    );
    let files = archive(&[(&lib, source.as_bytes())]);
    archive(&[
        ("metadata.gz", &gzip(specification.as_bytes())),
        ("data.tar.gz", &gzip(&files)),
    ])
}

/// The fixture's gem, with the text its consumer prints after `OUT: `.
fn victim(status: &str) -> Vec<u8> {
    gem(
        NAME,
        &format!("module SpVictim\n  STATUS = \"{status}\"\nend\n"),
    )
}

/// The gem beside it.
fn neighbour() -> Vec<u8> {
    gem(NEIGHBOUR, "module SpOther\nend\n")
}

/// The route of gem `name` on the registry the stand-in plays under
/// `/<base>`.
fn gem_route(base: &str, name: &str) -> String {
    format!("/{base}/gems/{name}-{VERSION}.gem")
}

/// The Socket API on `standin`: one free patch of the fixture's gem, granted
/// as the gem `patched`, with the artifact `url` (which hosted mode does not
/// fetch) and the patch registry `index`.
fn grant(standin: &StandIn, uuid: &str, url: &str, index: &str, patched: &[u8]) {
    let sum = sha256_hex(patched);
    let reference = json!({
        "status": "granted",
        "url": url,
        "purl": PURL,
        "artifacts": [{ "kind": "tarball", "url": url, "integrity": { "sha256": sum } }],
        "registryOverride": {
            "kind": "rubygems-compact-index",
            "indexUrl": index,
            "identifiers": { "name": NAME, "version": VERSION, "gemChecksumSha256": sum },
        },
    });
    let patch = Patch {
        purl: PURL.to_string(),
        uuid: uuid.to_string(),
        reference,
    };
    standin.api(&[patch]);
}

/// The flow of the module docs.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn hosted_bundle_fetch() {
    let test = "ruby::hosted_bundle_fetch";
    let started = Instant::now();
    let Some(mut cell) = Cell::open(test, &FIXTURE) else {
        return;
    };
    let release = cell.release().to_string();

    // The patched gem: the upstream gem with another text in its one file,
    // which holds an id that is new for every run. The grant names the
    // patch host as production does, with a token and the patch id in the
    // paths of the artifact and of the patch registry.
    let uuid = uuid::Uuid::new_v4().to_string();
    let token = uuid::Uuid::new_v4().to_string();
    let patched = format!("OUT: PATCHED {uuid}");
    let patched_gem = victim(&format!("PATCHED {uuid}"));
    let upstream_gem = victim("PRISTINE");
    let registry = format!("{PATCH_HOST}/patch-registry/gem/{token}/{uuid}");
    let index = format!("https://{registry}/");
    let artifact = format!(
        "https://{PATCH_HOST}/patch/gem/{NAME}/{VERSION}/{token}/{uuid}/{NAME}-{VERSION}.gem"
    );
    let (upstream_route, patched_route) = (gem_route(RUBYGEMS, NAME), gem_route(&registry, NAME));

    let standin = StandIn::start();
    let origin = standin.origin();
    standin.serve(5, &upstream_route, &upstream_gem);
    standin.serve(5, &gem_route(RUBYGEMS, NEIGHBOUR), &neighbour());
    standin.serve(5, &patched_route, &patched_gem);
    // What `rollback` reads to restore the upstream `CHECKSUMS` line: the
    // gem's file of the compact index, one line per version.
    let info = format!("---\n{VERSION} |checksum:{}\n", sha256_hex(&upstream_gem));
    standin.serve(5, &format!("/{RUBYGEMS}/info/{NAME}"), info.as_bytes());
    grant(&standin, &uuid, &artifact, &index, &patched_gem);
    let rubygems = format!("{origin}/{RUBYGEMS}");
    let socket_patch = |cell: &Cell, args: &[&str]| {
        cell.socket_patch(&origin, args, &[("SOCKET_RUBYGEMS_URL", rubygems.as_str())])
    };
    // Bazel's downloads of the fixture's two gems on rubygems.org and of
    // anything on the patch host go to the stand-in, under the route prefix
    // of the host. A URL of the patch host that no rule rewrote is refused,
    // so no download of Bazel's reaches the real one.
    let gems = |name: &str| rewrite(&format!("{RUBYGEMS}/gems/{name}-"), &origin);
    cell.route_downloads(&[
        gems(NAME),
        gems(NEIGHBOUR),
        rewrite(&format!("{PATCH_HOST}/"), &origin),
        format!("block {PATCH_HOST}"),
    ]);

    // (a) The unpatched build, with the upstream gem from the stand-in.
    let before = cell.builds_unpatched(UNPATCHED);
    let upstream_fetches = standin.asked(&upstream_route);
    assert!(
        upstream_fetches > 0,
        "{test}: the build did not fetch the upstream gem from the stand-in"
    );

    // (b) The one command of hosted mode. It rewrites those two files and
    // no other: the declaration gains the patch registry as its source, and
    // the lock resolves the gem from it, in a section of its own, with the
    // sha256 of the patched gem.
    let scan = socket_patch(&cell, &["scan", "--mode", "hosted", "--yes"]);
    let said = &scan.dump;
    let pinned = cell.pinned_by(&scan, PURL, &uuid, &before, &["Gemfile", "Gemfile.lock"]);
    let text = |rel: &str| String::from_utf8(pinned[rel].clone()).expect("a text file");
    let (gemfile, lock) = (text("Gemfile"), text("Gemfile.lock"));
    let declaration = format!("gem \"{NAME}\", \"{VERSION}\", source: \"{index}\"");
    let declared = gemfile.lines().filter(|line| *line == declaration).count();
    assert_eq!(declared, 1, "{test}: Gemfile:\n{gemfile}");
    let section = format!("GEM\n  remote: {index}\n  specs:\n    {NAME} ({VERSION})\n\n");
    let sum = |gem: &[u8]| format!("  {NAME} ({VERSION}) sha256={}\n", sha256_hex(gem));
    assert!(
        lock.contains(&section) && lock.contains(&sum(&patched_gem)),
        "{test}: Gemfile.lock:\n{lock}"
    );
    assert!(
        !lock.contains(&sum(&upstream_gem)),
        "{test}: Gemfile.lock:\n{lock}"
    );
    assert_eq!(standin.asked(&patched_route), 0, "{test}: {said}");

    // (c) The same build, no step in between: patched, from the patch
    // registry. Bazel changed no file, its own lock included, and that lock
    // still stands when Bazel may not update it.
    cell.builds_patched(&pinned, &patched);
    assert!(
        standin.asked(&patched_route) > 0,
        "{test}: the patched build did not fetch the patched gem from the stand-in"
    );
    assert_eq!(
        standin.asked(&upstream_route),
        upstream_fetches,
        "{test}: the patched build fetched the upstream gem"
    );

    // (d) The undo: every file is the one of before, and so is the build.
    let undo = socket_patch(&cell, &["rollback", "--yes"]);
    cell.undone(&undo, "rolledBack", &before, UNPATCHED);

    // (e) A second machine with the rewritten files, and a patch registry
    // that serves other bytes at the pinned URL: still a gem RubyGems
    // installs, with another sha256. The build must fail on the lock's
    // checksum, and must not go to the upstream gem instead.
    let twin = cell.twin();
    twin.write("Gemfile", &gemfile);
    twin.write("Gemfile.lock", &lock);
    let tampered_gem = victim("TAMPERED");
    standin.serve(1, &patched_route, &tampered_gem);
    // Counted here, so that only the twin's own requests are judged.
    let (patched_fetches, upstream_fetches) = (
        standin.asked(&patched_route),
        standin.asked(&upstream_route),
    );
    let build = twin.bazel("build", &[CONSUMER]);
    assert!(
        !build.ok(),
        "{test}: the tampered gem built:\n{}",
        build.dump()
    );
    // Bundler names the sha256 the lock pins and the one of the file.
    let stderr = build.stderr();
    let sums = [&patched_gem, &tampered_gem].map(|gem| format!("sha256={}", sha256_hex(gem)));
    assert!(
        stderr.contains("mismatched checksums") && sums.iter().all(|sum| stderr.contains(sum)),
        "{test}: the build did not fail on the checksum of the patched gem:\n{}",
        build.dump()
    );
    assert!(
        standin.asked(&patched_route) > patched_fetches,
        "{test}: the patch registry was not asked, so the failed build proves nothing"
    );
    assert_eq!(
        standin.asked(&upstream_route),
        upstream_fetches,
        "{test}: the build went to the upstream gem"
    );

    println!(
        "{test}: Bazel {release} built {patched:?} from {index} after `scan --mode hosted`; \
         `rollback` restored all {} files and the {UNPATCHED:?} build; other bytes at the patch \
         registry failed a second machine's build (Bundler: mismatched checksums); {origin} \
         answered {} requests for the upstream gem and {} for the patched gem; {:?}",
        before.len(),
        standin.asked(&upstream_route),
        standin.asked(&patched_route),
        started.elapsed()
    );
}

/// Without a Bazel: the fixture's directories are those of its table, and
/// the `CHECKSUMS` section of its lock pins the two gems the test serves
/// from the rubygems.org stand-in.
#[test]
fn the_fixture_pins_the_upstream_gems_the_test_serves() {
    FIXTURE.check();
    let path = fixture_path(FIXTURE.dir).join("common/Gemfile.lock");
    let lock = std::fs::read_to_string(&path).expect("the fixture's Gemfile.lock");
    let pin = |name: &str, gem: &[u8]| format!("  {name} ({VERSION}) sha256={}", sha256_hex(gem));
    let pins = [pin(NEIGHBOUR, &neighbour()), pin(NAME, &victim("PRISTINE"))];
    let section: Vec<&str> = lock
        .lines()
        .skip_while(|line| *line != "CHECKSUMS")
        .skip(1)
        .take_while(|line| !line.is_empty())
        .collect();
    // A sum is over the bytes [`gzip`] gives, so a release of flate2 that
    // stores them another way fails here: the lines on the right are then
    // the ones the lock must hold.
    assert_eq!(section, pins, "{}", path.display());
}
