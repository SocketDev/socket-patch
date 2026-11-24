//! Hosted mode for a gem that comes through rules_ruby's
//! `ruby.bundle_fetch(gemfile = "//:Gemfile", gemfile_lock = "//:Gemfile.lock")`
//! under Bzlmod, where `MODULE.bazel` gives no `gem_checksums` and
//! `Gemfile.lock` has a `CHECKSUMS` section.
//!
//! One flow, on the Bazel the run is given ([`FIXTURE`] says which ruleset
//! goes with its release), in a fresh output base:
//!
//! - (a) `bazel build` and `bazel run //:consumer` print the unpatched
//!   marker, and Bazel fetched the upstream gem from the stand-in.
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
//! The flow asserts the VEX document of its patch as `main.rs` says.
//!
//! A second flow, [`hosted_bundle_fetch_gem_checksums`], runs the command
//! in the same workspace with a `gem_checksums` on the call that names the
//! two gems. There the scan leaves the gem as it is and says how to go on,
//! the build stays the upstream one, and on each of the two ways on the
//! same scan pins the gem and the build is the patched one. Two tests
//! without a Bazel hold the command to the same in the fixture's checkout,
//! with what a person reads and the calls that stand against nothing.
//!
//! Both markers are read from what Bazel built, and each holds an id made
//! for the run, so no cache of an earlier run can supply either gem. The
//! fixture's lock therefore holds no sha256 of a gem: it has a placeholder
//! for each of its two gems, and the test writes the sums of the gems it
//! built into the lock of the workspace copy before the first build
//! ([`lock_pinning`]). No committed value depends on the bytes that the
//! gzip and tar libraries of the test emit.
//!
//! What fails the build in (e) is the lock's `CHECKSUMS` section and
//! nothing else. rules_ruby gives Bazel's downloader a sha256 only for a
//! gem that `gem_checksums` names, so here Bazel takes whatever the
//! registry serves, and it is Bundler, in the `bundle install` action of
//! the build, that holds the file to the lock. The fixture's lock has the
//! section. The flow proves nothing for a lock without one: there Bundler
//! has no sum to hold a gem to, the gem is pinned by its source alone, and
//! the build takes whatever bytes the patch registry serves. Many projects
//! have that lock. Bundler writes the section into a new lock by default
//! only from 4.0.0 on; from 2.6.0 it writes one on request (`bundle lock
//! --add-checksums`, or the `lockfile_checksums` setting for a new lock),
//! and a lock that exists keeps what it has. The fixture's lock names
//! Bundler 4.0.15; the Bundler of its Ruby 3.4.10 is 2.6.9.
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

use crate::envelope::{codes_in, event_for};
use crate::harness::{
    cell_without_bazel, changed, fixture_path, rewrite, with_vex, Cell, Claim, Fixture, How, Ran,
    StandIn, Tree, CONSUMER, NOTHING,
};
use crate::hosted_memory_common::{read_tree, Patch};

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
/// What the fixture's lock holds as the sha256 of each upstream gem: the
/// sum of no file.
const PLACEHOLDER: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// The route prefixes of the stand-in, one per host it plays.
const RUBYGEMS: &str = "rubygems.org";
const PATCH_HOST: &str = "patch.socket.dev";

/// gzip of `bytes`, stored and not compressed.
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
/// so no binary is committed, and no sha256 of one. `real_gem` of
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

/// The line of a lock's `CHECKSUMS` section that pins version [`VERSION`]
/// of the gem `name` to `sha256`.
fn checksum(name: &str, sha256: &str) -> String {
    format!("  {name} ({VERSION}) sha256={sha256}\n")
}

/// The fixture's lock with the sha256 of the two upstream gems, `neighbour`
/// and `upstream`, each in place of its placeholder: the lock a test writes
/// into its workspace copy before the first build.
fn lock_pinning(neighbour: &[u8], upstream: &[u8]) -> String {
    let path = fixture_path(FIXTURE.dir).join("common/Gemfile.lock");
    let mut lock = std::fs::read_to_string(&path).expect("the fixture's Gemfile.lock");
    for (name, gem) in [(NEIGHBOUR, neighbour), (NAME, upstream)] {
        let unpinned = checksum(name, PLACEHOLDER);
        let lines = lock.matches(&unpinned).count();
        assert_eq!(lines, 1, "{}: not one\n{unpinned}", path.display());
        lock = lock.replace(&unpinned, &checksum(name, &sha256_hex(gem)));
    }
    lock
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

/// What a flow serves on its stand-in and builds: the upstream gem and the
/// patched gem, one gem with two texts in its one file, each with an id
/// that is new for every run. The grant names the patch host as production
/// does, with a token and the patch id in the paths of the artifact and of
/// the patch registry.
struct Served {
    standin: StandIn,
    /// The id of the patch.
    uuid: String,
    /// The line the consumer prints from the upstream gem, and from the
    /// patched one.
    unpatched: String,
    patched: String,
    upstream_gem: Vec<u8>,
    patched_gem: Vec<u8>,
    neighbour_gem: Vec<u8>,
    /// The patch registry of the grant, and the routes of the gem on
    /// rubygems.org and on that registry.
    index: String,
    upstream_route: String,
    patched_route: String,
}

impl Served {
    /// Starts the stand-in, and sends the downloads of `cell`'s Bazel to it.
    fn start(cell: &mut Cell) -> Served {
        let run = uuid::Uuid::new_v4().to_string();
        let uuid = uuid::Uuid::new_v4().to_string();
        let token = uuid::Uuid::new_v4().to_string();
        let patched_gem = victim(&format!("PATCHED {uuid}"));
        let upstream_gem = victim(&format!("PRISTINE {run}"));
        let neighbour_gem = neighbour();
        let registry = format!("{PATCH_HOST}/patch-registry/gem/{token}/{uuid}");
        let index = format!("https://{registry}/");
        let artifact = format!(
            "https://{PATCH_HOST}/patch/gem/{NAME}/{VERSION}/{token}/{uuid}/{NAME}-{VERSION}.gem"
        );
        let (upstream_route, patched_route) =
            (gem_route(RUBYGEMS, NAME), gem_route(&registry, NAME));

        let standin = StandIn::start();
        let origin = standin.origin();
        standin.serve(5, &upstream_route, &upstream_gem);
        standin.serve(5, &gem_route(RUBYGEMS, NEIGHBOUR), &neighbour_gem);
        standin.serve(5, &patched_route, &patched_gem);
        // What `rollback` reads to restore the upstream `CHECKSUMS` line: the
        // gem's file of the compact index, one line per version.
        let info = format!("---\n{VERSION} |checksum:{}\n", sha256_hex(&upstream_gem));
        standin.serve(5, &format!("/{RUBYGEMS}/info/{NAME}"), info.as_bytes());
        grant(&standin, &uuid, &artifact, &index, &patched_gem);
        // Bazel's downloads of the fixture's two gems on rubygems.org and of
        // anything on the patch host go to the stand-in, under the route
        // prefix of the host. A URL of the patch host that no rule rewrote is
        // refused, so no download of Bazel's reaches the real one.
        let gems = |name: &str| rewrite(&format!("{RUBYGEMS}/gems/{name}-"), &origin);
        cell.route_downloads(&[
            gems(NAME),
            gems(NEIGHBOUR),
            rewrite(&format!("{PATCH_HOST}/"), &origin),
            format!("block {PATCH_HOST}"),
        ]);
        Served {
            standin,
            unpatched: format!("OUT: PRISTINE {run}"),
            patched: format!("OUT: PATCHED {uuid}"),
            uuid,
            upstream_gem,
            patched_gem,
            neighbour_gem,
            index,
            upstream_route,
            patched_route,
        }
    }
}

/// `socket-patch <args>` in `cell`, against `standin`.
fn socket_patch_at(standin: &StandIn, cell: &Cell, args: &[&str]) -> Ran {
    let origin = standin.origin();
    let rubygems = format!("{origin}/{RUBYGEMS}");
    cell.socket_patch(&origin, args, &[("SOCKET_RUBYGEMS_URL", rubygems.as_str())])
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
    let Served {
        standin,
        uuid,
        unpatched,
        patched,
        upstream_gem,
        patched_gem,
        neighbour_gem,
        index,
        upstream_route,
        patched_route,
    } = Served::start(&mut cell);
    let origin = standin.origin();
    let socket_patch = |cell: &Cell, args: &[&str]| socket_patch_at(&standin, cell, args);

    // (a) The unpatched build. The lock of the checkout pins the two
    // upstream gems of this run, which only the stand-in has.
    cell.write("Gemfile.lock", lock_pinning(&neighbour_gem, &upstream_gem));
    let before = cell.builds_unpatched(&unpatched);
    let upstream_fetches = standin.asked(&upstream_route);
    assert!(
        upstream_fetches > 0,
        "{test}: the build did not fetch the upstream gem from the stand-in"
    );

    // (b) The one command of hosted mode. It rewrites those two files and
    // no other: the declaration gains the patch registry as its source, and
    // the lock resolves the gem from it, in a section of its own, with the
    // sha256 of the patched gem.
    let hosted = ["scan", "--mode", "hosted", "--yes"];
    let claim = Claim::new(PURL, &uuid, How::Hosted);
    let in_run = cell.document("in-run");
    let scan = socket_patch(&cell, &[&hosted[..], &with_vex(&in_run)].concat());
    let said = &scan.dump;
    let pinned = cell.pinned_by(&scan, PURL, &uuid, &before, &["Gemfile", "Gemfile.lock"]);
    let text = |rel: &str| String::from_utf8(pinned[rel].clone()).expect("a text file");
    let (gemfile, lock) = (text("Gemfile"), text("Gemfile.lock"));
    let declaration = format!("gem \"{NAME}\", \"{VERSION}\", source: \"{index}\"");
    let declared = gemfile.lines().filter(|line| *line == declaration).count();
    assert_eq!(declared, 1, "{test}: Gemfile:\n{gemfile}");
    let section = format!("GEM\n  remote: {index}\n  specs:\n    {NAME} ({VERSION})\n\n");
    let sum = |gem: &[u8]| checksum(NAME, &sha256_hex(gem));
    assert!(
        lock.contains(&section) && lock.contains(&sum(&patched_gem)),
        "{test}: Gemfile.lock:\n{lock}"
    );
    assert!(
        !lock.contains(&sum(&upstream_gem)),
        "{test}: Gemfile.lock:\n{lock}"
    );
    // The document of that run and the one of `vex` say so, in a checkout
    // Bazel has built in, before anything has fetched the patched gem.
    cell.wrote_in_run(&scan, &in_run, &claim);
    cell.stands_alone(socket_patch, &claim, true);
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
    // `vex` says the same of the build that printed the patched marker,
    // and with `--no-verify` that it checked no file.
    cell.stands_alone(socket_patch, &claim, true);
    cell.stands_alone(socket_patch, &claim, false);
    // Without a product, as a user types it, `vex` writes none: the
    // checkout has no file it reads a product from.
    cell.detects_product(socket_patch, None);

    // (d) The undo: every file is the one of before, and so is the build,
    // and `vex` has no document for it.
    let undo = socket_patch(&cell, &["rollback", "--yes"]);
    cell.undone(&undo, "rolledBack", &before, &unpatched);
    cell.attests_nothing(socket_patch, 2, "manifest_not_found");
    // The same two documents where no Bazel has built.
    cell.attests_unbuilt(socket_patch, &hosted, &before, &pinned, &claim);

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
         `rollback` restored all {} files and the {unpatched:?} build; other bytes at the patch \
         registry failed a second machine's build (Bundler: mismatched checksums); {origin} \
         answered {} requests for the upstream gem and {} for the patched gem; {:?}",
        before.len(),
        standin.asked(&upstream_route),
        standin.asked(&patched_route),
        started.elapsed()
    );
}

/// The fixture's `MODULE.bazel` with a `gem_checksums` on its
/// `ruby.bundle_fetch` call, which holds version [`VERSION`] of each gem of
/// `sums` to the sha256 beside its name: the file a test writes into its
/// workspace copy. The call stays on the line it is on.
fn module_pinning(sums: &[(&str, &str)]) -> String {
    let path = fixture_path(FIXTURE.dir).join("e9/MODULE.bazel");
    let module = std::fs::read_to_string(&path).expect("the fixture's MODULE.bazel");
    let lock = "    gemfile_lock = \"//:Gemfile.lock\",\n";
    assert_eq!(module.matches(lock).count(), 1, "{}", path.display());
    let entry =
        |(name, sha256): &(&str, &str)| format!("        \"{name}-{VERSION}\": \"{sha256}\",\n");
    let entries: String = sums.iter().map(entry).collect();
    module.replace(
        lock,
        &format!("{lock}    gem_checksums = {{\n{entries}    }},\n"),
    )
}

/// The code of the warning for a gem that a call holds to another sha256.
const HELD: &str = "redirect_bazel_gem_checksums_pinned";

/// What a hosted scan that left the fixture's gem as it is says, for its
/// finished `scan`: it passes, applies nothing and rewrites no file, the
/// gem is skipped as one that nothing pins, one warning names the call of
/// `MODULE.bazel` and the entry of the gem, and no file of the checkout
/// differs from `before`. Gives the text of that warning.
fn left_alone(cell: &Cell, scan: &Ran, before: &Tree) -> String {
    let (test, said) = (&cell.test, &scan.dump);
    assert_eq!(scan.code, 0, "{test}: {said}");
    assert_eq!(scan.envelope["status"], "success", "{test}: {said}");
    assert_eq!(scan.envelope["summary"]["applied"], 0, "{test}: {said}");
    let event = event_for(&scan.envelope, PURL);
    assert_eq!(event["action"], "skipped", "{test}: {said}");
    assert_eq!(event["errorCode"], "redirect_unconfirmed", "{test}: {said}");
    let rewritten = &scan.envelope["redirect"]["rewrittenFiles"];
    assert_eq!(*rewritten, json!([]), "{test}: {said}");
    let warnings = scan.envelope["warnings"].as_array().expect("warnings");
    let held = |warning: &&serde_json::Value| warning["code"] == HELD;
    let held: Vec<_> = warnings.iter().filter(held).collect();
    assert_eq!(held.len(), 1, "{test}: {said}");
    let detail = held[0]["detail"].as_str().expect("a detail");
    let named = format!(
        "{NAME}@{VERSION}: `ruby.bundle_fetch` at MODULE.bazel:15 holds `{NAME}-{VERSION}` to \
         another sha256"
    );
    assert!(detail.starts_with(&named), "{test}: {said}");
    assert_eq!(changed(before, &cell.tree()), NOTHING, "{test}: {said}");
    assert!(!cell.path(".socket").exists(), "{test}: {said}");
    detail.to_string()
}

/// The sha256 that the warning `detail` says to put in the entry of the
/// fixture's gem, and whether it also offers to delete the gem from the
/// dict.
fn way_on(detail: &str) -> (&str, bool) {
    let change = format!("To patch it, change `{NAME}-{VERSION}` to `");
    let (_, sha256) = detail.split_once(&change).expect("the sha256 to put there");
    let sha256 = sha256.split('`').next().expect("a sha256");
    (sha256, detail.contains("or delete the gem from the dict"))
}

/// Hosted mode beside a hub that holds the gem to a sha256 of its own: the
/// `ruby.bundle_fetch` call of the workspace copy names the two gems in
/// `gem_checksums`, each with the sha256 of its upstream archive, as the
/// examples of rules_ruby do. rules_ruby gives Bazel's downloader that
/// sha256 for the gem, whatever the lock says.
///
/// - (a) The build prints the unpatched marker.
/// - (b) `socket-patch scan --mode hosted --yes` leaves the gem as it is
///   ([`left_alone`]): the redirect would fail the next build on the
///   sha256 of the call.
/// - (c) The same build passes, on the upstream gem, and nothing asked the
///   patch registry.
/// - (d) The first way on of the warning: with the sha256 it names in the
///   entry, the same scan rewrites `Gemfile` and `Gemfile.lock` and the
///   build prints the patched marker, from the patch registry. The VEX
///   documents of that run and of `vex` say so.
/// - (e) `rollback` restores the two files and leaves the call. With the
///   old sha256 back in the entry, as the warning says, every file is the
///   one of before and so is the build.
/// - (f) The second way on, which the warning offers for a lock with a
///   `CHECKSUMS` section: with the gem deleted from the dict, which then
///   names the other gem alone, the same scan rewrites the two files and
///   the build prints the patched marker.
///
/// After (a), which writes Bazel's own lock, no build of the flow changes
/// a file of the checkout, also after the test changed the call:
/// rules_ruby declares its extension reproducible, and Bazel keeps such a
/// one out of that lock.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn hosted_bundle_fetch_gem_checksums() {
    let test = "ruby::hosted_bundle_fetch_gem_checksums";
    let started = Instant::now();
    let Some(mut cell) = Cell::open(test, &FIXTURE) else {
        return;
    };
    let release = cell.release().to_string();
    let served = Served::start(&mut cell);
    let standin = &served.standin;
    let socket_patch = |cell: &Cell, args: &[&str]| socket_patch_at(standin, cell, args);
    let (other, upstream, patched) = (
        sha256_hex(&served.neighbour_gem),
        sha256_hex(&served.upstream_gem),
        sha256_hex(&served.patched_gem),
    );
    let files = ["Gemfile", "Gemfile.lock"];

    // (a) The unpatched build, with the two upstream gems pinned in the
    // lock and in the call.
    cell.write(
        "Gemfile.lock",
        lock_pinning(&served.neighbour_gem, &served.upstream_gem),
    );
    let held = module_pinning(&[(NEIGHBOUR, &other), (NAME, &upstream)]);
    cell.write("MODULE.bazel", &held);
    let before = cell.builds_unpatched(&served.unpatched);
    let upstream_fetches = standin.asked(&served.upstream_route);

    // (b) The one command of hosted mode leaves the gem as it is.
    let hosted = ["scan", "--mode", "hosted", "--yes"];
    let warned = left_alone(&cell, &socket_patch(&cell, &hosted), &before);
    let named = way_on(&warned);
    assert_eq!(named, (patched.as_str(), true), "{test}: {warned}");
    let (named, _) = named;

    // (c) The same build, on the upstream gem.
    cell.builds(&served.unpatched);
    assert_eq!(changed(&before, &cell.tree()), NOTHING, "{test}");
    assert_eq!(standin.asked(&served.patched_route), 0, "{test}");

    // (d) The first way on: the sha256 the warning names, in the entry.
    cell.write(
        "MODULE.bazel",
        module_pinning(&[(NEIGHBOUR, &other), (NAME, named)]),
    );
    let edited = cell.tree();
    let claim = Claim::new(PURL, &served.uuid, How::Hosted);
    let in_run = cell.document("in-run");
    let scan = socket_patch(&cell, &[&hosted[..], &with_vex(&in_run)].concat());
    let pinned = cell.pinned_by(&scan, PURL, &served.uuid, &edited, &files);
    let lock = String::from_utf8_lossy(&pinned["Gemfile.lock"]).into_owned();
    assert!(lock.contains(&checksum(NAME, &patched)), "{test}:\n{lock}");
    cell.wrote_in_run(&scan, &in_run, &claim);
    cell.builds_patched(&pinned, &served.patched);
    assert!(standin.asked(&served.patched_route) > 0, "{test}");
    assert_eq!(
        standin.asked(&served.upstream_route),
        upstream_fetches,
        "{test}: the patched build fetched the upstream gem"
    );
    cell.stands_alone(socket_patch, &claim, true);

    // (e) The undo restores the two files and leaves the call, which the
    // warning says to put back by hand: then nothing differs from before.
    let undo = socket_patch(&cell, &["rollback", "--yes"]);
    let left = changed(&before, &cell.tree());
    assert_eq!(left, ["MODULE.bazel"], "{test}: {}", undo.dump);
    cell.write("MODULE.bazel", &held);
    cell.undone(&undo, "rolledBack", &before, &served.unpatched);

    // (f) The second way on: the gem deleted from the dict.
    cell.write("MODULE.bazel", module_pinning(&[(NEIGHBOUR, &other)]));
    let edited = cell.tree();
    let patched_fetches = standin.asked(&served.patched_route);
    let scan = socket_patch(&cell, &hosted);
    let pinned = cell.pinned_by(&scan, PURL, &served.uuid, &edited, &files);
    assert_eq!(codes_in(&scan.envelope["warnings"]), NOTHING, "{test}");
    cell.builds_patched(&pinned, &served.patched);
    assert!(
        standin.asked(&served.patched_route) > patched_fetches,
        "{test}: the patched build did not fetch the patched gem from the stand-in"
    );

    println!(
        "{test}: Bazel {release} built {:?} before and after `scan --mode hosted` left the gem \
         that `gem_checksums` holds as it was ({HELD}); with the sha256 of the warning in the \
         entry, and again with the gem deleted from the dict, the same scan pinned it and the \
         build printed {:?} and changed no file; `rollback` restored the files but the call; \
         {:?}",
        served.unpatched,
        served.patched,
        started.elapsed()
    );
}

/// Without a Bazel: the fixture in a checkout of its own, with the lock
/// that pins the two upstream gems of `served` and `module` as its
/// `MODULE.bazel`; `None` leaves the checkout without one, in no Bazel
/// workspace.
fn checkout(served: &Served, module: Option<&str>) -> Cell {
    let cell = cell_without_bazel("9.3.2");
    for part in ["common", "e9"] {
        for (rel, bytes) in read_tree(&fixture_path(FIXTURE.dir).join(part)) {
            cell.write(&rel, bytes);
        }
    }
    cell.write(".git/HEAD", "ref: refs/heads/main\n");
    cell.write(
        "Gemfile.lock",
        lock_pinning(&served.neighbour_gem, &served.upstream_gem),
    );
    match module {
        Some(module) => cell.write("MODULE.bazel", module),
        None => std::fs::remove_file(cell.path("MODULE.bazel")).expect("remove MODULE.bazel"),
    }
    cell
}

/// `text` without its white space: a line a terminal may have wrapped.
fn unspaced(text: &str) -> String {
    text.split_whitespace().collect()
}

/// Without a Bazel: steps (b), (d) and (f) of
/// [`hosted_bundle_fetch_gem_checksums`] in the fixture's checkout, with
/// what a person reads of (b), and (b) again with `--dry-run` and with
/// `--vex`. On either way on, the two files a scan rewrites are, byte for
/// byte, the ones it rewrites in the same checkout without a
/// `MODULE.bazel`, and `rollback` restores them and leaves the call.
#[test]
fn a_gem_that_the_hub_holds_to_its_upstream_sha256_is_left_alone() {
    let served = Served::start(&mut cell_without_bazel("9.3.2"));
    let run = |cell: &Cell, args: &[&str]| socket_patch_at(&served.standin, cell, args);
    let (other, upstream, patched) = (
        sha256_hex(&served.neighbour_gem),
        sha256_hex(&served.upstream_gem),
        sha256_hex(&served.patched_gem),
    );
    let hosted = ["scan", "--mode", "hosted", "--yes"];
    let files = ["Gemfile", "Gemfile.lock"];
    let plain = checkout(&served, None);
    let before = plain.tree();
    let scan = run(&plain, &hosted);
    let plain = plain.pinned_by(&scan, PURL, &served.uuid, &before, &files);

    let held = module_pinning(&[(NEIGHBOUR, &other), (NAME, &upstream)]);
    let cell = checkout(&served, Some(&held));
    let before = cell.tree();
    let warned = left_alone(&cell, &run(&cell, &hosted), &before);
    assert_eq!(way_on(&warned), (patched.as_str(), true), "{warned}");
    let preview = run(&cell, &[&hosted[..], &["--dry-run"]].concat());
    assert_eq!(left_alone(&cell, &preview, &before), warned);
    // With `--vex` the run has nothing to attest, like any run that pins
    // nothing: it fails on that, with the warning and no document.
    let document = cell.document("left-alone");
    let scan = run(&cell, &[&hosted[..], &with_vex(&document)].concat());
    assert_eq!(scan.code, 1, "{}", scan.dump);
    let error = &scan.envelope["error"]["code"];
    assert_eq!(error, "manifest_not_found", "{}", scan.dump);
    let warnings = codes_in(&scan.envelope["warnings"]);
    assert!(warnings.iter().any(|code| code == HELD), "{}", scan.dump);
    assert!(!document.exists(), "{}", scan.dump);
    assert_eq!(changed(&before, &cell.tree()), NOTHING, "{}", scan.dump);

    // A person reads the same words, after the line that names the gem.
    let origin = served.standin.origin();
    let [stdout, stderr] = cell.socket_patch_person(&origin, &hosted, &[]);
    let said = format!("--- stdout\n{stdout}\n--- stderr\n{stderr}");
    let summary = "Switched 0 packages to hosted patches; rewrote 0 files.";
    assert!(stdout.lines().any(|line| line == summary), "{said}");
    let unpinned = format!(
        "  {PURL}: no lockfile entry pinning it could be rewritten (see the warning below)"
    );
    assert!(stderr.lines().any(|line| line == unpinned), "{said}");
    let warning = unspaced(&format!("Warning: {warned}"));
    assert!(unspaced(&stderr).contains(&warning), "{said}");
    assert_eq!(changed(&before, &cell.tree()), NOTHING, "{said}");

    // A pin that an earlier release wrote beside the entry stays: the scan
    // names the entry and says that the pin stays, not that a redirect was
    // skipped, and counts the gem as hosted, for the pin in the lock.
    for file in files {
        cell.write(file, &plain[file]);
    }
    let earlier = cell.tree();
    let scan = run(&cell, &hosted);
    assert_eq!(scan.code, 0, "{}", scan.dump);
    let event = event_for(&scan.envelope, PURL);
    assert_eq!(event["action"], "applied", "{}", scan.dump);
    assert_eq!(
        codes_in(&scan.envelope["warnings"]),
        [HELD],
        "{}",
        scan.dump
    );
    let detail = scan.envelope["warnings"][0]["detail"].as_str().unwrap();
    let stays = format!(
        "; the pin an earlier run wrote is left as it is (nothing rewritten). To build it \
         patched, change `{NAME}-{VERSION}` to `{patched}` there, or delete the gem from the dict"
    );
    assert!(detail.contains(&stays), "{}", scan.dump);
    let undo_one = format!("`socket-patch rollback pkg:gem/{NAME}@{VERSION}`");
    assert!(detail.contains(&undo_one), "{}", scan.dump);
    assert!(!detail.contains("redirect skipped"), "{}", scan.dump);
    assert_eq!(changed(&earlier, &cell.tree()), NOTHING, "{}", scan.dump);
    let undo = run(&cell, &["rollback", "--yes"]);
    assert_eq!(undo.envelope["summary"]["rolledBack"], 1, "{}", undo.dump);
    assert_eq!(changed(&before, &cell.tree()), NOTHING, "{}", undo.dump);

    // The two ways on.
    for sums in [
        vec![(NEIGHBOUR, other.as_str()), (NAME, patched.as_str())],
        vec![(NEIGHBOUR, other.as_str())],
    ] {
        cell.write("MODULE.bazel", module_pinning(&sums));
        let edited = cell.tree();
        let scan = run(&cell, &hosted);
        let pinned = cell.pinned_by(&scan, PURL, &served.uuid, &edited, &files);
        assert_eq!(codes_in(&scan.envelope["warnings"]), NOTHING, "{sums:?}");
        for file in files {
            assert_eq!(pinned[file], plain[file], "{file}: {sums:?}");
        }
        let undo = run(&cell, &["rollback", "--yes"]);
        assert_eq!(undo.envelope["summary"]["rolledBack"], 1, "{}", undo.dump);
        assert_eq!(changed(&edited, &cell.tree()), NOTHING, "{}", undo.dump);
    }
}

/// Without a Bazel: what else a call can say, each as the `MODULE.bazel`
/// of the fixture's checkout. A lock without a `CHECKSUMS` section leaves
/// the gem as it is too, and its warning does not offer to delete the gem
/// from the dict: nothing but the entry would hold the gem to a sha256.
/// A `gem_checksums` that is not written out may hold the gem. A call that
/// reads the lock of another project, and one without `gem_checksums`,
/// stand against nothing: the scan rewrites what it rewrites without a
/// `MODULE.bazel`.
#[test]
fn a_call_stands_against_a_gem_only_where_it_may_hold_it() {
    let served = Served::start(&mut cell_without_bazel("9.3.2"));
    let run = |cell: &Cell, args: &[&str]| socket_patch_at(&served.standin, cell, args);
    let (upstream, patched) = (
        sha256_hex(&served.upstream_gem),
        sha256_hex(&served.patched_gem),
    );
    let hosted = ["scan", "--mode", "hosted", "--yes"];
    let files = ["Gemfile", "Gemfile.lock"];
    let held = module_pinning(&[(NAME, &upstream)]);

    // A lock that Bundler holds no gem to.
    let cell = checkout(&served, Some(&held));
    let lock = lock_pinning(&served.neighbour_gem, &served.upstream_gem);
    let (unchecked, _) = lock.split_once("CHECKSUMS\n").expect("the section");
    cell.write(
        "Gemfile.lock",
        format!("{unchecked}BUNDLED WITH\n  4.0.15\n"),
    );
    let before = cell.tree();
    let warned = left_alone(&cell, &run(&cell, &hosted), &before);
    assert_eq!(way_on(&warned), (patched.as_str(), false), "{warned}");

    // A `gem_checksums` that names a constant of the file.
    let (calls, _) = held.split_once("    gem_checksums = {").expect("the dict");
    let unread = format!("{calls}    gem_checksums = HELD,\n)\n");
    let unread = unread.replace("ruby.bundle_fetch(", "HELD = {}\n\nruby.bundle_fetch(");
    let cell = checkout(&served, Some(&unread));
    let before = cell.tree();
    let scan = run(&cell, &hosted);
    let warned = codes_in(&scan.envelope["warnings"]);
    assert_eq!(warned, [HELD], "{}", scan.dump);
    let detail = scan.envelope["warnings"][0]["detail"].as_str().unwrap();
    let named = format!(
        "{NAME}@{VERSION}: `ruby.bundle_fetch` at MODULE.bazel:17 has a `gem_checksums` that is \
         not written out"
    );
    assert!(detail.starts_with(&named), "{}", scan.dump);
    assert_eq!(changed(&before, &cell.tree()), NOTHING, "{}", scan.dump);

    // Nothing stands against the gem: as without a `MODULE.bazel`.
    let plain = checkout(&served, None);
    let before = plain.tree();
    let scan = run(&plain, &hosted);
    let plain = plain.pinned_by(&scan, PURL, &served.uuid, &before, &files);
    let elsewhere = held.replace("\"//:Gemfile.lock\"", "\"//other:Gemfile.lock\"");
    let unheld = fixture_path(FIXTURE.dir).join("e9/MODULE.bazel");
    let unheld = std::fs::read_to_string(unheld).expect("the fixture's MODULE.bazel");
    for module in [elsewhere, unheld] {
        assert!(module.contains("ruby.bundle_fetch("), "{module}");
        let cell = checkout(&served, Some(&module));
        let before = cell.tree();
        let scan = run(&cell, &hosted);
        let pinned = cell.pinned_by(&scan, PURL, &served.uuid, &before, &files);
        assert_eq!(codes_in(&scan.envelope["warnings"]), NOTHING, "{module}");
        for file in files {
            assert_eq!(pinned[file], plain[file], "{file}: {module}");
        }
    }
}

/// Without a Bazel, what stays fixed now that no sum is committed: the
/// fixture's directories and the legs of its workflow are those of its
/// table, and the `CHECKSUMS` section of the fixture's lock is one line per
/// gem the test serves, each with the placeholder, so that a pinned lock
/// holds the sums of those two gems and no other.
#[test]
fn a_test_pins_the_two_upstream_gems_of_the_fixture_lock() {
    FIXTURE.check();
    let (other, upstream) = (neighbour(), victim("PRISTINE of a run"));
    let pinned = lock_pinning(&other, &upstream);
    let sum = |name, gem: &[u8]| checksum(name, &sha256_hex(gem));
    let sums = sum(NEIGHBOUR, &other) + &sum(NAME, &upstream);
    let section = format!("\nCHECKSUMS\n{sums}\n");
    assert!(pinned.contains(&section), "{pinned}");
}
