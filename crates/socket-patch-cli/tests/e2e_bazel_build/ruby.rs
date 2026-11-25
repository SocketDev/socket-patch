//! Hosted and vendored mode for a gem that comes through rules_ruby's
//! `ruby.bundle_fetch(gemfile = "//:Gemfile", gemfile_lock = "//:Gemfile.lock")`
//! under Bzlmod, where `MODULE.bazel` gives no `gem_checksums` and
//! `Gemfile.lock` has a `CHECKSUMS` section.
//!
//! The hosted flow, on the Bazel the run is given ([`FIXTURE`] says which
//! ruleset goes with its release), in a fresh output base:
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
//! Outside a Bazel workspace vendored mode commits the unpacked patched gem
//! under `.socket/vendor/gem` and makes `Gemfile` and `Gemfile.lock` name
//! it by its path from the project. rules_ruby runs `bundle install` in a
//! repository of Bazel's that holds the two files and not the copy, so that
//! form fails the build of this checkout, where the hub reads both files.
//!
//! A vendored gem that this hub does build is one the lock names as hosted
//! mode names it, with the patch registry's URL replaced by a relative
//! `file:` URL of a directory of the checkout that holds the patched gem at
//! `gems/<name>-<version>.gem`. rules_ruby asks Bazel for that URL, Bazel
//! reads it from the root of the workspace, and Bundler holds the file to
//! the lock's `CHECKSUMS` line. [`file_source_by_hand`] writes those three
//! files by hand ([`by_hand`]) and builds them on a second machine that
//! reaches no patch host, and on a third one where one byte of the gem is
//! another. The hub runs the Bundler its lock names, so the flow does both
//! again with a lock that names Bundler 2.6.9 ([`OLDER_BUNDLER`]).
//!
//! [`vendored_bundle_fetch`] holds `scan --mode vendored` to writing those
//! files, byte for byte, where the checkout names the Bazel release it is
//! built with, and to declining the gem where it names none: Bazel 9.1.0
//! fails on such a URL, and nothing in the checkout says that another
//! release builds it. The tests without a Bazel hold it to every other
//! condition under which it declines
//! ([`a_gem_is_declined_where_the_committed_gem_is_not_known_to_build`]):
//! a Bundler in the lock that no hub here was built with, a second call
//! that reads the pair and holds the gem to other bytes or to none, and
//! the rest.
//! With `--allow-vendored-in-bazel` the command writes the copy of every
//! other project, as it did.
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
//! from rubygems.org. Vendored mode downloads the patched gem itself, from
//! the patch host: the commands of that mode are told that the stand-in is
//! that host (`SOCKET_PATCH_SERVER_URL`).

use std::io::Write as _;
use std::path::PathBuf;
use std::time::Instant;

use base64::Engine as _;
use serde_json::json;
use sha2::{Digest, Sha256, Sha512};

use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;

use crate::envelope::{codes_in, event_for, events};
use crate::harness::{
    cell_without_bazel, changed, fixture_path, rewrite, with_vex, Cell, Claim, Declined, Fixture,
    How, Ran, StandIn, Tree, ALLOW, CONSUMER, NOTHING, REPO_CACHE, VENDORED,
};
use crate::hosted_memory_common::{read_tree, Patch, ORG};

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

/// The one file of the fixture's gem.
const LIB: &str = "lib/sp_victim.rb";

/// What that file holds in the gem whose consumer prints `status` after
/// `OUT: `.
fn source(status: &str) -> String {
    format!("module SpVictim\n  STATUS = \"{status}\"\nend\n")
}

/// The fixture's gem, with the text its consumer prints after `OUT: `.
fn victim(status: &str) -> Vec<u8> {
    gem(NAME, &source(status))
}

/// The specification the patch service serves beside a patched gem, which
/// vendored mode keeps in the copy: what RubyGems prints for the one of
/// [`gem`] (`Gem::Specification#to_ruby`).
fn stub() -> String {
    format!(
        "# -*- encoding: utf-8 -*-\n# stub: {NAME} {VERSION} ruby lib\n\n\
         Gem::Specification.new do |s|\n\
         \x20 s.name = \"{NAME}\".freeze\n\
         \x20 s.version = \"{VERSION}\".freeze\n\
         \x20 s.require_paths = [\"lib\".freeze]\n\
         \x20 s.authors = [\"socket-patch\".freeze]\n\
         \x20 s.files = [\"{LIB}\".freeze]\n\
         \x20 s.summary = \"a test fixture\".freeze\n\
         end\n"
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

/// A sum of `bytes` as a grant spells the one vendored mode holds a
/// download to.
fn sha512_sri(bytes: &[u8]) -> String {
    let digest = base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes));
    format!("sha512-{digest}")
}

/// What a flow builds from and patches with: the fixture's two gems as one
/// run has them, and one patch of [`NAME`], on a stand-in. Each gem of
/// [`NAME`] holds an id that is new for every run.
struct Served {
    standin: StandIn,
    /// The id of the patch.
    uuid: String,
    /// The line the consumer prints for the upstream gem, and for the
    /// patched one.
    unpatched: String,
    patched: String,
    upstream_gem: Vec<u8>,
    patched_gem: Vec<u8>,
    neighbour_gem: Vec<u8>,
    /// The patch registry of the grant.
    index: String,
    /// The routes of the stand-in for the upstream gem and for the patched
    /// one, as Bazel fetches them.
    upstream_route: String,
    patched_route: String,
    /// The route of the patched gem as vendored mode downloads it.
    artifact_route: String,
}

impl Served {
    /// The stand-in of a flow in `cell`, whose lock then pins the two
    /// upstream gems of this run, which only the stand-in has.
    ///
    /// The grant names the patch host as production does, with a token and
    /// the patch id in the paths of its artifacts and of the patch
    /// registry: the patched gem and its specification, which vendored
    /// mode downloads, and the registry hosted mode writes into the lock.
    /// The record of the patch holds the hashes of the file it changes.
    ///
    /// Bazel's downloads of the fixture's two gems on rubygems.org and of
    /// anything on the patch host go to the stand-in, under the route
    /// prefix of the host. A URL of the patch host that no rule rewrote is
    /// refused, so no download of Bazel's reaches the real one.
    fn to(cell: &mut Cell) -> Served {
        let [run, uuid, token] = [(); 3].map(|()| uuid::Uuid::new_v4().to_string());
        let (pristine, fixed) = (format!("PRISTINE {run}"), format!("PATCHED {uuid}"));
        let (upstream_gem, patched_gem) = (victim(&pristine), victim(&fixed));
        let neighbour_gem = neighbour();
        let registry = format!("{PATCH_HOST}/patch-registry/gem/{token}/{uuid}");
        let index = format!("https://{registry}/");
        let artifacts = format!("/patch/gem/{NAME}/{VERSION}/{token}/{uuid}/{NAME}-{VERSION}");
        let (upstream_route, patched_route) =
            (gem_route(RUBYGEMS, NAME), gem_route(&registry, NAME));

        let standin = StandIn::start();
        let origin = standin.origin();
        standin.serve(5, &upstream_route, &upstream_gem);
        standin.serve(5, &gem_route(RUBYGEMS, NEIGHBOUR), &neighbour_gem);
        standin.serve(5, &patched_route, &patched_gem);
        // What `rollback` reads to restore the upstream `CHECKSUMS` line:
        // the gem's file of the compact index, one line per version.
        let info = format!("---\n{VERSION} |checksum:{}\n", sha256_hex(&upstream_gem));
        standin.serve(5, &format!("/{RUBYGEMS}/info/{NAME}"), info.as_bytes());

        let sum = sha256_hex(&patched_gem);
        let url = |file: &str| format!("https://{PATCH_HOST}{artifacts}.{file}");
        let stub = stub();
        standin.serve(5, &format!("{artifacts}.gem"), &patched_gem);
        standin.serve(5, &format!("{artifacts}.gemspec"), stub.as_bytes());
        let reference = json!({
            "status": "granted",
            "url": url("gem"),
            "purl": PURL,
            "artifacts": [{
                "kind": "tarball",
                "url": url("gem"),
                "integrity": { "sha256": sum, "sha512": sha512_sri(&patched_gem) },
            }, {
                "kind": "gem-stub-gemspec",
                "url": url("gemspec"),
                "integrity": { "sha512": sha512_sri(stub.as_bytes()) },
            }],
            "registryOverride": {
                "kind": "rubygems-compact-index",
                "indexUrl": index,
                "identifiers": { "name": NAME, "version": VERSION, "gemChecksumSha256": sum },
            },
        });
        standin.api(&[Patch {
            purl: PURL.to_string(),
            uuid: uuid.clone(),
            reference,
        }]);
        let hash = |status: &str| compute_git_sha256_from_bytes(source(status).as_bytes());
        let record = json!({
            "uuid": uuid,
            "purl": PURL,
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": { LIB: { "beforeHash": hash(&pristine), "afterHash": hash(&fixed) } },
            "vulnerabilities": { "GHSA-test-aaaa-bbbb": {
                "cves": ["CVE-2024-0001"], "summary": "s", "severity": "high", "description": "d",
            }},
            "description": "fixture",
            "license": "MIT",
            "tier": "free",
        });
        let record_route = format!("/v0/orgs/{ORG}/patches/view/{uuid}");
        standin.serve(1, &record_route, record.to_string().as_bytes());

        cell.route_downloads(&routes(&origin, true));
        cell.write("Gemfile.lock", lock_pinning(&neighbour_gem, &upstream_gem));
        Served {
            standin,
            uuid,
            unpatched: format!("OUT: {pristine}"),
            patched: format!("OUT: {fixed}"),
            upstream_gem,
            patched_gem,
            neighbour_gem,
            index,
            upstream_route,
            patched_route,
            artifact_route: format!("{artifacts}.gem"),
        }
    }
}

/// The downloader config of a flow whose stand-in is at `origin`: the
/// fixture's two gems on rubygems.org go there, and so does everything on
/// the patch host where the machine reaches one (`patch_host`). A URL of the
/// patch host that no rule rewrote is refused, so on a machine that reaches
/// none a build that asks for it fails, and no download of Bazel's goes to
/// the real one.
fn routes(origin: &str, patch_host: bool) -> Vec<String> {
    let gems = |name: &str| rewrite(&format!("{RUBYGEMS}/gems/{name}-"), origin);
    let mut rules = vec![gems(NAME), gems(NEIGHBOUR)];
    rules.extend(patch_host.then(|| rewrite(&format!("{PATCH_HOST}/"), origin)));
    rules.push(format!("block {PATCH_HOST}"));
    rules
}

/// `socket-patch <args>` in `cell`, with `standin` as the Socket API and as
/// rubygems.org, and with the variables `env` as well.
fn run(standin: &StandIn, cell: &Cell, args: &[&str], env: &[(&str, &str)]) -> Ran {
    let origin = standin.origin();
    let rubygems = format!("{origin}/{RUBYGEMS}");
    let env = [&[("SOCKET_RUBYGEMS_URL", rubygems.as_str())], env].concat();
    cell.socket_patch(&origin, args, &env)
}

/// `text` without its white space: a line a terminal may have wrapped, or a
/// message Bundler broke at the width of its console.
fn squeezed(text: &str) -> String {
    text.split_whitespace().collect()
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
        index,
        upstream_route,
        patched_route,
        ..
    } = Served::to(&mut cell);
    let origin = standin.origin();
    let socket_patch = |cell: &Cell, args: &[&str]| run(&standin, cell, args, &[]);

    // (a) The unpatched build, from the upstream gem of this run.
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
    let served = Served::to(&mut cell);
    let standin = &served.standin;
    let socket_patch = |cell: &Cell, args: &[&str]| run(standin, cell, args, &[]);
    let (other, upstream, patched) = (
        sha256_hex(&served.neighbour_gem),
        sha256_hex(&served.upstream_gem),
        sha256_hex(&served.patched_gem),
    );
    let files = ["Gemfile", "Gemfile.lock"];

    // (a) The unpatched build, with the two upstream gems pinned in the
    // lock, as `Served::to` left it, and in the call.
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

/// Where the patched gem of the patch `uuid` is committed for a hub: the
/// directory of the patch under `.socket/vendor`, which the lock names as
/// the gem's source, and in it the path rules_ruby asks a source for.
fn committed_gem(uuid: &str) -> String {
    format!(".socket/vendor/gem/{uuid}/gems/{NAME}-{VERSION}.gem")
}

/// The fixture's checkout with the patched gem `patched` of the patch
/// `uuid` vendored for the hub, written by hand: the files that differ from
/// the fixture's, each whole, by its path from the checkout. `Gemfile` and
/// `Gemfile.lock` are what hosted mode writes with the patch registry's URL
/// replaced by `file:.socket/vendor/gem/<uuid>/`, and the gem is committed
/// where rules_ruby asks that source for it.
fn by_hand(uuid: &str, patched: &[u8]) -> Tree {
    let source = format!("file:.socket/vendor/gem/{uuid}/");
    let gemfile = format!(
        "source \"https://rubygems.org/\"\n\n\
         gem \"{NAME}\", \"{VERSION}\", source: \"{source}\"\n\
         gem \"{NEIGHBOUR}\", \"{VERSION}\"\n"
    );
    let lock = format!(
        "GEM\n  remote: {source}\n  specs:\n    {NAME} ({VERSION})\n\n\
         GEM\n  remote: https://rubygems.org/\n  specs:\n    {NEIGHBOUR} ({VERSION})\n\n\
         PLATFORMS\n  ruby\n\n\
         DEPENDENCIES\n  {NEIGHBOUR} (= {VERSION})\n  {NAME} (= {VERSION})!\n\n\
         CHECKSUMS\n{}{}\n\
         BUNDLED WITH\n  4.0.15\n",
        checksum(NEIGHBOUR, &sha256_hex(&neighbour())),
        checksum(NAME, &sha256_hex(patched)),
    );
    Tree::from([
        (committed_gem(uuid), patched.to_vec()),
        ("Gemfile".to_string(), gemfile.into_bytes()),
        ("Gemfile.lock".to_string(), lock.into_bytes()),
    ])
}

/// Whether the repository cache of `cell`, which its twins share, holds a
/// download of `gem`: Bazel keeps a file there under its sha256.
fn cached(cell: &Cell, gem: &[u8]) -> bool {
    let cache = match std::env::var_os(REPO_CACHE) {
        Some(shared) => PathBuf::from(shared),
        None => cell.path("../cache"),
    };
    let files = cache.join("content_addressable/sha256");
    assert!(files.is_dir(), "no repository cache at {}", cache.display());
    files.join(sha256_hex(gem)).join("file").exists()
}

/// A second machine with the files of `cell` that reaches no patch host: a
/// new output base, and a downloader config that sends nothing there.
fn without_patch_host(cell: &Cell, origin: &str) -> Cell {
    let mut twin = cell.twin();
    twin.route_downloads(&routes(origin, false));
    twin
}

/// The build of `cell`, where one byte of the committed gem is not the one
/// the lock pins (`patched`), fails on the lock's checksum: Bundler names
/// the sha256 of the lock and the one of the file.
fn fails_on_the_checksum(cell: &Cell, patched: &[u8], changed: &[u8]) {
    let build = cell.bazel("build", &[CONSUMER]);
    let stderr = squeezed(&build.stderr());
    let sums = [patched, changed].map(|gem| format!("sha256={}", sha256_hex(gem)));
    assert!(
        !build.ok()
            && stderr.contains("mismatchedchecksums")
            && sums.iter().all(|sum| stderr.contains(sum)),
        "{}: the build did not fail on the checksum of the committed gem:\n{}",
        cell.test,
        build.dump()
    );
}

/// A Bundler of the 2 line, which most locks name today, in the place of
/// the fixture's 4.0.15: rules_ruby installs the Bundler of the lock's
/// `BUNDLED WITH` in the hub, and the hub's `bundle install` is that one's.
const OLDER_BUNDLER: &str = "2.6.9";

/// Makes the lock of `cell` name Bundler `version`.
fn names_bundler(cell: &Cell, version: &str) {
    let lock = String::from_utf8(cell.tree()["Gemfile.lock"].clone()).expect("a text file");
    let named = "\nBUNDLED WITH\n  4.0.15\n";
    assert!(lock.ends_with(named), "{}: {lock}", cell.test);
    let other = format!("\nBUNDLED WITH\n  {version}\n");
    cell.write("Gemfile.lock", lock.replace(named, &other));
}

/// `gem` with its last byte changed: one of the padding a tar ends with, so
/// the file is still a gem RubyGems reads, with another sha256.
fn one_byte_changed(gem: &[u8]) -> Vec<u8> {
    let mut changed = gem.to_vec();
    *changed.last_mut().expect("a gem has bytes") ^= 1;
    changed
}

/// A vendored gem that the hub builds, written by hand.
///
/// - (a) `bazel build` and `bazel run //:consumer` print the unpatched
///   marker.
/// - (b) By hand ([`by_hand`]): `Gemfile` gives the gem the source
///   `file:.socket/vendor/gem/<uuid>/`, `Gemfile.lock` resolves it from a
///   `GEM` section of that remote with the sha256 of the patched gem in
///   `CHECKSUMS`, and the patched gem is committed at
///   `.socket/vendor/gem/<uuid>/gems/<name>-<version>.gem`. No file of
///   Bazel's is touched.
/// - (c) On a second machine with those files (a new output base and, on
///   Bazel 9, a new contents cache), which reaches no patch host and whose
///   repository cache holds no copy of the patched gem, the same two Bazel
///   commands print the patched marker. Bazel changed no file, and a
///   `--lockfile_mode=error` build passes. The stand-in was asked for no
///   patched gem and for no further upstream one.
/// - (d) On a third machine, with one byte of the committed gem changed,
///   the build fails on the lock's checksum.
/// - (e) On a fourth machine, whose lock names Bundler 2.6.9, the hub holds
///   that Bundler and the same two Bazel commands print the patched marker;
///   on a fifth one, with the changed byte, the build fails on the lock's
///   checksum.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn file_source_by_hand() {
    let test = "ruby::file_source_by_hand";
    let started = Instant::now();
    let Some(mut cell) = Cell::open(test, &FIXTURE) else {
        return;
    };
    let release = cell.release().to_string();
    let served = Served::to(&mut cell);
    let (standin, uuid) = (&served.standin, served.uuid.as_str());
    let origin = standin.origin();

    // (a) The unpatched build.
    let before = cell.builds_unpatched(&served.unpatched);
    let upstream_fetches = standin.asked(&served.upstream_route);

    // (b) The three files, by hand.
    let files = by_hand(uuid, &served.patched_gem);
    for (rel, bytes) in &files {
        cell.write(rel, bytes);
    }
    let wired = cell.tree();
    let written: Vec<String> = files.keys().cloned().collect();
    assert_eq!(changed(&before, &wired), written, "{test}");

    // (c) A second machine: patched, from the committed gem and nothing
    // else.
    assert!(!cached(&cell, &served.patched_gem), "{test}");
    let second = without_patch_host(&cell, &origin);
    second.builds_patched(&wired, &served.patched);
    let patch_host = |path: &String| path.starts_with(&format!("/{PATCH_HOST}/"));
    let asked: Vec<String> = standin.requests().into_iter().filter(patch_host).collect();
    assert_eq!(asked, NOTHING, "{test}: the patch host was asked");
    assert_eq!(
        standin.asked(&served.upstream_route),
        upstream_fetches,
        "{test}: the patched build fetched the upstream gem"
    );

    // (d) A third machine, where one byte of the committed gem is another.
    let third = without_patch_host(&second, &origin);
    let other = one_byte_changed(&served.patched_gem);
    third.write(&committed_gem(uuid), &other);
    fails_on_the_checksum(&third, &served.patched_gem, &other);

    // (e) The same two machines with the Bundler of most locks.
    let fourth = without_patch_host(&third, &origin);
    fourth.write(&committed_gem(uuid), &served.patched_gem);
    names_bundler(&fourth, OLDER_BUNDLER);
    fourth.builds_patched(&fourth.tree(), &served.patched);
    let bundler = format!("@bundle//:bundler-{OLDER_BUNDLER}");
    let held = fourth.bazel("query", &[&bundler]);
    assert!(held.ok(), "{test}: no {bundler}:\n{}", held.dump());
    let fifth = without_patch_host(&fourth, &origin);
    fifth.write(&committed_gem(uuid), &other);
    fails_on_the_checksum(&fifth, &served.patched_gem, &other);
    assert_eq!(
        standin.asked(&served.upstream_route),
        upstream_fetches,
        "{test}: the build went to the upstream gem"
    );
    let asked: Vec<String> = standin.requests().into_iter().filter(patch_host).collect();
    assert_eq!(asked, NOTHING, "{test}: the patch host was asked");

    println!(
        "{test}: Bazel {release} built {:?} on a second machine that reaches no patch host, \
         from {} and a `file:` source in Gemfile and Gemfile.lock written by hand; one changed \
         byte of that gem failed a third machine's build (Bundler: mismatched checksums); the \
         same with Bundler {OLDER_BUNDLER} in the lock and the hub, on a fourth and a fifth; {:?}",
        served.patched,
        committed_gem(uuid),
        started.elapsed()
    );
}

/// The code under which vendored mode declines a gem whose Gemfile or lock
/// a hub of the workspace reads, and what a refusal has to name in the
/// fixture's checkout: the hub's call with its line in `MODULE.bazel`, the
/// file it reads, and why the committed gem is not known to build there.
/// The fixture names no Bazel release.
const DECLINED: Declined = Declined {
    purl: PURL,
    code: "vendor_gem_bazel_hub",
    names: &[
        "`ruby.bundle_fetch` (MODULE.bazel:15)",
        "names Gemfile.lock; ",
        "the checkout names no Bazel release as three numbers (`.bazelversion`",
    ],
};

/// The advisory of a run that committed a gem for a hub.
const ADVISORY: &str = "vendor_gem_bazel_file_source";
/// The warning of an undo that leaves a `gem_checksums` entry of the call
/// holding the gem to the patched one.
const ENTRY_LEFT: &str = "vendor_gem_bazel_checksum_left";

/// The variables of a command of vendored mode, which downloads the
/// patched gem from the patch host: the stand-in at `origin` is that host.
fn patch_host(origin: &str) -> [(&str, &str); 1] {
    [("SOCKET_PATCH_SERVER_URL", origin)]
}

/// For a finished `scan --mode vendored --yes` in the fixture's checkout
/// with the files `before`, where the hub reads the lock and the checkout
/// names its Bazel release: the command vendored the one gem and says what
/// that form costs. It wrote the three files of [`by_hand`], byte for
/// byte, and beside them only its own: the ledger, the marker of the
/// patch's directory, and the two files that keep git from ignoring or
/// converting the gem. Gives the files of the checkout.
fn committed_for_the_hub(cell: &Cell, scan: &Ran, served: &Served, before: &Tree) -> Tree {
    let (test, said) = (&cell.test, &scan.dump);
    assert_eq!(scan.code, 0, "{test}: {said}");
    assert_eq!(scan.envelope["status"], "success", "{test}: {said}");
    assert_eq!(scan.envelope["summary"]["applied"], 1, "{test}: {said}");
    let advised = |event: &&serde_json::Value| event["errorCode"] == ADVISORY;
    let advisory = events(&scan.envelope).iter().find(advised);
    let advisory = advisory.and_then(|event| event["reason"].as_str());
    let advisory = advisory.unwrap_or_default();
    let costs = [
        "through Bazel only",
        "keeps that unpatched copy",
        "`--mode hosted`",
        "does not watch",
    ];
    for cost in costs {
        assert!(advisory.contains(cost), "{test}: no {cost:?} in {said}");
    }
    let by_hand = by_hand(&served.uuid, &served.patched_gem);
    let dir = format!(".socket/vendor/gem/{}", served.uuid);
    let own = [".gitattributes", ".gitignore", "socket-patch.vendor.json"];
    let own = own.map(|file| format!("{dir}/{file}"));
    let ledger = ".socket/vendor/state.json".to_string();
    let mut written: Vec<String> = by_hand.keys().cloned().chain(own).chain([ledger]).collect();
    written.sort();
    let vendored = cell.tree();
    assert_eq!(changed(before, &vendored), written, "{test}: {said}");
    for (rel, bytes) in &by_hand {
        let same = vendored[rel] == *bytes;
        assert!(same, "{test}: {rel} is not the file written by hand");
    }
    vendored
}

/// Vendored mode beside a hub that reads the Gemfile and its lock, on a
/// machine whose Bazel reaches no patch host.
///
/// - (a) `bazel build` and `bazel run //:consumer` print the unpatched
///   marker.
/// - (b) The checkout names no Bazel release, so `socket-patch scan --mode
///   vendored --yes` declines the gem: it exits 1, names the call of
///   `MODULE.bazel` that reads the lock, the missing release, hosted mode
///   and the switch, writes nothing and downloads no gem. The same two
///   Bazel commands print the unpatched marker, and change no file. With
///   `--allow-vendored-in-bazel` the command writes the unpacked copy named
///   by its path, as in every other project, and the same build fails in
///   `bundle install`, where the path names nothing: the failure the
///   decline is for. `vendor --revert` puts every file and the build back.
/// - (c) With the release of this Bazel in `.bazelversion`, the same
///   command vendors the gem: it writes the three files of
///   [`file_source_by_hand`], byte for byte, with its ledger, and says
///   what the form costs.
/// - (d) The same two Bazel commands, with no step in between, print the
///   patched marker. Bazel asked for no patched gem and no upstream one,
///   changed no file, and a `--lockfile_mode=error` build passes.
///   `vendor --check` passes.
/// - (e) On a second machine with those files, where one byte of the
///   committed gem is another, `vendor --check` fails on the sha256 of the
///   ledger and the build fails on the lock's checksum.
/// - (f) `socket-patch vendor --revert`: every file of the checkout is the
///   one of before, and the build prints the unpatched marker again.
/// - (g) Hosted mode, which the refusal names, on a machine that reaches
///   the patch host: the same two Bazel commands print the patched marker.
///
/// The flow asserts the VEX document of its patch as `main.rs` says.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn vendored_bundle_fetch() {
    let test = "ruby::vendored_bundle_fetch";
    let started = Instant::now();
    let Some(mut cell) = Cell::open(test, &FIXTURE) else {
        return;
    };
    let release = cell.release().to_string();
    let served = Served::to(&mut cell);
    let (standin, uuid) = (&served.standin, served.uuid.as_str());
    let origin = standin.origin();
    cell.route_downloads(&routes(&origin, false));
    let run = |cell: &Cell, args: &[&str]| run(standin, cell, args, &patch_host(&origin));

    // (a) The unpatched build.
    let before = cell.builds_unpatched(&served.unpatched);

    // (b) No release is named: declined, with nothing written and nothing
    // of the patch fetched. The same build passes, on the upstream gem.
    cell.declined(&run(&cell, &VENDORED), &DECLINED, 1, "failed", &before);
    assert_eq!(standin.asked(&served.artifact_route), 0, "{test}");
    cell.builds_patched(&before, &served.unpatched);

    // What the decline is for: on the user's word the command writes the
    // copy of every other project, named by its path, and the same build
    // fails where rules_ruby runs Bundler, in a repository of Bazel's that
    // does not hold that path. Bundler breaks its message at the width of
    // its console, so it is compared without white space. The undo, which
    // takes no switch, puts every file and the build back.
    {
        let scan = run(&cell, &[&VENDORED[..], &[ALLOW]].concat());
        assert_eq!(scan.code, 0, "{test}: {}", scan.dump);
        let copy = format!(".socket/vendor/gem/{uuid}/{NAME}-{VERSION}");
        let lock = String::from_utf8(cell.tree()["Gemfile.lock"].clone()).expect("a text file");
        let section = format!("PATH\n  remote: {copy}\n  specs:\n    {NAME} ({VERSION})\n\n");
        assert!(lock.starts_with(&section), "{test}: Gemfile.lock:\n{lock}");
        let build = cell.bazel("build", &[CONSUMER]);
        let stderr = squeezed(&build.stderr());
        let missing = squeezed(&format!("{copy}` does not exist."));
        assert!(
            !build.ok() && stderr.contains("Runningbundleinstall") && stderr.contains(&missing),
            "{test}: the build did not fail on the path of the copy ({missing:?}):\n{}",
            build.dump()
        );
        let undo = run(&cell, &["vendor", "--revert", "--yes"]);
        cell.undone(&undo, "removed", &before, &served.unpatched);
    }
    // The build after the undo fetched the upstream gem once more.
    let upstream_fetches = standin.asked(&served.upstream_route);

    // (c) The release is named: the gem, its ledger, and the two files
    // that name it. The document of that run and the one of `vex` say so,
    // before the patched build.
    cell.write(".bazelversion", format!("{release}\n"));
    let before = cell.tree();
    let claim = Claim::new(PURL, uuid, How::Vendored);
    let in_run = cell.document("in-run");
    let scan = run(&cell, &[&VENDORED[..], &with_vex(&in_run)].concat());
    let vendored = committed_for_the_hub(&cell, &scan, &served, &before);
    cell.wrote_in_run(&scan, &in_run, &claim);
    cell.stands_alone(run, &claim, true);

    // (d) The same build, no step in between: patched, from the committed
    // gem.
    cell.builds_patched(&vendored, &served.patched);
    assert_eq!(standin.asked(&served.patched_route), 0, "{test}");
    assert_eq!(
        standin.asked(&served.upstream_route),
        upstream_fetches,
        "{test}: the patched build fetched the upstream gem"
    );
    cell.stands_alone(run, &claim, true);
    cell.stands_alone(run, &claim, false);
    cell.detects_product(run, None);
    let check = run(&cell, &["vendor", "--check"]);
    assert_eq!(check.code, 0, "{test}: {}", check.dump);

    // (e) A second machine, where one byte of the committed gem is another.
    {
        let second = cell.twin();
        let other = one_byte_changed(&served.patched_gem);
        second.write(&committed_gem(uuid), &other);
        let check = run(&second, &["vendor", "--check"]);
        let caught = check.dump.contains("vendor_sha256_mismatch");
        assert!(check.code == 1 && caught, "{test}: {}", check.dump);
        fails_on_the_checksum(&second, &served.patched_gem, &other);
    }

    // (f) The undo: every file is the one of before, and so is the build,
    // and `vex` has no document for it. The same two documents where no
    // Bazel has built.
    let undo = run(&cell, &["vendor", "--revert", "--yes"]);
    cell.undone(&undo, "removed", &before, &served.unpatched);
    cell.attests_nothing(run, 2, "manifest_not_found");
    cell.attests_unbuilt(run, &VENDORED, &before, &vendored, &claim);

    // (g) The remedy the refusal names, where Bazel reaches the patch host:
    // hosted mode patches the build.
    cell.route_downloads(&routes(&origin, true));
    let scan = run(&cell, &["scan", "--mode", "hosted", "--yes"]);
    let pinned = cell.pinned_by(&scan, PURL, uuid, &before, &["Gemfile", "Gemfile.lock"]);
    cell.builds_patched(&pinned, &served.patched);

    println!(
        "{test}: Bazel {release} built {:?}; `scan --mode vendored` declined ({}) in a checkout \
         that names no Bazel release, and the build stayed the same; with the release named it \
         wrote {} and a `file:` source in Gemfile and Gemfile.lock, the files written by hand, \
         and the next build printed {:?} with no patch host; one changed byte failed `vendor \
         --check` and a second machine's build (Bundler: mismatched checksums); `vendor \
         --revert` restored all {} files and the build; `scan --mode hosted` built {:?}; {:?}",
        served.unpatched,
        DECLINED.code,
        committed_gem(uuid),
        served.patched,
        before.len(),
        served.patched,
        started.elapsed()
    );
}

/// Without a Bazel: the fixture in a checkout of its own, with the lock
/// that pins the two upstream gems of `served` and `module` as its
/// `MODULE.bazel`; `None` leaves the checkout without one, in no Bazel
/// workspace.
fn checkout_with(served: &Served, module: Option<&str>) -> Cell {
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

/// Without a Bazel: the fixture in a checkout of its own, as it is, whose
/// lock pins the gems of the stand-in that comes with it.
fn checkout() -> (Cell, Served) {
    let served = Served::to(&mut cell_without_bazel("9.3.2"));
    let module = fixture_path(FIXTURE.dir).join("e9/MODULE.bazel");
    let module = std::fs::read_to_string(module).expect("the fixture's MODULE.bazel");
    (checkout_with(&served, Some(&module)), served)
}

/// Without a Bazel: in the fixture's checkout, where the hub reads the
/// Gemfile and its lock and no file names a Bazel release, every command
/// that would vendor the gem declines it, writes nothing and fetches no
/// gem. On the user's word vendored mode goes on, with the copy of every
/// other project, and a later run without it passes and writes nothing:
/// the lock the hub reads already names the copy.
#[test]
fn every_command_that_would_vendor_declines_beside_a_hub_that_reads_the_lock() {
    let (cell, served) = checkout();
    let standin = &served.standin;
    let origin = standin.origin();
    let run = |cell: &Cell, args: &[&str], env: &[(&str, &str)]| {
        run(
            standin,
            cell,
            args,
            &[&patch_host(&origin)[..], env].concat(),
        )
    };
    let module = String::from_utf8(cell.tree()["MODULE.bazel"].clone()).expect("a text file");
    let called = module.lines().nth(14);
    assert_eq!(called, Some("ruby.bundle_fetch("), "{}", DECLINED.names[0]);
    let before = cell.tree();
    cell.declines_every_vendoring(run, &DECLINED);
    assert_eq!(standin.asked(&served.artifact_route), 0);
    let undo = run(&cell, &["rollback", "--yes"], &[]);
    assert_eq!(changed(&before, &cell.tree()), NOTHING, "{}", undo.dump);
    cell.vendors_on_the_users_word(run, &DECLINED);
}

/// Without a Bazel: in the fixture's checkout with its Bazel release named
/// in `.bazelversion`, vendored mode commits the gem for the hub.
///
/// - A dry run names no refusal and writes nothing.
/// - The run writes the three files of [`by_hand`], byte for byte, and
///   says what the form costs.
/// - A later run passes and writes nothing, also a scan that names no mode
///   and one with the switch: the pair names the committed gem.
/// - A hosted scan leaves the pair alone and names the undo.
/// - `vendor --check` passes, and fails on one changed byte of the gem,
///   which `repair` puts right.
/// - `vendor --revert`, `rollback` and `remove` each put every file back,
///   byte for byte, and the gem is vendored the same again after each.
/// - Run as a person runs it, the command names the Bazel build as the
///   next step, and no reinstall: Bundler by itself fails on the source.
/// - With Bundler 2.6.9 in the lock the gem is vendored the same way.
/// - With the switch the run writes the copy of every other project.
/// - A vendored scan takes over a hosted pin of the gem, and writes the
///   same three files.
#[test]
fn a_gem_is_committed_for_the_hub_and_put_back() {
    let (cell, served) = checkout();
    cell.write(".bazelversion", "9.3.2\n");
    let (standin, uuid) = (&served.standin, served.uuid.as_str());
    let origin = standin.origin();
    let go = |args: &[&str]| run(standin, &cell, args, &patch_host(&origin));
    let before = cell.tree();
    let same = |ran: &Ran, tree: &Tree| {
        assert_eq!(ran.code, 0, "{}", ran.dump);
        assert_eq!(changed(tree, &cell.tree()), NOTHING, "{}", ran.dump);
    };

    let dry = go(&[&VENDORED[..], &["--dry-run"]].concat());
    same(&dry, &before);
    assert!(!dry.dump.contains(DECLINED.code), "{}", dry.dump);
    let vendored = committed_for_the_hub(&cell, &go(&VENDORED), &served, &before);
    for in_sync in [
        &VENDORED[..],
        &["scan", "--yes"],
        &[&VENDORED[..], &[ALLOW]].concat(),
    ] {
        let again = go(in_sync);
        same(&again, &vendored);
        assert_eq!(again.envelope["status"], "success", "{}", again.dump);
        assert!(!again.dump.contains(DECLINED.code), "{}", again.dump);
    }

    // Hosted mode leaves a gem vendored this way alone, and says how to
    // hand it over.
    let hosted = go(&["scan", "--mode", "hosted", "--yes"]);
    same(&hosted, &vendored);
    let handed_over = hosted.dump.contains("socket-patch's own vendored wiring");
    assert!(handed_over, "{}", hosted.dump);

    same(&go(&["vendor", "--check"]), &vendored);
    cell.write(&committed_gem(uuid), one_byte_changed(&served.patched_gem));
    let check = go(&["vendor", "--check"]);
    let caught = check.dump.contains("vendor_sha256_mismatch");
    assert!(check.code == 1 && caught, "{}", check.dump);
    same(&go(&["repair"]), &vendored);

    for undo in [
        &["vendor", "--revert", "--yes"][..],
        &["rollback", "--yes"],
        &["remove", PURL, "--yes"],
    ] {
        same(&go(undo), &before);
        committed_for_the_hub(&cell, &go(&VENDORED), &served, &before);
    }
    same(&go(&["vendor", "--revert", "--yes"]), &before);

    // As a person runs it: the next step is the build, and no reinstall.
    let rubygems = format!("{origin}/{RUBYGEMS}");
    let env = [
        ("SOCKET_RUBYGEMS_URL", rubygems.as_str()),
        patch_host(&origin)[0],
    ];
    let [stdout, stderr] = cell.socket_patch_person(&origin, &VENDORED, &env);
    let said = format!("--- stdout\n{stdout}\n--- stderr\n{stderr}");
    let step =
        "2. Build with Bazel, which installs the committed gems, then run `socket-patch vex`";
    let stepped = squeezed(&stdout).contains(&squeezed(step));
    assert!(stepped && !stdout.contains("Reinstall"), "{said}");
    assert!(
        stderr.contains("Warning: ") && stderr.contains("through Bazel only"),
        "{said}"
    );
    same(&go(&["vendor", "--revert", "--yes"]), &before);

    // The Bundler of most locks, which a hub was built with too.
    names_bundler(&cell, OLDER_BUNDLER);
    let older = cell.tree();
    let ran = go(&VENDORED);
    assert_eq!(ran.envelope["summary"]["applied"], 1, "{}", ran.dump);
    assert!(ran.dump.contains(ADVISORY), "{}", ran.dump);
    same(&go(&["vendor", "--revert", "--yes"]), &older);
    cell.write("Gemfile.lock", &before["Gemfile.lock"]);

    // On the user's word: the copy of every other project, named by its
    // path.
    let allowed = go(&[&VENDORED[..], &[ALLOW]].concat());
    assert_eq!(
        allowed.envelope["summary"]["applied"], 1,
        "{}",
        allowed.dump
    );
    let lock = String::from_utf8(cell.tree()["Gemfile.lock"].clone()).expect("a text file");
    let copy = format!("PATH\n  remote: .socket/vendor/gem/{uuid}/{NAME}-{VERSION}\n");
    assert!(lock.starts_with(&copy), "{lock}");
    same(&go(&["vendor", "--revert", "--yes"]), &before);

    let hosted = go(&["scan", "--mode", "hosted", "--yes"]);
    assert_eq!(hosted.envelope["summary"]["applied"], 1, "{}", hosted.dump);
    let taken_over = go(&VENDORED);
    assert_eq!(taken_over.code, 0, "{}", taken_over.dump);
    let tree = cell.tree();
    for (rel, bytes) in by_hand(uuid, &served.patched_gem) {
        assert!(tree[&rel] == bytes, "{rel}: {}", taken_over.dump);
    }
    same(&go(&["vendor", "--revert", "--yes"]), &before);
}

/// A `WORKSPACE` file that defines a repository, as a move to Bzlmod can
/// leave one behind.
const LEFT_BEHIND: &str = "local_repository(name = \"x\", path = \"x\")\n";

/// Without a Bazel: each condition under which the committed gem is not
/// known to build declines the gem, with nothing written and no gem
/// fetched, and names the call, the lock and the condition. The lock's
/// `CHECKSUMS` line or the `gem_checksums` entry of every call that reads
/// the pair is what holds the committed gem to its bytes: an entry that
/// holds the gem to other bytes declines it once the patched gem is known,
/// naming the call, the entry and both sums, also where it is a second
/// call's. With the sum of the patched gem written there the gem is
/// vendored, also in a lock with no `CHECKSUMS` section, and each undo
/// then puts every file back and says that the entry it leaves in the call
/// fails the build.
#[test]
fn a_gem_is_declined_where_the_committed_gem_is_not_known_to_build() {
    let scan = |cell: &Cell, served: &Served| {
        let origin = served.standin.origin();
        run(&served.standin, cell, &VENDORED, &patch_host(&origin))
    };
    let text =
        |cell: &Cell, rel: &str| String::from_utf8(cell.tree()[rel].clone()).expect("a text file");
    // The lock without its `CHECKSUMS` section.
    let unchecked = |cell: &Cell| {
        let lock = text(cell, "Gemfile.lock");
        let (head, sums) = lock.split_once("CHECKSUMS\n").expect("a CHECKSUMS section");
        let (_, tail) = sums.split_once("\n\n").expect("a section after it");
        cell.write("Gemfile.lock", format!("{head}{tail}"));
    };
    // The call with `gem_checksums = <sums>`.
    let pins = |cell: &Cell, sums: &str| {
        let lock = "    gemfile_lock = \"//:Gemfile.lock\",\n";
        let module = text(cell, "MODULE.bazel");
        assert!(module.contains(lock), "{module}");
        let pinned = format!("{lock}    gem_checksums = {sums},\n");
        cell.write("MODULE.bazel", module.replace(lock, &pinned));
    };
    // A second call that reads the same pair, for a hub of its own, with
    // the arguments `more`: the line of `MODULE.bazel` it is on.
    let second = |cell: &Cell, more: &str| {
        let module = text(cell, "MODULE.bazel");
        let call = format!(
            "ruby.bundle_fetch(name = \"tools\", gemfile = \"//:Gemfile\", gemfile_lock = \
             \"//:Gemfile.lock\"{more})\n"
        );
        cell.write("MODULE.bazel", format!("{module}{call}"));
        module.lines().count() + 1
    };
    let entry = |sum: &str| format!("{{\"{NAME}-{VERSION}\": \"{sum}\"}}");
    let unheld = |line: usize| {
        format!(
            "has no CHECKSUMS section and `ruby.bundle_fetch` (MODULE.bazel:{line}) has no \
             `gem_checksums` entry for {NAME}-{VERSION}"
        )
    };
    let (first_unheld, second_unheld) = (unheld(15), unheld(28));
    type Edit<'a> = &'a dyn Fn(&Cell);
    let cases: [(Edit, &str); 10] = [
        (
            &|cell| cell.write(".bazelversion", "9.1.0\n"),
            "Bazel 9.1.0 fails on such a URL",
        ),
        (
            &|cell| cell.write(".bazelversion", "10.0.0\n"),
            "not known to build on Bazel 10.0.0",
        ),
        (
            &|cell| cell.write(".bazelversion", "latest\n"),
            DECLINED.names[2],
        ),
        (&unchecked, &first_unheld),
        (
            // The first call holds the gem, and the second one does not.
            &|cell| {
                unchecked(cell);
                pins(cell, &entry(PLACEHOLDER));
                assert_eq!(second(cell, ""), 28);
            },
            &second_unheld,
        ),
        (
            &|cell| names_bundler(cell, "2.5.23"),
            "not known to build with Bundler 2.5.23, which Gemfile.lock names",
        ),
        (
            &|cell| names_bundler(cell, "5.0.0"),
            "not known to build with Bundler 5.0.0, which Gemfile.lock names",
        ),
        (
            &|cell| pins(cell, "SUMS"),
            "the `gem_checksums` of `ruby.bundle_fetch` (MODULE.bazel:15) are not written out",
        ),
        (
            // Under a Bazel that reads the file: 9.3.2 reads none.
            &|cell| {
                cell.write(".bazelversion", "7.7.2\n");
                cell.write("WORKSPACE", LEFT_BEHIND)
            },
            "a `WORKSPACE` file of the workspace defines repositories",
        ),
        (
            &|cell| cell.write(".bazelrc", "build --repository_disable_download\n"),
            ".bazelrc:1 names `--repository_disable_download`, under which Bazel may not read the \
             committed gem",
        ),
    ];
    for (edit, why) in cases {
        let (cell, served) = checkout();
        cell.write(".bazelversion", "9.3.2\n");
        edit(&cell);
        let package = Declined {
            names: &[DECLINED.names[0], DECLINED.names[1], why],
            ..DECLINED
        };
        let before = cell.tree();
        cell.declined(&scan(&cell, &served), &package, 1, "failed", &before);
        assert_eq!(served.standin.asked(&served.artifact_route), 0, "{why}");
    }

    // The same `WORKSPACE` file under the Bazel 9.3.2 the checkout names,
    // which reads none: it stands against nothing, and the gem is
    // committed for the hub.
    let (cell, served) = checkout();
    cell.write(".bazelversion", "9.3.2\n");
    cell.write("WORKSPACE", LEFT_BEHIND);
    let before = cell.tree();
    committed_for_the_hub(&cell, &scan(&cell, &served), &served, &before);

    // An entry that holds the gem to the upstream bytes.
    let (cell, served) = checkout();
    cell.write(".bazelversion", "9.3.2\n");
    let sums = [&served.upstream_gem, &served.patched_gem].map(|gem| sha256_hex(gem));
    let unpinned = text(&cell, "MODULE.bazel");
    pins(&cell, &entry(&sums[0]));
    let before = cell.tree();
    let ran = scan(&cell, &served);
    let said = squeezed(&ran.dump);
    let named = [
        format!("hold {NAME}-{VERSION} to sha256 {}", sums[0]),
        format!("the patched gem has {}", sums[1]),
        DECLINED.code.to_string(),
    ];
    let named = named.iter().all(|part| said.contains(&squeezed(part)));
    assert!(ran.code == 1 && named, "{}", ran.dump);
    assert_eq!(changed(&before, &cell.tree()), NOTHING, "{}", ran.dump);

    // The sum of the patched gem there, and a second call that reads the
    // pair and holds the gem to the upstream bytes: its hub would fail.
    cell.write("MODULE.bazel", &unpinned);
    pins(&cell, &entry(&sums[1]));
    let pinned = text(&cell, "MODULE.bazel");
    let line = second(&cell, &format!(", gem_checksums = {}", entry(&sums[0])));
    let before = cell.tree();
    let ran = scan(&cell, &served);
    let said = squeezed(&ran.dump);
    let named = format!(
        "`ruby.bundle_fetch` (MODULE.bazel:{line}) hold {NAME}-{VERSION} to sha256 {}",
        sums[0]
    );
    let named = said.contains(&squeezed(&named)) && said.contains(DECLINED.code);
    assert!(ran.code == 1 && named, "{}", ran.dump);
    assert_eq!(changed(&before, &cell.tree()), NOTHING, "{}", ran.dump);

    // The one call, with the sum of the patched gem: vendored, with and
    // without a `CHECKSUMS` section in the lock. Each undo puts every file
    // back and names the entry it leaves in the call.
    cell.write("MODULE.bazel", &pinned);
    for (with_section, undo) in [
        (true, &["vendor", "--revert", "--yes"][..]),
        (true, &["rollback", "--yes"]),
        (false, &["remove", PURL, "--yes"]),
    ] {
        if !with_section {
            unchecked(&cell);
        }
        let before = cell.tree();
        let ran = scan(&cell, &served);
        assert_eq!(ran.envelope["summary"]["applied"], 1, "{}", ran.dump);
        let pinned = text(&cell, "Gemfile.lock").contains(&checksum(NAME, &sums[1]));
        assert_eq!(pinned, with_section, "{}", ran.dump);
        let undo = run(&served.standin, &cell, undo, &[]);
        assert_eq!(changed(&before, &cell.tree()), NOTHING, "{}", undo.dump);
        let said = squeezed(&undo.dump);
        let left = format!("`ruby.bundle_fetch` (MODULE.bazel:15) still hold {NAME}-{VERSION}");
        let left = said.contains(ENTRY_LEFT) && said.contains(&squeezed(&left));
        assert!(undo.code == 0 && left, "{}", undo.dump);
    }
}

/// Without a Bazel: the refusal is the project's whose files a hub reads,
/// and no other's. In a workspace whose hub reads the files of another
/// project, and in no workspace at all, vendored mode vendors the gem as
/// it did, with no switch. Where the files the hub is given are not
/// written out in `MODULE.bazel`, the gem is declined, and the refusal
/// names the call and the reason.
#[test]
fn vendored_mode_goes_on_where_no_hub_reads_the_lock() {
    let own = [
        "gemfile = \"//:Gemfile\"",
        "gemfile_lock = \"//:Gemfile.lock\"",
    ];
    let reads = |cell: &Cell, files: [&str; 2]| {
        let module = String::from_utf8(cell.tree()["MODULE.bazel"].clone()).expect("a text file");
        let other = module.replace(own[0], files[0]).replace(own[1], files[1]);
        assert_ne!(other, module);
        cell.write("MODULE.bazel", other);
    };
    let scan = |cell: &Cell, served: &Served| {
        let origin = served.standin.origin();
        run(&served.standin, cell, &VENDORED, &patch_host(&origin))
    };
    let vendors = |cell: &Cell, served: &Served| {
        let scan = scan(cell, served);
        assert_eq!(scan.code, 0, "{}", scan.dump);
        assert_eq!(scan.envelope["summary"]["applied"], 1, "{}", scan.dump);
    };
    let (cell, served) = checkout();
    reads(
        &cell,
        [
            "gemfile = \"//svc:Gemfile\"",
            "gemfile_lock = \"//svc:Gemfile.lock\"",
        ],
    );
    vendors(&cell, &served);
    let (cell, served) = checkout();
    std::fs::remove_file(cell.path("MODULE.bazel")).expect("MODULE.bazel");
    vendors(&cell, &served);

    // Files that are not written out: the hub may read any.
    let (cell, served) = checkout();
    reads(&cell, ["gemfile = GEMFILE", "gemfile_lock = LOCK"]);
    let package = Declined {
        names: &[
            "(MODULE.bazel:15: the files `ruby.bundle_fetch` names",
            "cannot be read with certainty",
        ],
        ..DECLINED
    };
    let before = cell.tree();
    cell.declined(&scan(&cell, &served), &package, 1, "failed", &before);
}

/// Without a Bazel: a `WORKSPACE` file that a migration left behind still
/// hands the Gemfile and its lock to the ruleset's older rule, beside a
/// `MODULE.bazel` whose hub reads the files of another project. Bazel 9
/// never reads a `WORKSPACE` file, so where the checkout names a release of
/// 9 or later the gem is vendored as it is without that file. Where it
/// names an older release, none, or one that is no release, a Bazel that
/// reads the file may build the checkout: the gem is declined, and the
/// refusal names the call of the `WORKSPACE` file.
#[test]
fn a_workspace_file_counts_unless_the_checkout_names_bazel_9_or_later() {
    let legacy = "rb_bundle_fetch(\n    name = \"bundle\",\n    gemfile = \"//:Gemfile\",\n    \
                  gemfile_lock = \"//:Gemfile.lock\",\n)\n";
    // The fixture's checkout with a hub that reads the files of another
    // project, the `WORKSPACE` file where it is `kept`, and what names
    // the Bazel release.
    let retained = |release: Option<&str>, kept: bool| {
        let (cell, served) = checkout();
        let module = String::from_utf8(cell.tree()["MODULE.bazel"].clone()).expect("a text file");
        let other = module.replace("\"//:Gemfile", "\"//svc:Gemfile");
        assert_ne!(other, module);
        cell.write("MODULE.bazel", other);
        if kept {
            cell.write("WORKSPACE", legacy);
        }
        if let Some(release) = release {
            cell.write(".bazelversion", format!("{release}\n"));
        }
        (cell, served)
    };
    let scan = |cell: &Cell, served: &Served| {
        let origin = served.standin.origin();
        run(&served.standin, cell, &VENDORED, &patch_host(&origin))
    };
    // A run that vendors the gem by its path, and the files it writes,
    // with the id of the patch left out of their names.
    let vendors = |cell: &Cell, served: &Served| -> Vec<String> {
        let before = cell.tree();
        let ran = scan(cell, served);
        assert_eq!(ran.code, 0, "{}", ran.dump);
        assert_eq!(ran.envelope["summary"]["applied"], 1, "{}", ran.dump);
        let after = cell.tree();
        let copy = format!(".socket/vendor/gem/{}/{NAME}-{VERSION}", served.uuid);
        let lock = String::from_utf8_lossy(&after["Gemfile.lock"]);
        let section = format!("PATH\n  remote: {copy}\n");
        assert!(lock.starts_with(&section), "{lock}");
        let written = changed(&before, &after).into_iter();
        written
            .map(|path| path.replace(&served.uuid, "<id>"))
            .collect()
    };
    let (cell, served) = retained(Some("9.3.2"), false);
    let written = vendors(&cell, &served);
    for release in ["9.3.2", "9.0.0", "10.0.0"] {
        let (cell, served) = retained(Some(release), true);
        assert_eq!(vendors(&cell, &served), written, "{release}");
    }
    let package = Declined {
        names: &["`rb_bundle_fetch` (WORKSPACE:1)", "names Gemfile.lock; "],
        ..DECLINED
    };
    for release in [Some("7.7.2"), Some("8.8.2"), None, Some("latest")] {
        let (cell, served) = retained(release, true);
        let before = cell.tree();
        cell.declined(&scan(&cell, &served), &package, 1, "failed", &before);
    }
}

/// Without a Bazel: steps (b), (d) and (f) of
/// [`hosted_bundle_fetch_gem_checksums`] in the fixture's checkout, with
/// what a person reads of (b), and (b) again with `--dry-run` and with
/// `--vex`. On either way on, the two files a scan rewrites are, byte for
/// byte, the ones it rewrites in the same checkout without a
/// `MODULE.bazel`, and `rollback` restores them and leaves the call.
#[test]
fn a_gem_that_the_hub_holds_to_its_upstream_sha256_is_left_alone() {
    let served = Served::to(&mut cell_without_bazel("9.3.2"));
    let run = |cell: &Cell, args: &[&str]| run(&served.standin, cell, args, &[]);
    let (other, upstream, patched) = (
        sha256_hex(&served.neighbour_gem),
        sha256_hex(&served.upstream_gem),
        sha256_hex(&served.patched_gem),
    );
    let hosted = ["scan", "--mode", "hosted", "--yes"];
    let files = ["Gemfile", "Gemfile.lock"];
    let plain = checkout_with(&served, None);
    let before = plain.tree();
    let scan = run(&plain, &hosted);
    let plain = plain.pinned_by(&scan, PURL, &served.uuid, &before, &files);

    let held = module_pinning(&[(NEIGHBOUR, &other), (NAME, &upstream)]);
    let cell = checkout_with(&served, Some(&held));
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
    let warning = squeezed(&format!("Warning: {warned}"));
    assert!(squeezed(&stderr).contains(&warning), "{said}");
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

/// Without a Bazel: with `SOCKET_NO_BAZEL=1` a hosted scan pins the gem
/// that the hub holds to its upstream sha256, as it does in the same
/// checkout without its `MODULE.bazel`, to the byte, and says nothing of
/// the call. Without the variable it leaves the gem alone there.
#[test]
fn the_switch_makes_a_hosted_scan_the_one_of_a_checkout_without_bazel() {
    let served = Served::to(&mut cell_without_bazel("9.3.2"));
    let sums = [&served.neighbour_gem, &served.upstream_gem].map(|gem| sha256_hex(gem));
    let held = module_pinning(&[(NEIGHBOUR, &sums[0]), (NAME, &sums[1])]);
    let cell = checkout_with(&served, Some(&held));
    let origin = served.standin.origin();
    let rubygems = format!("{origin}/{RUBYGEMS}");
    let env = [("SOCKET_RUBYGEMS_URL", rubygems.as_str())];
    let hosted = ["scan", "--mode", "hosted", "--yes"];
    let left_alone = cell.off_is_without_bazel(&origin, &hosted, &env, &["MODULE.bazel"]);
    let said = left_alone[0]["stdout"].as_str().expect("an envelope");
    let envelope: serde_json::Value = serde_json::from_str(said).expect("an envelope");
    assert_eq!(codes_in(&envelope["warnings"]), [HELD], "{left_alone:#}");
}

/// Without a Bazel: with `SOCKET_NO_BAZEL=1` vendored mode vendors the gem
/// whose lock the hub reads, as it does in the same checkout without its
/// `MODULE.bazel`, to the byte. Without the variable it declines the gem
/// there.
#[test]
fn the_switch_makes_vendored_mode_the_one_of_a_checkout_without_bazel() {
    let (cell, served) = checkout();
    let origin = served.standin.origin();
    let rubygems = format!("{origin}/{RUBYGEMS}");
    let env = [
        ("SOCKET_RUBYGEMS_URL", rubygems.as_str()),
        patch_host(&origin)[0],
    ];
    let declined = cell.off_is_without_bazel(&origin, &VENDORED, &env, &["MODULE.bazel"]);
    assert_eq!(declined[0]["code"], 1, "{declined:#}");
}

/// Without a Bazel: the switch is for the gem committed for a hub as well.
/// In the checkout where vendored mode commits the gem as its archive,
/// `SOCKET_NO_BAZEL=1` makes it vendor the gem as it does in the same
/// checkout without its `MODULE.bazel`, to the byte: the unpacked copy,
/// which the lock names by its path, and no archive. Without the variable
/// the run commits the gem for the hub there.
#[test]
fn the_switch_makes_a_gem_for_the_hub_the_vendoring_of_a_checkout_without_bazel() {
    let (cell, served) = checkout();
    cell.write(".bazelversion", "9.3.2\n");
    let origin = served.standin.origin();
    let rubygems = format!("{origin}/{RUBYGEMS}");
    let env = [
        ("SOCKET_RUBYGEMS_URL", rubygems.as_str()),
        patch_host(&origin)[0],
    ];
    let (plain, for_the_hub) = cell.without_and_beside(&origin, &VENDORED, &env, &["MODULE.bazel"]);
    let uuid = served.uuid.as_str();
    let copy = format!("PATH\n  remote: .socket/vendor/gem/{uuid}/{NAME}-{VERSION}\n");
    let source = format!("file:.socket/vendor/gem/{uuid}/");
    let archive = committed_gem(uuid);
    for (run, committed) in [(&plain, false), (&for_the_hub, true)] {
        for form in [&run[0], &run[1]] {
            assert_eq!(form["code"], 0, "{form:#}");
            let files = &form["files"];
            let lock = files["Gemfile.lock"].as_str().expect("Gemfile.lock");
            let gemfile = files["Gemfile"].as_str().expect("Gemfile");
            assert_eq!(lock.starts_with(&copy), !committed, "{form:#}");
            assert_eq!(gemfile.contains(&source), committed, "{form:#}");
            assert_eq!(files[archive.as_str()].is_string(), committed, "{form:#}");
        }
    }
}

/// Every code a run names in its envelope: of its events, its warnings and
/// the warnings of its events, in the order they stand.
fn named_codes(envelope: &serde_json::Value) -> Vec<String> {
    let mut codes = Vec::new();
    let mut left = vec![envelope];
    while let Some(value) = left.pop() {
        match value {
            serde_json::Value::Array(items) => left.extend(items.iter().rev()),
            serde_json::Value::Object(fields) => {
                for (key, value) in fields.iter().rev() {
                    match value.as_str() {
                        Some(code) if key == "code" || key == "errorCode" => {
                            codes.push(code.to_string())
                        }
                        _ => left.push(value),
                    }
                }
            }
            _ => {}
        }
    }
    codes
}

/// Without a Bazel: what an earlier run wrote for Bazel is still listed
/// and undone with `SOCKET_NO_BAZEL=1`. A run without the variable commits
/// the gem for the hub. With the variable, `list` shows a vendored gem and
/// `vendor --check` holds the committed gem to the patch, and each of
/// `vendor --revert`, `rollback` and `remove` puts every file back, to the
/// byte: the `Gemfile`, its lock, the committed gem and the ledger. It
/// names the codes it names without the variable: none in the fixture's
/// checkout, and the entry it leaves in the call where the call's
/// `gem_checksums` hold the gem to the patched one.
#[test]
fn the_switch_still_undoes_a_gem_committed_for_the_hub() {
    let (cell, served) = checkout();
    cell.write(".bazelversion", "9.3.2\n");
    let standin = &served.standin;
    let origin = standin.origin();
    let go = |args: &[&str], env: &[(&str, &str)]| {
        let env = [&patch_host(&origin)[..], env].concat();
        run(standin, &cell, args, &env)
    };
    let off = [("SOCKET_NO_BAZEL", "1")];
    let undos: [&[&str]; 3] = [
        &["vendor", "--revert", "--yes"],
        &["rollback", "--yes"],
        &["remove", PURL, "--yes"],
    ];
    // The fixture's call, and the same call with a `gem_checksums` that
    // holds the gem to the sha256 of the patched one.
    let lock = "    gemfile_lock = \"//:Gemfile.lock\",\n";
    let module = String::from_utf8(cell.tree()["MODULE.bazel"].clone()).expect("a text file");
    assert!(module.contains(lock), "{module}");
    let sum = sha256_hex(&served.patched_gem);
    let held = format!("{lock}    gem_checksums = {{\"{NAME}-{VERSION}\": \"{sum}\"}},\n");
    let held = module.replace(lock, &held);
    for (module, left) in [(&module, false), (&held, true)] {
        cell.write("MODULE.bazel", module);
        let before = cell.tree();
        for undo in undos {
            let vendored = committed_for_the_hub(&cell, &go(&VENDORED, &[]), &served, &before);
            let list = go(&["list"], &off);
            let listed = list.envelope.to_string();
            let as_vendored = listed.contains("\"vendored\"") && !listed.contains("\"hosted\"");
            assert!(as_vendored, "{}", list.dump);
            let check = go(&["vendor", "--check"], &off);
            assert_eq!(check.code, 0, "{}", check.dump);
            assert_eq!(changed(&vendored, &cell.tree()), NOTHING, "{}", check.dump);

            // The undo without the variable, for what it names.
            let plain = go(undo, &[]);
            assert_eq!(changed(&before, &cell.tree()), NOTHING, "{}", plain.dump);
            committed_for_the_hub(&cell, &go(&VENDORED, &[]), &served, &before);
            let switched = go(undo, &off);
            assert_eq!(switched.code, 0, "{undo:?}: {}", switched.dump);
            let undone = changed(&before, &cell.tree());
            assert_eq!(undone, NOTHING, "{undo:?}: {}", switched.dump);
            let names = named_codes(&switched.envelope);
            let without = named_codes(&plain.envelope);
            assert_eq!(names, without, "{undo:?}: {}", switched.dump);
            let says = names.contains(&ENTRY_LEFT.to_string());
            assert_eq!(says, left, "{undo:?}: {}", switched.dump);
        }
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
    let served = Served::to(&mut cell_without_bazel("9.3.2"));
    let run = |cell: &Cell, args: &[&str]| run(&served.standin, cell, args, &[]);
    let (upstream, patched) = (
        sha256_hex(&served.upstream_gem),
        sha256_hex(&served.patched_gem),
    );
    let hosted = ["scan", "--mode", "hosted", "--yes"];
    let files = ["Gemfile", "Gemfile.lock"];
    let held = module_pinning(&[(NAME, &upstream)]);

    // A lock that Bundler holds no gem to.
    let cell = checkout_with(&served, Some(&held));
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
    let cell = checkout_with(&served, Some(&unread));
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
    let plain = checkout_with(&served, None);
    let before = plain.tree();
    let scan = run(&plain, &hosted);
    let plain = plain.pinned_by(&scan, PURL, &served.uuid, &before, &files);
    let elsewhere = held.replace("\"//:Gemfile.lock\"", "\"//other:Gemfile.lock\"");
    let unheld = fixture_path(FIXTURE.dir).join("e9/MODULE.bazel");
    let unheld = std::fs::read_to_string(unheld).expect("the fixture's MODULE.bazel");
    for module in [elsewhere, unheld] {
        assert!(module.contains("ruby.bundle_fetch("), "{module}");
        let cell = checkout_with(&served, Some(&module));
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
