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
//! Vendored mode would commit the unpacked patched gem under
//! `.socket/vendor/gem` and make `Gemfile` and `Gemfile.lock` name it by
//! its path from the project, and rules_ruby runs `bundle install` in a
//! repository of Bazel's that holds the two files and not the copy. So in
//! this checkout, where the hub reads both files, the command declines the
//! gem and writes nothing ([`vendored_bundle_fetch`]): the build stays the
//! unpatched one. With `--allow-vendored-in-bazel` it does what it did
//! before it declined, and the build fails until `vendor --revert` has put
//! the two files back. Hosted mode, which the refusal names, then patches
//! the build.
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

/// What `text` reads without its white space: Bundler breaks a message at
/// the width of the console it runs in.
fn squeezed(text: &str) -> String {
    text.split_whitespace().collect()
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

/// Makes the lock of `cell` name [`OLDER_BUNDLER`].
fn names_the_older_bundler(cell: &Cell) {
    let lock = String::from_utf8(cell.tree()["Gemfile.lock"].clone()).expect("a text file");
    let named = "\nBUNDLED WITH\n  4.0.15\n";
    assert!(lock.ends_with(named), "{}: {lock}", cell.test);
    let older = format!("\nBUNDLED WITH\n  {OLDER_BUNDLER}\n");
    cell.write("Gemfile.lock", lock.replace(named, &older));
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
    names_the_older_bundler(&fourth);
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
/// fixture's checkout: the hub's call with its line in `MODULE.bazel`, and
/// the file it reads.
const DECLINED: Declined = Declined {
    purl: PURL,
    code: "vendor_gem_bazel_hub",
    names: &[
        "`ruby.bundle_fetch` (MODULE.bazel:15)",
        "names Gemfile.lock; ",
    ],
};

/// The variables of a command of vendored mode, which downloads the
/// patched gem from the patch host: the stand-in at `origin` is that host.
fn patch_host(origin: &str) -> [(&str, &str); 1] {
    [("SOCKET_PATCH_SERVER_URL", origin)]
}

/// Vendored mode beside a hub that reads the Gemfile and its lock.
///
/// - (a) `bazel build` and `bazel run //:consumer` print the unpatched
///   marker.
/// - (b) `socket-patch scan --mode vendored --yes` declines the gem: it
///   exits 1, names the call of `MODULE.bazel` that reads the lock, hosted
///   mode and the switch, writes nothing and downloads no gem. The same
///   two Bazel commands print the unpatched marker, and change no file.
/// - (c) With `--allow-vendored-in-bazel` the command does what it did
///   before it declined: it passes and reports the gem vendored. It
///   commits the unpacked patched gem, with its specification and its
///   ledger, under `.socket/vendor`, and makes the declaration of
///   `Gemfile` and a `PATH` section of `Gemfile.lock` name that copy by
///   its path from the project. The same `bazel build` fails: rules_ruby
///   copies `Gemfile` and `Gemfile.lock` into a repository of Bazel's and
///   runs `bundle install` there, where the path names nothing. `vex`
///   attests the gem as patched all the same: it reads the committed
///   copy, and what rules_ruby builds from one is not judged.
/// - (d) `socket-patch vendor --revert`, which takes no switch: every file
///   of the checkout is the one of before, and the build prints the
///   unpatched marker again.
/// - (e) Hosted mode, which the refusal names: the same two Bazel commands
///   print the patched marker.
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
    let vendoring = |args: &[&str]| run(standin, &cell, args, &patch_host(&origin));

    // (a) The unpatched build.
    let before = cell.builds_unpatched(&served.unpatched);

    // (b) The one command of vendored mode: declined, with nothing written
    // and nothing of the patch fetched. The same build passes, on the
    // upstream gem.
    cell.declined(&vendoring(&VENDORED), &DECLINED, 1, "failed", &before);
    assert_eq!(standin.asked(&served.artifact_route), 0, "{test}");
    cell.builds_patched(&before, &served.unpatched);

    // (c) On the user's word: the copy, its ledger, and the two files that
    // name it.
    let scan = vendoring(&[&VENDORED[..], &[ALLOW]].concat());
    let said = &scan.dump;
    assert_eq!(scan.code, 0, "{test}: {said}");
    assert_eq!(scan.envelope["status"], "success", "{test}: {said}");
    assert_eq!(scan.envelope["summary"]["applied"], 1, "{test}: {said}");
    let vendored = cell.tree();
    let kept = format!(".socket/vendor/gem/{uuid}");
    let copy = format!("{kept}/{NAME}-{VERSION}");
    let mut written = vec![
        format!("{kept}/socket-patch.vendor.json"),
        format!("{copy}/{LIB}"),
        format!("{copy}/{NAME}.gemspec"),
        ".socket/vendor/state.json".to_string(),
        "Gemfile".to_string(),
        "Gemfile.lock".to_string(),
    ];
    written.sort();
    assert_eq!(changed(&before, &vendored), written, "{test}: {said}");
    let patched_source = source(&format!("PATCHED {uuid}"));
    let lib = &vendored[&format!("{copy}/{LIB}")];
    assert_eq!(*lib, patched_source.as_bytes(), "{test}");
    let text = |rel: &str| String::from_utf8(vendored[rel].clone()).expect("a text file");
    let (gemfile, lock) = (text("Gemfile"), text("Gemfile.lock"));
    let declaration = format!("gem \"{NAME}\", \"{VERSION}\", path: \"{copy}\"");
    let declared = gemfile.lines().filter(|line| *line == declaration).count();
    assert_eq!(declared, 1, "{test}: Gemfile:\n{gemfile}");
    let section = format!("PATH\n  remote: {copy}\n  specs:\n    {NAME} ({VERSION})\n\n");
    assert!(lock.starts_with(&section), "{test}: Gemfile.lock:\n{lock}");

    // The same build fails where rules_ruby runs Bundler, on the path of
    // the copy, and changes no file of the checkout. Bundler breaks the
    // message at the width of its console, so it is compared without white
    // space.
    let build = cell.bazel("build", &[CONSUMER]);
    let stderr = squeezed(&build.stderr());
    let missing = squeezed(&format!("{copy}` does not exist."));
    assert!(
        !build.ok() && stderr.contains("Runningbundleinstall") && stderr.contains(&missing),
        "{test}: the build did not fail on the path of the copy ({missing:?}):\n{}",
        build.dump()
    );
    assert_eq!(changed(&vendored, &cell.tree()), NOTHING, "{test}");
    let socket_patch = |cell: &Cell, args: &[&str]| run(standin, cell, args, &[]);
    cell.stands_alone(socket_patch, &Claim::new(PURL, uuid, How::Vendored), true);

    // (d) The undo: every file is the one of before, and so is the build.
    let undo = socket_patch(&cell, &["vendor", "--revert", "--yes"]);
    cell.undone(&undo, "removed", &before, &served.unpatched);

    // (e) The remedy the refusal names: hosted mode patches the build.
    let scan = socket_patch(&cell, &["scan", "--mode", "hosted", "--yes"]);
    let pinned = cell.pinned_by(&scan, PURL, uuid, &before, &["Gemfile", "Gemfile.lock"]);
    cell.builds_patched(&pinned, &served.patched);

    println!(
        "{test}: Bazel {release} built {:?}; `scan --mode vendored` declined ({}), wrote \
         nothing, and the build stayed the same; with {ALLOW} it wrote {copy} and pointed \
         Gemfile and Gemfile.lock at it, and the next build failed (Bundler: The path ... does \
         not exist) while `vex` attested the gem; `vendor --revert` restored all {} files and \
         the build; `scan --mode hosted` built {:?}; {:?}",
        served.unpatched,
        DECLINED.code,
        before.len(),
        served.patched,
        started.elapsed()
    );
}

/// Without a Bazel: the fixture in a checkout of its own, whose lock pins
/// the gems of the stand-in that comes with it.
fn checkout() -> (Cell, Served) {
    let mut cell = cell_without_bazel("9.3.2");
    for part in ["common", "e9"] {
        for (rel, bytes) in read_tree(&fixture_path(FIXTURE.dir).join(part)) {
            cell.write(&rel, bytes);
        }
    }
    cell.write(".git/HEAD", "ref: refs/heads/main\n");
    let served = Served::to(&mut cell);
    (cell, served)
}

/// Without a Bazel: in the fixture's checkout, where the hub reads the
/// Gemfile and its lock, every command that would vendor the gem declines
/// it, writes nothing and fetches no gem. On the user's word vendored mode
/// goes on, and a later run without it passes and writes nothing: the lock
/// the hub reads already names the copy.
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
