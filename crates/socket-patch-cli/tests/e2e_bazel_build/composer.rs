//! Hosted, agent and vendored mode for a Composer package in a Bazel
//! workspace that builds PHP with rules of its own.
//!
//! No Bazel ruleset builds PHP or takes Composer packages, and the Bazel
//! registry holds none. A PHP project under Bazel writes the few lines that
//! bring its packages into the build itself. The fixture is a workspace with
//! three such projects, each in a directory below the root as a monorepo
//! has them, and each stands for one hand-written shape:
//!
//! - `services/api`: a repository rule (`composer.bzl`) runs `composer
//!   install` from the committed `composer.lock`. It takes the lock with
//!   `rctx.read`, so Bazel fetches the repository again when the lock
//!   changes.
//! - `services/worker`: a genrule runs `composer install` from the lock in
//!   a build action.
//! - `services/legacy`: the project commits its `vendor/` tree, and Bazel
//!   reads the packages as source files.
//!
//! Three flows, one test each, on the Bazel the run is given, each in a
//! fresh output base: hosted mode in the first two projects, where Bazel
//! runs Composer on the lock that `socket-patch` rewrites, and agent mode
//! in the third, where Bazel reads the files that `socket-patch` patches in
//! place. Vendored mode has two flows of its own, which their tests
//! describe. In the first project it is declined, because the build would
//! fail on the path it writes into the lock, and hosted mode patches the
//! build in its place; with the flag that lifts the refusal the build does
//! fail. In the third it is declined as well, and with the flag the build
//! is the patched one once the developer has installed from the lock. The
//! tests at the end that need no Bazel hold every command that would
//! vendor to the refusal, and to the user's word, which alone lifts it.
//! The harness builds `//:consumer`, so a test writes the root
//! `BUILD.bazel` that points that label at the consumer of its project.
//!
//! - (a) `bazel build` and `bazel run //:consumer` print the unpatched
//!   marker. The upstream archive came from the stand-in: Composer fetched
//!   it inside Bazel (hosted), or the developer's Composer did when it made
//!   the committed tree (agent), and then Bazel asks no host at all.
//! - (b) The one command of the mode, in the project's directory, writes
//!   its files and no other. `scan --mode hosted --yes` rewrites
//!   `composer.lock`: the package's `dist` is the patched archive on the
//!   patch host with its sha1, and its git `source` is gone, so Composer
//!   cannot fall back to the upstream commit. `scan --mode agent --yes`
//!   patches the package's file under `vendor/` and writes
//!   `.socket/manifest.json` and two blobs.
//! - (c) The same two Bazel commands, with no step in between, print the
//!   patched marker; Bazel changed no file of the checkout, and a
//!   `--lockfile_mode=error` build passes. Hosted: Composer fetched the
//!   archive from the stand-in patch host inside Bazel. Then `vex` attests
//!   the package.
//! - (d) The undo. `rollback --yes` puts the lock back byte for byte, from
//!   the registry's metadata, and the build prints the unpatched marker
//!   again (hosted). In agent mode it restores the file byte for byte and
//!   leaves one file behind, a `.socket/manifest.json` that lists no patch.
//! - (e) A second machine, and other bytes where the patch should be.
//!   Hosted: the checkout has the rewritten lock and the patch host serves
//!   another archive at the pinned URL. Composer refuses it on the sha1 of
//!   the lock, the build fails, and the upstream archive is not fetched in
//!   its place. Agent: a patch service hands out another blob than the
//!   patch names. `scan` refuses it and writes nothing, and the build is
//!   the unpatched one. Nothing at build time holds a committed tree to a
//!   sum, so that refusal is the check there is.
//!
//! What a flow records beside its steps, as the behaviour of today:
//!
//! - In a monorepo the commands run per project. `scan --json` at the
//!   workspace root patches nothing and names the directory to scan
//!   (repository rule flow). Every command of a flow gets its project as
//!   `--cwd`.
//! - A hosted pin does not survive a relock. `composer update --lock` puts
//!   the upstream entry back without a word, the next build is the
//!   unpatched one, and `vex` has nothing to attest until `scan` runs again
//!   (genrule flow). The registry of the stand-in lists no security
//!   advisory for the version, so Composer resolves it as before.
//! - The check of step (e) is one of an empty Composer cache. A machine
//!   whose cache already holds the patched archive does not ask the host
//!   again: with the first machine's cache, the second machine builds the
//!   patch while the host serves other bytes (repository rule flow). In a
//!   build action the fixture turns Composer's cache off, so the genrule's
//!   Composer asks the host on every run.
//!
//! The markers are read from what Bazel built: PHP runs the consumer in a
//! build action, on the tree Bazel has, and `bazel run` prints what it
//! said. Each marker holds an id made for the run, and so does the commit
//! id of the upstream package, which is part of its archive's URL: no cache
//! of an earlier run can supply either archive.
//!
//! PHP and Composer are the machine's own, the `php` and `composer` on
//! `PATH`: Bazel brings neither, there being no ruleset. Without one of
//! them, or with one older than the flows take, a test prints `SKIP <why>`
//! and passes, and fails instead under `SOCKET_PATCH_BAZEL_E2E_REQUIRED`,
//! which the module reads itself ([`tools`]) as the harness does for a
//! missing Bazel. The fixture's `.bazelrc` hands the `PATH` of the shell to
//! the build actions, which on Bazel 9 get a fixed one otherwise, and the
//! Composer home with it. No other `COMPOSER*` variable of the shell
//! reaches a Composer of a flow: the harness removes them from every Bazel
//! child, and a flow sets the ones of [`Machine::env`] after that.
//!
//! One loopback server per checkout stands in for four hosts, by route
//! prefix: the Socket API (`/v0`), the patch host (`/patch`),
//! `repo.packagist.org` (the registry's metadata, which the developer's
//! Composer resolves the lock from and `rollback` restores it from, through
//! `SOCKET_PACKAGIST_URL`) and `api.github.com` (the upstream archive,
//! where the registry's metadata points). The package is the tests' own
//! ([`NAME`]). On Packagist a vendor name belongs to whoever published under
//! it first, and no test can know who that is, so what keeps a stranger's
//! package of that name out of a build, and the name away from the public
//! registry, is the Composer home of the machine ([`Machine`]):
//!
//! - Every Composer of a flow reads that home: the developer's, which a
//!   test starts itself to make the lock, the one the repository rule
//!   starts and the one the genrule's action starts. Composer reads the
//!   root file of every repository it knows on an install from a lock too,
//!   not only when it resolves one (2.11.2 does), so each of the three
//!   would ask the public registry on its defaults.
//! - The home names the stand-in as the one repository and turns
//!   `packagist.org` off. It is also the one place that turns `secure-http`
//!   off, which the plain http of the stand-in needs (production pins https
//!   URLs): a Composer that reads another home, and so might know the
//!   public registry, cannot fetch the package at all, and its build fails.
//! - The developer's Composer is the only one that looks a package up by
//!   name. Every proxy it could use is a port of the test's that counts
//!   what connects ([`Trap`]), and a test fails when anything did: no
//!   request of that Composer left loopback. Bazel's own downloads need
//!   the proxy of the machine, so the two Composers it starts have no such
//!   trap; the lock they install from names the stand-in in every URL
//!   ([`open`] holds it to that).

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use base64::Engine as _;
use serde_json::{json, Value};
use sha1::{Digest as _, Sha1};
use sha2::{Sha256, Sha512};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;

use crate::envelope::{codes_in, event_for, event_triples};
use crate::harness::{
    cell_without_bazel, changed, fixture_path, Cell, Fixture, Ran, Release, StandIn, Tree,
    CONSUMER, NOTHING, REQUIRED,
};
use crate::hosted_memory_common::hermetic::{self, Extra};
use crate::hosted_memory_common::{read_tree, Patch, ORG};

/// The workspace the tests build. No ruleset is in it, so every Bazel
/// release builds the same files.
const FIXTURE: Fixture = Fixture {
    name: "composer::FIXTURE",
    dir: "composer/bzlmod",
    workflow: "bazel-composer.yml",
    eras: &[
        // `use_repo_rule` is Bazel 7's. The flows ran on Bazel 9.3.2, 8.8.2
        // and 7.7.2, the legs of the workflow: every other release of the
        // range is untested.
        ((7, 0, 0)..(10, 0, 0), "e9"),
    ],
};

/// The three projects of the workspace, by directory: the one whose
/// packages a repository rule installs, the one whose packages a genrule
/// installs, and the one that commits its `vendor/` tree.
const API: &str = "services/api";
const WORKER: &str = "services/worker";
const LEGACY: &str = "services/legacy";
const PROJECTS: [&str; 3] = [API, WORKER, LEGACY];

/// The package every project requires, at the version its lock pins.
const NAME: &str = "socketsecurity/bazel-fixture-upstream";
const VERSION: &str = "1.0.0";
const PURL: &str = "pkg:composer/socketsecurity/bazel-fixture-upstream@1.0.0";
/// The file name of its archive on the patch host: the name without its
/// vendor.
const ZIP: &str = "bazel-fixture-upstream-1.0.0.zip";
/// Its `composer.json`. The other file of an archive is [`FILE`].
const MANIFEST: &str = "{\"name\": \"socketsecurity/bazel-fixture-upstream\", \
    \"type\": \"library\", \"license\": \"MIT\", \
    \"autoload\": {\"psr-4\": {\"SocketFixture\\\\\": \"src/\"}}}\n";
/// The file a patch changes, as a patch names it: relative to the package.
const FILE: &str = "src/Upstream.php";
/// The directory every archive of the package unpacks to, named as GitHub
/// names the one of a zipball. Composer drops it.
const TOP: &str = "socketsecurity-bazel-fixture-upstream-0000000";
/// The route prefixes under which the stand-in plays the registry and the
/// host of the upstream archive.
const PACKAGIST: &str = "repo.packagist.org";
const GITHUB_API: &str = "api.github.com";
/// The access-token level of a hosted archive's URL, which `socket-patch`
/// writes as the API hands it out.
const TOKEN: &str = "22222222-2222-4222-8222-222222222222";
/// What `vex` is told the project is. A checkout with a git remote needs no
/// such option; these have none, and their `composer.json` has no name.
const PRODUCT: &str = "pkg:composer/socketsecurity/bazel-fixture-app@1.0.0";
/// What Composer says when a file is not the one its lock pins.
const REFUSAL: &str = "The checksum verification of the file failed";
/// The hosts a proxy is never asked for: a stand-in listens on loopback.
const LOOPBACK: &str = "127.0.0.1,localhost";
/// The code under which vendored mode declines a Composer project in a
/// Bazel workspace, and the flag and the variable that lift it.
const DECLINED: &str = "vendor_composer_bazel_workspace";
const ALLOW: &str = "--allow-vendored-in-bazel";
const ALLOW_ENV: &str = "SOCKET_ALLOW_VENDORED_IN_BAZEL";

/// The two tools of the machine a flow runs: the program, the arguments
/// that make it print its release, the text before the release, and the
/// oldest release a flow runs on. Composer 2: the stand-in speaks the
/// registry protocol of Composer 2 and the flows assert a lock of its
/// form. PHP 7.2.5: the oldest that the Composer releases of today run on.
/// No flow ran on either floor ([`RAN_ON`]).
const TOOLS: [(&str, &[&str], &str, Release); 2] = [
    ("php", &["--version"], "PHP ", (7, 2, 5)),
    (
        "composer",
        &["--version", "--no-ansi"],
        "Composer version ",
        (2, 0, 0),
    ),
];

/// The releases the flows were run on. Every other one is untested, so a
/// flow prints this beside the two it found: a failure deep in a flow on
/// another release then has its first hint.
const RAN_ON: &str = "PHP 8.4.23 and Composer 2.11.2";

/// The release in what a tool printed: the three numbers after `prefix` on
/// the first line that starts with it, whatever a build adds after them
/// (`PHP 8.3.6-0ubuntu1 (cli)` is `(8, 3, 6)`).
fn release(printed: &str, prefix: &str) -> Option<Release> {
    let line = printed.lines().find_map(|line| line.strip_prefix(prefix))?;
    let mut parts = line.splitn(3, '.').map(|part| {
        let digits = part
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(part.len());
        part[..digits].parse::<u32>().ok()
    });
    Some((parts.next()??, parts.next()??, parts.next()??))
}

/// The release of a tool that a flow can run on, from what its `command`
/// printed. Else why no flow runs: the tool did not run, or its release is
/// below `oldest`, which is a tool that is not there.
fn usable(command: &str, printed: &str, prefix: &str, oldest: Release) -> Result<Release, String> {
    let dotted = |(major, minor, patch): Release| format!("{major}.{minor}.{patch}");
    match release(printed, prefix) {
        None => Err(format!("`{command}` did not run: {printed}")),
        Some(found) if found < oldest => Err(format!(
            "`{command}` says {}, and the flows need {} or later (they were run on {RAN_ON})",
            dotted(found),
            dotted(oldest)
        )),
        Some(found) => Ok(found),
    }
}

/// The PHP and the Composer on `PATH`, as one line for the report of
/// `test`: what the repository rule and the genrule of the fixture find
/// there too. `None` after a `SKIP` line when one of them does not run
/// here or is older than its floor in [`TOOLS`]; a panic instead under
/// [`REQUIRED`].
fn tools(test: &str) -> Option<String> {
    let home = tempfile::tempdir().expect("a temp dir");
    let mut found = Vec::new();
    for (program, args, prefix, oldest) in TOOLS {
        let mut cmd = hermetic::tool_command(program);
        hermetic::scrub_extra(&mut cmd, &[Extra::Composer]);
        cmd.args(args).env("HOME", home.path());
        let printed = match cmd.output() {
            Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).into_owned(),
            Ok(out) => String::from_utf8_lossy(&out.stderr).into_owned(),
            Err(e) => e.to_string(),
        };
        let command = format!("{program} {}", args.join(" "));
        let (major, minor, patch) = match usable(&command, &printed, prefix, oldest) {
            Ok(numbers) => numbers,
            Err(why) => {
                let required = std::env::var_os(REQUIRED).is_some_and(|value| !value.is_empty());
                assert!(!required, "{test}: {REQUIRED} is set and {why}");
                println!("SKIP {test}: {why}");
                return None;
            }
        };
        found.push(format!("{program} {major}.{minor}.{patch}"));
    }
    Some(found.join(", "))
}

/// The package with `source` as its one PHP file, as the archive GitHub
/// and the patch host serve: a zip with everything under one directory.
/// Every sum a test holds a build to is computed from the bytes it serves.
fn archive(source: &str) -> Vec<u8> {
    use std::io::Write as _;
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, text) in [("composer.json", MANIFEST), (FILE, source)] {
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file(format!("{TOP}/{name}"), options)
            .expect("zip");
        zip.write_all(text.as_bytes()).expect("zip");
    }
    zip.finish().expect("zip").into_inner()
}

/// One build of the package: a class whose constant is `<word> <id>`, the
/// archive of it, and the line the consumer prints once Bazel built that
/// archive in.
struct Package {
    /// [`FILE`].
    source: String,
    archive: Vec<u8>,
    marker: String,
}

impl Package {
    fn new(word: &str, id: &str) -> Package {
        let source = format!(
            "<?php\n\nnamespace SocketFixture;\n\nfinal class Upstream\n{{\n    \
             public const STATUS = '{word} {id}';\n}}\n"
        );
        Package {
            archive: archive(&source),
            marker: format!("OUT: {word} {id}"),
            source,
        }
    }
}

/// The package as the registry of one run has it: the commit it names is
/// new for every run, and so is the URL of the archive.
struct Upstream {
    package: Package,
    /// The commit id: forty hex digits.
    reference: String,
}

impl Upstream {
    fn new() -> Upstream {
        let run = uuid::Uuid::new_v4().to_string();
        Upstream {
            package: Package::new("PRISTINE", &run),
            reference: hex::encode(Sha1::digest(run.as_bytes())),
        }
    }

    /// The route of the archive on the stand-in, in the form of the URL
    /// Packagist names for a package on GitHub.
    fn route(&self) -> String {
        format!("/{GITHUB_API}/repos/{NAME}/zipball/{}", self.reference)
    }
}

/// One patch of the package, under an id that is new for every run.
struct Patched {
    uuid: String,
    package: Package,
    /// The route of the archive on the patch host.
    route: String,
}

impl Patched {
    fn new() -> Patched {
        let uuid = uuid::Uuid::new_v4().to_string();
        Patched {
            package: Package::new("PATCHED", &uuid),
            route: format!("/patch/composer/{NAME}/{VERSION}/{TOKEN}/{uuid}/{ZIP}"),
            uuid,
        }
    }
}

/// What the registry says of `upstream` at `origin`: the entry of its one
/// version, with the git `source` and the `dist` archive of the commit.
fn metadata(origin: &str, upstream: &Upstream) -> Value {
    json!({
        "name": NAME,
        "version": VERSION,
        "version_normalized": format!("{VERSION}.0"),
        "source": {
            "type": "git",
            "url": format!("{origin}/github.com/{NAME}.git"),
            "reference": upstream.reference,
        },
        "dist": {
            "type": "zip",
            "url": format!("{origin}{}", upstream.route()),
            "reference": upstream.reference,
            "shasum": "",
        },
        "type": "library",
        "time": "2026-01-01T00:00:00+00:00",
        "autoload": { "psr-4": { "SocketFixture\\": "src/" } },
        "license": ["MIT"],
    })
}

/// A stand-in that holds `upstream` as the registry and GitHub do: the
/// registry's root file, which lists the package as the only one it has,
/// the metadata of the package, and the archive.
fn registry(upstream: &Upstream) -> StandIn {
    let standin = StandIn::start();
    let root = json!({
        "packages": [],
        "metadata-url": format!("/{PACKAGIST}/p2/%package%.json"),
        "available-packages": [NAME],
    });
    let entry = metadata(&standin.origin(), upstream);
    let package = json!({ "minified": "composer/2.0", "packages": { NAME: [entry] } });
    let bytes = |document: &Value| serde_json::to_vec(document).expect("a JSON document");
    standin.serve(5, &format!("/{PACKAGIST}/packages.json"), &bytes(&root));
    standin.serve(5, &format!("/{PACKAGIST}/p2/{NAME}.json"), &bytes(&package));
    standin.serve(5, &upstream.route(), &upstream.package.archive);
    standin
}

/// The Socket API on `standin` for `patch` of `upstream`, free for every
/// caller, and the patch host. The API names the sums of the patch's own
/// archive and file, whatever is served, which is `served`: its archive at
/// the URL the API hands out, and its file as the content of the patched
/// file, which agent mode writes.
fn grant(standin: &StandIn, upstream: &Upstream, patch: &Patched, served: &Package) {
    let url = format!("{}{}", standin.origin(), patch.route);
    let archive = &patch.package.archive;
    let base64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    let reference = json!({
        "status": "granted",
        "url": url,
        "purl": PURL,
        "artifacts": [{
            "kind": "tarball",
            "url": url,
            "integrity": {
                "sha1": hex::encode(Sha1::digest(archive)),
                "sha256": hex::encode(Sha256::digest(archive)),
                "sha512": format!("sha512-{}", base64(&Sha512::digest(archive))),
            },
        }],
        "registryOverride": null,
    });
    let granted = Patch {
        purl: PURL.to_string(),
        uuid: patch.uuid.clone(),
        reference,
    };
    standin.api(&[granted]);
    // Priority 1: ahead of the shared API mock's patch record, whose hashes
    // are fixed, because agent mode and `vex` hold a file to `afterHash`.
    let record = json!({
        "uuid": patch.uuid,
        "purl": PURL,
        "publishedAt": "2026-01-01T00:00:00Z",
        "files": { FILE: {
            "beforeHash": compute_git_sha256_from_bytes(upstream.package.source.as_bytes()),
            "afterHash": compute_git_sha256_from_bytes(patch.package.source.as_bytes()),
            "blobContent": base64(served.source.as_bytes()),
            "beforeBlobContent": base64(upstream.package.source.as_bytes()),
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
    standin.serve(5, &patch.route, &served.archive);
}

/// The `config.json` of a Composer home that knows one repository, the
/// registry the stand-in at `origin` plays, and not the public one, and
/// that takes the plain http of that stand-in.
fn home_config(origin: &str) -> String {
    let config = json!({
        "config": { "secure-http": false },
        "repositories": {
            "packagist.org": false,
            "stand-in": { "type": "composer", "url": format!("{origin}/{PACKAGIST}") },
        },
    });
    format!("{config:#}\n")
}

/// A proxy that answers nothing: a port that takes every connection, counts
/// it and drops it. A tool that has it as its proxy for every host but
/// loopback connects once per request it sends anywhere else, and fails
/// that request at once.
struct Trap {
    /// `http://127.0.0.1:<port>`.
    address: String,
    connections: Arc<AtomicUsize>,
}

impl Trap {
    fn set() -> Trap {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let port = listener.local_addr().expect("the port").port();
        let connections = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&connections);
        // Ends with the test process.
        std::thread::spawn(move || {
            for connection in listener.incoming() {
                if connection.is_err() {
                    break;
                }
                counted.fetch_add(1, Ordering::SeqCst);
            }
        });
        Trap {
            address: format!("http://127.0.0.1:{port}"),
            connections,
        }
    }
}

/// Composer's own files on one machine: its home, whose config is
/// [`home_config`], and its cache, which starts empty. A second machine
/// has its own, as it has an output base of its own.
struct Machine {
    // Removed on drop.
    dir: tempfile::TempDir,
    /// The proxy of the developer's Composer.
    trap: Trap,
}

impl Machine {
    /// Under the target directory, not the temp directory of the machine:
    /// the Linux sandbox of a build action has a `/tmp` of its own, where
    /// a home of the real one is not there for the action's Composer. The
    /// genrule flow checks that the target directory is not under `/tmp`
    /// itself.
    fn new(standin: &StandIn) -> Machine {
        let target = env!("CARGO_TARGET_TMPDIR");
        let dir = tempfile::Builder::new()
            .prefix("sp-composer-")
            .tempdir_in(target);
        let machine = Machine {
            dir: dir.expect("a temp dir"),
            trap: Trap::set(),
        };
        for dir in [machine.home(), machine.cache()] {
            std::fs::create_dir(&dir).unwrap_or_else(|e| panic!("create {}: {e}", dir.display()));
        }
        let config = machine.home().join("config.json");
        std::fs::write(&config, home_config(&standin.origin())).expect("write config.json");
        machine
    }

    /// Canonical: a target directory may sit behind a symlink.
    fn root(&self) -> PathBuf {
        let root = self.dir.path().canonicalize();
        root.expect("a canonical directory")
    }

    fn home(&self) -> PathBuf {
        self.root().join("home")
    }

    fn cache(&self) -> PathBuf {
        self.root().join("cache")
    }

    /// What a Composer of this machine reads in place of the caller's own
    /// settings, for [`Cell::repo_env`] and for the developer's Composer:
    /// its home and its cache, the two names that say where a project
    /// keeps its files, which a shell may have moved, and the version of
    /// the project itself. Without that last one Composer asks git for it,
    /// and the developer's Composer runs under the target directory,
    /// inside the checkout of this repository: the `vendor/` tree it makes
    /// would name the branch and the commit of that checkout. With it
    /// Composer starts no git. The repository rule starts its Composer
    /// with all five. A build action sees the home alone, by the fixture's
    /// `.bazelrc`, which also turns the cache off there.
    fn env(&self) -> Vec<(String, String)> {
        let path = |dir: PathBuf| dir.to_string_lossy().into_owned();
        let pins = [
            ("COMPOSER_HOME", path(self.home())),
            ("COMPOSER_CACHE_DIR", path(self.cache())),
            ("COMPOSER", "composer.json".to_string()),
            ("COMPOSER_VENDOR_DIR", "vendor".to_string()),
            // What Composer gives a project it finds no version for.
            ("COMPOSER_ROOT_VERSION", "1.0.0".to_string()),
        ];
        pins.map(|(name, value)| (name.to_string(), value)).to_vec()
    }

    /// The developer's own Composer, outside Bazel: `composer <args>` in a
    /// new project directory that holds `files`. Gives the files of the
    /// project as the command left them, and what it printed. Every proxy
    /// is the [`Trap`], and nothing may have connected to it: the command
    /// sent no request to a host that is not loopback.
    fn composer(&self, test: &str, files: &[(&str, &[u8])], args: &[&str]) -> (Tree, String) {
        let project = tempfile::tempdir_in(self.root()).expect("a project directory");
        for (rel, bytes) in files {
            let path = project.path().join(rel);
            std::fs::create_dir_all(path.parent().expect("a file path")).expect("create a parent");
            std::fs::write(path, bytes).expect("write a project file");
        }
        let mut cmd = hermetic::tool_command("composer");
        hermetic::scrub_socket_vars(&mut cmd);
        hermetic::scrub_extra(&mut cmd, &[Extra::Composer]);
        cmd.args(args)
            .args(["--no-interaction", "--no-ansi"])
            .current_dir(project.path())
            .envs(self.env())
            .env("HOME", self.root());
        for proxy in ["HTTP_PROXY", "HTTPS_PROXY"] {
            cmd.env(proxy, &self.trap.address);
            cmd.env(proxy.to_ascii_lowercase(), &self.trap.address);
        }
        cmd.env("NO_PROXY", LOOPBACK).env("no_proxy", LOOPBACK);
        let line = format!("{cmd:?}");
        let out = cmd
            .output()
            .unwrap_or_else(|e| panic!("{test}: spawn {line}: {e}"));
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.status.success(), "{test}: {line}\n{said}");
        let beyond = self.trap.connections.load(Ordering::SeqCst);
        assert_eq!(
            beyond, 0,
            "{test}: Composer sent {beyond} requests beyond loopback:\n{line}\n{said}"
        );
        (read_tree(project.path()), said)
    }
}

/// The fixture's `composer.json` of `project`.
fn manifest(project: &str) -> Vec<u8> {
    let common = fixture_path(FIXTURE.dir).join("common");
    let path = common.join(project).join("composer.json");
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The root `BUILD.bazel` that makes `//:consumer`, the label the harness
/// builds, the consumer of `project`.
fn root_build(project: &str) -> String {
    format!("alias(\n    name = \"consumer\",\n    actual = \"//{project}:consumer\",\n)\n")
}

/// The path of a project's lock in the checkout.
fn lock_of(project: &str) -> String {
    format!("{project}/composer.lock")
}

/// One flow's start: the checkout, the stand-in its builds and commands
/// talk to, the Composer files of the machine, and the upstream package of
/// the run.
struct Flow {
    cell: Cell,
    standin: StandIn,
    machine: Machine,
    upstream: Upstream,
    /// [`tools`].
    tools: String,
}

/// The checkout of the fixture for `test`, with `//:consumer` as the
/// consumer of `project` and with what the developer's Composer made of
/// that project's `composer.json`, against a stand-in that holds the
/// upstream package of this run: `composer update <args>` writes the lock,
/// and without `--no-install` the `vendor/` tree beside it. Every URL of
/// the lock is the stand-in's. `None` after a `SKIP` line when no Bazel, no
/// PHP or no Composer runs here.
fn open(test: &str, project: &str, args: &[&str]) -> Option<Flow> {
    let tools = tools(test)?;
    let mut cell = Cell::open(test, &FIXTURE)?;
    println!("{test}: {tools}; the flows were run on {RAN_ON}");
    let upstream = Upstream::new();
    let standin = registry(&upstream);
    let machine = Machine::new(&standin);
    cell.repo_env = machine.env();
    cell.write("BUILD.bazel", root_build(project));

    let update = [&["update"][..], args].concat();
    let (made, _) = machine.composer(test, &[("composer.json", &manifest(project))], &update);
    let lock: Value = serde_json::from_slice(&made["composer.lock"]).expect("a JSON lock");
    assert_eq!(lock["packages"].as_array().map(Vec::len), Some(1), "{test}");
    let entry = &lock["packages"][0];
    for url in [&entry["dist"]["url"], &entry["source"]["url"]] {
        let ours = url.as_str().is_some_and(|url| {
            url.strip_prefix(&standin.origin())
                .is_some_and(|rest| rest.starts_with('/'))
        });
        assert!(ours, "{test}: the lock names {url}:\n{lock:#}");
    }
    for (rel, bytes) in made.iter().filter(|(rel, _)| *rel != "composer.json") {
        cell.write(&format!("{project}/{rel}"), bytes);
    }
    Some(Flow {
        cell,
        standin,
        machine,
        upstream,
        tools,
    })
}

/// `socket-patch <args> --cwd <project>` in `cell`, as a user in that
/// directory of the checkout runs it, with `standin` as the Socket API, as
/// the patch server (a hosted pin is recognised by that origin) and as the
/// registry `rollback` reads the upstream entry from.
fn socket_patch(cell: &Cell, standin: &StandIn, project: &str, args: &[&str]) -> Ran {
    socket_patch_with(cell, standin, project, args, &[])
}

/// [`socket_patch`] with the variables `more` set as well.
fn socket_patch_with(
    cell: &Cell,
    standin: &StandIn,
    project: &str,
    args: &[&str],
    more: &[(&str, &str)],
) -> Ran {
    let origin = standin.origin();
    let packagist = format!("{origin}/{PACKAGIST}");
    let env = [
        ("SOCKET_PATCH_SERVER_URL", origin.as_str()),
        ("SOCKET_PACKAGIST_URL", packagist.as_str()),
    ];
    let args = [args, &["--cwd", project][..]].concat();
    cell.socket_patch(&origin, &args, &[&env[..], more].concat())
}

/// What a command reports when its one event is about the package: that
/// event's `action` and error `code`, as `event_triples` reads them.
fn one(action: &str, code: &str) -> [(String, String, String); 1] {
    [(PURL.to_string(), action.to_string(), code.to_string())]
}

/// `vex` in `project`: the finished command, and the document it wrote,
/// which is empty when it wrote none. The document goes into the temp
/// directory of the machine, under a new name: it is no file of the
/// checkout.
fn vex(flow: &Flow, project: &str) -> (Ran, String) {
    let name = format!("vex-{}.json", uuid::Uuid::new_v4());
    let document = flow.machine.root().join(name);
    let output = document.to_string_lossy();
    let args = ["vex", "--output", &output, "--product", PRODUCT];
    let ran = socket_patch(&flow.cell, &flow.standin, project, &args);
    (ran, std::fs::read_to_string(&document).unwrap_or_default())
}

/// The second half of step (c): `vex` attests the package of `project` in
/// its document.
fn attested(flow: &Flow, project: &str) {
    let test = &flow.cell.test;
    let (vex, document) = vex(flow, project);
    let said = &vex.dump;
    assert_eq!(vex.code, 0, "{test}: {said}");
    let verified = one("verified", "");
    assert_eq!(event_triples(&vex.envelope), verified, "{test}: {said}");
    // With its closing quote, as the document writes `"@id": "<purl>"`.
    let names = document.contains(&format!("\"{PURL}\""));
    assert!(names, "{test}: {said}\n{document}");
}

/// Step (b) of a hosted flow: `scan --mode hosted --yes` in `project`
/// applies `patch` and rewrites the lock of the project, and no other file
/// of the checkout differs from `before`. The entry of the package has the
/// patched archive on the patch host as its `dist`, with the upstream
/// commit and the sha1 of the archive, and no `source`; the rest of the
/// lock says what it said. The scan fetched nothing from the patch host.
/// Gives the files of the checkout as the command left them.
fn pins(flow: &Flow, project: &str, patch: &Patched, before: &Tree) -> Tree {
    let (cell, standin) = (&flow.cell, &flow.standin);
    let fetches = standin.asked(&patch.route);
    let scan = socket_patch(
        cell,
        standin,
        project,
        &["scan", "--mode", "hosted", "--yes"],
    );
    let (test, said) = (&cell.test, &scan.dump);
    assert_eq!(scan.code, 0, "{test}: {said}");
    assert_eq!(scan.envelope["status"], "success", "{test}: {said}");
    assert_eq!(scan.envelope["summary"]["applied"], 1, "{test}: {said}");
    let event = event_for(&scan.envelope, PURL);
    assert_eq!(event["action"], "applied", "{test}: {said}");
    assert_eq!(event["uuid"], patch.uuid.as_str(), "{test}: {said}");
    // The command names the file as the project has it.
    let rewritten = &scan.envelope["redirect"]["rewrittenFiles"];
    assert_eq!(*rewritten, json!(["composer.lock"]), "{test}: {said}");
    let pinned = cell.tree();
    let lock = lock_of(project);
    assert_eq!(changed(before, &pinned), [lock.as_str()], "{test}: {said}");

    let parsed = |tree: &Tree| -> Value { serde_json::from_slice(&tree[&lock]).expect("a lock") };
    let mut expected = parsed(before);
    let entry = expected["packages"][0].as_object_mut().expect("an entry");
    entry.remove("source");
    entry["dist"] = json!({
        "type": "zip",
        "url": format!("{}{}", standin.origin(), patch.route),
        "reference": flow.upstream.reference,
        "shasum": hex::encode(Sha1::digest(&patch.package.archive)),
    });
    assert_eq!(parsed(&pinned), expected, "{test}: {lock}");
    assert_eq!(standin.asked(&patch.route), fetches, "{test}: {said}");
    pinned
}

/// Step (e) of a hosted flow: the build of `twin`, whose lock pins the
/// archive of `patch`, fails because Composer refuses what `standin` serves
/// at that URL. The build asked the patch host, so the failure is about
/// those bytes, and did not go to the upstream archive of `upstream`
/// instead.
fn refuses(twin: &Cell, standin: &StandIn, patch: &Patched, upstream: &Upstream) {
    let test = &twin.test;
    let (patched, pristine) = (
        standin.asked(&patch.route),
        standin.asked(&upstream.route()),
    );
    let build = twin.bazel("build", &[CONSUMER]);
    assert!(!build.ok(), "{test}: other bytes built:\n{}", build.dump());
    assert!(
        build.stderr().contains(REFUSAL),
        "{test}: the build did not fail with {REFUSAL:?}:\n{}",
        build.dump()
    );
    assert!(
        standin.asked(&patch.route) > patched,
        "{test}: the patch host was not asked, so the failed build proves nothing"
    );
    assert_eq!(
        standin.asked(&upstream.route()),
        pristine,
        "{test}: the build went to the upstream archive"
    );
}

/// What a host serves in place of the package of `patch`: still the
/// package, with another file and so another archive.
fn other_bytes(patch: &Patched) -> Package {
    Package::new("TAMPERED", &patch.uuid)
}

/// The hosted flow of the module docs for the project whose packages a
/// repository rule installs. It also records what a scan at the workspace
/// root does, and what a Composer cache that holds the patched archive
/// means for step (e).
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn hosted_repository_rule() {
    let test = "composer::hosted_repository_rule";
    let started = Instant::now();
    let Some(flow) = open(test, API, &["--no-install"]) else {
        return;
    };
    let (cell, standin, upstream) = (&flow.cell, &flow.standin, &flow.upstream);
    let release = cell.release().to_string();
    let origin = standin.origin();
    let patch = Patched::new();
    grant(standin, upstream, &patch, &patch.package);
    let lock = lock_of(API);

    // (a) The unpatched build: the repository rule ran Composer, which
    // fetched the upstream archive from the stand-in.
    let before = cell.builds_unpatched(&upstream.package.marker);
    let pristine_fetches = standin.asked(&upstream.route());
    assert!(
        pristine_fetches > 0,
        "{test}: the build did not fetch the upstream archive from the stand-in"
    );

    // At the workspace root a scan that prints JSON takes one project
    // directory, and the root is none: it patches nothing, writes nothing
    // and names the directory to scan.
    let args = ["scan", "--mode", "hosted", "--yes"];
    let at_root = cell.socket_patch(&origin, &args, &[]);
    let said = &at_root.dump;
    assert_eq!(at_root.code, 0, "{test}: {said}");
    assert_eq!(at_root.envelope["scannedPackages"], 0, "{test}: {said}");
    assert_eq!(at_root.envelope["summary"]["applied"], 0, "{test}: {said}");
    let warnings = &at_root.envelope["warnings"];
    assert_eq!(
        codes_in(warnings),
        ["projects_not_scanned"],
        "{test}: {said}"
    );
    let advice = format!("`socket-patch scan {API}`");
    let advised = warnings[0]["detail"].as_str().unwrap_or_default();
    assert!(advised.contains(&advice), "{test}: {said}");
    assert_eq!(changed(&before, &cell.tree()), NOTHING, "{test}: {said}");

    // (b) The one command of hosted mode, in the project.
    let pinned = pins(&flow, API, &patch, &before);

    // (c) The same build, no step in between: Bazel read the lock again,
    // the rule ran, and Composer fetched the patched archive.
    cell.builds_patched(&pinned, &patch.package.marker);
    assert!(
        standin.asked(&patch.route) > 0,
        "{test}: the patched build did not fetch the archive from the stand-in patch host"
    );
    assert_eq!(
        standin.asked(&upstream.route()),
        pristine_fetches,
        "{test}: the patched build fetched the upstream archive"
    );
    attested(&flow, API);

    // (d) The undo: every file is the one of before, and so is the build.
    let undo = socket_patch(cell, standin, API, &["rollback", "--yes"]);
    cell.undone(&undo, "rolledBack", &before, &upstream.package.marker);

    // (e) A second machine with the rewritten lock and an empty Composer
    // cache, and a patch host that serves other bytes at the pinned URL.
    let mut twin = cell.twin();
    let second = Machine::new(standin);
    twin.repo_env = second.env();
    twin.write(&lock, &pinned[&lock]);
    standin.serve(1, &patch.route, &other_bytes(&patch).archive);
    refuses(&twin, standin, &patch, upstream);

    // The same machine with the Composer cache of the first, which fetched
    // the patched archive in (c): Composer takes the archive from there
    // and does not ask the host, so the build is the patched one although
    // the host still serves other bytes.
    let fetches = standin.asked(&patch.route);
    twin.repo_env = flow.machine.env();
    twin.builds(&patch.package.marker);
    assert_eq!(
        standin.asked(&patch.route),
        fetches,
        "{test}: a Composer whose cache holds the archive asked the patch host"
    );

    println!(
        "{test}: Bazel {release} with {} built {:?} from {origin}{} after `scan --mode hosted \
         --cwd {API}`; the same scan at the workspace root patched nothing and named the \
         directory; `vex` attested the package; `rollback` restored all {} files and the {:?} \
         build; other bytes at the patch host failed a second machine's build ({REFUSAL}), and \
         with the first machine's Composer cache that machine built the patch without a request; \
         the stand-in answered {} requests for the upstream archive and {} for the patched one; \
         {:?}",
        flow.tools,
        patch.package.marker,
        patch.route,
        before.len(),
        upstream.package.marker,
        standin.asked(&upstream.route()),
        standin.asked(&patch.route),
        started.elapsed()
    );
}

/// The hosted flow of the module docs for the project whose packages a
/// genrule installs: here the lock is an input of a build action, and
/// Composer runs in that action. It also records what a relock does to the
/// pin.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn hosted_genrule() {
    let test = "composer::hosted_genrule";
    let started = Instant::now();
    let Some(flow) = open(test, WORKER, &["--no-install"]) else {
        return;
    };
    // The action's Composer finds the home of the machine by its path, and
    // on Linux Bazel's sandbox gives an action a `/tmp` of its own.
    let home = flow.machine.home();
    if cfg!(target_os = "linux") && home.starts_with("/tmp") {
        panic!(
            "{test}: the Composer home {} is under /tmp, where a build action in Bazel's Linux \
             sandbox does not see it: give cargo a target directory outside /tmp \
             (CARGO_TARGET_DIR)",
            home.display()
        );
    }
    let (cell, standin, upstream) = (&flow.cell, &flow.standin, &flow.upstream);
    let release = cell.release().to_string();
    let origin = standin.origin();
    let patch = Patched::new();
    grant(standin, upstream, &patch, &patch.package);
    let lock = lock_of(WORKER);

    // (a) The unpatched build: the action ran Composer, which fetched the
    // upstream archive from the stand-in.
    let before = cell.builds_unpatched(&upstream.package.marker);
    assert!(
        standin.asked(&upstream.route()) > 0,
        "{test}: the build did not fetch the upstream archive from the stand-in"
    );

    // (b) The one command of hosted mode, in the project.
    let pinned = pins(&flow, WORKER, &patch, &before);

    // (c) The same build, no step in between: the lock is an input of the
    // action, so it ran again, and Composer fetched the patched archive.
    cell.builds_patched(&pinned, &patch.package.marker);
    let patched_fetches = standin.asked(&patch.route);
    assert!(
        patched_fetches > 0,
        "{test}: the patched build did not fetch the archive from the stand-in patch host"
    );
    attested(&flow, WORKER);

    // A relock, as a developer runs one after a change to composer.json:
    // Composer resolves the package from the registry again and writes the
    // upstream entry over the pin, without a word about it. The lock is the
    // one of before, the build is the unpatched one, and `vex` has nothing
    // to attest.
    let files: [(&str, &[u8]); 2] = [
        ("composer.json", &manifest(WORKER)),
        ("composer.lock", &pinned[&lock]),
    ];
    let relock = ["update", "--lock", "--no-install"];
    let (relocked, said) = flow.machine.composer(test, &files, &relock);
    assert!(!said.contains(&patch.uuid), "{test}: {said}");
    cell.write(&lock, &relocked["composer.lock"]);
    assert_eq!(changed(&before, &cell.tree()), NOTHING, "{test}: {said}");
    cell.builds(&upstream.package.marker);
    let (unattested, document) = vex(&flow, WORKER);
    let said = &unattested.dump;
    assert_ne!(unattested.code, 0, "{test}: {said}");
    assert!(
        event_triples(&unattested.envelope).is_empty(),
        "{test}: {said}"
    );
    assert_eq!(document, "", "{test}: {said}");

    // The scan pins the package again, to the same bytes of the lock, and
    // the build is the patched one again.
    let again = pins(&flow, WORKER, &patch, &before);
    assert_eq!(changed(&pinned, &again), NOTHING, "{test}");
    cell.builds_patched(&pinned, &patch.package.marker);
    assert!(
        standin.asked(&patch.route) > patched_fetches,
        "{test}: the build after the second scan did not fetch the patched archive"
    );

    // (d) The undo: every file is the one of before, and so is the build.
    let undo = socket_patch(cell, standin, WORKER, &["rollback", "--yes"]);
    cell.undone(&undo, "rolledBack", &before, &upstream.package.marker);

    // (e) A second machine with the rewritten lock, and a patch host that
    // serves other bytes at the pinned URL. Composer keeps no cache in a
    // build action, so nothing stands between it and the host.
    let twin = cell.twin();
    twin.write(&lock, &pinned[&lock]);
    standin.serve(1, &patch.route, &other_bytes(&patch).archive);
    refuses(&twin, standin, &patch, upstream);

    println!(
        "{test}: Bazel {release} with {} built {:?} from {origin}{} after `scan --mode hosted \
         --cwd {WORKER}`; `vex` attested the package; `composer update --lock` dropped the pin, \
         the build printed {:?} and `vex` attested nothing, until a second scan pinned the same \
         bytes; `rollback` restored all {} files and the unpatched build; other bytes at the \
         patch host failed a second machine's build ({REFUSAL}); the stand-in answered {} \
         requests for the upstream archive and {} for the patched one; {:?}",
        flow.tools,
        patch.package.marker,
        patch.route,
        upstream.package.marker,
        before.len(),
        standin.asked(&upstream.route()),
        standin.asked(&patch.route),
        started.elapsed()
    );
}

/// The agent flow of the module docs, for the project that commits its
/// `vendor/` tree.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn agent_committed_vendor() {
    let test = "composer::agent_committed_vendor";
    let started = Instant::now();
    // The developer's Composer installs as well: the tree it makes is the
    // one the project commits.
    let Some(flow) = open(test, LEGACY, &[]) else {
        return;
    };
    let (cell, standin, upstream) = (&flow.cell, &flow.standin, &flow.upstream);
    let release = cell.release().to_string();
    let patch = Patched::new();
    grant(standin, upstream, &patch, &patch.package);
    let installed = format!("{LEGACY}/vendor/{NAME}/{FILE}");
    let ledger = format!("{LEGACY}/.socket/manifest.json");
    assert!(
        standin.asked(&upstream.route()) > 0,
        "{test}: Composer did not fetch the upstream archive from the stand-in"
    );

    // (a) The unpatched build, from the committed tree: Bazel asks no host.
    let requests = standin.requests();
    let before = cell.builds_unpatched(&upstream.package.marker);
    assert_eq!(
        before[&installed],
        upstream.package.source.as_bytes(),
        "{test}"
    );
    assert_eq!(standin.requests(), requests, "{test}: Bazel asked a host");
    // The committed tree is the same in every checkout of this repository:
    // the one commit that Composer's record of the tree names is the
    // package's. Composer did not ask git, which would have given it the
    // commit of the checkout around the target directory
    // ([`Machine::env`]).
    let record = format!("{LEGACY}/vendor/composer/installed.php");
    let record = String::from_utf8_lossy(&before[&record]);
    let quoted = record.lines().filter_map(|line| {
        let commit = line.trim().strip_prefix("'reference' => '")?;
        commit.strip_suffix("',")
    });
    let commits: Vec<&str> = quoted.collect();
    assert_eq!(commits, [upstream.reference.as_str()], "{test}: {record}");

    // (b) The one command of agent mode, in the project. It patches the
    // file of the package in place and keeps its record under `.socket`:
    // the manifest, and the file's content of before and after, each under
    // its git sha256. No other file of the checkout differs.
    let scan = socket_patch(cell, standin, LEGACY, &["scan", "--mode", "agent", "--yes"]);
    let said = &scan.dump;
    assert_eq!(scan.code, 0, "{test}: {said}");
    assert_eq!(scan.envelope["status"], "success", "{test}: {said}");
    assert_eq!(scan.envelope["summary"]["downloaded"], 1, "{test}: {said}");
    assert_eq!(scan.envelope["summary"]["applied"], 1, "{test}: {said}");
    let blob = |package: &Package| {
        let sum = compute_git_sha256_from_bytes(package.source.as_bytes());
        format!("{LEGACY}/.socket/blobs/{sum}")
    };
    let mut written = [
        blob(&upstream.package),
        blob(&patch.package),
        ledger.clone(),
        installed.clone(),
    ];
    written.sort();
    let patched = cell.tree();
    assert_eq!(changed(&before, &patched), written, "{test}: {said}");
    assert_eq!(
        patched[&installed],
        patch.package.source.as_bytes(),
        "{test}"
    );

    // (c) The same build, no step in between: patched, from the tree, and
    // again without a request. `apply`, the command a pipeline runs after
    // an install, finds the patch in place and changes nothing, and `vex`
    // attests the package from the file it hashes.
    let requests = standin.requests();
    cell.builds_patched(&patched, &patch.package.marker);
    assert_eq!(standin.requests(), requests, "{test}: Bazel asked a host");
    let apply = socket_patch(cell, standin, LEGACY, &["apply"]);
    let said = &apply.dump;
    assert_eq!(apply.code, 0, "{test}: {said}");
    let in_place = one("skipped", "already_patched");
    assert_eq!(event_triples(&apply.envelope), in_place, "{test}: {said}");
    assert_eq!(changed(&patched, &cell.tree()), NOTHING, "{test}: {said}");
    attested(&flow, LEGACY);

    // (d) The undo. The file of the package is the one of before, byte for
    // byte, and the blobs are gone. One file stays that was not there
    // before: the manifest, which now lists no patch. The build is the
    // unpatched one and changes no file.
    let undo = socket_patch(cell, standin, LEGACY, &["rollback", "--yes"]);
    let said = &undo.dump;
    assert_eq!(undo.code, 0, "{test}: {said}");
    assert_eq!(undo.envelope["summary"]["rolledBack"], 1, "{test}: {said}");
    let restored = cell.tree();
    assert_eq!(
        changed(&before, &restored),
        [ledger.as_str()],
        "{test}: {said}"
    );
    let left: Value = serde_json::from_slice(&restored[&ledger]).expect("a JSON manifest");
    assert_eq!(left, json!({ "patches": {} }), "{test}: {said}");
    cell.builds(&upstream.package.marker);
    assert_eq!(changed(&restored, &cell.tree()), NOTHING, "{test}");

    // (e) A second machine, and a patch service whose record of a second
    // patch carries other bytes than the hash it names. The scan refuses
    // the blob and writes nothing, so the build is the unpatched one. A
    // build of a committed tree checks no sum: this refusal is the check.
    let twin = cell.twin();
    let rogue = StandIn::start();
    let second = Patched::new();
    grant(&rogue, upstream, &second, &other_bytes(&second));
    let scan = socket_patch(&twin, &rogue, LEGACY, &["scan", "--mode", "agent", "--yes"]);
    let said = &scan.dump;
    assert_eq!(scan.code, 1, "{test}: {said}");
    assert_eq!(scan.envelope["status"], "partialFailure", "{test}: {said}");
    let refused = one("failed", "blob_write_failed");
    assert_eq!(event_triples(&scan.envelope), refused, "{test}: {said}");
    assert_eq!(changed(&restored, &twin.tree()), NOTHING, "{test}: {said}");
    twin.builds(&upstream.package.marker);

    println!(
        "{test}: Bazel {release} with {} built {:?} from {installed} after `scan --mode agent \
         --cwd {LEGACY}`, with no request to the stand-in; `apply` found the patch in place and \
         `vex` attested the package; `rollback` restored the file and the {:?} build and left \
         {ledger} with no patch; a patch service that served another blob was refused \
         (blob_write_failed) and a second machine's build stayed unpatched; {:?}",
        flow.tools,
        patch.package.marker,
        upstream.package.marker,
        started.elapsed()
    );
}

/// The one command of vendored mode.
const VENDORED: [&str; 4] = ["scan", "--mode", "vendored", "--yes"];

/// Vendored mode where it declines: `socket-patch <args>` in `project`
/// ends with `code` and reports the package under [`DECLINED`], as the one
/// event `action`, in words that name hosted mode and the flag. No file of
/// the checkout differs from `before`. Gives the finished command.
fn declines(
    flow: &Flow,
    project: &str,
    args: &[&str],
    code: i32,
    action: &str,
    before: &Tree,
) -> Ran {
    let (cell, standin) = (&flow.cell, &flow.standin);
    let ran = socket_patch(cell, standin, project, args);
    let (test, said) = (&cell.test, &ran.dump);
    assert_eq!(ran.code, code, "{test}: {said}");
    let declined = one(action, DECLINED);
    assert_eq!(event_triples(&ran.envelope), declined, "{test}: {said}");
    let event = event_for(&ran.envelope, PURL);
    let why = event["error"].as_str().or(event["reason"].as_str());
    let why = why.unwrap_or_default();
    let named = ["`--mode hosted`", &format!("`{ALLOW}`")];
    assert!(
        named.iter().all(|part| why.contains(part)),
        "{test}: {said}"
    );
    assert_eq!(changed(before, &cell.tree()), NOTHING, "{test}: {said}");
    ran
}

/// Where vendored mode keeps the copy of the package for `patch`, as the
/// lock names it: a path from the directory Composer runs in.
fn copy_of(patch: &Patched) -> String {
    format!(".socket/vendor/composer/{}/{NAME}@{VERSION}", patch.uuid)
}

/// Vendored mode where it goes on: `scan --mode vendored --yes <allow>` in
/// `project` vendors `patch`. It keeps the patched package under the
/// project's `.socket/vendor`, with its ledger, and rewrites the lock, and
/// no other file of the checkout differs from `before`. The entry of the
/// package has that copy as its `dist`, by the relative path of
/// [`copy_of`] and under the id of the patch, to be copied and never
/// linked, and no `source`; the rest of the lock says what it said. Gives
/// the files of the checkout as the command left them.
fn vendors(flow: &Flow, project: &str, patch: &Patched, before: &Tree, allow: &[&str]) -> Tree {
    let (cell, standin) = (&flow.cell, &flow.standin);
    let args = [&VENDORED[..], allow].concat();
    let scan = socket_patch(cell, standin, project, &args);
    let (test, said) = (&cell.test, &scan.dump);
    assert_eq!(scan.code, 0, "{test}: {said}");
    assert_eq!(scan.envelope["status"], "success", "{test}: {said}");
    assert_eq!(scan.envelope["summary"]["applied"], 1, "{test}: {said}");
    let event = event_for(&scan.envelope, PURL);
    assert_eq!(event["uuid"], patch.uuid.as_str(), "{test}: {said}");
    let events = ["downloaded", "applied", "skipped"].map(|action| {
        let code = if action == "skipped" {
            "vendor_prebuilt_downloaded"
        } else {
            ""
        };
        (PURL.to_string(), action.to_string(), code.to_string())
    });
    assert_eq!(event_triples(&scan.envelope), events, "{test}: {said}");
    let vendored = cell.tree();
    let lock = lock_of(project);
    let kept = format!("{project}/.socket/vendor");
    let copy = format!("{project}/{}", copy_of(patch));
    let mut written = vec![
        format!("{kept}/composer/{}/socket-patch.vendor.json", patch.uuid),
        format!("{copy}/composer.json"),
        format!("{copy}/{FILE}"),
        format!("{kept}/state.json"),
        lock.clone(),
    ];
    written.sort();
    assert_eq!(changed(before, &vendored), written, "{test}: {said}");
    let patched = patch.package.source.as_bytes();
    assert_eq!(vendored[&format!("{copy}/{FILE}")], patched, "{test}");

    let parsed = |tree: &Tree| -> Value { serde_json::from_slice(&tree[&lock]).expect("a lock") };
    let mut expected = parsed(before);
    let entry = expected["packages"][0].as_object_mut().expect("an entry");
    entry.remove("source");
    entry["dist"] = json!({ "type": "path", "url": copy_of(patch), "reference": patch.uuid });
    entry.insert("transport-options".to_string(), json!({ "symlink": false }));
    assert_eq!(parsed(&vendored), expected, "{test}: {lock}");
    vendored
}

/// Vendored mode in the project whose packages a repository rule
/// installs. The lock would name the copy by a path from the directory
/// Composer runs in, and the rule runs Composer in a repository of Bazel's
/// that holds the two Composer files and nothing else. So the command
/// declines: it writes nothing, and the build stays the one of before.
/// Hosted mode, which the refusal names, patches that build. With the flag
/// the command does what it did before the refusal was there: it reports
/// the package vendored, the build fails, and `vex` attests the package
/// all the same. `vendor --revert`, which takes no flag, puts every file
/// back, and the build with them.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn vendored_repository_rule() {
    let test = "composer::vendored_repository_rule";
    let started = Instant::now();
    let Some(flow) = open(test, API, &["--no-install"]) else {
        return;
    };
    let (cell, standin, upstream) = (&flow.cell, &flow.standin, &flow.upstream);
    let release = cell.release().to_string();
    let patch = Patched::new();
    grant(standin, upstream, &patch, &patch.package);

    // (a) The unpatched build.
    let before = cell.builds_unpatched(&upstream.package.marker);

    // (b) The one command of vendored mode, in the project: declined, with
    // nothing written and nothing of the patch fetched.
    declines(&flow, API, &VENDORED, 1, "failed", &before);
    assert_eq!(standin.asked(&patch.route), 0, "{test}");

    // (c) The same build passes, on the upstream package.
    cell.builds_patched(&before, &upstream.package.marker);

    // The remedy the refusal names: hosted mode patches the build, and its
    // undo puts every file back.
    let pinned = pins(&flow, API, &patch, &before);
    cell.builds_patched(&pinned, &patch.package.marker);
    let undo = socket_patch(cell, standin, API, &["rollback", "--yes"]);
    cell.undone(&undo, "rolledBack", &before, &upstream.package.marker);

    // With the flag the package is vendored, and the same build fails:
    // Composer finds no copy where the rule runs it.
    vendors(&flow, API, &patch, &before, &[ALLOW]);
    let build = cell.bazel("build", &[CONSUMER]);
    assert!(!build.ok(), "{test}: the build passed:\n{}", build.dump());
    let copy = copy_of(&patch);
    let missing = format!("Source path \"{copy}\" is not found for package {NAME}");
    // Composer breaks the message into lines of its console's width, inside
    // a word too, so the two are compared without white space.
    let squeezed = |text: &str| text.split_whitespace().collect::<String>();
    assert!(
        squeezed(&build.stderr()).contains(&squeezed(&missing)),
        "{test}: the build did not fail with {missing:?}:\n{}",
        build.dump()
    );
    attested(&flow, API);

    // (d) The undo: every file is the one of before, and so is the build.
    let undo = socket_patch(cell, standin, API, &["vendor", "--revert"]);
    cell.undone(&undo, "removed", &before, &upstream.package.marker);

    println!(
        "{test}: Bazel {release} with {}: `scan --mode vendored --cwd {API}` declined \
         ({DECLINED}), wrote nothing, and the build stayed {:?}; `scan --mode hosted` built \
         {:?} and `rollback` restored all {} files; with {ALLOW} the package was vendored and \
         the next build failed (Composer: {missing}) while `vex` attested the package; `vendor \
         --revert` restored the files and the build; {:?}",
        flow.tools,
        upstream.package.marker,
        patch.package.marker,
        before.len(),
        started.elapsed()
    );
}

/// Vendored mode in the project that commits its `vendor/` tree. The
/// command declines it like any project in a Bazel workspace: the tree
/// does not show that no rule of the workspace runs Composer somewhere
/// else as well. Here none does, and Composer runs in the project's
/// directory, so with the flag the path the lock names leads to the copy.
/// The build reads the committed tree and stays the unpatched one until
/// the developer's `composer install` has copied the package from
/// `.socket/vendor`; then it is the patched one.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn vendored_committed_vendor() {
    let test = "composer::vendored_committed_vendor";
    let started = Instant::now();
    let Some(flow) = open(test, LEGACY, &[]) else {
        return;
    };
    let (cell, standin, upstream) = (&flow.cell, &flow.standin, &flow.upstream);
    let release = cell.release().to_string();
    let patch = Patched::new();
    grant(standin, upstream, &patch, &patch.package);

    // (a) The unpatched build, from the committed tree.
    let before = cell.builds_unpatched(&upstream.package.marker);

    // (b) The one command of vendored mode, in the project: declined, with
    // nothing written. With the flag it vendors the package.
    declines(&flow, LEGACY, &VENDORED, 1, "failed", &before);
    let vendored = vendors(&flow, LEGACY, &patch, &before, &[ALLOW]);

    // (c) The same build passes and is the unpatched one: Bazel reads the
    // tree, which no command has touched.
    cell.builds_patched(&vendored, &upstream.package.marker);
    // The developer installs from the lock, in the project's directory:
    // Composer copies the package from `.socket/vendor`, with no request
    // to a host, and the build is the patched one.
    let prefix = format!("{LEGACY}/");
    let project: Vec<(&str, &[u8])> = vendored
        .iter()
        .filter_map(|(path, bytes)| Some((path.strip_prefix(&prefix)?, bytes.as_slice())))
        .collect();
    let requests = standin.requests();
    let (installed, said) = flow.machine.composer(test, &project, &["install"]);
    assert_eq!(standin.requests(), requests, "{test}: {said}");
    for (rel, bytes) in &installed {
        cell.write(&format!("{LEGACY}/{rel}"), bytes);
    }
    let copied = format!("{LEGACY}/vendor/{NAME}/{FILE}");
    let reinstalled = cell.tree();
    assert_eq!(
        reinstalled[&copied],
        patch.package.source.as_bytes(),
        "{test}: {said}"
    );
    cell.builds_patched(&reinstalled, &patch.package.marker);

    // (d) The undo: the lock is the one of before and `.socket/vendor` is
    // gone. The tree keeps what Composer installed, as in any project,
    // until the developer installs again.
    let undo = socket_patch(cell, standin, LEGACY, &["vendor", "--revert"]);
    let said = &undo.dump;
    assert_eq!(undo.code, 0, "{test}: {said}");
    let reverted = cell.tree();
    let lock = lock_of(LEGACY);
    assert_eq!(reverted[&lock], before[&lock], "{test}: {said}");
    let kept = format!("{LEGACY}/.socket/vendor/");
    let left: Vec<&String> = reverted
        .keys()
        .filter(|path| path.starts_with(&kept))
        .collect();
    assert!(left.is_empty(), "{test}: {left:?}\n{said}");

    println!(
        "{test}: Bazel {release} with {}: `scan --mode vendored --cwd {LEGACY}` declined \
         ({DECLINED}) and wrote nothing; with {ALLOW} it vendored the package into {} and the \
         build stayed {:?}; after the developer's `composer install` it built {:?} from \
         {copied}; `vendor --revert` restored {lock} and removed the copy; {:?}",
        flow.tools,
        copy_of(&patch),
        upstream.package.marker,
        patch.package.marker,
        started.elapsed()
    );
}

/// Without a Bazel, a PHP or a Composer: a checkout whose project [`API`]
/// has a lock that pins the upstream package of a stand-in, with the files
/// `marks` at the root of the checkout, which make it a Bazel workspace
/// when one has a name of Bazel's, and a patch of the package that the
/// stand-in grants.
fn checkout(marks: &[&str]) -> (Flow, Patched) {
    let cell = cell_without_bazel("9.3.2");
    let (upstream, patch) = (Upstream::new(), Patched::new());
    let standin = registry(&upstream);
    grant(&standin, &upstream, &patch, &patch.package);
    cell.write(".git/HEAD", "ref: refs/heads/main\n");
    for mark in marks {
        cell.write(mark, "");
    }
    cell.write(&format!("{API}/composer.json"), manifest(API));
    let entry = metadata(&standin.origin(), &upstream);
    let lock = json!({ "packages": [entry], "packages-dev": [] });
    cell.write(&lock_of(API), format!("{lock:#}\n"));
    let flow = Flow {
        machine: Machine::new(&standin),
        cell,
        standin,
        upstream,
        tools: String::new(),
    };
    (flow, patch)
}

/// Without a Bazel: in a Bazel workspace every command that would vendor
/// the package declines the project and writes nothing: the scan, `get`,
/// `vendor` for a patch the manifest records and, where the package is
/// pinned hosted, the scan that would take the pin over and the `vendor`
/// that would eject it, so the pin stays. A dry run of the scan names the
/// refusal and passes; one of `vendor` fails as its run does. No command
/// fetches the patched archive.
#[test]
fn every_command_that_would_vendor_declines_a_project_in_a_bazel_workspace() {
    let (flow, patch) = checkout(&["MODULE.bazel"]);
    let (cell, standin) = (&flow.cell, &flow.standin);
    let before = cell.tree();
    let get = ["get", PURL, "--mode", "vendored", "--yes"];
    let dry_run = [&VENDORED[..], &["--dry-run"]].concat();
    declines(&flow, API, &VENDORED, 1, "failed", &before);
    declines(&flow, API, &get, 1, "failed", &before);
    declines(&flow, API, &dry_run, 0, "skipped", &before);

    let record = ["get", PURL, "--save-only", "--yes"];
    let saved = socket_patch(cell, standin, API, &record);
    assert_eq!(saved.code, 0, "{}", saved.dump);
    let vendor = [["vendor", "--yes"], ["vendor", "--dry-run"]];
    for vendor in &vendor {
        declines(&flow, API, vendor, 1, "failed", &cell.tree());
    }
    std::fs::remove_dir_all(cell.path(&format!("{API}/.socket"))).expect("remove .socket");

    // The eject is refused whole, before it restores a pin or asks the
    // service for a record, and so is its dry run.
    let pinned = pins(&flow, API, &patch, &before);
    declines(&flow, API, &VENDORED, 1, "failed", &pinned);
    for eject in &vendor {
        let asked = standin.requests();
        let eject = declines(&flow, API, eject, 1, "failed", &pinned);
        assert_eq!(standin.requests(), asked, "{}", eject.dump);
        let refused = &eject.envelope["error"]["code"];
        assert_eq!(*refused, "eject_refused", "{}", eject.dump);
        let why = event_for(&eject.envelope, PURL)["error"].as_str();
        let kept = why.is_some_and(|why| why.starts_with("kept hosted: "));
        assert!(kept, "{}", eject.dump);
    }
    assert_eq!(standin.asked(&patch.route), 0);
}

/// Without a Bazel: vendored mode goes on as before in a project that is
/// in no Bazel workspace, and in one on the user's word, the flag or its
/// variable. A later run without the flag passes and writes nothing: the
/// lock already names the copy of that patch, so the run is in sync, and
/// so is a scan that names no mode, which runs in vendored mode in a
/// vendored project. `vendor --revert` takes no flag: it puts every file
/// back.
#[test]
fn vendored_mode_goes_on_outside_bazel_and_on_the_users_word() {
    let (flow, patch) = checkout(&["BUILD.bazel"]);
    vendors(&flow, API, &patch, &flow.cell.tree(), &[]);

    let (flow, patch) = checkout(&["WORKSPACE"]);
    let (cell, standin) = (&flow.cell, &flow.standin);
    let before = cell.tree();
    let reverts = |why: &str| {
        let undo = socket_patch(cell, standin, API, &["vendor", "--revert", "--yes"]);
        assert_eq!(undo.code, 0, "{why}: {}", undo.dump);
        assert_eq!(changed(&before, &cell.tree()), NOTHING, "{why}");
    };
    let by_variable = socket_patch_with(cell, standin, API, &VENDORED, &[(ALLOW_ENV, "1")]);
    let said = &by_variable.dump;
    assert_eq!(by_variable.code, 0, "{said}");
    assert_eq!(by_variable.envelope["summary"]["applied"], 1, "{said}");
    reverts(ALLOW_ENV);
    let vendored = vendors(&flow, API, &patch, &before, &[ALLOW]);
    for in_sync in [&VENDORED[..], &["scan", "--yes"]] {
        let again = socket_patch(cell, standin, API, in_sync);
        let said = &again.dump;
        assert_eq!(again.code, 0, "{in_sync:?}: {said}");
        assert_eq!(again.envelope["status"], "success", "{in_sync:?}: {said}");
        let refused = said.contains(DECLINED);
        assert!(!refused, "{in_sync:?}: {said}");
        assert_eq!(changed(&vendored, &cell.tree()), NOTHING, "{in_sync:?}");
    }
    reverts(ALLOW);
}

/// Without a Bazel: a project that a release before the refusal vendored,
/// in a checkout with a Bazel workspace file that no Bazel builds it from.
/// Its lock names the copy of the patch of then. A newer patch of the
/// package is declined, by the scan in vendored mode and by the scan that
/// names no mode, which such a pipeline runs: each exits 1 where it exited
/// 0, writes nothing and fetches nothing, and the older copy stays.
#[test]
fn a_project_vendored_by_an_earlier_release_is_declined_a_newer_patch() {
    let (flow, newer) = checkout(&[]);
    let (cell, upstream) = (&flow.cell, &flow.upstream);
    let older = Patched::new();
    let then = registry(upstream);
    grant(&then, upstream, &older, &older.package);
    let earlier = socket_patch(cell, &then, API, &VENDORED);
    assert_eq!(earlier.code, 0, "{}", earlier.dump);
    cell.write("MODULE.bazel", "");
    let vendored = cell.tree();
    let lock: Value = serde_json::from_slice(&vendored[&lock_of(API)]).expect("a lock");
    assert_eq!(lock["packages"][0]["dist"]["url"], copy_of(&older).as_str());

    for scan in [&VENDORED[..], &["scan", "--yes"]] {
        declines(&flow, API, scan, 1, "failed", &vendored);
    }
    assert_eq!(flow.standin.asked(&newer.route), 0);
}

/// Without a Bazel: a regular file named `workspace`, in lower case, at
/// the root of a checkout that has no Bazel file. On a disk that folds
/// case it is what a lookup of `WORKSPACE` finds, and vendored mode
/// declines the project; on a disk that does not, the project is vendored.
/// The test asks the disk which of the two it runs on and says so.
#[test]
fn a_file_named_workspace_in_lower_case_declines_where_the_disk_folds_case() {
    let (flow, patch) = checkout(&["workspace"]);
    let before = flow.cell.tree();
    let folds = flow.cell.path("WORKSPACE").is_file();
    if folds {
        declines(&flow, API, &VENDORED, 1, "failed", &before);
    } else {
        vendors(&flow, API, &patch, &before, &[]);
    }
    let ran = ["does not fold case: vendored", "folds case: declined"][usize::from(folds)];
    println!("a file named `workspace`: the disk {ran}");
}

/// Without a Bazel, a PHP or a Composer: the fixture's directories and the
/// legs of its workflow are those of its table. The fixture commits no
/// lock, no `vendor/` tree and no root `BUILD.bazel`: the run makes them.
/// The `composer.json` of each project requires the package at the version
/// the tests serve and says nothing else: it names no repository, which
/// `rollback` needs to take the registry's word for the upstream entry. A
/// Composer home of the tests knows the stand-in's registry and not the
/// public one, and is what allows plain http. Two runs serve two upstream
/// archives under two commits, and the names written out above are those
/// of the one package.
#[test]
fn the_fixture_leaves_the_lock_and_the_tree_to_the_run() {
    FIXTURE.check();
    let common = fixture_path(FIXTURE.dir).join("common");
    assert!(!common.join("BUILD.bazel").exists());
    for project in PROJECTS {
        for made in ["composer.lock", "vendor"] {
            let path = common.join(project).join(made);
            assert!(!path.exists(), "{}", path.display());
        }
        let manifest: Value = serde_json::from_slice(&manifest(project)).expect("composer.json");
        assert_eq!(
            manifest,
            json!({ "require": { NAME: VERSION } }),
            "{project}"
        );
        let build = format!("actual = \"//{project}:consumer\"");
        assert!(root_build(project).contains(&build), "{project}");
    }

    let config: Value = serde_json::from_str(&home_config("http://127.0.0.1:1")).expect("JSON");
    let stand_in = json!({ "type": "composer", "url": "http://127.0.0.1:1/repo.packagist.org" });
    let repositories = json!({ "packagist.org": false, "stand-in": stand_in });
    let settings = json!({ "secure-http": false });
    assert_eq!(
        config,
        json!({ "config": settings, "repositories": repositories })
    );

    let (one, other) = (Upstream::new(), Upstream::new());
    assert_ne!(one.package.archive, other.package.archive);
    assert_ne!(one.reference, other.reference);
    assert_eq!(one.reference.len(), 40);
    let entry = metadata("http://127.0.0.1:1", &one);
    let archive = format!(
        "http://127.0.0.1:1/api.github.com/repos/{NAME}/zipball/{}",
        one.reference
    );
    assert_eq!(entry["dist"]["url"], archive.as_str());

    let package: Value = serde_json::from_str(MANIFEST).expect("the package's composer.json");
    assert_eq!(package["name"], NAME);
    assert_eq!(PURL, format!("pkg:composer/{NAME}@{VERSION}"));
    let bare = NAME.strip_prefix("socketsecurity/").expect("the vendor");
    assert_eq!(ZIP, format!("{bare}-{VERSION}.zip"));
    assert!(TOP.starts_with(&NAME.replace('/', "-")));
}

/// Without a PHP or a Composer: the release is read from what each of them
/// prints, on the machines of the workflow and on a developer's.
#[test]
fn a_tool_release_is_read_from_what_the_tool_prints() {
    let [(_, _, php, _), (_, _, composer, _)] = TOOLS;
    for (printed, prefix, numbers) in [
        (
            "PHP 8.4.23 (cli) (built: Jul  7 2026) (NTS)\n",
            php,
            Some((8, 4, 23)),
        ),
        (
            "PHP 8.3.6-0ubuntu0.24.04.2 (cli)\nCopyright\n",
            php,
            Some((8, 3, 6)),
        ),
        (
            "Composer version 2.11.2 2026-11-10 10:09:37\n",
            composer,
            Some((2, 11, 2)),
        ),
        (
            "Warning: root\nComposer version 1.10.28 2025\n",
            composer,
            Some((1, 10, 28)),
        ),
        ("Composer version 2.11.2\n", php, None),
        ("PHP 8.x\n", php, None),
        ("", composer, None),
    ] {
        assert_eq!(release(printed, prefix), numbers, "{printed:?}");
    }
}

/// Without a PHP or a Composer: a tool below its floor of [`TOOLS`] is a
/// tool that is not there, and the reason names the release, the floor and
/// the releases the flows were run on.
#[test]
fn a_tool_below_its_floor_is_a_tool_that_is_not_there() {
    let [(_, _, prefix, oldest), _] = TOOLS;
    let usable = |printed: &str| usable("php --version", printed, prefix, oldest);
    assert_eq!(usable("PHP 8.3.6-0ubuntu0.24.04.2 (cli)\n"), Ok((8, 3, 6)));
    assert_eq!(usable("PHP 7.2.5 (cli)\n"), Ok(oldest));
    let why = usable("PHP 7.2.4 (cli)\n").expect_err("below the floor");
    let named = ["`php --version` says 7.2.4", "need 7.2.5 or later", RAN_ON];
    assert!(named.iter().all(|part| why.contains(part)), "{why}");
    let why = usable("sh: php: not found\n").expect_err("no PHP");
    assert_eq!(why, "`php --version` did not run: sh: php: not found\n");
}

/// Without a Bazel: the workflow names the product files of the flows one
/// by one, and a path that names no file would start no run.
#[test]
fn the_workflow_names_files_that_exist() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let workflow = root.join(".github/workflows").join(FIXTURE.workflow);
    let text = std::fs::read_to_string(&workflow).expect("the workflow");
    let listed = text
        .lines()
        .filter_map(|line| line.trim().strip_prefix("- '")?.strip_suffix('\''));
    let files: Vec<&str> = listed.filter(|path| !path.contains('*')).collect();
    assert!(!files.is_empty(), "{}", workflow.display());
    for path in files {
        assert!(root.join(path).is_file(), "{}: {path}", workflow.display());
    }
}
