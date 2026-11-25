//! A Maven artifact that Bazel builds through a rules_jvm_external hub:
//! `maven.install(artifacts = [...], lock_file = "//:maven_install.json")`
//! under Bzlmod, pinned with the ruleset's own `REPIN=1 bazel run
//! @fixture_maven//:pin`.
//!
//! Such a hub fetches each jar its lock names, with the sha256 the lock
//! holds, through a repository of its own, and reads no `pom.xml` and no
//! Gradle file. Hosted mode patches it with one block at the end of the
//! root `MODULE.bazel`: a repository that downloads the patched jar at
//! its sha256, and Bazel's `override_repo` of the hub's one. These flows
//! hold that on the Bazel the run is given ([`FIXTURE`] says which ruleset
//! goes with its release):
//!
//! - [`a_tree_only_bazel_builds`]: a checkout without a `pom.xml`.
//!   `socket-patch get <purl> --mode hosted --yes` reports the patch
//!   `applied` and rewrites `MODULE.bazel` alone, which is then the file of
//!   before with the block of [`block`] after one blank line. The same
//!   build prints the marker of the patched jar, which Bazel fetched from
//!   the patch host; a `--lockfile_mode=error` build passes; the
//!   ruleset's relock leaves the lock as it is; `bazel mod tidy` leaves
//!   the file as it is; `rollback --yes` puts every file back
//!   byte for byte, and the upstream build with them. A second machine
//!   gets a patch whose host serves other bytes than the patch pins: its
//!   build fails on the sha256 and never goes to the upstream jar. On a
//!   Bazel before 7.5.0 the checkout first has no `.bazelversion`: the
//!   command then writes nothing and says so (`maven_bazel_release`).
//! - [`a_hosted_scan_of_a_tree_only_bazel_builds`]: the same checkout, and
//!   `socket-patch scan --mode hosted --yes` in the place of the `get`. The
//!   two jars of the hub's lock are its packages, neither of them
//!   installed where a crawl looks; it finds the patch of the victim and
//!   writes the same block. The build is patched, a second scan writes
//!   nothing, and `rollback --yes` restores every file.
//! - [`a_pom_patch_beside_a_pinned_hub`]: a checkout that Maven builds
//!   too. The one command pins both builds: the three files of a Maven pin
//!   and `MODULE.bazel`. The Bazel build is patched, and `rollback --yes`
//!   restores every file.
//! - [`a_version_bump_of_the_patched_artifact`]: after the command the
//!   checkout asks for the artifact one version up and pins again, which
//!   passes. The build then stops at the line of the entry's
//!   `override_repo(`, where the block says what to run. `socket-patch
//!   rollback <purl> --yes` takes the entry out, and the build takes the
//!   new upstream jar. The API has a patch of that release too: a hosted
//!   `scan` of the checkout with the stale entry takes the entry out,
//!   reads the release from the lock, pins that patch, and the build
//!   takes its jar.
//! - [`the_users_own_override_of_the_artifact`]: the hub has a
//!   `maven.override` that puts a target of the checkout in the artifact's
//!   place. The command writes nothing and names the override's line
//!   (`maven_bazel_no_effect`), and the build prints that target's marker
//!   before and after.
//!
//! - [`a_vendored_patch_in_a_tree_only_bazel_builds`]: vendored mode in the
//!   checkout without a `pom.xml`. `socket-patch get <purl> --mode vendored
//!   --yes` downloads the patched jar once, from Socket's patch service,
//!   and commits it: the jar and the two files that make its directory a
//!   Bazel repository under `.socket/vendor/maven/<patch id>`, the block of
//!   [`vendored_block`] in `MODULE.bazel`, which puts that directory in the
//!   place of the hub's repository, the directory's line in `.bazelignore`
//!   and the vendor ledger. The same build prints the marker of the patched
//!   jar and asks no host for it; `bazel query //...` lists no package
//!   under `.socket`; a `--lockfile_mode=error` build passes; `vex` attests
//!   the patch. `vendor --check` passes, and fails for a committed jar
//!   that is not the patched one, which Bazel builds all the same: nothing
//!   checks a directory at build time. A second machine, with the
//!   stand-in stopped, builds the patched jar from the checkout alone, and
//!   the repository cache holds no copy of it. `vendor --revert` puts
//!   every file back byte for byte, and the upstream build with them.
//! - [`a_hub_goes_from_hosted_to_vendored_and_back`]: after the hosted
//!   command, `socket-patch vendor` puts the vendored entry in the place
//!   of the hosted one, and the build takes the jar of the checkout; the
//!   hosted command then takes the vendored entry, its directory and its
//!   ledger entry out again, and the checkout is the one the first hosted
//!   command left; `rollback` undoes a vendored patch to the byte.
//! - [`an_agent_patch_beside_a_pinned_hub`]: agent mode in a checkout that
//!   Maven builds too. `scan --mode agent --yes` puts the patched jar in
//!   the Maven local repository and patches no hub: the build prints the
//!   upstream marker before and after, and the document of the run, of
//!   `apply`, of `vex` and of `vex --no-verify` says that the artifact is
//!   affected, with the lock and the `maven.install` Bazel builds it from
//!   and the command that patches the hub. After that command, the hosted
//!   one, the build prints the marker of the patched jar and `vex` says
//!   not affected.
//!
//! A command that writes the block gives no warning. One that does not
//! gives one, in the place of "no pom.xml", with the reason and the words
//! that the Bazel build keeps the upstream jar. The lock each ruleset
//! release writes is the one socket-patch reads ([`Lock`]).
//!
//! The artifacts are made here, for the run, under the group
//! `dev.socket.fixture`, which only the owner of `socket.dev` can publish
//! to Maven Central: `consumer:2.0`, the one artifact `MODULE.bazel` names,
//! and `victim:1.10.0`, which `consumer` depends on and the patch is for.
//! The victim's jar holds one file, the text `//:consumer` prints after
//! `OUT: `, with an id of the run in it, so no cache of an earlier run can
//! supply the jar. No lock is committed: a flow writes its stand-in's
//! origin into `MODULE.bazel` in the place of the hub's one repository
//! and pins, so the lock is the one the ruleset of the era writes (format
//! 3 from rules_jvm_external 6.10, format 2 before).
//!
//! One loopback server stands in for three hosts, by route prefix: the
//! Socket API at its own paths, the Maven repository of the two artifacts
//! (`/maven2`), and `patch.socket.dev` with the patched jar at the path of
//! the production patch registry. The pin runs Coursier, which the ruleset
//! starts and which asks the stand-in alone; the build fetches each jar
//! with Bazel's downloader from the URL in the lock, and the patched jar
//! from the URL in the block, which names the patch host as production
//! does: a downloader config, given on the command line as a machine
//! behind a mirror has it, sends that host to the stand-in and refuses
//! every other URL of it.
//!
//! No pin and no build asks a public Maven repository. The hub is named
//! [`HUB`], not `maven`: other Bazel modules of the build add artifacts of
//! their own to a hub named `maven` (protobuf does), which a pin would
//! resolve from Maven Central, and nothing but the fixture adds to this
//! one. Its one repository is the stand-in, and [`Pinned::open`] holds
//! that the lock names the two artifacts and that repository, and nothing
//! else. A hub of the default name, whose lock also holds what other
//! modules added, is read without a Bazel in `e2e_bazel_maven_beside.rs`.
//!
//! What the stand-in lacks still comes from the network: the Bazel
//! registry, the ruleset archives, Coursier itself and the JDK that
//! rules_java downloads (each era's `.bazelrc` names the one its rules_java
//! runs javac on, so a build takes no Java from the machine and downloads
//! one JDK). rules_jvm_external before 6.8 (era `e7`) runs Coursier with
//! the Java of `JAVA_HOME`, else the `java` on `PATH`; later ones use the
//! Java embedded in Bazel.

use std::io::Write as _;
use std::path::Path;
use std::time::Instant;

use base64::Engine as _;

use serde_json::{json, Value};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use socket_patch_core::bazel::maven::{Lock, Pinned as Jar};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes as git_sha256;

use crate::envelope::{codes_in, event_for, event_triples};
use crate::harness::{
    cell_without_bazel, changed, fixture_path, rewrite, with_vex, Cell, Claim, Fixture, How, Ran,
    StandIn, Tree, CONSUMER, NOTHING,
};
use crate::hosted_memory_common::{Patch, ORG};

/// The workspace the tests build, and the ruleset each Bazel release
/// builds it with. One era per way the ruleset names an artifact's
/// repository and writes its lock.
const FIXTURE: Fixture = Fixture {
    name: "maven::FIXTURE",
    dir: "rules_jvm_external/bzlmod",
    workflow: "bazel-maven.yml",
    eras: &[
        // rules_jvm_external 6.5 and rules_java 7.6.5: lock format 2.
        ((7, 0, 0)..(8, 0, 0), "e7"),
        // rules_jvm_external 6.9 and rules_java 8.13.0: lock format 2.
        ((8, 0, 0)..(9, 0, 0), "e8"),
        // rules_jvm_external 7.2 and rules_java 9.3.0: lock format 3.
        ((9, 0, 0)..(10, 0, 0), "e9"),
    ],
};

/// The group of the fixture's artifacts, and its directory in a Maven
/// repository.
const GROUP: &str = "dev.socket.fixture";
const GROUP_PATH: &str = "dev/socket/fixture";
/// The artifact the patch is for, which `consumer:2.0` depends on.
const VICTIM: &str = "victim";
const VERSION: &str = "1.10.0";
const PURL: &str = "pkg:maven/dev.socket.fixture/victim@1.10.0";
/// The release a flow moves the checkout to, which has a patch too.
const BUMPED: &str = "1.11.0";
/// The file of the victim's jar that `App.java` prints.
const MARKER: &str = "dev/socket/fixture/victim/marker.txt";
/// The fixture's hub, under a name no other Bazel module adds to.
const HUB: &str = "fixture_maven";
/// The one repository of the fixture's `maven.install`, which a flow
/// replaces with its stand-in's.
const PLACEHOLDER: &str = "http://socket-fixture.invalid/maven2";
/// The route prefixes of the stand-in, one per host it plays.
const UPSTREAM: &str = "maven2";
const PATCH_HOST: &str = "patch.socket.dev";
/// The file of the block, and the files hosted mode writes in a checkout
/// that Maven builds too: those of a Maven pin, and that one.
const MODULE: &str = "MODULE.bazel";
const PINNED: [&str; 4] = [
    ".mvn/checksums/checksums.sha256",
    ".mvn/maven.config",
    MODULE,
    "pom.xml",
];
/// What the command says after its reason when it writes no entry.
const KEEPS: &str = "socket-patch wrote nothing to MODULE.bazel for it, so the Bazel build keeps \
                     the upstream jar";
/// Its reason on a Bazel before 7.5.0 in a checkout without a launcher's
/// file: the lock such a Bazel writes does not tell it from one without
/// `override_repo`.
const NO_RELEASE: &str = "no file of the checkout says that Bazel 7.4.0 or later builds it, and \
                          an older Bazel fails on the `override_repo` an entry needs: name the \
                          release in `.bazelversion`";

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// A jar of `files`, stored and with one fixed time.
fn jar(files: &[(&str, &str)]) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .last_modified_time(
            zip::DateTime::from_date_and_time(2026, 1, 1, 0, 0, 0).expect("a date"),
        );
    let manifest = ("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\n\r\n");
    for (name, text) in std::iter::once(&manifest).chain(files) {
        zip.start_file(*name, options).expect("a jar member");
        zip.write_all(text.as_bytes()).expect("a jar member");
    }
    zip.finish().expect("a jar").into_inner()
}

/// The victim's jar, whose one file holds `marker`.
fn victim(marker: &str) -> Vec<u8> {
    jar(&[(MARKER, &format!("{marker}\n"))])
}

/// The pom of `artifact` at `version`, which depends on `needs`.
fn pom(artifact: &str, version: &str, needs: Option<(&str, &str)>) -> String {
    let needs = needs.map_or_else(String::new, |(artifact, version)| {
        format!(
            "  <dependencies>\n    <dependency>\n      <groupId>{GROUP}</groupId>\n      \
             <artifactId>{artifact}</artifactId>\n      <version>{version}</version>\n    \
             </dependency>\n  </dependencies>\n"
        )
    });
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n  \
         <modelVersion>4.0.0</modelVersion>\n  <groupId>{GROUP}</groupId>\n  \
         <artifactId>{artifact}</artifactId>\n  <version>{version}</version>\n{needs}</project>\n"
    )
}

/// `<group>/<artifact>/<version>/<artifact>-<version>.<ext>`, the path of
/// a file in a Maven repository.
fn repo_path(artifact: &str, version: &str, ext: &str) -> String {
    format!("{GROUP_PATH}/{artifact}/{version}/{artifact}-{version}.{ext}")
}

/// Puts the jar `bytes` of `artifact` at `version` and its pom, which
/// depends on `needs`, in the stand-in's Maven repository. Gives the route
/// of the jar.
fn serve_upstream(
    standin: &StandIn,
    artifact: &str,
    version: &str,
    bytes: &[u8],
    needs: Option<(&str, &str)>,
) -> String {
    let pom = pom(artifact, version, needs);
    for (ext, bytes) in [("jar", bytes), ("pom", pom.as_bytes())] {
        // Coursier takes a file only with a checksum beside it.
        let route = format!("/{UPSTREAM}/{}", repo_path(artifact, version, ext));
        let sha1 = hex::encode(Sha1::digest(bytes));
        standin.serve(5, &route, bytes);
        standin.serve(5, &format!("{route}.sha1"), sha1.as_bytes());
    }
    format!("/{UPSTREAM}/{}", repo_path(artifact, version, "jar"))
}

/// A patch of the victim that a stand-in grants.
struct Granted {
    /// The release of the victim it is for.
    version: String,
    uuid: String,
    /// The sha256 the grant pins, of a jar with [`Granted::marker`].
    sha256: String,
    /// The URL of the patched jar on the patch host, and its route on the
    /// stand-in.
    url: String,
    route: String,
    /// The route of the same jar as vendored mode downloads it: the path of
    /// the grant's own URL for it on the patch host.
    archive: String,
    /// What `//:consumer` prints with the patched jar.
    marker: String,
}

/// The grant of a new patch of the victim at `version`, as production has
/// it: a token and the patch id in the path of the patch registry, the
/// version with the suffix only that registry serves. The route of the jar
/// on `standin` answers with `tampered`, or with the jar the grant pins.
/// Gives the patch for the API of the stand-in too, which takes every
/// patch it grants in one call ([`StandIn::api`]).
///
/// Vendored mode downloads that jar from the grant's own URL for it, whose
/// host a flow sends to the stand-in, and holds it to the record of the
/// patch, which the stand-in serves: the one file that differs from the
/// upstream jar of the run `run` at that version.
fn grant(standin: &StandIn, run: &str, version: &str, tampered: Option<&[u8]>) -> (Granted, Patch) {
    let uuid = uuid::Uuid::new_v4().to_string();
    let token = uuid::Uuid::new_v4().to_string();
    let purl = format!("pkg:maven/{GROUP}/{VICTIM}@{version}");
    let suffixed = format!("{version}-socket.{}", &uuid[..8]);
    let jar = victim(&format!("PATCHED {uuid}"));
    let registry = format!("{PATCH_HOST}/patch-registry/maven/{token}/{uuid}/maven2");
    let file = repo_path(VICTIM, &suffixed, "jar");
    let route = format!("/{registry}/{file}");
    standin.serve(5, &route, tampered.unwrap_or(&jar));
    let archive =
        format!("/patch/maven/{GROUP}/{VICTIM}/{version}/{token}/{uuid}/{VICTIM}-{suffixed}.jar");
    standin.serve(5, &archive, &jar);
    let artifact = format!("https://{PATCH_HOST}{archive}");
    let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    let sha512 = format!("sha512-{}", b64(&Sha512::digest(&jar)));
    let reference = json!({
        "status": "granted",
        "url": artifact,
        "purl": purl,
        "artifacts": [{
            "kind": "tarball",
            "url": artifact,
            "integrity": { "sha256": sha256_hex(&jar), "sha512": sha512 },
        }],
        "registryOverride": {
            "kind": "maven2",
            "indexUrl": format!("https://{registry}"),
            "identifiers": {
                "name": format!("{GROUP}/{VICTIM}"),
                "version": version,
                "mavenGroupId": GROUP,
                "mavenArtifactId": VICTIM,
                "mavenSuffixedVersion": suffixed,
                "mavenPomSha256": sha256_hex(pom(VICTIM, &suffixed, None).as_bytes()),
            },
        },
    });
    let patch = Patch {
        purl,
        uuid: uuid.clone(),
        reference,
    };
    // The upstream jar of a run prints its release from the bump on.
    let upstream = match version {
        VERSION => format!("PRISTINE {run}\n"),
        _ => format!("PRISTINE {version} {run}\n"),
    };
    let patched = format!("PATCHED {uuid}\n");
    let record = json!({
        "uuid": uuid,
        "purl": patch.purl,
        "publishedAt": "2026-01-01T00:00:00Z",
        "files": { MARKER: {
            "beforeHash": git_sha256(upstream.as_bytes()),
            "afterHash": git_sha256(patched.as_bytes()),
            "blobContent": b64(patched.as_bytes()),
            "beforeBlobContent": b64(upstream.as_bytes()),
        }},
        "vulnerabilities": { "GHSA-test-aaaa-bbbb": {
            "cves": ["CVE-2024-0001"], "summary": "s", "severity": "high", "description": "d",
        }},
        "description": "fixture",
        "license": "MIT",
        "tier": "free",
    });
    let view = format!("/v0/orgs/{ORG}/patches/view/{uuid}");
    standin.serve(1, &view, record.to_string().as_bytes());
    let granted = Granted {
        version: version.to_string(),
        sha256: sha256_hex(&jar),
        url: format!("https://{registry}/{file}"),
        route,
        archive,
        marker: format!("OUT: PATCHED {uuid}"),
        uuid,
    };
    (granted, patch)
}

/// The name of the repository through which the fixture's hub fetches the
/// victim, on every era.
const REPOSITORY: &str = "dev_socket_fixture_victim_1_10_0";

/// The block of `MODULE.bazel` for `patch`, with its last line break.
fn block(patch: &Granted) -> String {
    let Granted {
        version,
        uuid,
        sha256,
        url,
        ..
    } = patch;
    let repository = REPOSITORY.replace("1_10_0", &version.replace('.', "_"));
    let purl = format!("pkg:maven/{GROUP}/{VICTIM}@{version}");
    format!(
        r#"# >>> socket-patch: Maven patches for Bazel (managed block: socket-patch writes and removes it) >>>
socket_patch_http_file = use_repo_rule("@bazel_tools//tools/build_defs/repo:http.bzl", "http_file")

socket_patch_maven = use_extension("@rules_jvm_external//:extensions.bzl", "maven")

# {purl}, Socket patch {uuid}
socket_patch_http_file(
    name = "socket_patch_{repository}",
    downloaded_file_path = "v1/{GROUP_PATH}/{VICTIM}/{version}/{VICTIM}-{version}.jar",
    sha256 = "{sha256}",
    urls = ["{url}"],
)

# If Bazel stops at the next line ("does not generate repository"), the hub's lock no longer pins
# {GROUP}:{VICTIM} at {version}: run `socket-patch rollback {purl}`.
# Do not change it to inject_repo(): the build would pass without the patch.
override_repo(
    socket_patch_maven,
    {repository} = "socket_patch_{repository}",
)
# <<< socket-patch <<<
"#
    )
}

/// A checkout whose hub is pinned, and what its flow reads afterwards.
struct Pinned {
    cell: Cell,
    standin: StandIn,
    /// Where the JVM tools of the machine keep artifacts: `m2`, the Maven
    /// local repository, with the victim in it as a Maven build of the
    /// checkout leaves it; `coursier`, the cache the ruleset's Coursier
    /// fills when it pins; `gradle`, which nothing fills.
    tools: tempfile::TempDir,
    /// The patch the stand-in grants, whose jar it serves, and the one it
    /// grants for the victim at [`BUMPED`].
    patch: Granted,
    next: Granted,
    /// The id of the run, which every upstream jar made for it holds.
    run: String,
    /// What `//:consumer` prints while Bazel builds the upstream jar, and
    /// the route of that jar on the stand-in.
    upstream: String,
    upstream_route: String,
    started: Instant,
}

impl Pinned {
    /// Step 0 of every flow: the fixture's checkout for `test`
    /// ([`Pinned::laid_out`]), pinned by the ruleset against its stand-in.
    /// `None` when no Bazel runs here.
    fn open(test: &str, maven: bool, prepare: &dyn Fn(&Cell, &mut String)) -> Option<Pinned> {
        let flow = Pinned::laid_out(Cell::open(test, &FIXTURE)?, maven, prepare);
        let (cell, repository) = (&flow.cell, flow.repository());

        // The ruleset's own relock. The lock it writes holds the victim,
        // which `MODULE.bazel` does not name, at the sha256 of this run's
        // jar, in the format of the era.
        let pin = cell.bazel_env("run", &[&format!("@{HUB}//:pin")], &[("REPIN", "1")]);
        assert!(pin.ok(), "{test}: {}", pin.dump());
        let lock = std::fs::read_to_string(cell.path("maven_install.json")).expect("the lock");
        let raw: Value = serde_json::from_str(&lock).expect("the lock is JSON");
        // Nothing else is in it: no other Bazel module added to the hub,
        // and its one repository is the stand-in.
        let keys = |of: &str| {
            let map = raw[of].as_object().expect("a map of the lock");
            map.keys().map(String::as_str).collect::<Vec<_>>().join(" ")
        };
        assert_eq!(
            (keys("artifacts"), keys("repositories")),
            (
                format!("{GROUP}:consumer {GROUP}:{VICTIM}"),
                format!("{repository}/")
            ),
            "{test}: {raw:#}"
        );
        let lock = Lock::parse(&lock).unwrap_or_else(|why| panic!("{test}: {why}:\n{lock}"));
        let format = if cell.numbers() >= (9, 0, 0) { 3 } else { 2 };
        let jar = Jar {
            version: VERSION.to_string(),
            jar_sha256: Some(sha256_hex(&flow.upstream_jar())),
            fetched: true,
        };
        assert_eq!(
            (lock.format, lock.plain_jar(GROUP, VICTIM)),
            (format, Some(&jar)),
            "{test}: {lock:?}"
        );
        Some(flow)
    }

    /// The repository of the hub: the stand-in's.
    fn repository(&self) -> String {
        format!("{}/{UPSTREAM}", self.standin.origin())
    }

    /// The upstream jar of the victim that the stand-in serves.
    fn upstream_jar(&self) -> Vec<u8> {
        victim(&format!("PRISTINE {}", self.run))
    }

    /// The checkout `cell` of the fixture before its hub is pinned, with a
    /// `pom.xml` that declares the victim when `maven` is set and with
    /// what `prepare` adds to its files and to the text of `MODULE.bazel`,
    /// against a stand-in that has the two artifacts, the patched jar and
    /// the grant of its patch. The lock is the empty file the ruleset's
    /// documentation starts from.
    fn laid_out(mut cell: Cell, maven: bool, prepare: &dyn Fn(&Cell, &mut String)) -> Pinned {
        let started = Instant::now();
        let test = cell.test.clone();
        // The cache of the Coursier that pins. Before 7.2 the ruleset
        // leaves the choice to Coursier, which without this takes the home
        // directory from the system, whatever `HOME` says.
        let tools = tempfile::tempdir().expect("the directories of the JVM tools");
        let coursier = tools.path().join("coursier").to_string_lossy().into_owned();
        cell.repo_env.push(("COURSIER_CACHE".to_string(), coursier));
        let run = uuid::Uuid::new_v4().to_string();
        let upstream_jar = victim(&format!("PRISTINE {run}"));
        let victim_pom = pom(VICTIM, VERSION, None);

        let standin = StandIn::start();
        let origin = standin.origin();
        // Bazel's downloads from the patch host go to the stand-in, under
        // the route prefix of the host. A URL of that host that the rule
        // did not rewrite is refused, so no download reaches the real one.
        let rules = |origin: &str| {
            let host = format!("{PATCH_HOST}/");
            [rewrite(&host, origin), format!("block {PATCH_HOST}")]
        };
        cell.route_downloads(&rules(&origin));
        serve_upstream(&standin, VICTIM, VERSION, &upstream_jar, None);
        serve_upstream(
            &standin,
            "consumer",
            "2.0",
            &jar(&[]),
            Some((VICTIM, VERSION)),
        );
        let (patch, first) = grant(&standin, &run, VERSION, None);
        let (next, second) = grant(&standin, &run, BUMPED, None);
        standin.api(&[first, second]);

        // The checkout: the hub's repository is the stand-in, the lock is
        // the empty file the ruleset's documentation starts from.
        let module = std::fs::read_to_string(cell.path("MODULE.bazel")).expect("MODULE.bazel");
        assert_eq!(module.matches(PLACEHOLDER).count(), 1, "{test}: {module}");
        let repository = format!("{origin}/{UPSTREAM}");
        let mut module = module.replace(PLACEHOLDER, &repository);
        prepare(&cell, &mut module);
        cell.write("MODULE.bazel", module);
        cell.write("maven_install.json", "");
        if maven {
            cell.write("pom.xml", pom("app", "1.0.0", Some((VICTIM, VERSION))));
        }
        for (ext, bytes) in [("jar", &upstream_jar[..]), ("pom", victim_pom.as_bytes())] {
            let file = tools
                .path()
                .join("m2")
                .join(repo_path(VICTIM, VERSION, ext));
            std::fs::create_dir_all(file.parent().expect("a directory")).expect("create it");
            std::fs::write(&file, bytes).expect("write the local repository");
        }

        let upstream = format!("OUT: PRISTINE {run}");
        Pinned {
            cell,
            standin,
            tools,
            patch,
            next,
            run,
            upstream,
            upstream_route: format!("/{UPSTREAM}/{}", repo_path(VICTIM, VERSION, "jar")),
            started,
        }
    }

    /// Step 1: the build prints the upstream marker, from a jar Bazel
    /// fetched from the stand-in. Gives the files of the checkout.
    fn builds_upstream(&self) -> Tree {
        let (test, route) = (&self.cell.test, &self.upstream_route);
        let pinned = self.standin.asked(route);
        let before = self.cell.builds_unpatched(&self.upstream);
        let fetched = self.standin.asked(route) > pinned;
        assert!(fetched, "{test}: the build did not fetch {route}");
        before
    }

    /// `socket-patch <args>` in the checkout, against the stand-in.
    fn socket_patch(&self, args: &[&str]) -> Ran {
        self.socket_patch_in(&self.cell, &self.standin, args)
    }

    /// `socket-patch <args>` in the checkout `cell`, against the API of
    /// `standin`, with the directories of [`Pinned::tools`] in the place of
    /// the machine's.
    fn socket_patch_in(&self, cell: &Cell, standin: &StandIn, args: &[&str]) -> Ran {
        let tools = self.tools_env();
        let env = tools.each_ref().map(|(name, dir)| (*name, dir.as_str()));
        cell.socket_patch(&standin.origin(), args, &env)
    }

    /// The directories of [`Pinned::tools`], each as the variable that
    /// puts it in the place of the machine's.
    fn tools_env(&self) -> [(&'static str, String); 3] {
        let dir = |name: &str| self.tools.path().join(name).to_string_lossy().into_owned();
        [
            ("MAVEN_REPO_LOCAL", dir("m2")),
            ("GRADLE_USER_HOME", dir("gradle")),
            ("COURSIER_CACHE", dir("coursier")),
        ]
    }

    /// `socket-patch <args>` for a command of vendored mode, which downloads
    /// the patched jar from the URL the grant has for it on the patch host:
    /// that host is the stand-in here.
    fn vendored(&self, args: &[&str]) -> Ran {
        self.serviced(&self.cell, args)
    }

    /// [`Pinned::vendored`] in the checkout `cell`. Agent mode takes the
    /// patched jar from that URL as well.
    fn serviced(&self, cell: &Cell, args: &[&str]) -> Ran {
        let origin = self.standin.origin();
        self.socket_patch_in(
            cell,
            &self.standin,
            &[args, &["--patch-server-url", &origin]].concat(),
        )
    }

    /// The command where it writes no entry for the hub, in a tree without
    /// `pom.xml`: it reports the patch skipped, gives one warning, `code`
    /// with the reason `why` and the words that the Bazel build keeps the
    /// upstream jar, and changes no file of `before`.
    fn declines(&self, before: &Tree, code: &str, why: &str) {
        let test = &self.cell.test;
        let get = self.socket_patch(&["get", PURL, "--mode", "hosted", "--yes"]);
        let said = &get.dump;
        assert_eq!(get.code, 0, "{test}: {said}");
        let event = event_for(&get.envelope, PURL);
        assert_eq!(
            (&event["action"], &event["errorCode"]),
            (&json!("skipped"), &json!("redirect_unconfirmed")),
            "{test}: {said}"
        );
        let detail = format!("{PURL}: {why}. {KEEPS}");
        let warnings = json!([{ "code": code, "detail": detail }]);
        assert_eq!(get.envelope["warnings"], warnings, "{test}: {said}");
        assert_eq!(
            changed(before, &self.cell.tree()),
            NOTHING,
            "{test}: {said}"
        );
    }

    /// `socket-patch scan --mode hosted --yes` in a checkout without a
    /// `pom.xml`: the two jars of the hub's lock are its packages, neither
    /// installed where a crawl looks, and it pins the one `patch` is for
    /// as the `get` of [`Pinned::pins`] does. `stale` is the patch of an
    /// entry in the block that the lock no longer pins the jar of: the
    /// scan takes that entry out first, and says so. `before` is the
    /// checkout without any entry. Gives the files of the checkout.
    fn scan_pins(&self, patch: &Granted, before: &Tree, stale: Option<&Granted>) -> Tree {
        let test = &self.cell.test;
        let scan = self.socket_patch(&["scan", "--mode", "hosted", "--yes"]);
        let said = &scan.dump;
        let counted = ["scannedPackages", "lockfileOnlyPackages"].map(|n| &scan.envelope[n]);
        assert_eq!(counted, [&json!(2), &json!(2)], "{test}: {said}");
        let gone = |stale: &Granted| {
            let purl = format!("pkg:maven/{GROUP}/{VICTIM}@{}", stale.version);
            (purl, "rolledBack".into(), "maven_bazel_entry_stale".into())
        };
        let taken_out: Vec<_> = stale.map(gone).into_iter().collect();
        let events = event_triples(&scan.envelope);
        assert_eq!(events[..taken_out.len()], taken_out, "{test}: {said}");
        assert_eq!(events.len(), taken_out.len() + 1, "{test}: {said}");
        self.pinned(&scan, patch, before, &[MODULE])
    }

    /// A Bazel before 7.5.0 writes a lock that does not tell it from one
    /// without `override_repo`, so its checkout names the release as a
    /// launcher reads it. Gives the files of the checkout.
    fn names_its_bazel(&self) -> Tree {
        if self.cell.numbers() < (7, 5, 0) {
            let release = format!("{}\n", self.cell.release());
            self.cell.write(".bazelversion", release);
        }
        self.cell.tree()
    }

    /// The one command of hosted mode, a `get` of the purl: what
    /// [`Pinned::pinned`] holds of it. Gives the files of the checkout.
    fn pins(&self, before: &Tree, files: &[&str]) -> Tree {
        let get = self.socket_patch(&["get", PURL, "--mode", "hosted", "--yes"]);
        self.pinned(&get, &self.patch, before, files)
    }

    /// What a finished hosted command did for `patch`: it reports the
    /// patch applied, rewrote `files` and no other file of `before`, and
    /// gave no warning. `MODULE.bazel` is the one of before with the block
    /// after one blank line, and nothing has asked for the patched jar
    /// yet. Gives the files of the checkout.
    fn pinned(&self, ran: &Ran, patch: &Granted, before: &Tree, files: &[&str]) -> Tree {
        let (test, said) = (&self.cell.test, &ran.dump);
        let purl = format!("pkg:maven/{GROUP}/{VICTIM}@{}", patch.version);
        let pinned = self.cell.pinned_by(ran, &purl, &patch.uuid, before, files);
        assert_eq!(ran.envelope["warnings"], Value::Null, "{test}: {said}");
        let text = |tree: &Tree| String::from_utf8(tree[MODULE].clone()).expect("a text file");
        let with_block = format!("{}\n{}", text(before), block(patch));
        assert_eq!(text(&pinned), with_block, "{test}: {said}");
        let asked = self.standin.asked(&patch.route);
        assert_eq!(asked, 0, "{test}: the command fetched the patched jar");
        pinned
    }

    /// The same build after the command, no step in between: it prints the
    /// marker of the patched jar, which Bazel fetched from the patch host
    /// and not from the hub's repository. Bazel changed no file of
    /// `pinned`, its own lock included, and that lock still stands when
    /// Bazel may not update it.
    fn builds_patched(&self, pinned: &Tree) {
        let test = &self.cell.test;
        let upstream = self.standin.asked(&self.upstream_route);
        self.cell.builds_patched(pinned, &self.patch.marker);
        let asked = self.standin.asked(&self.patch.route);
        assert!(asked > 0, "{test}: the build did not fetch the patched jar");
        let again = self.standin.asked(&self.upstream_route);
        assert_eq!(
            again, upstream,
            "{test}: the build fetched the upstream jar"
        );
    }

    /// A second machine with the checkout. Bazel keeps a download that has
    /// a checksum in the repository cache, which the two machines share,
    /// so this one gets a patch whose jar no machine has fetched: another
    /// service grants it, and its host serves other bytes than the grant
    /// pins. The build has to ask that host, fails on the sha256 of the
    /// entry, and does not go to the upstream jar. Gives what Bazel said.
    fn a_second_machine_refuses_other_bytes(&self) -> String {
        let test = &self.cell.test;
        let mut twin = self.cell.twin();
        let rogue = StandIn::start();
        let tampered = victim("TAMPERED");
        let (other, served) = grant(&rogue, &self.run, VERSION, Some(&tampered));
        rogue.api(&[served]);
        let host = format!("{PATCH_HOST}/");
        twin.route_downloads(&[
            rewrite(&host, &rogue.origin()),
            format!("block {PATCH_HOST}"),
        ]);
        let get = self.socket_patch_in(&twin, &rogue, &["get", PURL, "--mode", "hosted", "--yes"]);
        let said = &get.dump;
        assert_eq!(get.code, 0, "{test}: {said}");
        assert_eq!(get.envelope["summary"]["applied"], 1, "{test}: {said}");
        let upstream = self.standin.asked(&self.upstream_route);
        let build = twin.bazel("build", &[CONSUMER]);
        assert!(
            !build.ok(),
            "{test}: the tampered jar built:\n{}",
            build.dump()
        );
        let refusal = format!(
            "Checksum was {} but wanted {}",
            sha256_hex(&tampered),
            other.sha256
        );
        assert!(
            build.stderr().contains(&refusal),
            "{test}: the build did not fail on the sha256 of the entry:\n{}",
            build.dump()
        );
        assert!(
            rogue.asked(&other.route) > 0,
            "{test}: the patch host was not asked, so the failed build proves nothing"
        );
        let again = self.standin.asked(&self.upstream_route);
        assert_eq!(
            again, upstream,
            "{test}: the build went to the upstream jar"
        );
        refusal
    }

    /// The ruleset's own relock passes with the block in place, and
    /// leaves the lock as it is: the hub still pins the upstream jar.
    fn relock_keeps_the_lock(&self) {
        let test = &self.cell.test;
        let lock = std::fs::read(self.cell.path("maven_install.json")).expect("the lock");
        let pin = self
            .cell
            .bazel_env("run", &[&format!("@{HUB}//:pin")], &[("REPIN", "1")]);
        assert!(pin.ok(), "{test}: {}", pin.dump());
        let after = std::fs::read(self.cell.path("maven_install.json")).expect("the lock");
        assert!(
            lock == after,
            "{test}: the relock changed maven_install.json"
        );
    }

    /// `bazel mod tidy` passes and leaves `MODULE.bazel` as it is.
    fn tidy_keeps_the_module_file(&self) {
        let test = &self.cell.test;
        let module = std::fs::read(self.cell.path("MODULE.bazel")).expect("MODULE.bazel");
        let tidy = self.cell.bazel("mod", &["tidy"]);
        assert!(tidy.ok(), "{test}: {}", tidy.dump());
        let after = std::fs::read(self.cell.path("MODULE.bazel")).expect("MODULE.bazel");
        assert!(
            module == after,
            "{test}: `bazel mod tidy` changed MODULE.bazel to:\n{}",
            String::from_utf8_lossy(&after)
        );
    }

    /// The checkout asks for the victim at `version` by name, the stand-in
    /// has that release, and the ruleset's relock takes it into the lock.
    /// Gives what `//:consumer` prints with that jar.
    fn bump(&self, version: &str) -> String {
        let test = &self.cell.test;
        let marker = format!("PRISTINE {version} {}", self.run);
        serve_upstream(&self.standin, VICTIM, version, &victim(&marker), None);
        let module = std::fs::read_to_string(self.cell.path("MODULE.bazel")).expect("MODULE.bazel");
        let named = format!("\"{GROUP}:consumer:2.0\"");
        assert_eq!(module.matches(&named).count(), 1, "{test}: {module}");
        let both = format!("{named}, \"{GROUP}:{VICTIM}:{version}\"");
        self.cell
            .write("MODULE.bazel", module.replace(&named, &both));
        let pin = self
            .cell
            .bazel_env("run", &[&format!("@{HUB}//:pin")], &[("REPIN", "1")]);
        assert!(pin.ok(), "{test}: {}", pin.dump());
        let lock = std::fs::read_to_string(self.cell.path("maven_install.json")).expect("the lock");
        let lock = Lock::parse(&lock).unwrap_or_else(|why| panic!("{test}: {why}:\n{lock}"));
        let pinned = lock
            .plain_jar(GROUP, VICTIM)
            .map(|jar| jar.version.as_str());
        assert_eq!(pinned, Some(version), "{test}: {lock:?}");
        format!("OUT: {marker}")
    }
}

/// A Maven build and a Bazel build of one checkout: the one command pins
/// both, the Bazel build takes the patched jar, and the undo restores
/// every file.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn a_pom_patch_beside_a_pinned_hub() {
    let test = "maven::a_pom_patch_beside_a_pinned_hub";
    let Some(flow) = Pinned::open(test, true, &|_, _| {}) else {
        return;
    };
    flow.builds_upstream();
    let before = flow.names_its_bazel();

    // The three files of a Maven pin, and the block for the hub.
    let pinned = flow.pins(&before, &PINNED);
    flow.builds_patched(&pinned);

    let undo = flow.socket_patch(&["rollback", "--yes"]);
    flow.cell
        .undone(&undo, "rolledBack", &before, &flow.upstream);
    println!(
        "{test}: Bazel {} built {:?}, then {:?} after `get --mode hosted` pinned {PURL} in \
         pom.xml and in MODULE.bazel; `rollback` restored all {} files and the first build; {:?}",
        flow.cell.release(),
        flow.upstream,
        flow.patch.marker,
        before.len(),
        flow.started.elapsed()
    );
}

/// The same checkout without a `pom.xml`: the command writes the block,
/// the build is patched from the patch host at the sha256 of the entry,
/// and the undo puts `MODULE.bazel` back byte for byte.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn a_tree_only_bazel_builds() {
    let test = "maven::a_tree_only_bazel_builds";
    let Some(flow) = Pinned::open(test, false, &|_, _| {}) else {
        return;
    };
    let before = flow.builds_upstream();
    // Nothing in the checkout of a Bazel before 7.5.0 says that it has
    // `override_repo`: the command writes nothing until a file does.
    let unnamed = flow.cell.numbers() < (7, 5, 0);
    if unnamed {
        flow.declines(&before, "maven_bazel_release", NO_RELEASE);
    }
    let before = flow.names_its_bazel();

    let pinned = flow.pins(&before, &[MODULE]);
    flow.builds_patched(&pinned);
    flow.relock_keeps_the_lock();
    flow.tidy_keeps_the_module_file();

    // The undo: every file is the one of before, `MODULE.bazel` to the
    // byte, and so is the build.
    let undo = flow.socket_patch(&["rollback", "--yes"]);
    flow.cell
        .undone(&undo, "rolledBack", &before, &flow.upstream);

    let refusal = flow.a_second_machine_refuses_other_bytes();
    println!(
        "{test}: Bazel {} built {:?}, then {:?} from the patch host after `get --mode hosted` \
         appended the block to MODULE.bazel{}; a `--lockfile_mode=error` build passed, the \
         relock left the lock and `bazel mod tidy` the file as it was; `rollback` restored \
         all {} files and the \
         first build; other bytes at the patch host failed a second machine's build \
         ({refusal}); {:?}",
        flow.cell.release(),
        flow.upstream,
        flow.patch.marker,
        if unnamed {
            ", which it declined (maven_bazel_release) until the checkout had a .bazelversion"
        } else {
            ""
        },
        before.len(),
        flow.started.elapsed()
    );
}

/// A hosted scan of the checkout without a `pom.xml`: the lock of the hub
/// is the one file that names the jars Bazel builds, and the command takes
/// them for the packages of the project. It finds the patch of the victim
/// and pins it as the `get` does: the build is patched, a second scan has
/// nothing to write, and the undo restores every file.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn a_hosted_scan_of_a_tree_only_bazel_builds() {
    let test = "maven::a_hosted_scan_of_a_tree_only_bazel_builds";
    let Some(flow) = Pinned::open(test, false, &|_, _| {}) else {
        return;
    };
    flow.builds_upstream();
    let before = flow.names_its_bazel();

    let pinned = flow.scan_pins(&flow.patch, &before, None);
    flow.builds_patched(&pinned);
    let again = flow.socket_patch(&["scan", "--mode", "hosted", "--yes"]);
    let said = &again.dump;
    let rewritten = &again.envelope["redirect"]["rewrittenFiles"];
    assert_eq!(
        (again.code, &again.envelope["summary"]["applied"], rewritten),
        (0, &json!(1), &json!([])),
        "{test}: {said}"
    );
    assert_eq!(
        changed(&pinned, &flow.cell.tree()),
        NOTHING,
        "{test}: {said}"
    );

    let undo = flow.socket_patch(&["rollback", "--yes"]);
    flow.cell
        .undone(&undo, "rolledBack", &before, &flow.upstream);
    println!(
        "{test}: Bazel {} built {:?}, then {:?} from the patch host after `scan --mode hosted \
         --yes` found {PURL} in the hub's lock and appended the block to MODULE.bazel; a second \
         scan wrote nothing; `rollback` restored all {} files and the first build; {:?}",
        flow.cell.release(),
        flow.upstream,
        flow.patch.marker,
        before.len(),
        flow.started.elapsed()
    );
}

/// The checkout moves the artifact one version up after the command: the
/// relock passes, the build stops at the line of the entry, and the
/// command the block names there takes the entry out. So does a hosted
/// scan of the checkout with the stale entry: it takes the entry out,
/// finds the new release in the lock, and pins the patch of it.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn a_version_bump_of_the_patched_artifact() {
    let test = "maven::a_version_bump_of_the_patched_artifact";
    let Some(flow) = Pinned::open(test, false, &|_, _| {}) else {
        return;
    };
    flow.builds_upstream();
    let before = flow.names_its_bazel();
    flow.pins(&before, &[MODULE]);

    // The relock evaluates the hub with the entry in place, and passes.
    let bumped = flow.bump(BUMPED);
    let module = std::fs::read_to_string(flow.cell.path(MODULE)).expect("MODULE.bazel");
    let entry = module.lines().position(|line| line == "override_repo(");
    let line = entry.expect("the entry's override_repo") + 1;
    // The lock no longer pins what the entry replaces: Bazel stops at the
    // entry's line, under which the block says what to run.
    let build = flow.cell.bazel("build", &[CONSUMER]);
    let stderr = build.stderr();
    let stops = format!("does not generate repository \"{REPOSITORY}\"");
    let at = format!("{MODULE}:{line}:");
    assert!(
        !build.ok() && stderr.contains(&stops) && stderr.contains(&at),
        "{test}: the build did not stop at {at} ({stops}):\n{}",
        build.dump()
    );
    let remedy = format!("run `socket-patch rollback {PURL}`.");
    let named = module
        .lines()
        .take(line)
        .any(|line| line.ends_with(&remedy));
    assert!(named, "{test}: {module}");

    let undo = flow.socket_patch(&["rollback", PURL, "--yes"]);
    let said = &undo.dump;
    assert_eq!(undo.code, 0, "{test}: {said}");
    assert_eq!(undo.envelope["summary"]["rolledBack"], 1, "{test}: {said}");
    // The file is the one the checkout had after its bump, without the
    // block and the blank line before it.
    let (start, _) = module.split_once(&block(&flow.patch)).expect("the block");
    let unpatched = start.strip_suffix('\n').expect("the blank line");
    let after = std::fs::read_to_string(flow.cell.path(MODULE)).expect("MODULE.bazel");
    assert_eq!(after, unpatched, "{test}: {said}");
    flow.cell.builds(&bumped);

    // A user who runs a hosted scan where the block says to roll back:
    // the stale entry is in the file again, as it was when the build
    // stopped. The scan takes it out as the rollback did, and the API has
    // a patch of the release the lock now pins.
    let rolled_back = flow.cell.tree();
    flow.cell.write(MODULE, module);
    let pinned = flow.scan_pins(&flow.next, &rolled_back, Some(&flow.patch));
    flow.cell.builds_patched(&pinned, &flow.next.marker);
    let asked = flow.standin.asked(&flow.next.route);
    assert!(asked > 0, "{test}: the build did not fetch the patched jar");
    println!(
        "{test}: Bazel {} built {:?}; after `get --mode hosted` and the checkout's bump to \
         {BUMPED} the relock passed and the build stopped at {at} ({stops}); `rollback {PURL}` \
         took the entry out and the build printed {bumped:?}; with the stale entry back, `scan \
         --mode hosted --yes` took it out, pinned the patch of {BUMPED} and the build printed \
         {:?}; {:?}",
        flow.cell.release(),
        flow.upstream,
        flow.next.marker,
        flow.started.elapsed()
    );
}

/// The command of vendored mode.
const VENDORED: [&str; 5] = ["get", PURL, "--mode", "vendored", "--yes"];
/// The pair that keeps the directory of the committed jars out of the
/// packages of the workspace, as the `.bazelignore` the command creates.
const JARS_IGNORED: &str =
    "# socket-patch: patched Maven jars for a Bazel hub, not Bazel packages \
                            (to opt out, comment out the next line)\n.socket/vendor/maven\n";

/// The block of `MODULE.bazel` for `patch` in vendored mode, with its last
/// line break: the repository is the directory of the patch in the
/// checkout, and no host is named.
fn vendored_block(patch: &Granted) -> String {
    let uuid = &patch.uuid;
    format!(
        r#"# >>> socket-patch: Maven patches for Bazel (managed block: socket-patch writes and removes it) >>>
socket_patch_local_repository = use_repo_rule("@bazel_tools//tools/build_defs/repo:local.bzl", "local_repository")

socket_patch_maven = use_extension("@rules_jvm_external//:extensions.bzl", "maven")

# {PURL}, Socket patch {uuid}
socket_patch_local_repository(
    name = "socket_patch_{REPOSITORY}",
    path = ".socket/vendor/maven/{uuid}",
)

# If Bazel stops at the next line ("does not generate repository"), the hub's lock no longer pins
# {GROUP}:{VICTIM} at {VERSION}: run `socket-patch rollback {PURL}`.
# Do not change it to inject_repo(): the build would pass without the patch.
override_repo(
    socket_patch_maven,
    {REPOSITORY} = "socket_patch_{REPOSITORY}",
)
# <<< socket-patch <<<
"#
    )
}

impl Pinned {
    /// The committed jar of the patch, from the checkout.
    fn committed_jar(&self) -> String {
        let uuid = &self.patch.uuid;
        format!(".socket/vendor/maven/{uuid}/file/{VICTIM}-{VERSION}.jar")
    }

    /// A finished command of vendored mode, `ran`, in a checkout whose
    /// files were `before`: it vendored the one patch and warned of
    /// nothing, and wrote the directory of the patch with the jar the
    /// grant pins, the block after one blank line, the line of
    /// `.bazelignore` and the ledger, and no other file. Gives the files of
    /// the checkout.
    fn vendored_by(&self, ran: &Ran, before: &Tree) -> Tree {
        let (test, said) = (&self.cell.test, &ran.dump);
        assert_eq!(ran.code, 0, "{test}: {said}");
        assert_eq!(ran.envelope["status"], "success", "{test}: {said}");
        assert_eq!(ran.envelope["summary"]["applied"], 1, "{test}: {said}");
        assert_eq!(ran.envelope["warnings"], Value::Null, "{test}: {said}");
        let unit = format!(".socket/vendor/maven/{}", self.patch.uuid);
        let written = [
            ".bazelignore".to_string(),
            format!("{unit}/.gitignore"),
            format!("{unit}/REPO.bazel"),
            format!("{unit}/file/BUILD.bazel"),
            self.committed_jar(),
            ".socket/vendor/state.json".to_string(),
            MODULE.to_string(),
        ];
        let vendored = self.cell.tree();
        assert_eq!(changed(before, &vendored), written, "{test}: {said}");
        let text =
            |tree: &Tree, file: &str| String::from_utf8(tree[file].clone()).expect("a text file");
        let with_block = format!("{}\n{}", text(before, MODULE), vendored_block(&self.patch));
        assert_eq!(text(&vendored, MODULE), with_block, "{test}: {said}");
        assert_eq!(text(&vendored, ".bazelignore"), JARS_IGNORED, "{test}");
        let build = format!(
            "filegroup(\n    name = \"file\",\n    srcs = [\"{VICTIM}-{VERSION}.jar\"],\n    \
             visibility = [\"//visibility:public\"],\n)\n"
        );
        assert_eq!(text(&vendored, &written[3]), build, "{test}");
        let jar = sha256_hex(&vendored[&written[4]]);
        assert_eq!(jar, self.patch.sha256, "{test}: not the jar the grant pins");
        vendored
    }

    /// The build of a vendored checkout: it prints the marker of the
    /// patched jar and changes no file of `vendored`, Bazel's lock
    /// included; a `--lockfile_mode=error` build passes; and no jar was
    /// asked of the patch host or of the hub's repository for it.
    fn builds_the_committed_jar(&self, vendored: &Tree) {
        let test = &self.cell.test;
        let asked = |route: &String| self.standin.asked(route);
        let before = [&self.patch.route, &self.upstream_route].map(asked);
        self.cell.builds_patched(vendored, &self.patch.marker);
        let after = [&self.patch.route, &self.upstream_route].map(asked);
        assert_eq!(after, before, "{test}: the build fetched a jar");
        assert_eq!(after[0], 0, "{test}: the patch host was asked for the jar");
    }
}

/// Vendored mode in a checkout that only Bazel builds: the command commits
/// the patched jar and the block that puts its directory in the place of
/// the hub's repository, the build is patched from the checkout alone, the
/// audit holds the committed jar to the patch, and the undo puts every
/// file back.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn a_vendored_patch_in_a_tree_only_bazel_builds() {
    let test = "maven::a_vendored_patch_in_a_tree_only_bazel_builds";
    let Some(flow) = Pinned::open(test, false, &|_, _| {}) else {
        return;
    };
    let before = flow.builds_upstream();
    // As in hosted mode: nothing in the checkout of a Bazel before 7.5.0
    // says that it has `override_repo`, and the command then fails for
    // the reason a hosted run warns of, before it downloads the patch
    // (the failure is the first event of the purl), and writes nothing.
    if flow.cell.numbers() < (7, 5, 0) {
        let get = flow.vendored(&VENDORED);
        let said = &get.dump;
        assert_eq!(get.code, 1, "{test}: {said}");
        let failed = event_for(&get.envelope, PURL);
        let why = format!("{NO_RELEASE}. {KEEPS}");
        assert_eq!(
            (&failed["action"], &failed["errorCode"], &failed["error"]),
            (&json!("failed"), &json!("maven_bazel_release"), &json!(why)),
            "{test}: {said}"
        );
        assert_eq!(
            changed(&before, &flow.cell.tree()),
            NOTHING,
            "{test}: {said}"
        );
    }
    let before = flow.names_its_bazel();

    let get = flow.vendored(&VENDORED);
    let vendored = flow.vendored_by(&get, &before);
    let downloads = flow.standin.asked(&flow.patch.archive);
    assert_eq!(
        downloads, 1,
        "{test}: the jar comes from the patch service, once"
    );
    flow.builds_the_committed_jar(&vendored);

    // The directory of the jar is no package of the workspace.
    let query = flow.cell.bazel("query", &["//..."]);
    let listed = query.stdout();
    assert!(
        query.ok() && listed.lines().any(|line| line == CONSUMER),
        "{test}: {}",
        query.dump()
    );
    let under_socket: Vec<&str> = listed.lines().filter(|l| l.contains(".socket")).collect();
    assert_eq!(under_socket, NOTHING, "{test}: {}", query.dump());

    // `list` and `vex` see the patch, as they see a hosted one.
    let run = |cell: &Cell, args: &[&str]| flow.socket_patch_in(cell, &flow.standin, args);
    let list = flow.socket_patch(&["list"]);
    let listed = event_for(&list.envelope, PURL);
    assert_eq!(
        (&listed["uuid"], &listed["details"]["mode"]),
        (&json!(flow.patch.uuid), &json!("vendored")),
        "{test}: {}",
        list.dump
    );
    let claim = Claim::new(PURL, &flow.patch.uuid, How::Vendored);
    flow.cell.stands_alone(run, &claim, true);

    // The audit passes for the committed jar, and fails for another one,
    // which Bazel builds all the same: no digest of a directory is
    // checked at build time.
    let audit = |passes: bool| {
        let check = flow.socket_patch(&["vendor", "--check"]);
        let said = &check.dump;
        let event = event_for(&check.envelope, PURL);
        let expected = match passes {
            true => (0, "verified", "vendor_check_ok"),
            false => (1, "failed", "vendor_check_failed"),
        };
        let found = (check.code, &event["action"], &event["errorCode"]);
        assert_eq!(
            found,
            (expected.0, &json!(expected.1), &json!(expected.2)),
            "{test}: {said}"
        );
    };
    audit(true);
    let jar = flow.committed_jar();
    flow.cell
        .write(&jar, victim(&format!("CHANGED {}", flow.run)));
    audit(false);
    flow.cell.builds(&format!("OUT: CHANGED {}", flow.run));
    flow.cell.write(&jar, &vendored[&jar]);
    audit(true);
    assert_eq!(changed(&vendored, &flow.cell.tree()), NOTHING, "{test}");

    // A second machine with the checkout, and no host to ask: the
    // stand-in is stopped, the output base is new, and the repository
    // cache, which the machines share, holds the hub's own jars and no
    // copy of the patched one.
    let twin = flow.cell.twin();
    let Pinned {
        cell,
        standin,
        patch,
        upstream,
        started,
        ..
    } = flow;
    let origin = standin.stop();
    twin.builds(&patch.marker);
    let lock = std::fs::read_to_string(twin.path("maven_install.json")).expect("the lock");
    let lock = Lock::parse(&lock).expect("the lock");
    let fetched = lock
        .plain_jar(GROUP, VICTIM)
        .and_then(|jar| jar.jar_sha256.clone());
    let fetched = fetched.expect("the sha256 of the upstream jar");
    assert_eq!(
        (twin.cached(&fetched), twin.cached(&patch.sha256)),
        (true, false),
        "{test}: the repository cache holds the hub's jar, and not the patched one"
    );
    drop(twin);

    // The undo: every file is the one of before, and so is the build.
    let undo = cell.socket_patch(&origin, &["vendor", "--revert", "--yes"], &[]);
    cell.undone(&undo, "removed", &before, &upstream);
    println!(
        "{test}: Bazel {} built {upstream:?}, then {:?} from the jar `get --mode vendored` \
         committed under .socket/vendor/maven, also on a second machine with no host to ask; \
         `bazel query //...` listed no package there, a `--lockfile_mode=error` build passed, \
         `vendor --check` failed for a changed jar, which Bazel built; `vendor --revert` \
         restored all {} files and the first build; {:?}",
        cell.release(),
        patch.marker,
        before.len(),
        started.elapsed()
    );
}

/// From hosted mode to vendored mode and back: one entry for the jar at
/// every step, and the checkout of the hosted command again at the end of
/// the way back.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn a_hub_goes_from_hosted_to_vendored_and_back() {
    let test = "maven::a_hub_goes_from_hosted_to_vendored_and_back";
    let Some(flow) = Pinned::open(test, false, &|_, _| {}) else {
        return;
    };
    flow.builds_upstream();
    let before = flow.names_its_bazel();
    let hosted = flow.pins(&before, &[MODULE]);

    // `vendor` takes the hosted patch over: its entry is the only one.
    let eject = flow.vendored(&["vendor"]);
    let vendored = flow.vendored_by(&eject, &before);
    flow.builds_the_committed_jar(&vendored);

    // And back: the hosted command takes the vendored entry, its
    // directory, its line and its ledger entry out, and says so.
    let back = flow.socket_patch(&["get", PURL, "--mode", "hosted", "--yes"]);
    let said = &back.dump;
    assert_eq!(back.code, 0, "{test}: {said}");
    assert_eq!(back.envelope["summary"]["applied"], 1, "{test}: {said}");
    let warned: Vec<&str> = back.envelope["warnings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|warning| warning["code"].as_str())
        .collect();
    assert_eq!(
        warned,
        ["redirect_takeover_reverted_vendored"],
        "{test}: {said}"
    );
    assert_eq!(
        changed(&hosted, &flow.cell.tree()),
        NOTHING,
        "{test}: {said}"
    );
    flow.builds_patched(&hosted);

    // Vendored again, by the command of the mode, and undone by `rollback`.
    let again = flow.vendored(&VENDORED);
    let same = flow.vendored_by(&again, &before);
    assert_eq!(changed(&vendored, &same), NOTHING, "{test}");
    let undo = flow.socket_patch(&["rollback", "--yes"]);
    flow.cell
        .undone(&undo, "rolledBack", &before, &flow.upstream);
    println!(
        "{test}: Bazel {} built {:?}, then {:?} from the checkout after `vendor` took the \
         hosted entry over, and from the patch host after `get --mode hosted` took the \
         vendored one over; `rollback` restored all {} files and the first build; {:?}",
        flow.cell.release(),
        flow.upstream,
        flow.patch.marker,
        before.len(),
        flow.started.elapsed()
    );
}

/// What the checkout builds in the artifact's place, and its package.
const OWN_MARKER: &str = "OUT: OWN of the checkout";
const OWN_BUILD: &str = r#"load("@rules_java//java:defs.bzl", "java_library")

java_library(
    name = "victim",
    resource_strip_prefix = "own",
    resources = ["dev/socket/fixture/victim/marker.txt"],
    visibility = ["//visibility:public"],
)
"#;

/// A hub whose `maven.override` gives the artifact a target of the
/// checkout: an entry would change nothing that Bazel builds, so the
/// command writes none and says where the override is, and the build
/// prints that target's marker before and after.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn the_users_own_override_of_the_artifact() {
    let test = "maven::the_users_own_override_of_the_artifact";
    let own = |cell: &Cell, module: &mut String| {
        cell.write("own/BUILD.bazel", OWN_BUILD);
        let marker = OWN_MARKER.trim_start_matches("OUT: ");
        cell.write(&format!("own/{MARKER}"), format!("{marker}\n"));
        module.push_str(&format!(
            "maven.override(\n    name = \"{HUB}\",\n    coordinates = \"{GROUP}:{VICTIM}\",\n    \
             target = \"//own:victim\",\n)\n"
        ));
    };
    let Some(flow) = Pinned::open(test, false, &own) else {
        return;
    };
    let before = flow.cell.builds_unpatched(OWN_MARKER);

    let before = match flow.cell.numbers() < (7, 5, 0) {
        true => flow.names_its_bazel(),
        false => before,
    };

    let module = std::fs::read_to_string(flow.cell.path(MODULE)).expect("MODULE.bazel");
    let line = module.lines().position(|line| line == "maven.override(");
    let line = line.expect("the override") + 1;
    let why = format!(
        "{MODULE}:{line}: a `maven.override` gives this artifact another target, so Bazel would \
         not build a patched jar: patch that target, or remove the override"
    );
    flow.declines(&before, "maven_bazel_no_effect", &why);

    flow.cell.builds(OWN_MARKER);
    assert_eq!(changed(&before, &flow.cell.tree()), NOTHING, "{test}");
    let asked = flow.standin.asked(&flow.patch.route);
    assert_eq!(asked, 0, "{test}: something fetched the patched jar");
    println!(
        "{test}: Bazel {} built {OWN_MARKER:?} before and after `get --mode hosted` declined \
         {PURL} (maven_bazel_no_effect) and named the override at {MODULE}:{line}; {:?}",
        flow.cell.release(),
        flow.started.elapsed()
    );
}

/// The warning of an agent run for an artifact that a pinned hub fetches:
/// the command patches no hub.
const HUB_UNPATCHED: &str = "maven_bazel_hub_unpatched";
/// What an action statement says to run where hosted and vendored mode
/// write an entry for the hub: the package by its coordinates.
const RUN: &str = "Run `socket-patch get pkg:maven/dev.socket.fixture/victim@1.10.0 --mode \
                   hosted` at the Bazel root to patch the hub, or with `--mode vendored` to \
                   commit the patched jar.";
/// And what it says where they write none, before the code of their
/// warning and its reason.
const NO_ENTRY: &str = "Hosted and vendored mode write no entry for this hub";

impl Pinned {
    /// Without a Bazel: the checkout of [`Pinned::open`] beside a `pom.xml`,
    /// in a workspace copy that no Bazel has built in. No ruleset pins it,
    /// so the lock is written here: the two artifacts under the stand-in's
    /// repository, in the format the ruleset of Bazel 9.3.2 writes. And no
    /// Bazel leaves its own lock, so what hosted and vendored mode read
    /// before they write an entry is written here too: the Bazel release,
    /// and the release of the ruleset that Bazel selected.
    fn unbuilt() -> Pinned {
        let cell = cell_without_bazel("9.3.2");
        let module = fixture_path(FIXTURE.dir).join("e9").join(MODULE);
        cell.write(MODULE, std::fs::read(module).expect(MODULE));
        cell.write(".git/HEAD", "ref: refs/heads/main\n");
        let flow = Pinned::laid_out(cell, true, &|_, _| {});
        let sums = |jar: &[u8]| json!({ "jar": sha256_hex(jar) });
        let keys = [format!("{GROUP}:consumer"), format!("{GROUP}:{VICTIM}")];
        let lock = json!({
            "artifacts": {
                &keys[0]: { "shasums": sums(&jar(&[])), "version": "2.0" },
                &keys[1]: { "shasums": sums(&flow.upstream_jar()), "version": VERSION },
            },
            "repositories": { format!("{}/", flow.repository()): keys },
            "version": "3",
        });
        flow.cell.write("maven_install.json", format!("{lock:#}\n"));
        let selected = "https://bcr.bazel.build/modules/rules_jvm_external/7.2/source.json";
        let lock = json!({ "lockFileVersion": 13, "registryFileHashes": { selected: "0" } });
        flow.cell.write("MODULE.bazel.lock", format!("{lock:#}\n"));
        flow.cell.write(".bazelversion", "9.3.2\n");
        flow
    }

    /// What every document of a patch that the hub does not take says, as
    /// its action statement and in the warning of its run: the lock of the
    /// hub, the call and its line, `remedy`, which is the command of the
    /// two modes that patch a pinned hub ([`RUN`]) or why they write no
    /// entry for this one, and the option for a repository that ships what
    /// Maven or Gradle builds.
    fn affected(&self, remedy: &str) -> Vec<String> {
        let module = std::fs::read_to_string(self.cell.path(MODULE)).expect(MODULE);
        let call = module.lines().position(|line| line == "maven.install(");
        vec![format!(
            "Bazel builds this package from maven_install.json (`maven.install`, {MODULE}:{}), \
             which does not name Socket patch {}: the patch is only in what Maven or Gradle \
             builds from. {remedy} If what you ship is what Maven or Gradle builds and not what \
             Bazel builds, pass `--no-bazel` (`--vex-no-bazel` on scan, apply and vendor).",
            call.expect("the hub") + 1,
            self.patch.uuid
        )]
    }

    /// Agent mode in the checkout ([`Cell::patches_outside`]). The victim's
    /// jar is in the Maven local repository, as a Maven build of the
    /// checkout's `pom.xml` leaves it: `scan --mode agent --yes` puts the
    /// jar of the patch service in its place and writes nothing into the
    /// checkout but its `.socket` directory, and each of the four
    /// documents says `claim`. A later `apply` warns that it patches no hub
    /// ([`HUB_UNPATCHED`]). Gives the files of the checkout.
    fn patches_the_installed_jar(&self, claim: &Claim) -> Tree {
        let test = &self.cell.test;
        let installed = self.tools.path().join("m2");
        let installed = installed.join(repo_path(VICTIM, VERSION, "jar"));
        let patched = victim(&format!("PATCHED {}", self.patch.uuid));
        let run = |cell: &Cell, args: &[&str]| self.serviced(cell, args);
        let left = self.cell.patches_outside(run, &installed, &patched, claim);
        let apply = self.serviced(&self.cell, &["apply"]);
        let warned = codes_in(&apply.envelope["warnings"]);
        assert_eq!(warned, [HUB_UNPATCHED], "{test}: {}", apply.dump);
        left
    }
}

/// Agent mode beside a pinned hub that fetches the artifact.
///
/// - (a) `bazel build` and `bazel run //:consumer` print the upstream
///   marker.
/// - (b) `scan --mode agent --yes` patches the jar in the Maven local
///   repository and warns that it patches no hub, and `apply` passes
///   ([`Pinned::patches_the_installed_jar`]). Both, `vex` and
///   `vex --no-verify` exit 0 and write a document that says the artifact
///   is affected, with what to do about it ([`Pinned::affected`]).
/// - (c) The same two Bazel commands print the upstream marker again, as
///   the documents said, and change no file: the hub fetches the jar its
///   lock pins, at the lock's sha256, and no build reads the Maven local
///   repository.
/// - (d) The hosted command the documents name pins the Maven build and
///   the hub. The same build prints the marker of the patched jar, and
///   `vex` says not affected, through the hosted patch.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn an_agent_patch_beside_a_pinned_hub() {
    let test = "maven::an_agent_patch_beside_a_pinned_hub";
    let Some(flow) = Pinned::open(test, true, &|_, _| {}) else {
        return;
    };
    // (a) The upstream build, with the jar from the stand-in.
    flow.builds_upstream();
    flow.names_its_bazel();

    // (b) Agent mode patches the installed jar, and every document says
    // the artifact is affected.
    let names = flow.affected(RUN);
    let claim = Claim::unbuilt(PURL, &flow.patch.uuid, &names);
    let patched = flow.patches_the_installed_jar(&claim);

    // (c) The build is the one of (a): Bazel never reads the patched jar.
    flow.cell.builds(&flow.upstream);
    assert_eq!(changed(&patched, &flow.cell.tree()), NOTHING, "{test}");

    // (d) What the documents say to run: the build is patched, and the
    // document says so.
    let pinned = flow.pins(&patched, &PINNED);
    flow.builds_patched(&pinned);
    let run = |cell: &Cell, args: &[&str]| flow.socket_patch_in(cell, &flow.standin, args);
    let hosted = Claim::new(PURL, &flow.patch.uuid, How::Hosted);
    flow.cell.stands_alone(run, &hosted, true);
    println!(
        "{test}: Bazel {} built {:?} before and after `scan --mode agent` patched {VICTIM}-\
         {VERSION}.jar in the Maven local repository, and every form of `vex` said the artifact \
         is affected, in the words {names:?}; after `get --mode hosted` it built {:?} and `vex` \
         said not affected; {:?}",
        flow.cell.release(),
        flow.upstream,
        flow.patch.marker,
        flow.started.elapsed()
    );
}

/// A second hub, which has no lock: what is not known of it leaves the hub
/// that fetches the jar as it is.
const MORE: &str = "maven.artifact(\n    name = \"more\",\n    artifact = \"gson\",\n    group = \
                    \"com.google.code.gson\",\n    version = \"2.8.9\",\n)\n";

/// Without a Bazel: step (b) of [`an_agent_patch_beside_a_pinned_hub`] in a
/// checkout whose hub is pinned ([`Pinned::unbuilt`]). Then each of the two
/// modes the document names, in a checkout of its own: the command pins or
/// vendors the artifact for the Maven build and for the hub, with no
/// warning about the hub, and `vex` says not affected, through that mode.
///
/// And each where the command writes no entry: in a checkout that names a
/// Bazel without `override_repo`, and beside a second hub without a lock,
/// where `apply` warns that the hub stays unpatched all the same. There
/// the documents of agent mode say affected too, and name the code and
/// the reason of the command's warning in the place of the command. The
/// command then pins or vendors for the Maven build alone and gives that
/// warning, and `vex` still says affected, in the same words: the hub
/// fetches the upstream jar as before, whichever mode holds the patch.
#[test]
fn an_installed_jar_is_affected_beside_a_hub_that_fetches_its_own() {
    let modes = [("hosted", How::Hosted), ("vendored", How::Vendored)];
    let old = "the checkout names Bazel 7.3.0 (`.bazeliskrc` or `.bazelversion`), and an entry \
               needs `override_repo`, which Bazel has from 7.4.0";
    let lockless = "hub \"more\" has no `lock_file`, so Bazel resolves its jars when it builds \
                    and none can be replaced: give the hub a `lock_file` and pin it (`REPIN=1 \
                    bazel run @more//:pin`)";
    // The file that differs, with what is added to it or put in its place,
    // and the code and the reason with which the command then declines.
    let checkouts = [
        (MODULE, "", None),
        (
            ".bazelversion",
            "7.3.0\n",
            Some(("maven_bazel_release", old)),
        ),
        (MODULE, MORE, Some(("maven_bazel_not_pinned", lockless))),
    ];
    let each =
        |(mode, how)| checkouts.map(|(file, text, declined)| (mode, how, file, text, declined));
    for (mode, how, file, text, declined) in modes.into_iter().flat_map(each) {
        let flow = Pinned::unbuilt();
        let module = std::fs::read_to_string(flow.cell.path(MODULE)).expect(MODULE);
        match file {
            MODULE => flow.cell.write(MODULE, format!("{module}{text}")),
            _ => flow.cell.write(file, text),
        }
        // The reason names the place of a tag: the one added last.
        let at = format!("{MODULE}:{}: ", module.lines().count() + 1);
        let remedy = declined.map(|(code, why)| {
            let at = if why.starts_with("hub ") { &at } else { "" };
            format!("{NO_ENTRY} (`{code}`): {at}{why}.")
        });
        let names = flow.affected(remedy.as_deref().unwrap_or(RUN));
        let claim = Claim::unbuilt(PURL, &flow.patch.uuid, &names);
        flow.patches_the_installed_jar(&claim);

        let get = flow.vendored(&["get", PURL, "--mode", mode, "--yes"]);
        assert_eq!(get.envelope["summary"]["applied"], 1, "{}", get.dump);
        let mut warned = codes_in(&get.envelope["warnings"]);
        warned.retain(|code| code.starts_with("maven_bazel_"));
        let module = std::fs::read_to_string(flow.cell.path(MODULE)).expect(MODULE);
        let entry = module.contains(&format!("Socket patch {}", flow.patch.uuid));
        let code = declined.map_or("", |(code, _)| code);
        assert_eq!(
            (warned.join(" "), entry),
            (code.to_string(), declined.is_none()),
            "{}",
            get.dump
        );
        let run = |cell: &Cell, args: &[&str]| flow.socket_patch_in(cell, &flow.standin, args);
        let patched = Claim::new(PURL, &flow.patch.uuid, how);
        let says = if declined.is_some() { &claim } else { &patched };
        flow.cell.stands_alone(run, says, true);
    }
}

/// Without a Bazel: what stays the statement of a project without Bazel
/// while the patch is in the installed jar alone
/// ([`Cell::keeps_its_statement`]). The hubs of which nothing is said: one
/// that has no lock, one with a `maven.override` of the artifact, and one
/// whose call may not run. So is the checkout that does not say that Bazel
/// reads `MODULE.bazel` as it stands: an rc file names the option that
/// switches Bzlmod off, for one `--config`; no release is named beside a
/// `WORKSPACE` file that defines a repository; the release named is one
/// before 7.0. And what a person reads of an `apply` beside the hub that
/// fetches the jar: the warning and the count of the statement, and
/// nothing under `--silent`.
#[test]
fn an_installed_jar_is_attested_where_no_hub_is_shown_to_fetch_its_own() {
    let flow = Pinned::unbuilt();
    let names = flow.affected(RUN);
    let claim = Claim::unbuilt(PURL, &flow.patch.uuid, &names);
    flow.patches_the_installed_jar(&claim);

    let (origin, tools) = (flow.standin.origin(), flow.tools_env());
    let told = tools.each_ref().map(|(name, dir)| (*name, dir.as_str()));
    let document = flow.cell.document("person");
    let warned = format!(
        "Warning: {PURL}: the VEX document says affected. {}",
        names[0]
    );
    let loud = [&["apply"][..], &with_vex(&document)].concat();
    let silent = [&loud[..], &["--silent"]].concat();
    for apply in [loud, silent] {
        flow.cell
            .tells_a_person(&origin, &apply, &told, &document, &claim, &warned);
    }

    let run = |cell: &Cell, args: &[&str]| flow.socket_patch_in(cell, &flow.standin, args);
    let installed = Claim::new(PURL, &flow.patch.uuid, How::Agent);
    let repository = "http_archive(name = \"zlib\", urls = [])\n";
    for (file, text, bazel) in [
        (".bazelrc", "build:legacy --noenable_bzlmod\n", "7.7.2\n"),
        ("WORKSPACE", repository, "latest\n"),
        ("WORKSPACE", "", "6.5.0\n"),
    ] {
        flow.cell.write(file, text);
        flow.cell.write(".bazelversion", bazel);
        flow.cell.stands_alone(run, &installed, true);
        std::fs::remove_file(flow.cell.path(file)).expect(file);
    }
    flow.cell.write(".bazelversion", "9.3.2\n");

    let module = std::fs::read_to_string(flow.cell.path(MODULE)).expect(MODULE);
    let lock = "    lock_file = \"//:maven_install.json\",\n";
    let own = format!(
        "maven.override(\n    name = \"{HUB}\",\n    coordinates = \"{GROUP}:{VICTIM}\",\n    \
         target = \"//own:victim\",\n)\n"
    );
    let undecided = [
        module.replace(lock, ""),
        format!("{module}{own}"),
        module.replace("maven.install(", "ENABLED and maven.install("),
    ];
    let gives = |args: &[&str], document: &Path| flow.cell.gives(&origin, args, &told, document);
    flow.cell
        .keeps_its_statement(run, gives, &installed, &undecided);
}

/// Without a Bazel: the fixture's directories and the legs of its workflow
/// are those of the table, each era's `MODULE.bazel` has a hub of its own
/// name with the one repository a flow replaces, and a jar made here holds
/// what `App.java` reads.
#[test]
fn the_fixture_has_one_repository_to_replace_per_era() {
    FIXTURE.check();
    for (_, era) in FIXTURE.eras {
        let module = crate::harness::fixture_path(FIXTURE.dir)
            .join(era)
            .join("MODULE.bazel");
        let module = std::fs::read_to_string(&module).expect("MODULE.bazel");
        assert_eq!(module.matches(PLACEHOLDER).count(), 1, "{era}: {module}");
        // No other URL, and the hub is [`HUB`]: no pin resolves what other
        // modules add to a hub named `maven`, or asks a public repository.
        assert_eq!(module.matches("://").count(), 1, "{era}: {module}");
        for named in [
            format!("name = \"{HUB}\","),
            format!("use_repo(maven, \"{HUB}\")"),
        ] {
            assert!(module.contains(&named), "{era}: {named} is not in {module}");
        }
    }
    let build = crate::harness::fixture_path(FIXTURE.dir).join("common/BUILD.bazel");
    let build = std::fs::read_to_string(&build).expect("BUILD.bazel");
    let dep = format!("\"@{HUB}//:dev_socket_fixture_consumer\"");
    assert!(build.contains(&dep), "{build}");
    let app = crate::harness::fixture_path(FIXTURE.dir).join("common/App.java");
    let app = std::fs::read_to_string(&app).expect("App.java");
    assert!(app.contains(&format!("\"/{MARKER}\"")), "{app}");
    let jar = victim("PRISTINE of a run");
    let mut jar = zip::ZipArchive::new(std::io::Cursor::new(&jar[..])).expect("a jar");
    let mut marker = String::new();
    let mut file = jar.by_name(MARKER).expect("the marker");
    std::io::Read::read_to_string(&mut file, &mut marker).expect("its text");
    assert_eq!(marker, "PRISTINE of a run\n");
}
