//! A deterministic fake Maven Central for the JVM build capstones (Gradle,
//! and sbt/Coursier, which resolve from the same maven2 layout).
//!
//! Everything under `com.socketfixture` is GENERATED here, byte-for-byte
//! reproducibly (stored zip entries, fixed timestamps and permissions,
//! hand-assembled class files, fixed-order JSON/XML):
//!
//! * `victim:{1.9,1.10.0}` — jar (a `Victim.marker()` class + a
//!   `META-INF/NOTICE.txt` marker), pom (parent `fixture-parent:1`, the
//!   `published-with-gradle-metadata` hint), `.module` (api / runtime /
//!   sources variants with size + md5/sha1/sha256/sha512), and
//!   `-tests` / `-sources` classifier jars. `victim-1.10.0.jar` carries a
//!   padding member brute-forced so its sha1 starts with `0` (Gradle may
//!   drop the leading zero from the `files-2.1` hash dir).
//! * `consumer:2.0` → `victim:1.10.0`; `consumer-range:2.0` → `victim:[1.9,1.11)`.
//! * `fixture-parent:1` (parent pom), `fixture-bom:1.0` (a Maven BOM, for a
//!   non-enforced `platform()` import), `fixture-platform:1.0` (a Gradle
//!   platform `.module` whose variants `require` `victim:1.10.0`).
//! * `buildlogic-plugin:1.0` — a buildscript-classpath library depending on
//!   `victim:1.10.0`; `BuildLogic.print()` prints [`BUILDLOGIC_MARKER`] +
//!   `Victim.marker()` from build logic.
//! * artifact-level `maven-metadata.xml`, and `.md5` / `.sha1` / `.sha256` /
//!   `.sha512` sidecars for every file (computed when served).
//!
//! COMMITTED under `fixtures/`: `.asc` signatures of every jar / pom /
//! `.module` (`fixtures/signatures/<repo path>.asc`) by a THROWAWAY key
//! (`fixtures/keys/`, secret included on purpose — never trust it), and
//! `fixtures/SHA256SUMS`, the digest of every generated file. The
//! stability self-test regenerates the repository and compares it with
//! `SHA256SUMS` on every OS. To change the fixture, edit the generator and
//! run that test with `SOCKET_PATCH_JVM_FIXTURES_REGENERATE=1` (needs
//! `gpg`): it rewrites `SHA256SUMS` and re-signs with the committed key.
//!
//! [`FakeCentral`] serves the repository over plain http (wiremock), plus
//! any overlay a test adds (e.g. the service-built patched jar the
//! member-keyed swap downloads, [`FakeCentral::serve_patched_jar`]).

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

pub const GROUP: &str = "com.socketfixture";
pub const GROUP_PATH: &str = "com/socketfixture";
pub const VICTIM: &str = "victim";
/// The base version patches target, and the older one a downgrade lands on.
pub const VICTIM_VERSION: &str = "1.10.0";
pub const VICTIM_OLD: &str = "1.9";
pub const VICTIM_VERSIONS: [&str; 2] = [VICTIM_OLD, VICTIM_VERSION];
pub const CONSUMER: &str = "consumer";
pub const CONSUMER_RANGE: &str = "consumer-range";
pub const CONSUMER_VERSION: &str = "2.0";
/// What `consumer-range:2.0`'s pom requests.
pub const VICTIM_RANGE: &str = "[1.9,1.11)";
pub const PARENT: &str = "fixture-parent";
pub const PARENT_VERSION: &str = "1";
pub const BOM: &str = "fixture-bom";
pub const PLATFORM: &str = "fixture-platform";
pub const PLATFORM_VERSION: &str = "1.0";
pub const BUILDLOGIC: &str = "buildlogic-plugin";
pub const BUILDLOGIC_VERSION: &str = "1.0";
pub const BUILDLOGIC_CLASS: &str = "com.socketfixture.buildlogic.BuildLogic";
pub const VICTIM_CLASS: &str = "com.socketfixture.victim.Victim";
/// The jar member a text patch rewrites.
pub const NOTICE: &str = "META-INF/NOTICE.txt";
/// The class member `Victim.marker()` lives in.
pub const VICTIM_CLASS_MEMBER: &str = "com/socketfixture/victim/Victim.class";
/// The leading-zero padding member of `victim-1.10.0.jar`.
pub const PAD_MEMBER: &str = "META-INF/socket-fixture-pad.txt";
/// What `BuildLogic.print()` prints before `Victim.marker()`.
pub const BUILDLOGIC_MARKER: &str = "SOCKET-FIXTURE-BUILDLOGIC ";
/// The `lastUpdated` of every `maven-metadata.xml`.
pub const LAST_UPDATED: &str = "20260101000000";
/// The throwaway signing key's fingerprint.
pub const KEY_FINGERPRINT: &str = "DD0CDDD2B4838EC95727B94B4C77A9C911D46A19";
pub const REGENERATE_ENV: &str = "SOCKET_PATCH_JVM_FIXTURES_REGENERATE";

/// The committed part of the fixture.
pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/jvm_fixture_repo/fixtures")
}

/// The throwaway key as an armored public keyring (Gradle accepts it as
/// `gradle/verification-keyring.keys`).
pub fn public_key_armored() -> PathBuf {
    fixtures_dir().join("keys/signing-key.public.asc")
}

/// The same keyring in binary form (`gradle/verification-keyring.gpg`).
pub fn public_keyring_gpg() -> PathBuf {
    fixtures_dir().join("keys/verification-keyring.gpg")
}

pub fn victim_purl(version: &str) -> String {
    format!("pkg:maven/{GROUP}/{VICTIM}@{version}")
}

/// `<group path>/<artifact>/<version>/<artifact>-<version>[-<classifier>].<ext>`.
pub fn repo_path(artifact: &str, version: &str, classifier: Option<&str>, ext: &str) -> String {
    let classifier = classifier.map(|c| format!("-{c}")).unwrap_or_default();
    format!("{GROUP_PATH}/{artifact}/{version}/{artifact}-{version}{classifier}.{ext}")
}

// ── member content ──────────────────────────────────────────────────────

/// `Victim.marker()`'s return value.
pub fn victim_marker(version: &str, state: &str) -> String {
    format!("SOCKET-FIXTURE-VICTIM {version} {state}")
}

/// A jar's `META-INF/NOTICE.txt`; `state` is `pristine` upstream.
pub fn notice(coordinate: &str, state: &str) -> String {
    format!("Socket fixture: {coordinate}\nSOCKET-FIXTURE-NOTICE {state}\n")
}

/// `com.socketfixture.victim.Victim` whose `marker()` returns
/// [`victim_marker`]`(version, state)`: build a patched class member with a
/// different `state`.
pub fn victim_class(version: &str, state: &str) -> Vec<u8> {
    let mut c = ClassFile::new("com/socketfixture/victim/Victim");
    let text = c.string(&victim_marker(version, state));
    let mut code = ldc(text);
    code.push(0xb0); // areturn
    c.method("marker", "()Ljava/lang/String;", 1, code);
    c.finish()
}

/// `com.socketfixture.buildlogic.BuildLogic`: `marker()` returns
/// [`BUILDLOGIC_MARKER`] + `Victim.marker()`, `print()` prints it.
pub fn buildlogic_class() -> Vec<u8> {
    let mut c = ClassFile::new("com/socketfixture/buildlogic/BuildLogic");
    let prefix = c.string(BUILDLOGIC_MARKER);
    let victim = c.methodref(
        "com/socketfixture/victim/Victim",
        "marker",
        "()Ljava/lang/String;",
    );
    let concat = c.methodref(
        "java/lang/String",
        "concat",
        "(Ljava/lang/String;)Ljava/lang/String;",
    );
    let out = c.fieldref("java/lang/System", "out", "Ljava/io/PrintStream;");
    let println = c.methodref("java/io/PrintStream", "println", "(Ljava/lang/String;)V");
    let this_marker = c.methodref(
        "com/socketfixture/buildlogic/BuildLogic",
        "marker",
        "()Ljava/lang/String;",
    );
    // marker(): ldc prefix; invokestatic Victim.marker; invokevirtual concat; areturn
    let mut code = ldc(prefix);
    code.extend(op_u2(0xb8, victim));
    code.extend(op_u2(0xb6, concat));
    code.push(0xb0);
    c.method("marker", "()Ljava/lang/String;", 2, code);
    // print(): getstatic System.out; invokestatic marker; invokevirtual println; return
    let mut code = op_u2(0xb2, out);
    code.extend(op_u2(0xb8, this_marker));
    code.extend(op_u2(0xb6, println));
    code.push(0xb1);
    c.method("print", "()V", 2, code);
    c.finish()
}

fn manifest_mf() -> Vec<u8> {
    b"Manifest-Version: 1.0\r\nCreated-By: socket-patch test fixture\r\n\r\n".to_vec()
}

fn victim_jar(version: &str) -> Vec<u8> {
    let coordinate = format!("{GROUP}:{VICTIM}:{version}");
    let mut members = vec![
        ("META-INF/MANIFEST.MF".to_string(), manifest_mf()),
        (
            NOTICE.to_string(),
            notice(&coordinate, "pristine").into_bytes(),
        ),
        (
            VICTIM_CLASS_MEMBER.to_string(),
            victim_class(version, "pristine"),
        ),
    ];
    if version != VICTIM_VERSION {
        return jar(&members);
    }
    // Brute-force the padding so the jar's sha1 starts with `0`.
    members.push((PAD_MEMBER.to_string(), Vec::new()));
    for n in 0u32.. {
        members.last_mut().unwrap().1 = format!("pad {n}\n").into_bytes();
        let bytes = jar(&members);
        if sha1_hex(&bytes).starts_with('0') {
            return bytes;
        }
    }
    unreachable!()
}

fn classifier_jar(artifact: &str, version: &str, classifier: &str) -> Vec<u8> {
    let coordinate = format!("{GROUP}:{artifact}:{version}:{classifier}");
    let mut members = vec![
        ("META-INF/MANIFEST.MF".to_string(), manifest_mf()),
        (
            NOTICE.to_string(),
            notice(&coordinate, "pristine").into_bytes(),
        ),
    ];
    if classifier == "sources" {
        members.push((
            "com/socketfixture/victim/Victim.java".to_string(),
            format!(
                "package com.socketfixture.victim;\n\npublic final class Victim {{\n    \
                 public static String marker() {{ return \"{}\"; }}\n}}\n",
                victim_marker(version, "pristine")
            )
            .into_bytes(),
        ));
    }
    jar(&members)
}

fn notice_jar(artifact: &str, version: &str, extra: Vec<(String, Vec<u8>)>) -> Vec<u8> {
    let coordinate = format!("{GROUP}:{artifact}:{version}");
    let mut members = vec![
        ("META-INF/MANIFEST.MF".to_string(), manifest_mf()),
        (
            NOTICE.to_string(),
            notice(&coordinate, "pristine").into_bytes(),
        ),
    ];
    members.extend(extra);
    jar(&members)
}

/// A deterministic jar: stored entries, a fixed 2026-01-01 timestamp and
/// 0644 Unix permissions, in the given order.
pub fn jar(members: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut out = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut out);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .last_modified_time(zip::DateTime::from_date_and_time(2026, 1, 1, 0, 0, 0).unwrap())
            .system(zip::System::Unix)
            .unix_permissions(0o644);
        for (name, bytes) in members {
            writer.start_file(name.as_str(), opts).unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap();
    }
    out.into_inner()
}

// ── metadata ────────────────────────────────────────────────────────────

const POM_HEAD: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<project xmlns=\"http://maven.apache.org/POM/4.0.0\" \
xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" \
xsi:schemaLocation=\"http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd\">\n";

/// Gradle reads the `.module` when a pom carries this comment.
const GRADLE_METADATA_HINT: &str = "  <!-- do_not_remove: published-with-gradle-metadata -->\n";

fn parent_block() -> String {
    format!(
        "  <parent>\n    <groupId>{GROUP}</groupId>\n    <artifactId>{PARENT}</artifactId>\n    \
         <version>{PARENT_VERSION}</version>\n  </parent>\n"
    )
}

fn dependency(artifact: &str, version: &str) -> String {
    format!(
        "    <dependency>\n      <groupId>{GROUP}</groupId>\n      <artifactId>{artifact}</artifactId>\n      \
         <version>{version}</version>\n    </dependency>\n"
    )
}

fn parent_pom() -> String {
    format!(
        "{POM_HEAD}  <modelVersion>4.0.0</modelVersion>\n  <groupId>{GROUP}</groupId>\n  \
         <artifactId>{PARENT}</artifactId>\n  <version>{PARENT_VERSION}</version>\n  \
         <packaging>pom</packaging>\n  <name>socket-patch fixture parent</name>\n  <licenses>\n    \
         <license>\n      <name>MIT</name>\n    </license>\n  </licenses>\n</project>\n"
    )
}

/// A jar pom under `fixture-parent` (the project's own `<version>` follows
/// `</parent>`, the shape `hosted_maven_common::Hosted::served_pom` rewrites).
fn jar_pom(artifact: &str, version: &str, gradle_metadata: bool, deps: &[(&str, &str)]) -> String {
    let mut pom = POM_HEAD.to_string();
    if gradle_metadata {
        pom.push_str(GRADLE_METADATA_HINT);
    }
    pom.push_str(&format!(
        "  <modelVersion>4.0.0</modelVersion>\n{}  <artifactId>{artifact}</artifactId>\n  \
         <version>{version}</version>\n  <packaging>jar</packaging>\n",
        parent_block()
    ));
    if !deps.is_empty() {
        pom.push_str("  <dependencies>\n");
        for (a, v) in deps {
            pom.push_str(&dependency(a, v));
        }
        pom.push_str("  </dependencies>\n");
    }
    pom.push_str("</project>\n");
    pom
}

/// A `pom`-packaged pom managing `victim:1.10.0` (the BOM, and the
/// platform's Maven face).
fn managing_pom(artifact: &str, version: &str, gradle_metadata: bool) -> String {
    let mut pom = POM_HEAD.to_string();
    if gradle_metadata {
        pom.push_str(GRADLE_METADATA_HINT);
    }
    pom.push_str(&format!(
        "  <modelVersion>4.0.0</modelVersion>\n{}  <artifactId>{artifact}</artifactId>\n  \
         <version>{version}</version>\n  <packaging>pom</packaging>\n  \
         <dependencyManagement>\n    <dependencies>\n{}    </dependencies>\n  \
         </dependencyManagement>\n</project>\n",
        parent_block(),
        dependency(VICTIM, VICTIM_VERSION)
            .lines()
            .map(|l| format!("  {l}\n"))
            .collect::<String>()
    ));
    pom
}

fn file_entry(name: &str, bytes: &[u8]) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "url": name,
        "size": bytes.len(),
        "sha512": sha512_hex(bytes),
        "sha256": sha256_hex(bytes),
        "sha1": sha1_hex(bytes),
        "md5": md5_hex(bytes),
    })
}

fn module_head(artifact: &str, version: &str) -> serde_json::Value {
    serde_json::json!({
        "formatVersion": "1.1",
        "component": {
            "group": GROUP,
            "module": artifact,
            "version": version,
            "attributes": { "org.gradle.status": "release" }
        },
        "createdBy": { "gradle": { "version": "8.14.3" } },
        "variants": []
    })
}

fn library_variant(name: &str, usage: &str, jar_name: &str, jar: &[u8]) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "attributes": {
            "org.gradle.category": "library",
            "org.gradle.dependency.bundling": "external",
            "org.gradle.jvm.version": 8,
            "org.gradle.libraryelements": "jar",
            "org.gradle.usage": usage
        },
        "files": [file_entry(jar_name, jar)]
    })
}

fn victim_module(version: &str, jar: &[u8], sources: &[u8]) -> String {
    let mut module = module_head(VICTIM, version);
    let jar_name = format!("{VICTIM}-{version}.jar");
    let sources_name = format!("{VICTIM}-{version}-sources.jar");
    module["variants"] = serde_json::json!([
        library_variant("apiElements", "java-api", &jar_name, jar),
        library_variant("runtimeElements", "java-runtime", &jar_name, jar),
        {
            "name": "sourcesElements",
            "attributes": {
                "org.gradle.category": "documentation",
                "org.gradle.dependency.bundling": "external",
                "org.gradle.docstype": "sources",
                "org.gradle.usage": "java-runtime"
            },
            "files": [file_entry(&sources_name, sources)]
        }
    ]);
    serde_json::to_string_pretty(&module).unwrap() + "\n"
}

fn platform_module() -> String {
    let mut module = module_head(PLATFORM, PLATFORM_VERSION);
    let constraint = serde_json::json!([{
        "group": GROUP,
        "module": VICTIM,
        "version": { "requires": VICTIM_VERSION }
    }]);
    module["variants"] = serde_json::json!([
        {
            "name": "apiElements",
            "attributes": { "org.gradle.category": "platform", "org.gradle.usage": "java-api" },
            "dependencyConstraints": constraint.clone()
        },
        {
            "name": "runtimeElements",
            "attributes": { "org.gradle.category": "platform", "org.gradle.usage": "java-runtime" },
            "dependencyConstraints": constraint
        }
    ]);
    serde_json::to_string_pretty(&module).unwrap() + "\n"
}

fn maven_metadata(artifact: &str, versions: &[&str]) -> String {
    let latest = versions.last().unwrap();
    let listed: String = versions
        .iter()
        .map(|v| format!("      <version>{v}</version>\n"))
        .collect();
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<metadata>\n  <groupId>{GROUP}</groupId>\n  \
         <artifactId>{artifact}</artifactId>\n  <versioning>\n    <latest>{latest}</latest>\n    \
         <release>{latest}</release>\n    <versions>\n{listed}    </versions>\n    \
         <lastUpdated>{LAST_UPDATED}</lastUpdated>\n  </versioning>\n</metadata>\n"
    )
}

// ── the repository ──────────────────────────────────────────────────────

/// Every primary file of the repository, keyed by its maven2 path (no
/// leading `/`). Sidecars (checksums, signatures) are not included.
pub fn generate() -> BTreeMap<String, Vec<u8>> {
    let mut repo = BTreeMap::new();
    let mut put = |path: String, bytes: Vec<u8>| {
        assert!(repo.insert(path, bytes).is_none());
    };
    put(
        repo_path(PARENT, PARENT_VERSION, None, "pom"),
        parent_pom().into_bytes(),
    );
    put(
        format!("{GROUP_PATH}/{PARENT}/maven-metadata.xml"),
        maven_metadata(PARENT, &[PARENT_VERSION]).into_bytes(),
    );
    for version in VICTIM_VERSIONS {
        let jar = victim_jar(version);
        let sources = classifier_jar(VICTIM, version, "sources");
        let tests = classifier_jar(VICTIM, version, "tests");
        put(
            repo_path(VICTIM, version, None, "module"),
            victim_module(version, &jar, &sources).into_bytes(),
        );
        put(
            repo_path(VICTIM, version, None, "pom"),
            jar_pom(VICTIM, version, true, &[]).into_bytes(),
        );
        put(repo_path(VICTIM, version, None, "jar"), jar);
        put(repo_path(VICTIM, version, Some("sources"), "jar"), sources);
        put(repo_path(VICTIM, version, Some("tests"), "jar"), tests);
    }
    put(
        format!("{GROUP_PATH}/{VICTIM}/maven-metadata.xml"),
        maven_metadata(VICTIM, &VICTIM_VERSIONS).into_bytes(),
    );
    for (artifact, victim) in [(CONSUMER, VICTIM_VERSION), (CONSUMER_RANGE, VICTIM_RANGE)] {
        put(
            repo_path(artifact, CONSUMER_VERSION, None, "pom"),
            jar_pom(artifact, CONSUMER_VERSION, false, &[(VICTIM, victim)]).into_bytes(),
        );
        put(
            repo_path(artifact, CONSUMER_VERSION, None, "jar"),
            notice_jar(artifact, CONSUMER_VERSION, Vec::new()),
        );
        put(
            format!("{GROUP_PATH}/{artifact}/maven-metadata.xml"),
            maven_metadata(artifact, &[CONSUMER_VERSION]).into_bytes(),
        );
    }
    put(
        repo_path(BOM, PLATFORM_VERSION, None, "pom"),
        managing_pom(BOM, PLATFORM_VERSION, false).into_bytes(),
    );
    put(
        format!("{GROUP_PATH}/{BOM}/maven-metadata.xml"),
        maven_metadata(BOM, &[PLATFORM_VERSION]).into_bytes(),
    );
    put(
        repo_path(PLATFORM, PLATFORM_VERSION, None, "pom"),
        managing_pom(PLATFORM, PLATFORM_VERSION, true).into_bytes(),
    );
    put(
        repo_path(PLATFORM, PLATFORM_VERSION, None, "module"),
        platform_module().into_bytes(),
    );
    put(
        format!("{GROUP_PATH}/{PLATFORM}/maven-metadata.xml"),
        maven_metadata(PLATFORM, &[PLATFORM_VERSION]).into_bytes(),
    );
    put(
        repo_path(BUILDLOGIC, BUILDLOGIC_VERSION, None, "pom"),
        jar_pom(
            BUILDLOGIC,
            BUILDLOGIC_VERSION,
            false,
            &[(VICTIM, VICTIM_VERSION)],
        )
        .into_bytes(),
    );
    put(
        repo_path(BUILDLOGIC, BUILDLOGIC_VERSION, None, "jar"),
        notice_jar(
            BUILDLOGIC,
            BUILDLOGIC_VERSION,
            vec![(
                "com/socketfixture/buildlogic/BuildLogic.class".to_string(),
                buildlogic_class(),
            )],
        ),
    );
    put(
        format!("{GROUP_PATH}/{BUILDLOGIC}/maven-metadata.xml"),
        maven_metadata(BUILDLOGIC, &[BUILDLOGIC_VERSION]).into_bytes(),
    );
    repo
}

/// Whether a repository file carries a committed `.asc`.
pub fn is_signed(path: &str) -> bool {
    path.ends_with(".jar") || path.ends_with(".pom") || path.ends_with(".module")
}

/// The committed `.asc` of every signed file, keyed by its repository path
/// with `.asc` appended.
pub fn signatures() -> BTreeMap<String, Vec<u8>> {
    let root = fixtures_dir().join("signatures");
    generate()
        .keys()
        .filter(|p| is_signed(p))
        .filter_map(|p| {
            let asc = format!("{p}.asc");
            std::fs::read(root.join(&asc)).ok().map(|b| (asc, b))
        })
        .collect()
}

/// The full served repository: [`generate`] + [`signatures`] + checksum
/// sidecars of both.
pub fn repository() -> BTreeMap<String, Vec<u8>> {
    let mut repo = generate();
    repo.extend(signatures());
    with_checksums(repo)
}

/// `files` plus `.md5` / `.sha1` / `.sha256` / `.sha512` of each.
pub fn with_checksums(files: BTreeMap<String, Vec<u8>>) -> BTreeMap<String, Vec<u8>> {
    let mut out = files.clone();
    for (path, bytes) in files {
        for (ext, digest) in checksums(&bytes) {
            out.insert(format!("{path}.{ext}"), digest.into_bytes());
        }
    }
    out
}

fn checksums(bytes: &[u8]) -> [(&'static str, String); 4] {
    [
        ("md5", md5_hex(bytes)),
        ("sha1", sha1_hex(bytes)),
        ("sha256", sha256_hex(bytes)),
        ("sha512", sha512_hex(bytes)),
    ]
}

/// `SHA256SUMS` text for `files` (`<sha256>  <path>` lines, sorted).
pub fn sha256sums(files: &BTreeMap<String, Vec<u8>>) -> String {
    files
        .iter()
        .map(|(path, bytes)| format!("{}  {path}\n", sha256_hex(bytes)))
        .collect()
}

// ── the server ──────────────────────────────────────────────────────────

/// The fake Central: every [`repository`] file at `/<maven2 path>`, plus
/// overlays, over plain http. 404 for anything else. Requests are logged.
pub struct FakeCentral {
    server: MockServer,
    rt: tokio::runtime::Runtime,
    files: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
}

impl FakeCentral {
    pub fn start() -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let server = rt.block_on(MockServer::start());
        let files = Arc::new(Mutex::new(repository()));
        let served = files.clone();
        rt.block_on(
            Mock::given(method("GET"))
                .and(path_regex("^/.+"))
                .respond_with(move |request: &Request| {
                    let path = request.url.path().trim_start_matches('/').to_string();
                    match served.lock().unwrap().get(&path) {
                        Some(bytes) => ResponseTemplate::new(200).set_body_bytes(bytes.clone()),
                        None => ResponseTemplate::new(404),
                    }
                })
                .mount(&server),
        );
        rt.block_on(
            Mock::given(method("HEAD"))
                .and(path_regex("^/.+"))
                .respond_with({
                    let served = files.clone();
                    move |request: &Request| {
                        let path = request.url.path().trim_start_matches('/');
                        if served.lock().unwrap().contains_key(path) {
                            ResponseTemplate::new(200)
                        } else {
                            ResponseTemplate::new(404)
                        }
                    }
                })
                .mount(&server),
        );
        FakeCentral { server, rt, files }
    }

    /// The repository url (`http://127.0.0.1:<port>`).
    pub fn uri(&self) -> String {
        self.server.uri()
    }

    /// Serve `bytes` (plus checksum sidecars) at `path` (no leading `/`),
    /// replacing whatever was there.
    pub fn put(&self, path: &str, bytes: &[u8]) {
        let one = BTreeMap::from([(path.to_string(), bytes.to_vec())]);
        self.files.lock().unwrap().extend(with_checksums(one));
    }

    /// Stop serving `path` and its sidecars.
    pub fn remove(&self, path: &str) {
        let mut files = self.files.lock().unwrap();
        files.remove(path);
        for (ext, _) in checksums(b"") {
            files.remove(&format!("{path}.{ext}"));
        }
    }

    /// The service-built patched jar a member-keyed record swaps in, at
    /// `/patched/<uuid>/<artifact>-<version>.jar`. Returns its url.
    pub fn serve_patched_jar(
        &self,
        uuid: &str,
        artifact: &str,
        version: &str,
        jar: &[u8],
    ) -> String {
        let path = format!("patched/{uuid}/{artifact}-{version}.jar");
        self.put(&path, jar);
        format!("{}/{path}", self.uri())
    }

    /// Every request path seen so far (leading `/` kept), in order.
    pub fn requests(&self) -> Vec<String> {
        self.rt
            .block_on(self.server.received_requests())
            .unwrap_or_default()
            .iter()
            .map(|r| r.url.path().to_string())
            .collect()
    }
}

// ── digests ─────────────────────────────────────────────────────────────

pub fn sha1_hex(bytes: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    hex::encode(Sha1::digest(bytes))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

pub fn sha512_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha512};
    hex::encode(Sha512::digest(bytes))
}

/// RFC 1321 MD5 (the dev-dependency set has no md5 crate; Gradle module
/// metadata and Maven sidecars still carry it).
pub fn md5_hex(bytes: &[u8]) -> String {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    // floor(|sin(i + 1)| * 2^32), tabulated: libm `sin` is not bit-identical
    // across platforms.
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];
    let mut state: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
    let mut msg = bytes.to_vec();
    let bit_len = (bytes.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());
    for chunk in msg.chunks(64) {
        let m: Vec<u32> = chunk
            .chunks(4)
            .map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
            .collect();
        let [mut a, mut b, mut c, mut d] = state;
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let rotated = a
                .wrapping_add(f)
                .wrapping_add(K[i])
                .wrapping_add(m[g])
                .rotate_left(S[i]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(rotated);
        }
        for (s, v) in state.iter_mut().zip([a, b, c, d]) {
            *s = s.wrapping_add(v);
        }
    }
    state
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .map(|b| format!("{b:02x}"))
        .collect()
}

// ── a minimal class-file writer ─────────────────────────────────────────

/// Just enough of JVMS §4 for public static methods without branches:
/// class version 52 (Java 8, loads on every JDK the matrix runs), no
/// StackMapTable needed, no constructor.
struct ClassFile {
    pool: Vec<Vec<u8>>,
    this: u16,
    object: u16,
    code_name: u16,
    methods: Vec<Vec<u8>>,
}

fn op_u2(op: u8, index: u16) -> Vec<u8> {
    let [hi, lo] = index.to_be_bytes();
    vec![op, hi, lo]
}

fn ldc(index: u16) -> Vec<u8> {
    match u8::try_from(index) {
        Ok(small) => vec![0x12, small],
        Err(_) => op_u2(0x13, index),
    }
}

impl ClassFile {
    fn new(name: &str) -> Self {
        let mut c = ClassFile {
            pool: Vec::new(),
            this: 0,
            object: 0,
            code_name: 0,
            methods: Vec::new(),
        };
        c.this = c.class(name);
        c.object = c.class("java/lang/Object");
        c.code_name = c.utf8("Code");
        c
    }

    fn add(&mut self, entry: Vec<u8>) -> u16 {
        if let Some(i) = self.pool.iter().position(|e| *e == entry) {
            return i as u16 + 1;
        }
        self.pool.push(entry);
        self.pool.len() as u16
    }

    fn utf8(&mut self, text: &str) -> u16 {
        let mut entry = vec![1];
        entry.extend((text.len() as u16).to_be_bytes());
        entry.extend(text.as_bytes());
        self.add(entry)
    }

    fn with_index(&mut self, tag: u8, indices: &[u16]) -> u16 {
        let mut entry = vec![tag];
        for i in indices {
            entry.extend(i.to_be_bytes());
        }
        self.add(entry)
    }

    fn class(&mut self, name: &str) -> u16 {
        let name = self.utf8(name);
        self.with_index(7, &[name])
    }

    fn string(&mut self, text: &str) -> u16 {
        let text = self.utf8(text);
        self.with_index(8, &[text])
    }

    fn name_and_type(&mut self, name: &str, descriptor: &str) -> u16 {
        let name = self.utf8(name);
        let descriptor = self.utf8(descriptor);
        self.with_index(12, &[name, descriptor])
    }

    fn methodref(&mut self, class: &str, name: &str, descriptor: &str) -> u16 {
        let class = self.class(class);
        let nt = self.name_and_type(name, descriptor);
        self.with_index(10, &[class, nt])
    }

    fn fieldref(&mut self, class: &str, name: &str, descriptor: &str) -> u16 {
        let class = self.class(class);
        let nt = self.name_and_type(name, descriptor);
        self.with_index(9, &[class, nt])
    }

    /// `public static <name><descriptor>` with no locals.
    fn method(&mut self, name: &str, descriptor: &str, max_stack: u16, code: Vec<u8>) {
        let name = self.utf8(name);
        let descriptor = self.utf8(descriptor);
        let mut m = Vec::new();
        m.extend(0x0009u16.to_be_bytes()); // ACC_PUBLIC | ACC_STATIC
        m.extend(name.to_be_bytes());
        m.extend(descriptor.to_be_bytes());
        m.extend(1u16.to_be_bytes());
        m.extend(self.code_name.to_be_bytes());
        m.extend((12 + code.len() as u32).to_be_bytes());
        m.extend(max_stack.to_be_bytes());
        m.extend(0u16.to_be_bytes()); // max_locals
        m.extend((code.len() as u32).to_be_bytes());
        m.extend(code);
        m.extend(0u16.to_be_bytes()); // exception table
        m.extend(0u16.to_be_bytes()); // attributes
        self.methods.push(m);
    }

    fn finish(self) -> Vec<u8> {
        let mut out = vec![0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52];
        out.extend((self.pool.len() as u16 + 1).to_be_bytes());
        for entry in &self.pool {
            out.extend(entry);
        }
        out.extend(0x0031u16.to_be_bytes()); // ACC_PUBLIC | ACC_FINAL | ACC_SUPER
        out.extend(self.this.to_be_bytes());
        out.extend(self.object.to_be_bytes());
        out.extend(0u16.to_be_bytes()); // interfaces
        out.extend(0u16.to_be_bytes()); // fields
        out.extend((self.methods.len() as u16).to_be_bytes());
        for m in &self.methods {
            out.extend(m);
        }
        out.extend(0u16.to_be_bytes()); // attributes
        out
    }
}

// ── regeneration ────────────────────────────────────────────────────────

/// Rewrite `SHA256SUMS` and re-sign every signed file with the committed
/// throwaway key (`gpg` with a scratch `GNUPGHOME`, a faked fixed signing
/// time, so the signatures are reproducible too).
fn regenerate(repo: &BTreeMap<String, Vec<u8>>) {
    let dir = fixtures_dir();
    std::fs::write(dir.join("SHA256SUMS"), sha256sums(repo)).unwrap();
    let gnupg = tempfile::tempdir().unwrap();
    let gpg = |args: &[&str]| {
        let out = std::process::Command::new("gpg")
            .env("GNUPGHOME", gnupg.path())
            .args(["--batch", "--yes", "--quiet"])
            .args(args)
            .output()
            .expect("run gpg");
        // Only gpg's stderr goes in the message: the arguments name the
        // signing-key file.
        assert!(
            out.status.success(),
            "gpg failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    let signing_key_path = dir.join("keys/signing-key.secret.asc");
    gpg(&["--import", signing_key_path.to_str().unwrap()]);
    let scratch = tempfile::tempdir().unwrap();
    for (path, bytes) in repo.iter().filter(|(p, _)| is_signed(p)) {
        let input = scratch.path().join("input");
        std::fs::write(&input, bytes).unwrap();
        let asc = dir.join("signatures").join(format!("{path}.asc"));
        std::fs::create_dir_all(asc.parent().unwrap()).unwrap();
        gpg(&[
            "--faked-system-time",
            "20260101T000000!",
            "--digest-algo",
            "SHA256",
            "--no-emit-version",
            "--armor",
            "--local-user",
            KEY_FINGERPRINT,
            "--output",
            asc.to_str().unwrap(),
            "--detach-sign",
            input.to_str().unwrap(),
        ]);
    }
}

fn path_of(root: &Path, rel: &str) -> PathBuf {
    rel.split('/').fold(root.to_path_buf(), |p, c| p.join(c))
}

// ── self-tests (integration crates get no cfg(test)) ────────────────────

mod jvm_fixture_repo_selftests {
    use super::*;

    /// The generator reproduces the committed digests byte-for-byte on this
    /// OS, and every signed file has its committed signature.
    #[test]
    fn jvm_fixture_repo_is_stable() {
        let repo = generate();
        if std::env::var_os(REGENERATE_ENV).is_some_and(|v| !v.is_empty()) {
            regenerate(&repo);
        }
        let committed = std::fs::read_to_string(fixtures_dir().join("SHA256SUMS")).unwrap();
        assert_eq!(
            sha256sums(&repo),
            committed,
            "the generated fixture repository drifted from fixtures/SHA256SUMS; \
             rerun with {REGENERATE_ENV}=1 if the change is intended"
        );
        let signatures = signatures();
        for path in repo.keys().filter(|p| is_signed(p)) {
            let asc = signatures
                .get(&format!("{path}.asc"))
                .unwrap_or_else(|| panic!("no committed signature for {path}"));
            assert!(
                asc.starts_with(b"-----BEGIN PGP SIGNATURE-----"),
                "{path}.asc"
            );
        }
        assert!(path_of(&fixtures_dir(), "keys/signing-key.public.asc").is_file());
        assert!(public_keyring_gpg().is_file());
    }

    #[test]
    fn the_patched_jar_has_a_leading_zero_sha1() {
        let repo = generate();
        let jar = &repo[&repo_path(VICTIM, VICTIM_VERSION, None, "jar")];
        assert!(sha1_hex(jar).starts_with('0'), "{}", sha1_hex(jar));
        let old = &repo[&repo_path(VICTIM, VICTIM_OLD, None, "jar")];
        assert_ne!(sha1_hex(old), sha1_hex(jar));
    }

    #[test]
    fn module_metadata_describes_the_served_jar() {
        let repo = generate();
        let jar = &repo[&repo_path(VICTIM, VICTIM_VERSION, None, "jar")];
        let module: serde_json::Value =
            serde_json::from_slice(&repo[&repo_path(VICTIM, VICTIM_VERSION, None, "module")])
                .unwrap();
        let file = &module["variants"][1]["files"][0];
        assert_eq!(file["name"], "victim-1.10.0.jar");
        assert_eq!(file["size"], jar.len());
        assert_eq!(file["sha1"], sha1_hex(jar));
        assert_eq!(file["sha256"], sha256_hex(jar));
        assert_eq!(file["md5"], md5_hex(jar));
        let pom = String::from_utf8(repo[&repo_path(VICTIM, VICTIM_VERSION, None, "pom")].clone())
            .unwrap();
        assert!(pom.contains("published-with-gradle-metadata"));
        assert!(pom
            .contains("</parent>\n  <artifactId>victim</artifactId>\n  <version>1.10.0</version>"));
        let range = String::from_utf8(
            repo[&repo_path(CONSUMER_RANGE, CONSUMER_VERSION, None, "pom")].clone(),
        )
        .unwrap();
        assert!(range.contains("<version>[1.9,1.11)</version>"));
    }

    #[test]
    fn md5_matches_rfc1321_vectors() {
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            md5_hex(
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            ),
            "57edf4a22be3c955ac49da2e2107b67a"
        );
    }

    #[test]
    fn class_files_are_well_formed() {
        let class = victim_class(VICTIM_VERSION, "patched");
        assert_eq!(&class[..8], &[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52]);
        let text = victim_marker(VICTIM_VERSION, "patched");
        assert!(class.windows(text.len()).any(|w| w == text.as_bytes()));
        assert_ne!(class, victim_class(VICTIM_VERSION, "pristine"));
        assert!(buildlogic_class()
            .windows(BUILDLOGIC_MARKER.len())
            .any(|w| w == BUILDLOGIC_MARKER.as_bytes()));
    }

    #[test]
    fn fake_central_serves_files_sidecars_and_overlays() {
        let central = FakeCentral::start();
        let get = |path: &str| {
            let url = format!("{}/{path}", central.uri());
            central.rt.block_on(async move {
                let response = reqwest::get(url).await.unwrap();
                let status = response.status().as_u16();
                (status, response.bytes().await.unwrap().to_vec())
            })
        };
        let jar_path = repo_path(VICTIM, VICTIM_VERSION, None, "jar");
        let jar = generate()[&jar_path].clone();
        assert_eq!(get(&jar_path), (200, jar.clone()));
        assert_eq!(
            get(&format!("{jar_path}.sha1")),
            (200, sha1_hex(&jar).into_bytes())
        );
        assert_eq!(get(&format!("{jar_path}.asc")).0, 200);
        assert_eq!(get("com/socketfixture/nope/1/nope-1.jar").0, 404);
        let url = central.serve_patched_jar("u-1", VICTIM, VICTIM_VERSION, b"patched");
        assert!(url.ends_with("/patched/u-1/victim-1.10.0.jar"));
        assert_eq!(
            get("patched/u-1/victim-1.10.0.jar"),
            (200, b"patched".to_vec())
        );
        central.remove("patched/u-1/victim-1.10.0.jar");
        assert_eq!(get("patched/u-1/victim-1.10.0.jar").0, 404);
        assert!(central.requests().contains(&format!("/{jar_path}")));
    }
}
