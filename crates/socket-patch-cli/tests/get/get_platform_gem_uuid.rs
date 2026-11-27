//! `get <uuid>` where the uuid names the patch of ONE PLATFORM GEM (its
//! record's purl is `pkg:gem/<name>@<version>?platform=<platform>`),
//! against a stand-in patch service (the real binary; no Ruby or Bundler
//! runs here).
//!
//! In hosted and vendored mode a gem is patched through the patch of the
//! gem itself, whose reference names the patched build of every platform.
//! The patch of one platform gem is no fix of its own there, so the run
//! takes the patch it was built from, which that patch's package reference
//! names (`rebuiltFromUuid`), and goes on as `get <that uuid>` does:
//!
//! * the project is left file for file as `get <the gem patch's uuid>`
//!   leaves it, in both modes;
//! * one plain line says which patch was taken (stderr, once, fitted to a
//!   terminal's width; nothing under `--silent`), and the `--json`
//!   envelope names the patch that was asked for under `platformGemPatch`;
//! * it costs one reference request more, for the platform gem's patch;
//! * with no patch named for the build to come from, nothing is written
//!   and the run names the command to run instead: hosted mode pins
//!   nothing under a warning, vendored mode refuses
//!   `platform_gem_unsupported`;
//! * agent mode applies the platform gem's own record to the installed
//!   copy of that platform, with no reference request;
//! * the uuid of a patch of the gem itself, and of a patch of another
//!   ecosystem, cost no request of this kind.

use std::collections::BTreeMap;
use std::path::Path;

use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha512};
use wiremock::matchers::{method, path as wm_path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::envelope::{
    envelope_error_code, envelope_error_message, event_triples, parse_json_envelope,
};
use crate::common::{self, git_sha256, sha256_hex};

const ORG: &str = "test-org";
/// A name nothing on the developer's machine can have installed.
const NAME: &str = "sockplatget";
const VERSION: &str = "1.0.0";
const PURL: &str = "pkg:gem/sockplatget@1.0.0";
/// The gem's patch: the patch of its ruby gem, the one fix of the gem.
const UUID: &str = "6e7f0000-0000-4000-8000-000000000001";
const DARWIN: &str = "arm64-darwin";
const LINUX: &str = "x86_64-linux-gnu";
/// The patches of its two patched platform gems.
const DARWIN_UUID: &str = "6e7f0000-0000-4000-8000-0000000000da";
const LINUX_UUID: &str = "6e7f0000-0000-4000-8000-0000000000f1";
const TOKEN: &str = "66666666-6666-4666-8666-666666666666";
const LIB: &str = "lib/sockplatget.rb";
const SO: &str = "lib/sockplatget/ext.so";
const PRISTINE: &[u8] = b"module SockPlatGet; VERSION = '1.0.0'; end\n";
const PATCHED: &[u8] = b"module SockPlatGet; VERSION = '1.0.0'; SAFE = true; end\n";
const GHSA: &str = "GHSA-plat-form-gems";
/// Shaped like a Socket API token, so no run warns about the token itself.
const API_TOKEN: &str = "sktsec_00000000000000000000000000000000000000000000_api";

const GEMFILE: &str = "source \"https://rubygems.org\"\n\ngem \"sockplatget\", \"~> 1.0\"\n";

/// Bundler's lock of a project that takes the gem as its two precompiled
/// platform gems.
fn lock() -> String {
    format!(
        "GEM\n  remote: https://rubygems.org/\n  specs:\n    {NAME} ({VERSION}-{DARWIN})\n    \
         {NAME} ({VERSION}-{LINUX})\n\nPLATFORMS\n  {DARWIN}\n  {LINUX}\n\nDEPENDENCIES\n  \
         {NAME} (~> 1.0)\n\nBUNDLED WITH\n   2.5.22\n"
    )
}

/// A minimal `.gem`: an uncompressed tar whose `data.tar.gz` holds `files`.
fn make_gem(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut data = tar::Builder::new(Vec::new());
    for (path, bytes) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        data.append_data(&mut header, path, *bytes).unwrap();
    }
    let data_tar = data.into_inner().unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut gz, &data_tar).unwrap();
    let data_tar_gz = gz.finish().unwrap();
    let mut gem = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(data_tar_gz.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    gem.append_data(&mut header, "data.tar.gz", data_tar_gz.as_slice())
        .unwrap();
    gem.into_inner().unwrap()
}

/// The patched gem of `platform`: the patched Ruby file and the platform's
/// own binary.
fn platform_gem(platform: &str) -> Vec<u8> {
    make_gem(&[(LIB, PATCHED), (SO, platform.as_bytes())])
}

fn stub(platform: &str) -> Vec<u8> {
    format!(
        "Gem::Specification.new do |s|\n  s.name = \"{NAME}\"\n  s.version = \"{VERSION}\"\n  \
         s.platform = \"{platform}\"\n  s.summary = \"a synthetic fixture gem\"\n  \
         s.authors = [\"Socket\"]\n  s.require_paths = [\"lib\"]\nend\n"
    )
    .into_bytes()
}

fn sri(bytes: &[u8]) -> String {
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes))
    )
}

fn build_uuid(platform: &str) -> &'static str {
    match platform {
        DARWIN => DARWIN_UUID,
        _ => LINUX_UUID,
    }
}

/// A patch record as the patch API's view serves it.
fn patch_view(uuid: &str, purl: &str) -> Value {
    json!({
        "uuid": uuid,
        "purl": purl,
        "publishedAt": "2026-01-01T00:00:00Z",
        "files": {
            LIB: {
                "beforeHash": git_sha256(PRISTINE),
                "afterHash": git_sha256(PATCHED),
                "blobContent": base64::engine::general_purpose::STANDARD.encode(PATCHED),
            }
        },
        "vulnerabilities": {
            GHSA: {
                "cves": ["CVE-2026-31337"],
                "summary": "a synthetic vulnerability",
                "severity": "high",
                "description": "details"
            }
        },
        "description": "synthetic platform gem patch",
        "license": "MIT",
        "tier": "free"
    })
}

/// What the reference of a platform gem's patch says of the patch it was
/// built from.
#[derive(Clone, Copy, Debug)]
enum BuiltFrom {
    /// `rebuiltFromUuid`: the gem's patch.
    Gem,
    /// No such field.
    Absent,
    /// `rebuiltFromUuid: null`.
    Null,
    /// A value that is no patch uuid.
    Malformed,
    /// The uuid of a patch the service has no record of.
    Unknown,
    /// The patch of the gem's other platform gem.
    PlatformPatch,
    /// The reference request answers nothing for the patch.
    NoResult,
}

/// A uuid the stand-in has no record of.
const UNKNOWN_UUID: &str = "6e7f0000-0000-4000-8000-00000000dead";
/// A second patch of the gem itself, whose record spells its purl with
/// `?platform=ruby`, and a patch of an npm package. The stand-in grants
/// neither a reference.
const RUBY_UUID: &str = "6e7f0000-0000-4000-8000-0000000000b1";
const NPM_UUID: &str = "6e7f0000-0000-4000-8000-0000000000c2";
const NPM_PURL: &str = "pkg:npm/sockplatget-js@1.0.0";

/// The patch service of the one gem: the gem's patch, whose reference
/// lists the version's gems (`gemBuilds`) under a registry snapshot, and
/// the patch of each platform gem, whose reference serves that gem and
/// its stub gemspec and names the gem's patch as `built_from` says.
async fn service(built_from: BuiltFrom) -> MockServer {
    let server = MockServer::start().await;
    let api = server.uri();
    let mut results = serde_json::Map::new();
    let ruby_gem = make_gem(&[(LIB, PATCHED)]);
    let mut gem_builds = vec![json!({
        "platform": "ruby", "gemChecksumSha256": sha256_hex(&ruby_gem), "patchUuid": UUID
    })];
    for platform in [DARWIN, LINUX] {
        let own = build_uuid(platform);
        let (gem, gemspec) = (platform_gem(platform), stub(platform));
        let base = format!("/patch/gem/{NAME}/{VERSION}/{TOKEN}/{own}/{NAME}-{VERSION}-{platform}");
        let mut artifacts = Vec::new();
        for (kind, ext, bytes) in [
            ("tarball", "gem", &gem),
            ("gem-stub-gemspec", "gemspec", &gemspec),
        ] {
            let route = format!("{base}.{ext}");
            artifacts.push(json!({
                "kind": kind,
                "url": format!("{api}{route}"),
                "integrity": { "sha512": sri(bytes) }
            }));
            Mock::given(method("GET"))
                .and(wm_path(route))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes.clone()))
                .mount(&server)
                .await;
        }
        gem_builds.push(json!({
            "platform": platform, "gemChecksumSha256": sha256_hex(&gem), "patchUuid": own
        }));
        let purl = format!("{PURL}?platform={platform}");
        let mut reference = json!({
            "status": "granted",
            "purl": purl,
            "url": format!("{api}{base}.gem"),
            "artifacts": artifacts,
        });
        match built_from {
            BuiltFrom::Gem => reference["rebuiltFromUuid"] = json!(UUID),
            BuiltFrom::Absent | BuiltFrom::NoResult => {}
            BuiltFrom::Null => reference["rebuiltFromUuid"] = Value::Null,
            BuiltFrom::Malformed => reference["rebuiltFromUuid"] = json!("../view/elsewhere"),
            BuiltFrom::Unknown => reference["rebuiltFromUuid"] = json!(UNKNOWN_UUID),
            BuiltFrom::PlatformPatch => reference["rebuiltFromUuid"] = json!(DARWIN_UUID),
        }
        if !matches!(built_from, BuiltFrom::NoResult) {
            results.insert(own.to_string(), reference);
        }
        mount_view(&server, own, &purl).await;
    }
    gem_builds.sort_by_key(|build| build["platform"].as_str().map(str::to_string));
    let ruby_url = format!("{api}/patch/gem/{NAME}/{VERSION}/{TOKEN}/{UUID}/{NAME}-{VERSION}.gem");
    results.insert(
        UUID.to_string(),
        json!({
            "status": "granted",
            "purl": PURL,
            "url": ruby_url,
            "artifacts": [{ "kind": "tarball", "url": ruby_url,
                            "integrity": { "sha512": sri(&ruby_gem),
                                           "sha256": sha256_hex(&ruby_gem) } }],
            "registryOverride": {
                "kind": "rubygems-compact-index",
                "indexUrl": format!("{api}/patch-registry/gem/{TOKEN}/{UUID}/s/4f0a/"),
                "identifiers": {
                    "name": NAME, "version": VERSION,
                    "gemChecksumSha256": sha256_hex(&ruby_gem),
                    "gemBuilds": gem_builds
                }
            }
        }),
    );
    Mock::given(method("POST"))
        .and(wm_path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(move |request: &wiremock::Request| {
            let asked: Value = serde_json::from_slice(&request.body).unwrap_or_default();
            let answered: serde_json::Map<String, Value> = asked["uuids"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|uuid| {
                    let uuid = uuid.as_str()?;
                    Some((uuid.to_string(), results.get(uuid)?.clone()))
                })
                .collect();
            ResponseTemplate::new(200).set_body_json(json!({ "results": answered }))
        })
        .mount(&server)
        .await;
    mount_view(&server, UUID, PURL).await;
    mount_view(&server, RUBY_UUID, &format!("{PURL}?platform=ruby")).await;
    mount_view(&server, NPM_UUID, NPM_PURL).await;
    server
}

async fn mount_view(server: &MockServer, uuid: &str, purl: &str) {
    Mock::given(method("GET"))
        .and(wm_path(format!("/v0/orgs/{ORG}/patches/view/{uuid}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(patch_view(uuid, purl)))
        .mount(server)
        .await;
}

/// The patch API calls `server` has seen since its first `skip` requests:
/// the uuids each reference request named, and the uuid of each record
/// that was fetched, in arrival order.
async fn api_calls(server: &MockServer, skip: usize) -> (Vec<Vec<String>>, Vec<String>) {
    let requests = server.received_requests().await.unwrap_or_default();
    let mut references = Vec::new();
    let mut views = Vec::new();
    for request in requests.iter().skip(skip) {
        let route = request.url.path();
        if route.ends_with("/patches/package") {
            let asked: Value = serde_json::from_slice(&request.body).unwrap_or_default();
            let uuids = asked["uuids"].as_array().into_iter().flatten();
            references.push(
                uuids
                    .filter_map(|uuid| Some(uuid.as_str()?.to_string()))
                    .collect(),
            );
        } else if let Some((_, uuid)) = route.rsplit_once("/patches/view/") {
            views.push(uuid.to_string());
        }
    }
    (references, views)
}

async fn request_count(server: &MockServer) -> usize {
    server.received_requests().await.unwrap_or_default().len()
}

/// A Bundler project that locks the gem as its two platform gems, in a
/// new temp dir.
fn project() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("Gemfile"), GEMFILE).unwrap();
    std::fs::write(dir.path().join("Gemfile.lock"), lock()).unwrap();
    dir
}

/// The arguments of `socket-patch get <uuid> [--mode <mode>]` against
/// `api`, with `extra` ones.
fn get_args<'a>(
    api: &'a str,
    uuid: &'a str,
    mode: Option<&'a str>,
    extra: &[&'a str],
) -> Vec<&'a str> {
    let mut args = vec!["get", uuid, "--yes", "--api-url", api, "--proxy-url", api];
    args.extend_from_slice(&["--org", ORG, "--api-token", API_TOKEN]);
    if let Some(mode) = mode {
        args.extend_from_slice(&["--mode", mode]);
    }
    args.extend_from_slice(extra);
    args
}

/// `socket-patch get <uuid> [--mode <mode>]` at `root` against `api`,
/// with `extra` arguments.
fn get(
    root: &Path,
    api: &str,
    uuid: &str,
    mode: Option<&str>,
    extra: &[&str],
) -> (i32, String, String) {
    common::run_with_env(root, &get_args(api, uuid, mode, extra), &[])
}

/// [`get`] under `--json`: the exit code, the envelope and stderr.
fn get_json(root: &Path, api: &str, uuid: &str, mode: &str) -> (i32, Value, String) {
    let (code, stdout, stderr) = get(root, api, uuid, Some(mode), &["--json"]);
    (code, parse_json_envelope(&stdout), stderr)
}

/// Every file under `root` with its content, by `/`-joined relative path.
/// A file reads as text (every file these runs write is text) with the
/// one thing that differs from run to run, the time a copy was vendored,
/// blanked.
fn tree(root: &Path) -> BTreeMap<String, String> {
    fn walk(dir: &Path, root: &Path, out: &mut BTreeMap<String, String>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, root, out);
                continue;
            }
            let rel: Vec<String> = path
                .strip_prefix(root)
                .unwrap()
                .components()
                .map(|part| part.as_os_str().to_string_lossy().into_owned())
                .collect();
            let text = String::from_utf8(std::fs::read(&path).unwrap())
                .unwrap_or_else(|_| panic!("{} is not text", path.display()));
            let lines: Vec<&str> = text
                .split_inclusive('\n')
                .map(
                    |line| match line.trim_start().starts_with("\"vendoredAt\":") {
                        true => "  \"vendoredAt\": <time>\n",
                        false => line,
                    },
                )
                .collect();
            out.insert(rel.join("/"), lines.concat());
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

/// The files of a project no run has touched.
fn untouched() -> BTreeMap<String, String> {
    tree(project().path())
}

/// The line a run prints when it takes the gem's patch for the patch of
/// the `x86_64-linux-gnu` gem.
fn taken_line(mode: &str) -> String {
    format!(
        "{LINUX_UUID} is the patch of {NAME} {VERSION}'s {LINUX} build; {mode} mode takes the \
         gem's patch {UUID}, which it was built from"
    )
}

/// What a run says when it finds no gem's patch to take for the patch of
/// the `x86_64-linux-gnu` gem: the command to run instead.
fn remedy(mode: &str) -> String {
    format!("Run `socket-patch get {PURL} --mode {mode}` instead")
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| item.to_string()).collect()
}

/// `get <the platform gem's patch>` against `get <the gem's patch>` in
/// `mode`: the same files, the same output but for the one line (stderr,
/// once), and the one reference request and record fetch it takes to find
/// the gem's patch. Returns the reference requests of the gem's own run.
/// Every other request is the gem's own run's: in vendored mode that
/// includes the record of each platform gem's own patch.
async fn assert_takes_the_gems_patch(mode: &str) -> Vec<Vec<String>> {
    let server = service(BuiltFrom::Gem).await;
    let api = server.uri();
    let line = taken_line(mode);

    let by_gem = project();
    let (code, gem_stdout, gem_stderr) = get(by_gem.path(), &api, UUID, Some(mode), &[]);
    assert_eq!(code, 0, "{gem_stdout}\n{gem_stderr}");
    let (gem_references, gem_views) = api_calls(&server, 0).await;
    // Vendored mode also reads the record of each platform gem's own
    // patch, which it checks that gem's tree against.
    let build_views: &[&str] = match mode {
        "vendored" => &[DARWIN_UUID, LINUX_UUID],
        _ => &[],
    };
    let sorted = |views: &[String]| {
        let mut views = views.to_vec();
        views.sort();
        views
    };
    assert_eq!(gem_views[..1], [UUID]);
    assert_eq!(sorted(&gem_views[1..]), sorted(&strings(build_views)));
    assert!(!gem_stderr.contains("is the patch of"), "{gem_stderr}");
    let written = tree(by_gem.path());
    assert_ne!(
        written,
        untouched(),
        "the gem's own run patches the project"
    );

    let seen = request_count(&server).await;
    let by_platform = project();
    let (code, stdout, stderr) = get(by_platform.path(), &api, LINUX_UUID, Some(mode), &[]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert_eq!(tree(by_platform.path()), written, "{stdout}\n{stderr}");
    assert_eq!(stdout, gem_stdout);
    assert_eq!(
        stderr,
        format!("{line}\n{gem_stderr}"),
        "the line once, then the gem's own run"
    );
    let (references, views) = api_calls(&server, seen).await;
    let mut expected = vec![strings(&[LINUX_UUID])];
    expected.extend(gem_references.iter().cloned());
    assert_eq!(references, expected, "one reference request more");
    assert_eq!(views[..2], [LINUX_UUID, UUID]);
    assert_eq!(sorted(&views[2..]), sorted(&strings(build_views)));

    // `--json`: the envelope of the gem's own run, and the patch that was
    // named. Nothing on stderr.
    let (_, gem_env, _) = get_json(project().path(), &api, UUID, mode);
    let json_project = project();
    let (code, mut env, stderr) = get_json(json_project.path(), &api, LINUX_UUID, mode);
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert_eq!(tree(json_project.path()), written);
    assert!(!stderr.contains("is the patch of"), "{stderr}");
    let named = env.as_object_mut().unwrap().remove("platformGemPatch");
    assert_eq!(
        named,
        Some(json!({
            "uuid": LINUX_UUID,
            "purl": format!("{PURL}?platform={LINUX}"),
            "platform": LINUX,
            "gemFix": UUID,
        }))
    );
    assert_eq!(env, gem_env);
    assert!(gem_env.get("platformGemPatch").is_none(), "{gem_env:#}");

    // `--silent`: the same files and not a word.
    let silent = project();
    let (code, stdout, stderr) = get(silent.path(), &api, LINUX_UUID, Some(mode), &["--silent"]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert_eq!(tree(silent.path()), written);
    assert_eq!((stdout.as_str(), stderr.as_str()), ("", ""));

    // A dry run says which patch it would take, and writes nothing.
    let dry = project();
    let (code, stdout, stderr) = get(dry.path(), &api, LINUX_UUID, Some(mode), &["--dry-run"]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert_eq!(tree(dry.path()), untouched());
    assert_eq!(stderr.matches(&line).count(), 1, "{stderr}");
    gem_references
}

/// Hosted mode: the lock and the Gemfile move to the gem's patch registry
/// exactly as for the gem patch's own uuid.
#[tokio::test(flavor = "multi_thread")]
async fn hosted_mode_takes_the_gems_patch_for_a_platform_gems_patch() {
    let gem_references = assert_takes_the_gems_patch("hosted").await;
    assert_eq!(gem_references, [strings(&[UUID])]);
}

/// Vendored mode: one tree per locked platform, each from its own patch,
/// exactly as for the gem patch's own uuid.
#[tokio::test(flavor = "multi_thread")]
async fn vendored_mode_takes_the_gems_patch_for_a_platform_gems_patch() {
    let gem_references = assert_takes_the_gems_patch("vendored").await;
    assert_eq!(
        gem_references,
        [strings(&[UUID]), strings(&[DARWIN_UUID, LINUX_UUID])]
    );
}

/// On a terminal the line is fitted to its width: it breaks after its
/// first clause where that fits and between words where it does not,
/// under a hanging indent, and no uuid or platform name is cut in two.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn the_line_breaks_between_words_on_a_terminal() {
    let server = service(BuiltFrom::Gem).await;
    for cols in [80u16, 100, 120] {
        let proj = project();
        let cwd = proj.path().to_path_buf();
        let api = server.uri();
        let run = tokio::task::spawn_blocking(move || {
            crate::pty_io::run_command_at(
                cols,
                common::hermetic::pty_binary_command(),
                &get_args(&api, LINUX_UUID, Some("hosted"), &[]),
                &cwd,
                &[],
                &[],
                std::time::Duration::from_secs(60),
            )
        })
        .await
        .expect("spawn_blocking join");
        let screen = crate::pty_io::render(run.output.as_bytes());
        let shown = screen.join("\n");
        println!("--- {cols} columns\n{shown}");
        assert_eq!(run.code, 0, "{shown}");
        let from = screen.iter().position(|row| row.starts_with(LINUX_UUID));
        let to = screen
            .iter()
            .position(|row| row.starts_with("Found patch for"));
        let (Some(from), Some(to)) = (from, to) else {
            panic!("no line, or nothing after it:\n{shown}");
        };
        let rows = &screen[from..to];
        assert!(rows.len() > 1, "{shown}");
        let words: Vec<&str> = rows.iter().map(|row| row.trim_start()).collect();
        assert_eq!(words.join(" "), taken_line("hosted"), "{shown}");
        for (at, row) in rows.iter().enumerate() {
            assert!(row.chars().count() <= usize::from(cols), "{row:?}\n{shown}");
            assert_eq!(row.starts_with("  "), at > 0, "{row:?}\n{shown}");
        }
    }
}

/// A reference that names no patch the build came from, or names one the
/// run cannot take (no patch uuid, no record, another platform gem's
/// patch), leaves the run where it was: hosted mode pins nothing and
/// exits 0, vendored mode refuses `platform_gem_unsupported` and exits 1.
/// Both say what to run instead, and neither writes a file.
#[tokio::test(flavor = "multi_thread")]
async fn a_platform_gems_patch_with_no_gem_patch_to_take_names_the_command_to_run() {
    for built_from in [
        BuiltFrom::Absent,
        BuiltFrom::Null,
        BuiltFrom::Malformed,
        BuiltFrom::Unknown,
        BuiltFrom::PlatformPatch,
        BuiltFrom::NoResult,
    ] {
        let server = service(built_from).await;
        let api = server.uri();
        let platform_purl = format!("{PURL}?platform={LINUX}");

        // Hosted, for a person and under `--json`.
        let hosted = project();
        let (code, stdout, stderr) = get(hosted.path(), &api, LINUX_UUID, Some("hosted"), &[]);
        assert_eq!(code, 0, "{built_from:?}\n{stdout}\n{stderr}");
        assert_eq!(tree(hosted.path()), untouched(), "{built_from:?}");
        assert_eq!(
            stdout,
            "Switched 0 packages to hosted patches; rewrote 0 files.\n"
        );
        let warning = format!(
            "Warning: {LINUX_UUID} is the patch of {NAME} {VERSION}'s {LINUX} build, which hosted \
             mode does not take by itself: it patches a gem through the gem's own patch. {}\n",
            remedy("hosted")
        );
        assert_eq!(
            stderr.matches(&warning).count(),
            1,
            "{built_from:?}\n{stderr}"
        );
        assert!(!stderr.contains("takes the gem's patch"), "{stderr}");
        let (code, env, stderr) = get_json(project().path(), &api, LINUX_UUID, "hosted");
        assert_eq!(code, 0, "{built_from:?}\n{env:#}\n{stderr}");
        assert_eq!(env["status"], "success", "{env:#}");
        // What the hosted engine says of a patch it has no registry for,
        // or no reference at all.
        let skip = match built_from {
            BuiltFrom::NoResult => "not_found",
            _ => "redirect_unconfirmed",
        };
        assert_eq!(
            event_triples(&env),
            [(
                platform_purl.clone(),
                "skipped".to_string(),
                skip.to_string()
            )],
            "{env:#}"
        );
        let warnings = env["warnings"].as_array().unwrap();
        let named: Vec<&Value> = warnings
            .iter()
            .filter(|warning| warning["code"] == "platform_gem_patch_not_taken")
            .collect();
        assert_eq!(named.len(), 1, "{env:#}");
        let detail = named[0]["detail"].as_str().unwrap();
        assert!(detail.ends_with(&remedy("hosted")), "{detail}");
        assert!(env.get("platformGemPatch").is_none(), "{env:#}");

        // Vendored: refused before anything is downloaded or written.
        let vendored = project();
        let (code, stdout, stderr) = get(vendored.path(), &api, LINUX_UUID, Some("vendored"), &[]);
        assert_eq!(code, 1, "{built_from:?}\n{stdout}\n{stderr}");
        assert_eq!(tree(vendored.path()), untouched(), "{built_from:?}");
        assert!(
            stderr.contains("platform_gem_unsupported") && stderr.contains(&remedy("vendored")),
            "{built_from:?}\n{stderr}"
        );
        assert!(!stderr.contains("--mode agent"), "{stderr}");
        let json_project = project();
        let (code, env, stderr) = get_json(json_project.path(), &api, LINUX_UUID, "vendored");
        assert_eq!(code, 1, "{built_from:?}\n{env:#}\n{stderr}");
        assert_eq!(tree(json_project.path()), untouched(), "{built_from:?}");
        assert_eq!(
            envelope_error_code(&env),
            Some("platform_gem_unsupported"),
            "{env:#}"
        );
        let message = envelope_error_message(&env).unwrap();
        assert!(message.ends_with(&remedy("vendored")), "{message}");
        assert_eq!(
            event_triples(&env),
            [(
                platform_purl,
                "failed".to_string(),
                "platform_gem_unsupported".to_string()
            )],
            "{env:#}"
        );
        assert!(env.get("platformGemPatch").is_none(), "{env:#}");

        // No artifact was downloaded, and a value that is no patch uuid
        // never reached a request.
        let requests = server.received_requests().await.unwrap_or_default();
        let routes: Vec<&str> = requests.iter().map(|request| request.url.path()).collect();
        assert!(
            !routes
                .iter()
                .any(|route| route.starts_with("/patch/gem/") || route.contains("elsewhere")),
            "{built_from:?}\n{routes:?}"
        );
    }
}

/// Agent mode patches the installed copy of that platform's gem with the
/// platform gem's own record: no reference request, no other patch, and
/// the manifest records the patch that was named. A run with no `--mode`
/// over that project keeps agent mode and does the same.
#[tokio::test(flavor = "multi_thread")]
async fn agent_mode_applies_the_platform_gems_own_patch() {
    let server = service(BuiltFrom::Gem).await;
    let api = server.uri();
    let proj = tempfile::tempdir().unwrap();
    let installed = proj
        .path()
        .join("vendor/bundle/ruby/3.3.0/gems")
        .join(format!("{NAME}-{VERSION}-{LINUX}"))
        .join(LIB);
    std::fs::create_dir_all(installed.parent().unwrap()).unwrap();
    std::fs::write(&installed, PRISTINE).unwrap();

    let (code, stdout, stderr) = get(proj.path(), &api, LINUX_UUID, Some("agent"), &[]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert_eq!(std::fs::read(&installed).unwrap(), PATCHED);
    assert!(!stderr.contains("is the patch of"), "{stderr}");
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(proj.path().join(".socket/manifest.json")).unwrap())
            .unwrap();
    let patches = manifest["patches"].as_object().unwrap();
    assert_eq!(
        patches.keys().collect::<Vec<_>>(),
        [&format!("{PURL}?platform={LINUX}")]
    );
    assert_eq!(
        patches[&format!("{PURL}?platform={LINUX}")]["uuid"],
        LINUX_UUID
    );
    let (references, views) = api_calls(&server, 0).await;
    assert_eq!(references, Vec::<Vec<String>>::new());
    assert_eq!(views, [LINUX_UUID]);

    // No `--mode`: the manifest holds a patch, so the run keeps agent mode.
    let seen = request_count(&server).await;
    let (code, stdout, stderr) = get(proj.path(), &api, LINUX_UUID, None, &[]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert_eq!(std::fs::read(&installed).unwrap(), PATCHED);
    assert!(!stderr.contains("is the patch of"), "{stderr}");
    let (references, views) = api_calls(&server, seen).await;
    assert_eq!(references, Vec::<Vec<String>>::new());
    assert_eq!(views, [LINUX_UUID]);
}

/// The uuid of a patch of the gem itself (whose record may spell its purl
/// with `?platform=ruby`) and the uuid of a patch of another ecosystem
/// are what the run takes, in hosted and vendored mode: each record is
/// fetched once, the run says nothing of a platform gem's patch, and the
/// only reference request is the one the hosted run makes for that uuid.
#[tokio::test(flavor = "multi_thread")]
async fn other_uuids_cost_no_request_and_no_line() {
    let server = service(BuiltFrom::Gem).await;
    let api = server.uri();
    for uuid in [RUBY_UUID, NPM_UUID] {
        for mode in ["hosted", "vendored"] {
            let seen = request_count(&server).await;
            let proj = project();
            let (_, stdout, stderr) = get(proj.path(), &api, uuid, Some(mode), &[]);
            assert!(
                !stderr.contains("is the patch of") && !stderr.contains("gem's own patch"),
                "{uuid} {mode}\n{stdout}\n{stderr}"
            );
            let (references, views) = api_calls(&server, seen).await;
            assert_eq!(views, [uuid], "{uuid} {mode}");
            // The mode's own request for the patch's reference, where it
            // gets that far: the vendor step stops at the npm package,
            // which this project has no lockfile for.
            let own: &[&str] = match (uuid, mode) {
                (NPM_UUID, "vendored") => &[],
                _ => &[uuid],
            };
            let own: Vec<Vec<String>> = own.iter().map(|uuid| strings(&[uuid])).collect();
            assert_eq!(references, own, "{uuid} {mode}\n{stdout}\n{stderr}");
        }
    }
}
