//! Real Bun binary-lock acceptance tests. The CLI must never invoke a Bun
//! conversion or replace bun.lockb with text. Every terminal mode is checked
//! with an empty-cache frozen install, and rollback restores the exact input
//! (v5: a hosted pin in a binary lock is refused by rollback — restored from
//! version control instead — while a vendor takeover rebuilds its registry
//! record from the npm registry, refusing only offline).
//!
//! Run scripts/backtest-bun-lockb.py for the writer/reader release matrix.
//! SOCKET_PATCH_BUN_LOCKB_REQUIRED=1 makes missing tools a hard error;
//! SOCKET_PATCH_BUN_LOCKB_WRITER points at the writer when testing a newer
//! reader against a binary lock from an older release.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha512};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "vex_e2e_common/bun.rs"]
mod bun_vex;
#[path = "common/cache_env.rs"]
mod cache_env;
mod prebuilt_common;

const ORG: &str = "binary-bun-test";
const PURL: &str = "pkg:npm/minimist@1.2.2";
const UUID: &str = "80630680-4da6-45f9-bba8-b888e0ffd58c";
const MARKER: &[u8] = b"/* SOCKET BINARY LOCK PATCH */\n";
/// The vulnerability the patch record carries (staged manifest and API
/// view alike) — what manifest-less VEX must attest.
const GHSA: &str = "GHSA-bunb-lock-0001";
const CVE: &str = "CVE-2026-4444";

fn command(program: impl AsRef<std::ffi::OsStr>, cwd: &Path) -> Command {
    let mut command = Command::new(program);
    command.current_dir(cwd);
    cache_env::scrub_ambient_bun_env(&mut command);
    cache_env::isolate(&mut command);
    // Historical Bun releases derive temporary filenames from timestamps.
    // Parallel writer/reader cells must not share their extraction directory.
    let temporary = cwd.parent().unwrap().join("tool-tmp");
    std::fs::create_dir_all(&temporary).unwrap();
    for key in ["TMPDIR", "TMP", "TEMP", "BUN_TMPDIR"] {
        command.env(key, &temporary);
    }
    command
        .env("SOCKET_NO_CONFIG", "1")
        .env("SOCKET_NO_UPDATE_CHECK", "1");
    command
}

fn require_success(output: Output, label: &str) -> Output {
    assert!(
        output.status.success(),
        "{label}: {:?}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn cli(project: &Path, args: &[&str]) -> Value {
    cli_env(project, args, &[])
}

/// [`cli`] with extra environment variables.
fn cli_env(project: &Path, args: &[&str], envs: &[(&str, &str)]) -> Value {
    let mut cmd = command(env!("CARGO_BIN_EXE_socket-patch"), project);
    let _prebuilt = prebuilt_common::prepare_command(&mut cmd, project, args, envs);
    let output = require_success(
        cmd.envs(envs.iter().copied())
            .args([
                "--cwd",
                project.to_str().unwrap(),
                "--json",
                "--no-telemetry",
            ])
            .output()
            .unwrap(),
        &format!("socket-patch {args:?}"),
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{error}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

/// [`cli`] for a run expected to fail: `(exit code, envelope)`.
fn cli_code(project: &Path, args: &[&str]) -> (i32, Value) {
    let output = command(env!("CARGO_BIN_EXE_socket-patch"), project)
        .args(args)
        .args([
            "--cwd",
            project.to_str().unwrap(),
            "--json",
            "--no-telemetry",
        ])
        .output()
        .unwrap();
    let envelope = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{error}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output.status.code().unwrap_or(-1), envelope)
}

/// v5 keeps no hosted ledger, so undoing a hosted pin means restoring the
/// entry's upstream registry form. For a binary `bun.lockb` only a vendor
/// takeover rebuilds that record (it refuses a workspace-normalized lock), so
/// `rollback` REFUSES the pin, naming the checkout remedy, and leaves the
/// lock exactly as found; the test then applies that remedy (`git checkout --
/// bun.lockb`, here: the original bytes written back).
fn rollback_refuses_binary_hosted_pin_then_checkout(fixture: &Fixture, server: &MockServer) {
    let hosted_lock = fixture.lock();
    let uri = server.uri();
    let (code, env) = cli_code(
        &fixture.project,
        &["rollback", "--yes", "--patch-server-url", &uri],
    );
    assert_eq!(code, 1, "a binary hosted pin cannot be restored: {env}");
    assert_eq!(env["status"], "partial_failure", "{env}");
    let failed = env["hosted"]["failed"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        failed.iter().any(|f| f["purl"] == PURL
            && f["error"]
                .as_str()
                .is_some_and(|e| e.contains("git checkout -- bun.lockb"))),
        "the refusal names the checkout remedy: {env}"
    );
    assert_eq!(
        fixture.lock(),
        hosted_lock,
        "a refused restore writes nothing"
    );
    assert!(
        !fixture
            .project
            .join(".socket/vendor/redirect-state.json")
            .exists(),
        "no hosted ledger exists"
    );
    std::fs::write(fixture.project.join("bun.lockb"), &fixture.original_lock).unwrap();
}

fn scan(project: &Path, server: &MockServer, mode: &str, extra: &[&str]) -> Value {
    let uri = server.uri();
    let mut args = vec![
        "scan",
        "--mode",
        mode,
        "--yes",
        "--api-url",
        &uri,
        "--api-token",
        "fake",
        "--org",
        ORG,
    ];
    if mode == "vendored" {
        args.extend(["--vendor-source", "service"]);
    }
    args.extend_from_slice(extra);
    cli(project, &args)
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk(root: &Path, dir: &Path, result: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.file_name().unwrap() == "node_modules" {
                continue;
            }
            if path.is_dir() {
                walk(root, &path, result);
            } else {
                // Every run removes its `apply.lock` on exit, so the
                // snapshot deliberately does NOT exclude it: a surviving
                // lock file is a real before/after difference.
                let relative = path.strip_prefix(root).unwrap();
                result.insert(relative.to_path_buf(), std::fs::read(path).unwrap());
            }
        }
    }
    let mut result = BTreeMap::new();
    walk(root, root, &mut result);
    result
}

fn copy_tree(source: &Path, target: &Path) {
    std::fs::create_dir_all(target).unwrap();
    for entry in std::fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target.join(entry.file_name()));
        } else {
            std::fs::copy(entry.path(), target.join(entry.file_name())).unwrap();
        }
    }
}

fn find_installed_target(root: &Path) -> Option<PathBuf> {
    fn visit(dir: &Path, seen: &mut std::collections::HashSet<PathBuf>) -> Option<PathBuf> {
        let canonical = dir.canonicalize().ok()?;
        if !seen.insert(canonical) {
            return None;
        }
        if let Ok(bytes) = std::fs::read(dir.join("package.json")) {
            if let Ok(package) = serde_json::from_slice::<Value>(&bytes) {
                if package["name"] == "minimist" && package["version"] == "1.2.2" {
                    return Some(dir.to_path_buf());
                }
            }
        }
        for entry in std::fs::read_dir(dir).ok()?.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(found) = visit(&path, seen) {
                    return Some(found);
                }
            }
        }
        None
    }
    visit(root, &mut std::collections::HashSet::new())
}

fn installed_target(root: &Path) -> PathBuf {
    find_installed_target(root).unwrap_or_else(|| {
        panic!(
            "installed minimist@1.2.2 not found under {}",
            root.display()
        )
    })
}

struct Fixture {
    temp: tempfile::TempDir,
    project: PathBuf,
    reader: PathBuf,
    legacy_reader: Option<PathBuf>,
    original_lock: Vec<u8>,
    original_manifest: Vec<u8>,
    original: Vec<u8>,
    patched: Vec<u8>,
    bystander: Vec<u8>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if std::thread::panicking()
            && std::env::var_os("SOCKET_PATCH_BUN_LOCKB_KEEP_FAILURE").is_some()
        {
            self.temp.disable_cleanup(true);
            eprintln!("PRESERVED BINARY FIXTURE {}", self.temp.path().display());
        }
    }
}

impl Fixture {
    fn new(shape: &str) -> Option<Self> {
        let reader = std::env::var_os("SOCKET_PATCH_BUN_LOCKB_READER")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("bun"));
        let required = std::env::var_os("SOCKET_PATCH_BUN_LOCKB_REQUIRED")
            .is_some_and(|value| !value.is_empty());
        let version = Command::new(&reader).arg("--version").output();
        let Ok(version) = version else {
            assert!(
                !required,
                "binary-lock Bun reader unavailable: {}",
                reader.display()
            );
            eprintln!("SKIP binary Bun E2E: Bun unavailable");
            return None;
        };
        assert!(version.status.success());
        let raw = String::from_utf8_lossy(&version.stdout).trim().to_string();
        if let Ok(expected) = std::env::var("SOCKET_PATCH_BUN_LOCKB_VERSION") {
            assert_eq!(
                raw, expected,
                "the matrix must run the exact requested reader"
            );
        }
        let writer = std::env::var_os("SOCKET_PATCH_BUN_LOCKB_WRITER")
            .map(PathBuf::from)
            .unwrap_or_else(|| reader.clone());
        // A modern reader can use the committed legacy fixture without a
        // separate writer executable; ordinary cargo test still exercises it.
        let major_minor: Vec<u32> = raw
            .split('.')
            .take(2)
            .filter_map(|p| p.parse().ok())
            .collect();
        // Only the `direct` shape has a captured lock; a modern reader
        // writes every other shape's binary lock itself.
        let captured_fixture = std::env::var_os("SOCKET_PATCH_BUN_LOCKB_WRITER").is_none()
            && major_minor.as_slice() >= [1, 2].as_slice()
            && shape == "direct";
        // Windows runners keep the checkout on D: and the system tempdir on
        // C:. Bun workspace writers cannot relativize paths across those
        // drives; keep the fixture on the working drive, as the public matrix
        // does, while retaining the space/Unicode project path below.
        let temp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let project = temp.path().join("binary project café");
        std::fs::create_dir_all(&project).unwrap();
        let dependencies = match shape {
            "alias" => json!({"alias":"npm:minimist@1.2.2", "is-number":"7.0.0"}),
            "transitive" => json!({"mkdirp":"0.5.3", "is-number":"7.0.0"}),
            "workspace" | "workspace-adder" => {
                json!({"consumer":"workspace:*", "is-number":"7.0.0"})
            }
            "workspace-nested" => {
                json!({"consumer":"workspace:*", "minimist":"1.2.8", "is-number":"7.0.0"})
            }
            // REGRESSION (#739): a release and a same-version prerelease
            // elsewhere in the lock must not fail the metadata hash check.
            "prerelease" => json!({"minimist":"1.2.2", "is-number":"7.0.0",
                "uuid":"8.0.0", "uuid-beta":"npm:uuid@8.0.0-beta.0"}),
            _ => json!({"minimist":"1.2.2", "is-number":"7.0.0"}),
        };
        let mut package = json!({"name":"native-binary-bun", "version":"1.0.0",
            "private":true, "dependencies":dependencies});
        if shape == "transitive" {
            package["overrides"] = json!({"minimist":"1.2.2"});
        }
        if shape == "production" {
            package["dependencies"]["mkdirp"] = json!("0.5.0");
            package["devDependencies"] = json!({"other":"npm:minimist@1.2.8", "left-pad":"1.3.0"});
            package["scripts"] =
                json!({"preinstall":"echo root-pre", "postinstall":"echo root-post"});
        }
        if shape.starts_with("workspace") || shape == "extensions" {
            package["workspaces"] = json!(["packages/*"]);
            std::fs::create_dir_all(project.join("packages/consumer")).unwrap();
            std::fs::write(
                project.join("packages/consumer/package.json"),
                br#"{"name":"consumer","version":"1.0.0","dependencies":{"minimist":"1.2.2"}}"#,
            )
            .unwrap();
        }
        if shape == "workspace-adder" {
            std::fs::create_dir_all(project.join("packages/adder")).unwrap();
            std::fs::write(
                project.join("packages/adder/package.json"),
                br#"{"name":"adder","version":"1.0.0","dependencies":{"is-number":"7.0.0"}}"#,
            )
            .unwrap();
        }
        if shape == "extensions" {
            package["dependencies"]["consumer"] = json!("workspace:*");
            package["dependencies"]["git-number"] = json!("github:jonschlinkert/is-number#7.0.0");
            package["scripts"] = json!({"preinstall":"echo root-preinstall", "install":"echo root-install", "postinstall":"echo root-postinstall"});
            std::fs::write(project.join("packages/consumer/package.json"),
                br#"{"name":"consumer","version":"1.0.0","dependencies":{"left-pad":"1.3.0"},"scripts":{"postinstall":"echo member-postinstall"}}"#).unwrap();
        }
        let original_manifest = if captured_fixture {
            assert_eq!(shape, "direct", "extended matrix must supply its writer");
            include_bytes!("../../socket-patch-core/tests/fixtures/bun-lockb/1.1.45/package.json")
                .to_vec()
        } else {
            serde_json::to_vec_pretty(&package).unwrap()
        };
        std::fs::write(project.join("package.json"), &original_manifest).unwrap();
        if captured_fixture {
            std::fs::write(
                project.join("bun.lockb"),
                include_bytes!("../../socket-patch-core/tests/fixtures/bun-lockb/1.1.45/bun.lockb"),
            )
            .unwrap();
        }
        std::fs::write(
            project.join("bunfig.toml"),
            "[install]\nsaveTextLockfile = false\n",
        )
        .unwrap();
        let mut install = command(&writer, &project);
        install.args(["install", "--ignore-scripts"]);
        if captured_fixture {
            install.arg("--frozen-lockfile");
        }
        install
            .env("BUN_INSTALL_CACHE_DIR", temp.path().join("initial-cache"))
            .env("BUN_INSTALL", temp.path().join("initial-home"));
        require_success(install.output().unwrap(), "binary fixture install");
        assert!(
            project.join("bun.lockb").is_file(),
            "writer must produce bun.lockb"
        );
        assert!(
            !project.join("bun.lock").exists(),
            "writer must not produce text"
        );
        let original_lock = std::fs::read(project.join("bun.lockb")).unwrap();
        let original = std::fs::read(installed_target(&project).join("index.js")).unwrap();
        let patched = [MARKER, original.as_slice()].concat();
        let bystander = std::fs::read(project.join("node_modules/is-number/index.js")).unwrap();
        eprintln!(
            "BINARY FIXTURE reader={raw} writer={} shape={shape} size={}",
            writer.display(),
            original_lock.len()
        );
        Some(Self {
            temp,
            project,
            reader,
            legacy_reader: std::env::var_os("SOCKET_PATCH_BUN_LOCKB_LEGACY_READER")
                .map(PathBuf::from),
            original_lock,
            original_manifest,
            original,
            patched,
            bystander,
        })
    }

    fn lock(&self) -> Vec<u8> {
        assert!(
            !self.project.join("bun.lock").exists(),
            "CLI must not create bun.lock"
        );
        std::fs::read(self.project.join("bun.lockb")).unwrap()
    }

    fn stage(&self) {
        let socket = self.project.join(".socket");
        std::fs::create_dir_all(socket.join("blobs")).unwrap();
        let after = compute_git_sha256_from_bytes(&self.patched);
        let manifest = json!({"patches":{PURL:{"uuid":UUID,
            "exportedAt":"2026-01-01T00:00:00Z", "files":{"package/index.js":{
                "beforeHash":compute_git_sha256_from_bytes(&self.original), "afterHash":after}},
            "vulnerabilities":{GHSA:{"cves":[CVE],"summary":"binary lock vuln","severity":"high","description":"d"}},
            "description":"binary lock marker", "license":"MIT", "tier":"free"}}});
        std::fs::write(
            socket.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        std::fs::write(socket.join("blobs").join(after), &self.patched).unwrap();
    }

    fn frozen(&self, label: &str, expected: &[u8], _target: &str) {
        self.frozen_install(label, expected, &self.bystander, false);
    }

    fn frozen_install(
        &self,
        label: &str,
        expected: &[u8],
        expected_bystander: &[u8],
        production: bool,
    ) -> PathBuf {
        let checkout = self.temp.path().join(label);
        std::fs::create_dir_all(&checkout).unwrap();
        for file in ["package.json", "bun.lockb", "bunfig.toml"] {
            std::fs::copy(self.project.join(file), checkout.join(file)).unwrap();
        }
        for (relative, bytes) in snapshot(&self.project) {
            if relative.starts_with("packages") {
                let file = checkout.join(relative);
                std::fs::create_dir_all(file.parent().unwrap()).unwrap();
                std::fs::write(file, bytes).unwrap();
            }
        }
        if self.project.join(".socket").exists() {
            copy_tree(&self.project.join(".socket"), &checkout.join(".socket"));
        }
        let cache = self.temp.path().join(format!("{label}-cache"));
        assert!(!cache.exists(), "fresh install must start with no cache");
        std::fs::create_dir(&cache).unwrap();
        let input_lock = self.lock();
        let revision_at = b"#!/usr/bin/env bun\nbun-lockfile-format-v0\n".len();
        // Bun 1.x no longer reads format 1. After exact rollback, validate
        // the original registry lock with the compatible 0.5.9 reader.
        let reader = if input_lock[revision_at..revision_at + 4] == 1u32.to_le_bytes() {
            self.legacy_reader.as_ref().unwrap_or(&self.reader)
        } else {
            &self.reader
        };
        let mut install = command(reader, &checkout);
        install.args(["install", "--frozen-lockfile", "--ignore-scripts"]);
        if production {
            install.arg("--production");
        }
        let output = install
            .env("BUN_INSTALL_CACHE_DIR", cache)
            .env(
                "BUN_INSTALL",
                self.temp.path().join(format!("{label}-home")),
            )
            .output()
            .unwrap();
        let output = require_success(output, label);
        let target = find_installed_target(&checkout).unwrap_or_else(|| {
            panic!(
                "{label}: installed target absent under {}\nstdout: {}\nstderr: {}",
                checkout.display(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
        assert_eq!(
            std::fs::read(target.join("index.js")).unwrap_or_else(|error| panic!(
                "{label}: installed target absent: {error}\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )),
            expected,
            "{label}: installed target bytes"
        );
        assert_eq!(
            std::fs::read(checkout.join("node_modules/is-number/index.js")).unwrap(),
            expected_bystander,
            "{label}: bystander must be preserved"
        );
        let live_lock = self.lock();
        let installed_lock = std::fs::read(checkout.join("bun.lockb")).unwrap();
        let revision_at = b"#!/usr/bin/env bun\nbun-lockfile-format-v0\n".len();
        if live_lock[revision_at..revision_at + 4] == 1u32.to_le_bytes() {
            // Bun 0.5.9 upgrades its predecessor's untouched v1 registry
            // lock to v2 even under --frozen-lockfile. The CLI's rollback
            // already proved exact original bytes before this fresh install.
            assert_eq!(
                expected, self.original,
                "only a pristine rollback can restore format 1"
            );
            assert_eq!(
                installed_lock[revision_at..revision_at + 4],
                2u32.to_le_bytes()
            );
            assert_eq!(
                installed_lock[revision_at + 4..revision_at + 36],
                live_lock[revision_at + 4..revision_at + 36],
                "registry graph hash must survive Bun's schema upgrade"
            );
        } else {
            assert!(
                installed_lock == live_lock,
                "{label}: frozen install must preserve lock bytes"
            );
        }
        assert!(
            !checkout.join("bun.lock").exists(),
            "{label}: install must remain binary"
        );
        checkout
    }

    /// The manifest-less VEX step ([`bun_vex::run_bun_vex_matrix`]) on a
    /// fresh checkout of the project's CURRENT binary-lock state: manifest
    /// deleted, a real empty-cache `bun install --frozen-lockfile` by the
    /// reader, then attested with the `mode` marker from the ledger and —
    /// ledgers deleted — from `bun.lockb` + the patch API; offline →
    /// `record_unavailable` with zero requests; the ORIGINAL registry
    /// `bun.lockb` back (ledgers, artifacts, patched install kept) → NOT
    /// attested, verified or not. `server` hosts the hosted tarballs.
    fn manifestless_vex(&self, label: &str, mode: bun_vex::BunMode, server: &str) {
        let case = bun_vex::BunVexCase {
            tag: label,
            mode,
            purl: PURL,
            uuid: UUID,
            files: vec![(
                "package/index.js".to_string(),
                compute_git_sha256_from_bytes(&self.patched),
            )],
            vulns: &[(GHSA, &[CVE])],
            lock: "bun.lockb",
            registry_lock: self.original_lock.clone(),
            patch_server_url: (mode == bun_vex::BunMode::Hosted).then(|| server.to_string()),
        };
        bun_vex::run_bun_vex_matrix(&self.project, self.temp.path(), &case, |checkout| {
            let output = command(&self.reader, checkout)
                .args(["install", "--frozen-lockfile", "--ignore-scripts"])
                .env(
                    "BUN_INSTALL_CACHE_DIR",
                    self.temp.path().join(format!("vex-{label}-cache")),
                )
                .env(
                    "BUN_INSTALL",
                    self.temp.path().join(format!("vex-{label}-home")),
                )
                .output()
                .unwrap();
            let output = require_success(output, &format!("vex-{label} frozen install"));
            let target = find_installed_target(checkout).unwrap_or_else(|| {
                panic!(
                    "vex-{label}: installed target absent\nstdout: {}\nstderr: {}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                )
            });
            assert_eq!(
                std::fs::read(target.join("index.js")).unwrap(),
                self.patched,
                "vex-{label}: the checkout must hold the patched install"
            );
            assert!(
                !checkout.join("bun.lock").exists(),
                "vex-{label}: install must remain binary"
            );
        });
    }

    fn pristine(&self) {
        assert_eq!(
            self.lock(),
            self.original_lock,
            "rollback must restore exact binary bytes"
        );
        assert_eq!(
            std::fs::read(self.project.join("package.json")).unwrap(),
            self.original_manifest
        );
    }
}

fn make_tgz_from_installed(pkg_dir: &Path, replaced_index: &[u8]) -> Vec<u8> {
    let pkg_dir = pkg_dir
        .canonicalize()
        .expect("installed package dir must resolve");
    let mut files: Vec<PathBuf> = Vec::new();
    let mut stack = vec![pkg_dir.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else {
                files.push(p);
            }
        }
    }
    files.sort();
    let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::default(),
    ));
    for p in &files {
        let rel = p.strip_prefix(&pkg_dir).unwrap();
        let name = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/");
        let bytes = if rel == Path::new("index.js") {
            replaced_index.to_vec()
        } else {
            std::fs::read(p).unwrap()
        };
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(file_mode(p, &name));
        header.set_mtime(0);
        header.set_cksum();
        builder
            .append_data(&mut header, format!("package/{name}"), bytes.as_slice())
            .unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

#[cfg(unix)]
fn file_mode(p: &Path, _name: &str) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn file_mode(_p: &Path, name: &str) -> u32 {
    if name.starts_with("bin/") {
        0o755
    } else {
        0o644
    }
}

async fn mock_api(server: &MockServer, fixture: &Fixture, _target: &str) {
    let tgz = make_tgz_from_installed(&installed_target(&fixture.project), &fixture.patched);
    prebuilt_common::mount_download(server, PURL, UUID, "minimist-1.2.2.tgz", &tgz).await;
    std::fs::write(fixture.temp.path().join("hosted.tgz"), &tgz).unwrap();
    let url = format!("{}/patch/npm/minimist/1.2.2/33333333-3333-4333-8333-333333333333/{UUID}/minimist-1.2.2.tgz", server.uri());
    let sri = format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(Sha512::digest(&tgz))
    );
    Mock::given(method("POST")).and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"packages":[{
            "purl":PURL,"patches":[{"uuid":UUID,"purl":PURL,"tier":"free","cveIds":[],"ghsaIds":[],"severity":"high","title":"binary lock patch"}]}],"canAccessPaidPatches":false})))
        .mount(server).await;
    Mock::given(method("GET")).and(path_regex(format!("^/v0/orgs/{ORG}/patches/by-package/.*minimist.*$")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"patches":[{
            "uuid":UUID,"purl":PURL,"publishedAt":"2026-01-01T00:00:00Z","description":"binary lock patch","license":"MIT","tier":"free","vulnerabilities":{}}],"canAccessPaidPatches":false})))
        .mount(server).await;
    Mock::given(method("POST")).and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"results":{UUID:{
            "status":"granted","url":url,"purl":PURL,"artifacts":[{"kind":"tarball","url":url,"integrity":{"sha512":sri}}],"registryOverride":null}}})))
        .mount(server).await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"uuid":UUID,"purl":PURL,
            "publishedAt":"2026-01-01T00:00:00Z","files":{"package/index.js":{
                "beforeHash":compute_git_sha256_from_bytes(&fixture.original),
                "afterHash":compute_git_sha256_from_bytes(&fixture.patched),
                "blobContent":base64::engine::general_purpose::STANDARD.encode(&fixture.patched)}},
            "vulnerabilities":{GHSA:{"cves":[CVE],"summary":"binary lock vuln","severity":"high","description":"d"}},
            "description":"binary lock patch","license":"MIT","tier":"free"})),
        )
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex("^/patch/npm/minimist/.*$"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(tgz, "application/octet-stream"))
        .mount(server)
        .await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn native_binary_hosted_vendored_takeover_roundtrip() {
    let Some(fixture) = Fixture::new("direct") else {
        return;
    };
    let server = MockServer::start().await;
    mock_api(&server, &fixture, "minimist").await;
    let project = &fixture.project;

    // Lock-only discovery and hosted wiring must work without invoking Bun.
    let modules = fixture.temp.path().join("initial-node_modules");
    std::fs::rename(project.join("node_modules"), &modules).unwrap();
    let before = snapshot(project);
    let preview = scan(project, &server, "hosted", &["--dry-run"]);
    assert_eq!(snapshot(project), before, "hosted dry run: {preview}");
    let hosted = scan(project, &server, "hosted", &[]);
    assert_eq!(
        hosted["redirect"]["redirected"], 1,
        "lock-only hosted scan must discover minimist: {hosted}"
    );
    let hosted_lock = fixture.lock();
    assert_ne!(hosted_lock, fixture.original_lock);
    fixture.frozen("hosted", &fixture.patched, "minimist");
    fixture.manifestless_vex("hosted", bun_vex::BunMode::Hosted, &server.uri());
    let repeat = scan(project, &server, "hosted", &[]);
    assert_eq!(
        repeat["redirect"]["redirected"], 1,
        "hosted rerun: {repeat}"
    );
    assert_eq!(fixture.lock(), hosted_lock);
    assert!(
        !project.join(".socket/vendor/redirect-state.json").exists(),
        "hosted mode writes no ledger"
    );
    std::fs::rename(&modules, project.join("node_modules")).unwrap();

    // Hosted -> vendored: v5 restores a hosted pin's upstream entry before
    // vendoring over it, re-resolving the registry record from the npm
    // registry — which an OFFLINE takeover cannot do, so it is REFUSED (dry
    // and wet alike, nothing written) with the checkout remedy. Online, the
    // takeover rebuilds the binary registry record exactly and vendors over
    // it; `vendor --revert` then gives back the original bytes. After that
    // (equivalently, after `git checkout -- bun.lockb`) the offline vendor
    // proceeds, with a truthful dry run and exact rerun state.
    fixture.stage();
    let uri = server.uri();
    let before = snapshot(project);
    for extra in [&["--dry-run"][..], &[][..]] {
        let mut args = vec!["vendor", "--offline", "--patch-server-url", &uri];
        args.extend_from_slice(extra);
        let (code, refused) = cli_code(project, &args);
        assert_eq!(
            code, 1,
            "vendor {extra:?} over a binary hosted pin: {refused}"
        );
        let failed = refused["events"]
            .as_array()
            .and_then(|events| {
                events
                    .iter()
                    .find(|e| e["errorCode"] == "redirect_revert_failed")
            })
            .unwrap_or_else(|| panic!("expected redirect_revert_failed: {refused}"));
        assert_eq!(failed["purl"], PURL, "{refused}");
        assert!(
            failed["error"].as_str().is_some_and(|e| {
                e.contains("cannot vendor over the live hosted pin")
                    && e.contains("git checkout -- bun.lockb")
            }),
            "{refused}"
        );
        assert_eq!(
            snapshot(project),
            before,
            "refused vendor {extra:?} wrote nothing"
        );
    }
    // The npm registry's version document for minimist@1.2.2 (the public
    // registry's values, which the original lock pins), served locally.
    let integrity = "sha512-rIqbOrKb8GJmx/5bc2M0QchhUouMXSpd1RTclXsB41JdL+VtnojfaJR+h7F9k18/4kHUsBFgk80Uk+q569vjPA==";
    let digest = base64::engine::general_purpose::STANDARD
        .decode(integrity.trim_start_matches("sha512-"))
        .unwrap();
    assert!(
        fixture
            .original_lock
            .windows(64)
            .any(|w| w == digest.as_slice()),
        "the original lock pins the registry digest"
    );
    Mock::given(method("GET"))
        .and(path("/minimist/1.2.2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"dist": {
            "tarball": "https://registry.npmjs.org/minimist/-/minimist-1.2.2.tgz",
            "integrity": integrity}})))
        .mount(&server)
        .await;
    let taken_over = cli_env(
        project,
        &[
            "vendor",
            "--patch-server-url",
            &uri,
            "--vendor-source",
            "service",
        ],
        &[("SOCKET_NPM_REGISTRY", &uri)],
    );
    assert_eq!(
        taken_over["summary"]["applied"], 1,
        "online vendor over the binary hosted pin: {taken_over}"
    );
    assert!(
        taken_over["events"].as_array().is_some_and(|events| events
            .iter()
            .any(|e| e["errorCode"] == "vendor_takeover_reverted_redirect")),
        "the takeover is reported: {taken_over}"
    );
    let vendor_lock = fixture.lock();
    assert!(
        !vendor_lock.windows(uri.len()).any(|w| w == uri.as_bytes()),
        "no hosted URL is left in bun.lockb"
    );
    let state: Value =
        serde_json::from_slice(&std::fs::read(project.join(".socket/vendor/state.json")).unwrap())
            .unwrap();
    let original = state["entries"][PURL]["wiring"]
        .as_array()
        .and_then(|w| w.iter().find(|r| r["kind"] == "bun_lockb_package"))
        .map(|r| r["original"].clone())
        .unwrap_or_else(|| panic!("bun_lockb_package wiring: {state}"));
    assert_eq!(original["name"], "minimist", "{original}");
    assert_eq!(original["version"], "1.2.2", "{original}");
    assert_eq!(
        original["resolution"], "https://registry.npmjs.org/minimist/-/minimist-1.2.2.tgz",
        "the vendor ledger records the registry record: {original}"
    );
    fixture.frozen("taken-over", &fixture.patched, "minimist");
    let reverted = cli(project, &["vendor", "--revert", "--offline"]);
    assert_eq!(
        fixture.lock(),
        fixture.original_lock,
        "the revert restores the pre-hosted bytes exactly: {reverted}"
    );
    assert!(!project.join(".socket/vendor").exists(), "{reverted}");
    let before = snapshot(project);
    let preview = cli(project, &["vendor", "--offline", "--dry-run"]);
    assert_eq!(snapshot(project), before, "vendor dry run: {preview}");
    let vendored = cli(project, &["vendor", "--offline"]);
    assert_eq!(
        vendored["summary"]["applied"], 1,
        "hosted -> vendored: {vendored}"
    );
    fixture.frozen("vendored", &fixture.patched, "minimist");
    fixture.manifestless_vex("vendored", bun_vex::BunMode::Vendored, &server.uri());
    let vendor_lock = fixture.lock();
    let repeat = cli(project, &["vendor", "--offline"]);
    assert_eq!(repeat["summary"]["applied"], 0, "vendor rerun: {repeat}");
    assert_eq!(repeat["summary"]["skipped"], 1, "vendor rerun: {repeat}");
    assert_eq!(fixture.lock(), vendor_lock);
    // The same rerun during a vendoring-service outage (closed port): the
    // committed archive is reused, so bun.lockb and the tarball stay
    // byte-identical, and no outage advisory is raised (the pre-reuse
    // fallback to a local pack also stayed in sync here, but only after
    // warning `vendor_prebuilt_unavailable` — that event is the tell).
    let tgz_path = project.join(format!(".socket/vendor/npm/{UUID}/minimist-1.2.2.tgz"));
    let vendor_tgz = std::fs::read(&tgz_path).unwrap();
    let outage = cli(
        project,
        &[
            "vendor",
            "--api-url",
            &server.uri(),
            "--vendor-url",
            "http://127.0.0.1:9",
            "--api-token",
            "fake",
            "--org",
            ORG,
        ],
    );
    assert_eq!(outage["summary"]["applied"], 0, "outage rerun: {outage}");
    assert_eq!(outage["summary"]["skipped"], 1, "outage rerun: {outage}");
    assert_eq!(fixture.lock(), vendor_lock);
    assert_eq!(std::fs::read(&tgz_path).unwrap(), vendor_tgz);
    let outage_events = outage["events"].as_array().cloned().unwrap_or_default();
    assert_eq!(
        outage_events
            .iter()
            .filter(|e| e["errorCode"] == "already_vendored")
            .count(),
        1,
        "outage rerun: {outage}"
    );
    assert!(
        outage_events
            .iter()
            .all(|e| e["errorCode"] != "vendor_prebuilt_unavailable"),
        "outage rerun must not touch the service: {outage}"
    );

    // Rebuild a deleted artifact from the manifest, preserve binary wiring.
    std::fs::remove_dir_all(project.join(".socket/vendor/npm")).unwrap();
    let repaired = cli(project, &["repair", "--offline", "--yes"]);
    assert_eq!(repaired["summary"]["rebuilt"], 1, "repair: {repaired}");
    fixture.frozen("repaired", &fixture.patched, "minimist");

    // A lost ledger is reported, not re-synthesized — and the reference is
    // still discovered from the native binary lock. Save the original
    // ledger to continue the takeover and exact-rollback assertions.
    let state_path = project.join(".socket/vendor/state.json");
    let saved_state = std::fs::read(&state_path).unwrap();
    std::fs::remove_file(&state_path).unwrap();
    let output = command(env!("CARGO_BIN_EXE_socket-patch"), project)
        .args(["repair", "--offline", "--yes", "--cwd"])
        .arg(project)
        .args(["--json", "--no-telemetry"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "ledgerless repair must fail");
    let recovered: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        recovered["events"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|e| e["errorCode"] == "vendor_ledger_missing"),
        "ledgerless repair: {recovered}"
    );
    assert!(!state_path.exists(), "no ledger is synthesized");
    std::fs::write(&state_path, saved_state).unwrap();

    let before = snapshot(project);
    let preview = scan(project, &server, "hosted", &["--dry-run"]);
    assert_eq!(
        snapshot(project),
        before,
        "hosted takeover dry run: {preview}"
    );
    let hosted = scan(project, &server, "hosted", &[]);
    assert_eq!(
        hosted["redirect"]["redirected"], 1,
        "vendored -> hosted: {hosted}"
    );
    fixture.frozen("hosted-again", &fixture.patched, "minimist");
    fixture.manifestless_vex("hosted-again", bun_vex::BunMode::Hosted, &server.uri());
    rollback_refuses_binary_hosted_pin_then_checkout(&fixture, &server);
    fixture.pristine();
    fixture.frozen("rolled-back", &fixture.original, "minimist");
}

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn native_binary_scan_vendored() {
    let Some(fixture) = Fixture::new("direct") else {
        return;
    };
    let server = MockServer::start().await;
    mock_api(&server, &fixture, "minimist").await;
    let result = scan(&fixture.project, &server, "vendored", &[]);
    assert_eq!(
        result["vendor"]["summary"]["applied"], 1,
        "scan vendored: {result}"
    );
    assert!(
        !fixture.project.join(".socket/manifest.json").exists(),
        "vendored scan must not write a manifest"
    );
    fixture.frozen("scan-vendored", &fixture.patched, "minimist");
    fixture.manifestless_vex("scan-vendored", bun_vex::BunMode::Vendored, &server.uri());
    let result = cli(&fixture.project, &["vendor", "--revert"]);
    assert_eq!(result["summary"]["removed"], 1, "vendor revert: {result}");
    fixture.pristine();
    fixture.frozen("reverted", &fixture.original, "minimist");
}

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn native_binary_alias_and_transitive() {
    if std::env::var_os("SOCKET_PATCH_BUN_LOCKB_PRODUCTION").is_some() {
        production_scoped_rollback();
    }
    // Very early Bun lacks npm alias/override support; the release matrix
    // runs these layouts only on versions that implement those features.
    if std::env::var_os("SOCKET_PATCH_BUN_LOCKB_EXTENDED").is_none() {
        return;
    }
    for shape in [
        "alias",
        "transitive",
        "workspace",
        "workspace-nested",
        "extensions",
        "prerelease",
    ] {
        let Some(fixture) = Fixture::new(shape) else {
            return;
        };
        let target = match shape {
            "alias" => "alias",
            "workspace-nested" => "../packages/consumer/node_modules/minimist",
            _ => "minimist",
        };
        let server = MockServer::start().await;
        mock_api(&server, &fixture, target).await;
        let result = scan(&fixture.project, &server, "hosted", &[]);
        assert_eq!(result["redirect"]["redirected"], 1, "{shape}: {result}");
        fixture.frozen("shape-hosted", &fixture.patched, target);
        fixture.manifestless_vex(
            &format!("{shape}-hosted"),
            bun_vex::BunMode::Hosted,
            &server.uri(),
        );
        rollback_refuses_binary_hosted_pin_then_checkout(&fixture, &server);
        fixture.pristine();
        fixture.stage();
        let result = cli(&fixture.project, &["vendor", "--offline"]);
        assert_eq!(result["summary"]["applied"], 1, "{shape}: {result}");
        fixture.frozen("shape-vendored", &fixture.patched, target);
        fixture.manifestless_vex(
            &format!("{shape}-vendored"),
            bun_vex::BunMode::Vendored,
            &server.uri(),
        );

        if shape.starts_with("workspace") {
            let mirror = fixture.project.join(format!(
                "packages/consumer/.socket/vendor/npm/{UUID}/minimist-1.2.2.tgz"
            ));
            let ledger = fixture.project.join(".socket/vendor/state.json");
            let original_state = std::fs::read(&ledger).unwrap();
            assert!(
                mirror.is_file(),
                "workspace requires its committed tarball copy"
            );
            for (label, corrupt) in [("missing-mirror", false), ("corrupt-mirror", true)] {
                if corrupt {
                    std::fs::write(&mirror, b"corrupt workspace artifact").unwrap();
                } else {
                    std::fs::remove_file(&mirror).unwrap();
                }
                let repaired = cli(&fixture.project, &["repair", "--offline", "--yes"]);
                assert_eq!(
                    repaired["summary"]["rebuilt"], 1,
                    "{shape} {label}: {repaired}"
                );
                fixture.frozen(label, &fixture.patched, target);
            }
            // Repair keeps the ledger byte-identical (the exact revert below
            // replays its originals).
            assert_eq!(std::fs::read(&ledger).unwrap(), original_state);
        }
        cli(&fixture.project, &["vendor", "--revert"]);
        fixture.pristine();
    }
}

/// #784: after Bun migrates a vendored `bun.lockb` to `bun.lock`
/// (`bun install --save-text-lockfile`), `vendor --revert` and `rollback`
/// must restore the registry tuple Bun writes when it migrates the pristine
/// binary lock, instead of failing on the missing `bun.lockb`, and a hosted
/// takeover must replace the vendored wiring; a fresh frozen install of the
/// result gets the original (or, hosted, the patched) bytes. Needs a Bun >= 1.2
/// reader (the text lock releases the vendored text path parses). Not named
/// `native_binary_*`, like the #803 test: it runs on the 1.4.2 CI leg.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn vendored_text_migration_reverts_to_registry() {
    for unwind in [
        &["vendor", "--revert"][..],
        &["rollback", "--yes"][..],
        &["scan"][..],
    ] {
        let Some(fixture) = Fixture::new("direct") else {
            return;
        };
        let raw = String::from_utf8_lossy(
            &command(&fixture.reader, &fixture.project)
                .arg("--version")
                .output()
                .unwrap()
                .stdout,
        )
        .trim()
        .to_string();
        let major_minor: Vec<u32> = raw
            .split('.')
            .take(2)
            .filter_map(|p| p.parse().ok())
            .collect();
        if major_minor.as_slice() < [1, 2].as_slice() {
            eprintln!("SKIP vendored text migration: Bun {raw} < 1.2");
            return;
        }
        let migrate = |dir: &Path, label: &str| {
            std::fs::remove_file(dir.join("bunfig.toml")).unwrap();
            let _ = std::fs::remove_dir_all(dir.join("node_modules"));
            let output = command(&fixture.reader, dir)
                .args(["install", "--save-text-lockfile", "--ignore-scripts"])
                .env(
                    "BUN_INSTALL_CACHE_DIR",
                    fixture.temp.path().join(format!("{label}-cache")),
                )
                .env(
                    "BUN_INSTALL",
                    fixture.temp.path().join(format!("{label}-home")),
                )
                .output()
                .unwrap();
            require_success(output, &format!("{label}: bun.lockb -> bun.lock migration"));
            assert!(!dir.join("bun.lockb").exists(), "{label}");
            std::fs::read_to_string(dir.join("bun.lock")).unwrap()
        };
        // What Bun writes for the pristine binary lock.
        let pristine_dir = fixture.temp.path().join("pristine-migration");
        std::fs::create_dir_all(&pristine_dir).unwrap();
        for file in ["package.json", "bun.lockb", "bunfig.toml"] {
            std::fs::copy(fixture.project.join(file), pristine_dir.join(file)).unwrap();
        }
        let pristine = migrate(&pristine_dir, "pristine");

        let server = MockServer::start().await;
        mock_api(&server, &fixture, "minimist").await;
        let project = &fixture.project;
        let vendored = scan(project, &server, "vendored", &[]);
        assert_eq!(vendored["vendor"]["summary"]["applied"], 1, "{vendored}");
        let migrated = migrate(project, "vendored");
        assert!(
            migrated.contains(&format!("minimist@.socket/vendor/npm/{UUID}/")),
            "the migration carries the vendored tuple:\n{migrated}"
        );

        let result = if unwind == ["scan"] {
            // The hosted takeover reverts the vendored wiring first.
            let hosted = scan(project, &server, "hosted", &[]);
            assert_eq!(hosted["redirect"]["redirected"], 1, "{hosted}");
            hosted
        } else {
            cli(project, unwind)
        };
        assert_eq!(result["status"], "success", "{unwind:?}: {result}");
        assert!(!project.join(".socket/vendor").exists(), "{unwind:?}");
        let expected = if unwind == ["scan"] {
            let lock = std::fs::read_to_string(project.join("bun.lock")).unwrap();
            assert!(lock.contains("/patch/npm/minimist/"), "{lock}");
            &fixture.patched
        } else {
            assert_eq!(
                std::fs::read_to_string(project.join("bun.lock")).unwrap(),
                pristine,
                "{unwind:?} restores the registry tuple"
            );
            &fixture.original
        };

        let checkout = fixture.temp.path().join("reverted-checkout");
        std::fs::create_dir_all(&checkout).unwrap();
        for file in ["package.json", "bun.lock"] {
            std::fs::copy(project.join(file), checkout.join(file)).unwrap();
        }
        let output = command(&fixture.reader, &checkout)
            .args(["install", "--frozen-lockfile", "--ignore-scripts"])
            .env(
                "BUN_INSTALL_CACHE_DIR",
                fixture.temp.path().join("revert-cache"),
            )
            .env("BUN_INSTALL", fixture.temp.path().join("revert-home"))
            .output()
            .unwrap();
        require_success(output, "frozen install of the reverted bun.lock");
        assert_eq!(
            std::fs::read(installed_target(&checkout).join("index.js")).unwrap(),
            *expected,
            "{unwind:?}: a fresh frozen install"
        );
    }
}

/// #803: Bun 1.4 migrates a hosted workspace `bun.lockb` to `bun.lock`
/// with the member path the binary normalization wrote as the root's
/// `consumer` literal, so a frozen install of the migrated lock fails and
/// an unfrozen one drops the pin. A hosted re-run must restore the
/// manifest's `workspace:*`, after which a fresh frozen install from the
/// text lock gets the patched bytes. Needs a Bun >= 1.4 reader (the only
/// releases whose text reader re-resolves on the path literal). Not named
/// `native_binary_*`: scripts/backtest-bun-lockb.py runs exactly those
/// three tests per writer/reader cell; this one has its own 1.4.2 CI leg.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn workspace_text_migration_heals_on_rerun() {
    let Some(fixture) = Fixture::new("workspace") else {
        return;
    };
    let raw = String::from_utf8_lossy(
        &command(&fixture.reader, &fixture.project)
            .arg("--version")
            .output()
            .unwrap()
            .stdout,
    )
    .trim()
    .to_string();
    let major_minor: Vec<u32> = raw
        .split('.')
        .take(2)
        .filter_map(|p| p.parse().ok())
        .collect();
    if major_minor.as_slice() < [1, 4].as_slice() {
        eprintln!("SKIP workspace text migration: Bun {raw} < 1.4");
        return;
    }
    let server = MockServer::start().await;
    mock_api(&server, &fixture, "minimist").await;
    let project = &fixture.project;
    let hosted = scan(project, &server, "hosted", &[]);
    assert_eq!(hosted["redirect"]["redirected"], 1, "{hosted}");

    // Bun's own migration, as its prompt suggests.
    std::fs::remove_file(project.join("bunfig.toml")).unwrap();
    let output = command(&fixture.reader, project)
        .args(["install", "--save-text-lockfile", "--ignore-scripts"])
        .env(
            "BUN_INSTALL_CACHE_DIR",
            fixture.temp.path().join("migrate-cache"),
        )
        .env("BUN_INSTALL", fixture.temp.path().join("migrate-home"))
        .output()
        .unwrap();
    require_success(output, "bun.lockb -> bun.lock migration");
    let migrated = std::fs::read_to_string(project.join("bun.lock")).unwrap();
    assert!(
        migrated.contains("\"consumer\": \"packages/consumer\""),
        "the migration carries the normalized path literal:\n{migrated}"
    );
    assert!(migrated.contains("/patch/npm/minimist/"), "{migrated}");

    let rerun = scan(project, &server, "hosted", &[]);
    assert_eq!(rerun["redirect"]["redirected"], 1, "{rerun}");
    let healed = std::fs::read_to_string(project.join("bun.lock")).unwrap();
    assert_eq!(
        healed,
        migrated.replace(
            "\"consumer\": \"packages/consumer\"",
            "\"consumer\": \"workspace:*\""
        ),
        "only the literal changes"
    );

    // A fresh checkout of the healed text lock installs frozen, patched.
    let checkout = fixture.temp.path().join("text-checkout");
    std::fs::create_dir_all(checkout.join("packages/consumer")).unwrap();
    for file in ["package.json", "bun.lock", "packages/consumer/package.json"] {
        std::fs::copy(project.join(file), checkout.join(file)).unwrap();
    }
    let output = command(&fixture.reader, &checkout)
        .args(["install", "--frozen-lockfile", "--ignore-scripts"])
        .env(
            "BUN_INSTALL_CACHE_DIR",
            fixture.temp.path().join("text-cache"),
        )
        .env("BUN_INSTALL", fixture.temp.path().join("text-home"))
        .output()
        .unwrap();
    let output = require_success(output, "frozen install of the healed bun.lock");
    let target = find_installed_target(&checkout).unwrap_or_else(|| {
        panic!(
            "installed target absent\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    assert_eq!(
        std::fs::read(target.join("index.js")).unwrap(),
        fixture.patched,
        "the healed lock installs the patched bytes"
    );
    assert_eq!(
        std::fs::read_to_string(checkout.join("bun.lock")).unwrap(),
        healed,
        "the frozen install keeps the lock"
    );
}

/// The `(name, resolution)` package lines of Bun's own yarn-style dump of
/// the project's `bun.lockb`.
fn dumped_records(fixture: &Fixture) -> Vec<String> {
    let output = command(&fixture.reader, &fixture.project)
        .arg("bun.lockb")
        .output()
        .unwrap();
    let dump =
        String::from_utf8_lossy(&require_success(output, "bun bun.lockb").stdout).into_owned();
    dump.lines()
        .filter(|line| line.trim_start().starts_with("resolved "))
        .map(str::trim)
        .map(str::to_string)
        .collect()
}

/// #861: after a vendored workspace `bun.lockb`, a new dependent of the
/// patched package (a member added later, or `bun add` in an existing
/// member) makes Bun write a second, nested REGISTRY record of the same
/// `name@version`, since the hoisted one is a local tarball now. The
/// vendored re-run must not rewire that record to the same tarball: two
/// records with one tarball resolution share one isolated store directory,
/// and frozen installs fail intermittently with `EEXIST`. It folds the
/// record into the existing tarball record instead, so every fresh frozen
/// install links the patched bytes into the new dependent too. The member
/// names hoist the late dependent after (`late`) and before (`adder`) the
/// vendored one. Isolated linker (Bun >= 1.3); not named `native_binary_*`
/// (the backtest matrix runs exactly those).
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn workspace_late_dependent_rerun_shares_the_tarball_record() {
    for (shape, member) in [("workspace", "late"), ("workspace-adder", "adder")] {
        let Some(fixture) = Fixture::new(shape) else {
            return;
        };
        let raw = String::from_utf8_lossy(
            &command(&fixture.reader, &fixture.project)
                .arg("--version")
                .output()
                .unwrap()
                .stdout,
        )
        .trim()
        .to_string();
        let major_minor: Vec<u32> = raw
            .split('.')
            .take(2)
            .filter_map(|p| p.parse().ok())
            .collect();
        if major_minor.as_slice() < [1, 3].as_slice() {
            eprintln!("SKIP late workspace dependent: Bun {raw} has no isolated linker");
            return;
        }
        late_dependent_rerun(&fixture, member).await;
    }
}

async fn late_dependent_rerun(fixture: &Fixture, member: &str) {
    let project = &fixture.project;
    std::fs::write(
        project.join("bunfig.toml"),
        "[install]\nsaveTextLockfile = false\nlinker = \"isolated\"\n",
    )
    .unwrap();
    let server = MockServer::start().await;
    mock_api(&server, fixture, "minimist").await;
    fixture.stage();
    let first = cli(project, &["vendor", "--offline"]);
    assert_eq!(
        first["summary"]["applied"], 1,
        "{member}: first vendor: {first}"
    );

    let dir = project.join("packages").join(member);
    let mut add = if dir.exists() {
        let mut add = command(&fixture.reader, &dir);
        add.args(["add", "minimist@1.2.2", "--ignore-scripts"]);
        add
    } else {
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("package.json"),
            format!(
                r#"{{"name":"{member}","version":"1.0.0","dependencies":{{"minimist":"1.2.2"}}}}"#
            ),
        )
        .unwrap();
        let mut install = command(&fixture.reader, project);
        install.args(["install", "--ignore-scripts"]);
        install
    };
    let output = add
        .env(
            "BUN_INSTALL_CACHE_DIR",
            fixture.temp.path().join("late-cache"),
        )
        .env("BUN_INSTALL", fixture.temp.path().join("late-home"))
        .output()
        .unwrap();
    require_success(output, &format!("{member}: the late dependent"));
    let before = dumped_records(fixture);
    assert!(
        before.iter().any(
            |line| line.contains("minimist-1.2.2.tgz") && !line.contains(".socket/vendor/npm/")
        ),
        "{member}: Bun writes a nested registry record: {before:?}"
    );

    let rerun = cli(project, &["vendor", "--offline"]);
    assert_eq!(
        rerun["summary"]["applied"], 1,
        "{member}: vendored re-run: {rerun}"
    );
    let after = dumped_records(fixture);
    assert_eq!(
        after
            .iter()
            .filter(|line| line.contains("minimist-1.2.2.tgz"))
            .collect::<Vec<_>>(),
        [&format!(
            "resolved \".socket/vendor/npm/{UUID}/minimist-1.2.2.tgz\""
        )],
        "{member}: one record, the tarball: {after:?}"
    );
    // EEXIST was intermittent (about half the cold frozen installs).
    for attempt in 0..6 {
        let checkout = fixture.frozen_install(
            &format!("{member}-{attempt}"),
            &fixture.patched,
            &fixture.bystander,
            false,
        );
        assert_eq!(
            std::fs::read(
                checkout
                    .join("packages")
                    .join(member)
                    .join("node_modules/minimist/index.js")
            )
            .unwrap(),
            fixture.patched,
            "{member} attempt {attempt}: the late dependent links the patched bytes"
        );
    }
    let again = cli(project, &["vendor", "--offline"]);
    assert_eq!(
        again["summary"]["skipped"], 1,
        "{member}: idempotent: {again}"
    );
    cli(project, &["vendor", "--revert"]);
    fixture.frozen_install(
        &format!("{member}-reverted"),
        &fixture.original,
        &fixture.bystander,
        false,
    );
}

fn production_scoped_rollback() {
    const SECOND_PURL: &str = "pkg:npm/is-number@7.0.0";
    for first in [PURL, SECOND_PURL] {
        let fixture = Fixture::new("production").expect("matrix requires its Bun writer");
        fixture.stage();
        let number_patched = [MARKER, fixture.bystander.as_slice()].concat();
        let after = compute_git_sha256_from_bytes(&number_patched);
        let manifest_path = fixture.project.join(".socket/manifest.json");
        let mut manifest: Value =
            serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
        manifest["patches"][SECOND_PURL] = json!({
            "uuid":"33333333-3333-4333-8333-333333333333",
            "exportedAt":"2026-01-01T00:00:00Z", "files":{"package/index.js":{
                "beforeHash":compute_git_sha256_from_bytes(&fixture.bystander), "afterHash":after}},
            "vulnerabilities":{}, "description":"second production patch", "license":"MIT", "tier":"free"});
        std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        std::fs::write(
            fixture.project.join(".socket/blobs").join(after),
            &number_patched,
        )
        .unwrap();
        let result = cli(&fixture.project, &["vendor", "--offline"]);
        assert_eq!(
            result["summary"]["applied"], 2,
            "two production patches: {result}"
        );
        let second = if first == PURL { SECOND_PURL } else { PURL };
        for (label, unwind) in [
            ("both", None),
            ("partial", Some(first)),
            ("all", Some(second)),
        ] {
            if let Some(purl) = unwind {
                let result = cli(&fixture.project, &["rollback", purl, "--yes"]);
                assert_eq!(result["status"], "success", "{label}: {result}");
            }
            let minimist = if label == "all" || (label == "partial" && first == PURL) {
                &fixture.original
            } else {
                &fixture.patched
            };
            let number = if label == "all" || (label == "partial" && first == SECOND_PURL) {
                &fixture.bystander
            } else {
                &number_patched
            };
            let checkout = fixture.frozen_install(label, minimist, number, true);
            assert!(
                !checkout.join("node_modules/other").exists(),
                "dev alias must be omitted"
            );
            assert!(
                !checkout.join("node_modules/left-pad").exists(),
                "dev package must be omitted"
            );
            assert!(checkout.join("node_modules/mkdirp/package.json").is_file());
            let bin = checkout.join("node_modules/.bin/mkdirp");
            assert!(
                bin.exists()
                    || bin.with_extension("cmd").exists()
                    || bin.with_extension("exe").exists(),
                "production bin must be installed"
            );
            assert_eq!(
                std::fs::read(fixture.project.join("package.json")).unwrap(),
                fixture.original_manifest
            );
        }
    }
}
