//! Real-cargo hosted-mode regressions for project SHAPES beyond the single
//! root dependency `e2e_redirect_cargo_build` covers — each one a defect a
//! real-cargo capture matrix found in the hosted rewriter / revert:
//!
//! * `multi_version` — two patched versions of one crate (`cfg-if` 1.0.4 and
//!   a renamed `cfg-if-legacy` at 0.1.10): each declaration is pinned to its
//!   own version's registry, and removing both purls restores every byte.
//! * `legacy_config` — an existing legacy `.cargo/config`: the registry
//!   block lands there, and `remove` restores the file byte-for-byte —
//!   also when it ends in a blank line (one lacking a final newline gets
//!   that newline back: v5 keeps no ledger fragment to tell them apart).
//! * `crlf` — CRLF `Cargo.toml` + `Cargo.lock`: rewritten with CRLF kept,
//!   and restored byte-for-byte.
//! * `workspace_direct_member` — a virtual workspace whose root pins
//!   `[workspace.dependencies]`, one member inheriting and one declaring the
//!   crate itself: both members build against the patched copy.
//! * `two_sections` — the same declaration line in `[dependencies]` and
//!   `[dev-dependencies]`: both pins revert on `remove`.
//! * `direct_and_transitive` — the crate is also a dependency of another
//!   crates.io crate: hosted mode refuses it loudly and rewrites nothing.
//! * `lockless_other_dependencies` — the same project with no committed
//!   `Cargo.lock`: with no resolved graph to read, a crate declared beside
//!   any other dependency is refused just as loudly.
//!
//! Every shape runs the same chain against the real cargo: a baseline build
//! with a private CARGO_HOME (network to crates.io for fixture setup only),
//! patched `.crate`s rebuilt from the ACTUAL crates.io bytes and served by a
//! wiremock sparse registry per patch, `scan --mode hosted`, then a FRESH
//! checkout (only the committed files travel) where `cargo fetch --locked`
//! and an offline `cargo build --locked` must link each patched-only symbol
//! and a post-install `vex` must attest exactly the patches (v5: no hosted
//! ledger, so each record comes from the patch API), and finally
//! `remove <purl>` for every patch — in apply order and, from the same
//! post-scan state, in reverse — which must leave the project
//! byte-identical to its pre-scan state. v5 `remove` restores each hosted
//! pin's crates.io entry, re-resolving the checksum from the sparse index:
//! a wiremock mirror of the pristine checksums (`SOCKET_CRATES_INDEX`), with
//! the mock origin named the patch server.
//!
//! `SOCKET_PATCH_CARGO_E2E_LOCK_VERSION` / `_TOOLCHAIN` (see
//! `cargo_e2e_matrix`) re-encode the baseline lock, so a v1 lock's full-id
//! dependency edges and `[metadata]` checksums meet every shape too.
//!
//! Skips (with a println) when `cargo` is missing or crates.io is
//! unreachable (a failure instead under `SOCKET_PATCH_CARGO_E2E_REQUIRED=1`).

#[path = "common/mod.rs"]
mod common;
use common::binary;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha256};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

#[path = "cargo_e2e_matrix/mod.rs"]
mod cargo_e2e_matrix;

const ORG: &str = "test-org";
/// Appended to each patched crate's `src/lib.rs`: the oracle links it.
const PATCH_SUFFIX: &str =
    "\n/// Socket-patch shape marker (added by the hosted patch).\npub fn socket_patched() -> u32 { 1 }\n";

/// One patched crate version the fixture serves.
#[derive(Clone, Copy)]
struct Patch {
    name: &'static str,
    version: &'static str,
    uuid: &'static str,
    token: &'static str,
}

impl Patch {
    fn purl(&self) -> String {
        format!("pkg:cargo/{}@{}", self.name, self.version)
    }
}

const CFG_IF_1: Patch = Patch {
    name: "cfg-if",
    version: "1.0.4",
    uuid: "c1f90104-5a0c-4e7a-9c0d-1a2b3c4d5e01",
    token: "70ce0104-1111-4111-8111-111111111101",
};
const CFG_IF_0: Patch = Patch {
    name: "cfg-if",
    version: "0.1.10",
    uuid: "c1f90010-5a0c-4e7a-9c0d-1a2b3c4d5e02",
    token: "70ce0010-1111-4111-8111-111111111102",
};

/// A project shape: its files before the lock exists, the patches, and the
/// oracle sources that reference each patched crate's marker.
struct Shape {
    tag: &'static str,
    files: Vec<(&'static str, String)>,
    patches: Vec<Patch>,
    /// Written into the fresh checkout before the offline build.
    oracle: Vec<(&'static str, String)>,
    /// Re-encode every `Cargo.toml` and the generated `Cargo.lock` with CRLF
    /// line endings (a Windows checkout) before the scan.
    crlf: bool,
    /// Delete `Cargo.lock` after the baseline build, before the scan: the
    /// shape a Rust library that gitignores its lock presents.
    lockless: bool,
    /// A shape hosted mode must REFUSE: the rewriter warning code every
    /// patch is skipped with. The scan must leave every file untouched.
    refused: Option<&'static str>,
    /// A dependency line the fresh checkout adds AFTER the scan, which
    /// locks its own crates.io copy of the (single) patched crate version
    /// beside the Socket one (#679, #863): VEX must then attest nothing, and
    /// `remove` must merge the Socket block into the crates.io one.
    contest: Option<&'static str>,
}

fn run_socket(cwd: &Path, args: &[&str], cargo_home: &Path) -> (i32, String, String) {
    run_socket_env(cwd, args, cargo_home, &[])
}

/// [`run_socket`] with extra env applied after the scrub.
fn run_socket_env(
    cwd: &Path,
    args: &[&str],
    cargo_home: &Path,
    env: &[(&str, &str)],
) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args(args).current_dir(cwd);
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("SOCKET_") {
            cmd.env_remove(&k);
        }
    }
    cmd.env("SOCKET_NO_CONFIG", "1");
    cmd.env("CARGO_HOME", cargo_home);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("failed to run socket-patch binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn cargo(cwd: &Path, args: &[&str], cargo_home: &Path) -> Output {
    cargo_e2e_matrix::cargo_command(cwd, cargo_home)
        .args(args)
        .output()
        .expect("failed to run cargo")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn find_registry_crate(cargo_home: &Path, leaf: &str) -> Option<PathBuf> {
    let src = cargo_home.join("registry").join("src");
    std::fs::read_dir(src)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path().join(leaf))
        .find(|p| p.is_dir())
}

fn sparse_index_rel(name: &str) -> String {
    match name.len() {
        1 => format!("1/{name}"),
        2 => format!("2/{name}"),
        3 => format!("3/{}/{name}", &name[..1]),
        _ => format!("{}/{}/{name}", &name[..2], &name[2..4]),
    }
}

/// A crates.io sparse-index mirror of the PRISTINE lock's checksums for
/// every patched crate — what the v5 upstream restore reads to put a hosted
/// `Cargo.lock` entry back on crates.io.
async fn mount_crates_index_mirror(pristine_lock: &str, patches: &[Patch]) -> MockServer {
    let server = MockServer::start().await;
    let lock = pristine_lock.replace("\r\n", "\n");
    let mut rows: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for pkg in cargo_e2e_matrix::parse_lock(&lock) {
        if !patches.iter().any(|p| p.name == pkg.name) {
            continue;
        }
        let cksum = pkg
            .checksum
            .unwrap_or_else(|| panic!("{} {} has no checksum", pkg.name, pkg.version));
        rows.entry(pkg.name.clone()).or_default().push(
            serde_json::json!({
                "name": pkg.name, "vers": pkg.version, "deps": [], "cksum": cksum,
                "features": {}, "yanked": false,
            })
            .to_string(),
        );
    }
    for (name, lines) in rows {
        Mock::given(wiremock::matchers::path(format!(
            "/{}",
            sparse_index_rel(&name)
        )))
        .respond_with(ResponseTemplate::new(200).set_body_string(lines.join("\n")))
        .mount(&server)
        .await;
    }
    server
}

fn build_crate(stage: &Path, crate_dir: &Path, leaf: &str, patched: &[u8]) -> Vec<u8> {
    let pkg = stage.join(leaf);
    copy_tree(crate_dir, &pkg);
    let _ = std::fs::remove_file(pkg.join(".cargo-checksum.json"));
    std::fs::write(pkg.join("src/lib.rs"), patched).unwrap();
    let mut bytes = Vec::new();
    {
        let enc = flate2::write::GzEncoder::new(&mut bytes, flate2::Compression::new(6));
        let mut builder = tar::Builder::new(enc);
        builder.append_dir_all(leaf, &pkg).unwrap();
        builder.into_inner().unwrap().finish().unwrap();
    }
    bytes
}

fn copy_tree(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), &to).unwrap();
        }
    }
}

/// Every project file except build output and the `.socket/` ledger dir.
fn snapshot(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if rel == "target" || rel == ".socket" || rel.ends_with("/target") {
                continue;
            }
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                out.insert(rel, std::fs::read(&path).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

struct Served {
    patch: Patch,
    orig: Vec<u8>,
    patched: Vec<u8>,
    crate_bytes: Vec<u8>,
}

/// Route every patch-API, sparse-index and download request the CLI and
/// cargo make, for any number of patches.
fn router(origin: String, served: Vec<Served>) -> impl Fn(&Request) -> ResponseTemplate {
    move |req: &Request| {
        let path = req.url.path().to_string();
        let find = |uuid: &str| served.iter().find(|s| s.patch.uuid == uuid);
        let index_url = |p: &Patch| {
            format!(
                "sparse+{origin}/patch-registry/cargo/{}/{}/index/",
                p.token, p.uuid
            )
        };
        let hosted_url = |p: &Patch| {
            format!(
                "{origin}/patch/cargo/{0}/{1}/{2}/{3}/{0}-{1}.crate",
                p.name, p.version, p.token, p.uuid
            )
        };
        let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let api = format!("/v0/orgs/{ORG}/patches/");
        if path == format!("{api}batch") {
            let packages: Vec<serde_json::Value> = served
                .iter()
                .map(|s| {
                    serde_json::json!({
                        "purl": s.patch.purl(),
                        "patches": [{
                            "uuid": s.patch.uuid, "purl": s.patch.purl(), "tier": "free",
                            "cveIds": [], "ghsaIds": [format!("GHSA-shape-{}", &s.patch.uuid[..8])],
                            "severity": "high", "title": "cargo shape fixture"
                        }]
                    })
                })
                .collect();
            return ResponseTemplate::new(200).set_body_json(
                serde_json::json!({ "packages": packages, "canAccessPaidPatches": false }),
            );
        }
        if let Some(rest) = path.strip_prefix(&format!("{api}by-package/")) {
            let purl = urlencoding_decode(rest);
            let patches: Vec<serde_json::Value> = served
                .iter()
                .filter(|s| s.patch.purl() == purl)
                .map(|s| {
                    serde_json::json!({
                        "uuid": s.patch.uuid, "purl": s.patch.purl(),
                        "publishedAt": "2026-01-01T00:00:00Z", "description": "x",
                        "license": "MIT", "tier": "free", "vulnerabilities": {}
                    })
                })
                .collect();
            return ResponseTemplate::new(200).set_body_json(
                serde_json::json!({ "patches": patches, "canAccessPaidPatches": false }),
            );
        }
        if path == format!("{api}package") {
            let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
            let mut results = serde_json::Map::new();
            for uuid in body["uuids"].as_array().into_iter().flatten() {
                let uuid = uuid.as_str().unwrap_or_default();
                let value = match find(uuid) {
                    Some(s) => {
                        let cksum = hex::encode(Sha256::digest(&s.crate_bytes));
                        serde_json::json!({
                            "status": "granted",
                            "url": hosted_url(&s.patch),
                            "purl": s.patch.purl(),
                            "artifacts": [{
                                "kind": "tarball", "url": hosted_url(&s.patch),
                                "integrity": { "sha256": cksum }
                            }],
                            "registryOverride": {
                                "kind": "cargo-sparse",
                                "indexUrl": index_url(&s.patch),
                                "identifiers": {
                                    "name": s.patch.name, "version": s.patch.version,
                                    "cargoCksumSha256": cksum,
                                }
                            }
                        })
                    }
                    None => serde_json::json!({ "status": "not_found" }),
                };
                results.insert(uuid.to_string(), value);
            }
            return ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "results": results }));
        }
        if let Some(uuid) = path.strip_prefix(&format!("{api}view/")) {
            if let Some(s) = find(uuid) {
                return ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "uuid": uuid, "purl": s.patch.purl(),
                    "publishedAt": "2026-01-01T00:00:00Z",
                    "files": { "src/lib.rs": {
                        "beforeHash": compute_git_sha256_from_bytes(&s.orig),
                        "afterHash": compute_git_sha256_from_bytes(&s.patched),
                    }},
                    "vulnerabilities": { format!("GHSA-shape-{}", &uuid[..8]): {
                        "cves": [], "summary": "s", "severity": "high", "description": "d"
                    }},
                    "description": "x", "license": "MIT", "tier": "free"
                }));
            }
        }
        // /patch-registry/cargo/<token>/<uuid>/index/...
        if segs.len() >= 6 && segs[..2] == ["patch-registry", "cargo"] && segs[4] == "index" {
            if let Some(s) = find(segs[3]) {
                let rest = segs[5..].join("/");
                if rest == "config.json" {
                    return ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "dl": format!("{origin}/dl/{}", s.patch.uuid),
                    }));
                }
                if rest == sparse_index_rel(s.patch.name) {
                    let line = serde_json::json!({
                        "name": s.patch.name, "vers": s.patch.version, "deps": [],
                        "cksum": hex::encode(Sha256::digest(&s.crate_bytes)),
                        "features": {}, "yanked": false,
                    });
                    return ResponseTemplate::new(200).set_body_string(line.to_string());
                }
            }
        }
        // /dl/<uuid>/<crate>/<version>/download
        if segs.len() == 5 && segs[0] == "dl" && segs[4] == "download" {
            if let Some(s) = find(segs[1]) {
                return ResponseTemplate::new(200).set_body_bytes(s.crate_bytes.clone());
            }
        }
        ResponseTemplate::new(404)
    }
}

fn urlencoding_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Run one shape through scan → fresh-checkout fetch + offline build →
/// remove. Returns `None` when the fixture could not be built (skipped).
async fn run_shape(shape: Shape) -> Option<()> {
    let suite = format!("e2e_redirect_cargo_shapes ({})", shape.tag);
    if !cargo_e2e_matrix::cargo_available(&suite) {
        return None;
    }
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    let home = tmp.path().join("cargo-home");
    std::fs::create_dir_all(&home).unwrap();
    for (rel, content) in &shape.files {
        let path = proj.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }
    let generate = cargo(&proj, &["generate-lockfile"], &home);
    if !generate.status.success() {
        let _ = cargo_e2e_matrix::skip(
            &suite,
            &format!(
                "`cargo generate-lockfile` failed (crates.io unreachable?):\n{}",
                stderr(&generate)
            ),
        );
        return None;
    }
    pin_patched_versions(&proj, &home, &shape.patches);
    cargo_e2e_matrix::apply_lock_version(&proj);
    let build = cargo(&proj, &["build", "-q", "--locked"], &home);
    if !build.status.success() {
        let _ = cargo_e2e_matrix::skip(
            &suite,
            &format!(
                "baseline `cargo build` failed (crates.io unreachable?):\n{}",
                stderr(&build)
            ),
        );
        return None;
    }
    let _ = std::fs::remove_dir_all(proj.join("target"));
    if shape.crlf {
        for rel in snapshot(&proj).keys() {
            if rel.ends_with("Cargo.toml") || rel == "Cargo.lock" {
                let path = proj.join(rel);
                let text = std::fs::read_to_string(&path).unwrap();
                std::fs::write(&path, text.replace('\n', "\r\n")).unwrap();
            }
        }
        let rebuilt = cargo(&proj, &["build", "-q", "--locked"], &home);
        assert!(
            rebuilt.status.success(),
            "{}: the CRLF baseline must build:\n{}",
            shape.tag,
            stderr(&rebuilt)
        );
        let _ = std::fs::remove_dir_all(proj.join("target"));
    }
    if shape.lockless {
        std::fs::remove_file(proj.join("Cargo.lock")).unwrap();
    }
    let before = snapshot(&proj);

    let mut served = Vec::new();
    for patch in &shape.patches {
        let leaf = format!("{}-{}", patch.name, patch.version);
        let dir = find_registry_crate(&home, &leaf)
            .unwrap_or_else(|| panic!("{leaf} must be extracted by the baseline build"));
        let orig = std::fs::read(dir.join("src/lib.rs")).unwrap();
        let patched = [orig.as_slice(), PATCH_SUFFIX.as_bytes()].concat();
        let crate_bytes = build_crate(&tmp.path().join("stage"), &dir, &leaf, &patched);
        served.push(Served {
            patch: *patch,
            orig,
            patched,
            crate_bytes,
        });
    }
    let server = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(router(server.uri(), served))
        .mount(&server)
        .await;

    let uri = server.uri();
    let proj_s = proj.to_str().unwrap().to_string();
    let (code, stdout, err) = run_socket(
        &proj,
        &[
            "scan",
            "--mode",
            "hosted",
            "--json",
            "--yes",
            "--no-telemetry",
            "--cwd",
            &proj_s,
            "--api-url",
            &uri,
            "--org",
            ORG,
            "--api-token",
            "fake",
        ],
        &home,
    );
    assert_eq!(
        code, 0,
        "{}: scan failed\nstdout:\n{stdout}\nstderr:\n{err}",
        shape.tag
    );
    let env: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    if let Some(code) = shape.refused {
        assert_eq!(hosted_pinned(&env), 0, "{}: {env}", shape.tag);
        let codes: Vec<&str> = env["warnings"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|w| w["code"].as_str())
            .collect();
        assert_eq!(
            codes,
            vec![code; shape.patches.len()],
            "{}: every patch refused loudly: {env}",
            shape.tag
        );
        assert_eq!(
            snapshot(&proj),
            before,
            "{}: a refused redirect rewrites nothing",
            shape.tag
        );
        assert!(!proj.join(".socket").exists(), "{}", shape.tag);
        if !shape.lockless {
            let fetch = cargo(&proj, &["fetch", "--locked"], &home);
            assert!(
                fetch.status.success(),
                "{}: the untouched project still fetches --locked:\n{}",
                shape.tag,
                stderr(&fetch)
            );
        }
        return Some(());
    }
    assert_eq!(
        hosted_pinned(&env),
        shape.patches.len() as u64,
        "{}: every patch redirected: {env}",
        shape.tag
    );
    assert!(
        env.get("warnings").is_none(),
        "{}: no warning: {env}",
        shape.tag
    );

    if shape.crlf {
        for (rel, bytes) in snapshot(&proj) {
            if rel.ends_with("Cargo.toml") || rel == "Cargo.lock" {
                let text = String::from_utf8(bytes).unwrap();
                assert_eq!(
                    text.matches("\r\n").count(),
                    text.matches('\n').count(),
                    "{}: {rel} must keep CRLF endings:\n{text}",
                    shape.tag
                );
            }
        }
    }

    // Fresh checkout: only committed files travel; an EMPTY CARGO_HOME.
    let fresh = tmp.path().join("fresh");
    for (rel, _) in snapshot(&proj) {
        let to = fresh.join(&rel);
        std::fs::create_dir_all(to.parent().unwrap()).unwrap();
        std::fs::copy(proj.join(&rel), to).unwrap();
    }
    if proj.join(".socket").is_dir() {
        copy_tree(&proj.join(".socket"), &fresh.join(".socket"));
    }
    let fresh_home = tmp.path().join("fresh-home");
    std::fs::create_dir_all(&fresh_home).unwrap();
    let fetch = cargo(&fresh, &["fetch", "--locked"], &fresh_home);
    assert!(
        fetch.status.success(),
        "{}: fresh `cargo fetch --locked` failed:\n{}",
        shape.tag,
        stderr(&fetch)
    );
    for (rel, content) in &shape.oracle {
        std::fs::write(fresh.join(rel), content).unwrap();
    }
    let build = cargo(&fresh, &["build", "--locked", "--offline"], &fresh_home);
    assert!(
        build.status.success(),
        "{}: offline `cargo build --locked` must link every patched marker:\n{}",
        shape.tag,
        stderr(&build)
    );

    if let Some(dep) = shape.contest {
        contest_after_scan(&shape, dep, &fresh, &fresh_home, &uri);
        return Some(());
    }

    // Post-install VEX over the fresh checkout: every patch is attested,
    // hash-verified against the extracted (patched) registry sources.
    let doc_path = fresh.join("doc.vex.json");
    let fresh_s = fresh.to_str().unwrap().to_string();
    let (code, stdout, err) = run_socket(
        &fresh,
        &[
            "vex",
            "--output",
            doc_path.to_str().unwrap(),
            "--product",
            "pkg:cargo/consumer@0.1.0",
            "--patch-server-url",
            &uri,
            // No hosted ledger (v5): the records come from the patch API.
            "--api-url",
            &uri,
            "--org",
            ORG,
            "--api-token",
            "fake",
            "--cwd",
            &fresh_s,
        ],
        &fresh_home,
    );
    assert_eq!(
        code, 0,
        "{}: vex\nstdout:\n{stdout}\nstderr:\n{err}",
        shape.tag
    );
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&doc_path).unwrap()).unwrap();
    let mut attested: Vec<String> = doc["statements"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|st| st["products"].as_array().unwrap().clone())
        .flat_map(|p| p["subcomponents"].as_array().unwrap().clone())
        .map(|c| c["@id"].as_str().unwrap().to_string())
        .collect();
    attested.sort();
    attested.dedup();
    let mut expected: Vec<String> = shape.patches.iter().map(Patch::purl).collect();
    expected.sort();
    assert_eq!(attested, expected, "{}: attested purls: {doc}", shape.tag);

    assert!(
        !proj.join(".socket/vendor/redirect-state.json").exists(),
        "{}: hosted mode writes no redirect ledger",
        shape.tag
    );

    // Rollback: removing every purl restores the pre-scan project exactly —
    // in apply order AND in reverse (a v1 lock's shared dependent blocks
    // once made the first-applied purl unremovable before its sibling).
    // v5: each removal restores the pin's crates.io entry from the index
    // mirror; the mock origin is named the patch server so the pins are
    // found without a ledger.
    let pristine_lock = String::from_utf8(before["Cargo.lock"].clone()).unwrap();
    let index = mount_crates_index_mirror(&pristine_lock, &shape.patches).await;
    let index_uri = index.uri();
    let unwind_env = [
        ("SOCKET_CRATES_INDEX", index_uri.as_str()),
        ("SOCKET_PATCH_SERVER_URL", uri.as_str()),
    ];
    let post_scan = tmp.path().join("post-scan");
    copy_tree(&proj, &post_scan);
    let mut orders = vec![shape.patches.clone()];
    if shape.patches.len() > 1 {
        orders.push(shape.patches.iter().rev().copied().collect());
    }
    for (n, order) in orders.iter().enumerate() {
        if n > 0 {
            std::fs::remove_dir_all(&proj).unwrap();
            copy_tree(&post_scan, &proj);
        }
        for patch in order {
            let purl = patch.purl();
            let (code, stdout, err) = run_socket_env(
                &proj,
                &[
                    "remove",
                    &purl,
                    "--cwd",
                    &proj_s,
                    "--json",
                    "--yes",
                    "--no-telemetry",
                ],
                &home,
                &unwind_env,
            );
            assert_eq!(
                code, 0,
                "{} (removal order {n}): remove {purl}\nstdout:\n{stdout}\nstderr:\n{err}",
                shape.tag
            );
        }
        let after = snapshot(&proj);
        for (rel, bytes) in &before {
            // v5 keeps no ledger fragment, and the rewriter separates its
            // appended registry block with the same bytes whether or not the
            // original file ended in a newline — so an UNTERMINATED file can
            // only come back with its final newline (every other byte exact).
            let want = match after.get(rel) {
                Some(got)
                    if !bytes.ends_with(b"\n") && *got == [bytes.as_slice(), b"\n"].concat() =>
                {
                    got.clone()
                }
                _ => bytes.clone(),
            };
            assert_eq!(
                after
                    .get(rel)
                    .map(|b| String::from_utf8_lossy(b).into_owned()),
                Some(String::from_utf8_lossy(&want).into_owned()),
                "{} (removal order {n}): {rel} not restored byte-for-byte by remove",
                shape.tag
            );
        }
        let extra: Vec<&String> = after.keys().filter(|k| !before.contains_key(*k)).collect();
        assert!(
            extra.is_empty(),
            "{} (removal order {n}): remove left files behind: {extra:?}",
            shape.tag
        );
    }
    Some(())
}

/// The cfg-if blocks of `dir`'s lock: `(version, source)`.
fn locked_blocks(dir: &Path, name: &str) -> Vec<(String, Option<String>)> {
    let lock = std::fs::read_to_string(dir.join("Cargo.lock")).unwrap();
    cargo_e2e_matrix::parse_lock(&lock)
        .into_iter()
        .filter(|p| p.name == name)
        .map(|p| (p.version, p.source))
        .collect()
}

/// #679 / #863: `dep` added to the hosted fresh checkout locks a crates.io
/// copy of the patched crate version beside the Socket one. VEX must not
/// attest the crate (the build compiles the unpatched copy too), and
/// `remove` must leave the single crates.io block cargo itself writes, so
/// `cargo build --locked` still parses and accepts the lock.
fn contest_after_scan(shape: &Shape, dep: &str, fresh: &Path, home: &Path, uri: &str) {
    let [patch] = shape.patches.as_slice() else {
        panic!("{}: a contest shape has one patch", shape.tag);
    };
    let toml_path = fresh.join("Cargo.toml");
    let toml = std::fs::read_to_string(&toml_path).unwrap();
    std::fs::write(
        &toml_path,
        toml.replace("[dependencies]\n", &format!("[dependencies]\n{dep}\n")),
    )
    .unwrap();
    let build = cargo(fresh, &["build", "-q"], home);
    assert!(build.status.success(), "{}: {}", shape.tag, stderr(&build));
    let crates_io = "registry+https://github.com/rust-lang/crates.io-index";
    let twin = |dir: &Path| {
        locked_blocks(dir, patch.name)
            .iter()
            .any(|(v, s)| v == patch.version && s.as_deref() == Some(crates_io))
    };
    if !twin(fresh) {
        // crates.io resolved a newer release: lock the patched version, the
        // case where the patch is for the newest release.
        let other = locked_blocks(fresh, patch.name)
            .into_iter()
            .find(|(_, s)| s.as_deref() == Some(crates_io))
            .map(|(v, _)| v)
            .expect("the added dependency locks a crates.io copy");
        let spec = format!("{crates_io}#{}@{other}", patch.name);
        let update = cargo(
            fresh,
            &["update", "-p", &spec, "--precise", patch.version],
            home,
        );
        assert!(
            update.status.success(),
            "{}: {}",
            shape.tag,
            stderr(&update)
        );
    }
    let build = cargo(fresh, &["build", "-q", "--locked"], home);
    assert!(build.status.success(), "{}: {}", shape.tag, stderr(&build));
    let blocks = locked_blocks(fresh, patch.name)
        .into_iter()
        .filter(|(v, _)| v == patch.version)
        .count();
    assert_eq!(blocks, 2, "{}: the contested lock", shape.tag);

    // VEX: the crate is not attested.
    let doc_path = fresh.join("doc.vex.json");
    let fresh_s = fresh.to_str().unwrap().to_string();
    let (code, stdout, err) = run_socket(
        fresh,
        &[
            "vex",
            "--output",
            doc_path.to_str().unwrap(),
            "--product",
            "pkg:cargo/consumer@0.1.0",
            "--patch-server-url",
            uri,
            "--api-url",
            uri,
            "--org",
            ORG,
            "--api-token",
            "fake",
            "--cwd",
            &fresh_s,
        ],
        home,
    );
    let doc = std::fs::read_to_string(&doc_path).unwrap_or_default();
    assert!(
        !doc.contains(&patch.purl()),
        "{}: a contested crate must not be attested (exit {code}):\n{doc}\n{stdout}\n{err}",
        shape.tag
    );
    assert!(
        format!("{stdout}{err}").contains("that copy stays UNPATCHED"),
        "{}: the contest is diagnosed:\n{stdout}\n{err}",
        shape.tag
    );

    // remove: one crates.io block, and the lock cargo itself writes.
    let purl = patch.purl();
    let (code, stdout, err) = run_socket_env(
        fresh,
        &[
            "remove",
            &purl,
            "--cwd",
            &fresh_s,
            "--json",
            "--yes",
            "--no-telemetry",
        ],
        home,
        &[("SOCKET_PATCH_SERVER_URL", uri)],
    );
    assert_eq!(
        code, 0,
        "{}: remove\nstdout:\n{stdout}\nstderr:\n{err}",
        shape.tag
    );
    let blocks: Vec<_> = locked_blocks(fresh, patch.name)
        .into_iter()
        .filter(|(v, _)| v == patch.version)
        .collect();
    assert_eq!(
        blocks,
        [(patch.version.to_string(), Some(crates_io.to_string()))],
        "{}: remove merges into the crates.io block",
        shape.tag
    );
    assert!(
        !std::fs::read_to_string(&toml_path)
            .unwrap()
            .contains("socket-patch-"),
        "{}: the Cargo.toml pin is gone",
        shape.tag
    );
    std::fs::write(fresh.join("src/main.rs"), "fn main() {}\n").unwrap();
    let build = cargo(fresh, &["build", "-q", "--locked", "--offline"], home);
    assert!(
        build.status.success(),
        "{}: the restored lock builds unchanged under --locked:\n{}",
        shape.tag,
        stderr(&build)
    );
}

/// Pin each patched version: a caret requirement locks the newest
/// compatible release, which moves as crates.io publishes.
fn pin_patched_versions(proj: &Path, home: &Path, patches: &[Patch]) {
    for patch in patches {
        let lock = std::fs::read_to_string(proj.join("Cargo.lock")).unwrap();
        let locked = cargo_e2e_matrix::parse_lock(&lock);
        if locked
            .iter()
            .any(|p| p.name == patch.name && p.version == patch.version)
        {
            continue;
        }
        let pinned = locked
            .iter()
            .filter(|p| p.name == patch.name)
            .filter(|p| {
                !patches
                    .iter()
                    .any(|q| q.name == p.name && q.version == p.version)
            })
            .any(|p| {
                let spec = format!("{}@{}", p.name, p.version);
                cargo(
                    proj,
                    &["update", "-p", &spec, "--precise", patch.version],
                    home,
                )
                .status
                .success()
            });
        assert!(
            pinned,
            "cannot lock {}@{}:\n{lock}",
            patch.name, patch.version
        );
    }
}

fn consumer_manifest(deps: &str) -> String {
    format!("[package]\nname = \"consumer\"\nversion = \"0.1.0\"\nedition = \"2018\"\n\n[dependencies]\n{deps}")
}

/// Bugs B + I: two patched versions of one crate.
#[tokio::test(flavor = "multi_thread")]
async fn cargo_hosted_multi_version_pins_each_declaration_and_removes_cleanly() {
    let shape = Shape {
        tag: "multi-version",
        files: vec![
            (
                "Cargo.toml",
                consumer_manifest(
                    "cfg-if = \"1.0.4\"\ncfg-if-legacy = { package = \"cfg-if\", version = \"0.1.10\" }\n",
                ),
            ),
            ("src/main.rs", "fn main() {}\n".to_string()),
        ],
        patches: vec![CFG_IF_1, CFG_IF_0],
        oracle: vec![(
            "src/main.rs",
            "fn main() { println!(\"{}\", cfg_if::socket_patched() + cfg_if_legacy::socket_patched()); }\n"
                .to_string(),
        )],
        crlf: false,
        lockless: false,
        refused: None,
        contest: None,
    };
    let _ = run_shape(shape).await;
}

/// Bug H: an existing legacy `.cargo/config` gets the registry block
/// appended; removing the purl must restore its exact bytes.
#[tokio::test(flavor = "multi_thread")]
async fn cargo_hosted_legacy_config_is_restored_byte_for_byte() {
    let shape = Shape {
        tag: "legacy-config",
        files: vec![
            ("Cargo.toml", consumer_manifest("cfg-if = \"1.0.4\"\n")),
            ("src/main.rs", "fn main() {}\n".to_string()),
            (".cargo/config", "[net]\nretry = 2\n".to_string()),
        ],
        patches: vec![CFG_IF_1],
        oracle: vec![(
            "src/main.rs",
            "fn main() { println!(\"{}\", cfg_if::socket_patched()); }\n".to_string(),
        )],
        crlf: false,
        lockless: false,
        refused: None,
        contest: None,
    };
    let _ = run_shape(shape).await;
}

/// Bug H: a config ending in a blank line comes back byte-for-byte (the
/// appended block's removal once normalized the trailing newline run). A
/// config without a final newline comes back with every byte but that
/// missing newline: v5 keeps no ledger fragment to tell it apart from a
/// terminated file, since the rewriter's separator is the same for both.
#[tokio::test(flavor = "multi_thread")]
async fn cargo_hosted_config_trailing_bytes_are_restored() {
    for (tag, rel, config) in [
        (
            "config-unterminated",
            ".cargo/config.toml",
            "[net]\nretry = 2",
        ),
        (
            "config-trailing-blank",
            ".cargo/config",
            "[net]\nretry = 2\n\n",
        ),
    ] {
        let shape = Shape {
            tag,
            files: vec![
                ("Cargo.toml", consumer_manifest("cfg-if = \"1.0.4\"\n")),
                ("src/main.rs", "fn main() {}\n".to_string()),
                (rel, config.to_string()),
            ],
            patches: vec![CFG_IF_1],
            oracle: vec![(
                "src/main.rs",
                "fn main() { println!(\"{}\", cfg_if::socket_patched()); }\n".to_string(),
            )],
            crlf: false,
            lockless: false,
            refused: None,
            contest: None,
        };
        if run_shape(shape).await.is_none() {
            return;
        }
    }
}

/// The crate declared with the SAME line in two dependency sections: the
/// rewrite records two identical manifest edits, and the ledger must keep
/// both — it collapsed them, so `remove` reverted one pin, kept the other
/// (and the registry block it references) and still reported success.
#[tokio::test(flavor = "multi_thread")]
async fn cargo_hosted_same_line_in_two_sections_removes_cleanly() {
    let shape = Shape {
        tag: "two-sections",
        files: vec![
            (
                "Cargo.toml",
                format!(
                    "{}\n[dev-dependencies]\ncfg-if = \"1.0.4\"\n",
                    consumer_manifest("cfg-if = \"1.0.4\"\n")
                ),
            ),
            ("src/main.rs", "fn main() {}\n".to_string()),
        ],
        patches: vec![CFG_IF_1],
        oracle: vec![(
            "src/main.rs",
            "fn main() { println!(\"{}\", cfg_if::socket_patched()); }\n".to_string(),
        )],
        crlf: false,
        lockless: false,
        refused: None,
        contest: None,
    };
    let _ = run_shape(shape).await;
}

/// Bug F: a workspace member's own declaration must be pinned too.
#[tokio::test(flavor = "multi_thread")]
async fn cargo_hosted_workspace_member_declaration_is_pinned() {
    let member = |name: &str, dep: &str| {
        format!(
            "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2018\"\n\n\
             [dependencies]\n{dep}\n"
        )
    };
    let oracle = "pub fn marker() -> u32 { cfg_if::socket_patched() }\n".to_string();
    let shape = Shape {
        tag: "workspace-direct-member",
        files: vec![
            (
                "Cargo.toml",
                "[workspace]\nmembers = [\"inherits\", \"direct\"]\n\n\
                 [workspace.dependencies]\ncfg-if = \"1.0.4\"\n"
                    .to_string(),
            ),
            (
                "inherits/Cargo.toml",
                member("inherits", "cfg-if = { workspace = true }"),
            ),
            ("inherits/src/lib.rs", String::new()),
            ("direct/Cargo.toml", member("direct", "cfg-if = \"1.0.4\"")),
            ("direct/src/lib.rs", String::new()),
        ],
        patches: vec![CFG_IF_1],
        oracle: vec![
            ("inherits/src/lib.rs", oracle.clone()),
            ("direct/src/lib.rs", oracle),
        ],
        crlf: false,
        lockless: false,
        refused: None,
        contest: None,
    };
    let _ = run_shape(shape).await;
}

/// Bug K: a CRLF checkout is redirected (it was refused) with its line
/// endings kept, and removed byte-for-byte.
#[tokio::test(flavor = "multi_thread")]
async fn cargo_hosted_crlf_project_keeps_its_line_endings() {
    let shape = Shape {
        tag: "crlf",
        files: vec![
            ("Cargo.toml", consumer_manifest("cfg-if = \"1.0.4\"\n")),
            ("src/main.rs", "fn main() {}\n".to_string()),
        ],
        patches: vec![CFG_IF_1],
        oracle: vec![(
            "src/main.rs",
            "fn main() { println!(\"{}\", cfg_if::socket_patched()); }\n".to_string(),
        )],
        crlf: true,
        lockless: false,
        refused: None,
        contest: None,
    };
    let _ = run_shape(shape).await;
}

/// A crate that is both a direct dependency and a dependency of another
/// crates.io crate (`crc32fast` depends on `cfg-if ^1`): a hosted pin cannot
/// reach crc32fast's edge, so the redirect is refused loudly instead of
/// repointing the lock (`--locked` then fails, and crc32fast compiled the
/// unpatched crates.io copy while scan reported the crate redirected).
#[tokio::test(flavor = "multi_thread")]
async fn cargo_hosted_refuses_a_crate_another_crate_depends_on() {
    let shape = Shape {
        tag: "direct-and-transitive",
        files: vec![
            (
                "Cargo.toml",
                consumer_manifest("cfg-if = \"1.0.4\"\ncrc32fast = \"=1.5.0\"\n"),
            ),
            ("src/main.rs", "fn main() {}\n".to_string()),
        ],
        patches: vec![CFG_IF_1],
        oracle: Vec::new(),
        crlf: false,
        lockless: false,
        refused: Some("redirect_cargo_transitive_dependents"),
        contest: None,
    };
    let _ = run_shape(shape).await;
}

/// The SAME project with its `Cargo.lock` gitignored (the common shape for
/// a Rust library): with no resolved graph the dependents check above has
/// nothing to read, so the manifests answer instead — cfg-if is declared
/// beside crc32fast, which may well pull it in, and the redirect is refused
/// rather than reported as one while the build links an unpatched copy
/// through crc32fast.
#[tokio::test(flavor = "multi_thread")]
async fn cargo_hosted_refuses_a_lockless_project_with_other_dependencies() {
    let shape = Shape {
        tag: "lockless-other-dependencies",
        files: vec![
            (
                "Cargo.toml",
                consumer_manifest("cfg-if = \"1.0.4\"\ncrc32fast = \"=1.5.0\"\n"),
            ),
            ("src/main.rs", "fn main() {}\n".to_string()),
        ],
        patches: vec![CFG_IF_1],
        oracle: Vec::new(),
        crlf: false,
        lockless: true,
        refused: Some("redirect_cargo_lockless_dependents"),
        contest: None,
    };
    let _ = run_shape(shape).await;
}

/// #679 / #863: a dependency added after the hosted scan locks its own
/// crates.io copy of the patched cfg-if 1.0.4.
#[tokio::test(flavor = "multi_thread")]
async fn cargo_hosted_contested_by_a_later_crates_io_copy() {
    let shape = Shape {
        tag: "contested-later-dependent",
        files: vec![
            ("Cargo.toml", consumer_manifest("cfg-if = \"1.0.4\"\n")),
            ("src/main.rs", "fn main() {}\n".to_string()),
        ],
        patches: vec![CFG_IF_1],
        oracle: vec![(
            "src/main.rs",
            "fn main() { println!(\"{}\", cfg_if::socket_patched()); }\n".to_string(),
        )],
        crlf: false,
        lockless: false,
        refused: None,
        contest: Some("crc32fast = \"=1.5.0\""),
    };
    let _ = run_shape(shape).await;
}

/// How many hosted pins the run wrote (v5.0: the `applied` / `verified`
/// events with `details.mode: "hosted"`, formerly `redirect.redirected`).
fn hosted_pinned(env: &serde_json::Value) -> u64 {
    env["events"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| {
            e["details"]["mode"] == "hosted"
                && (e["action"] == "applied" || e["action"] == "verified")
        })
        .count() as u64
}
