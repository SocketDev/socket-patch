//! Real-cargo hosted-mode regressions for project SHAPES beyond the single
//! root dependency `e2e_redirect_cargo_build` covers — each one a defect a
//! real-cargo capture matrix found in the hosted rewriter / revert:
//!
//! * `multi_version` — two patched versions of one crate (`cfg-if` 1.0.4 and
//!   a renamed `cfg-if-legacy` at 0.1.10): each declaration is pinned to its
//!   own version's registry, and removing both purls restores every byte.
//! * `legacy_config` — an existing legacy `.cargo/config`: the registry
//!   block lands there, and `remove` restores the file byte-for-byte —
//!   also when it lacks a final newline or ends in a blank line.
//! * `crlf` — CRLF `Cargo.toml` + `Cargo.lock`: rewritten with CRLF kept,
//!   and restored byte-for-byte.
//! * `workspace_direct_member` — a virtual workspace whose root pins
//!   `[workspace.dependencies]`, one member inheriting and one declaring the
//!   crate itself: both members build against the patched copy.
//! * `direct_and_transitive` — the crate is also a dependency of another
//!   crates.io crate: hosted mode refuses it loudly and rewrites nothing.
//!
//! Every shape runs the same chain against the real cargo: a baseline build
//! with a private CARGO_HOME (network to crates.io for fixture setup only),
//! patched `.crate`s rebuilt from the ACTUAL crates.io bytes and served by a
//! wiremock sparse registry per patch, `scan --mode hosted`, then a FRESH
//! checkout (only the committed files travel) where `cargo fetch --locked`
//! and an offline `cargo build --locked` must link each patched-only symbol
//! and a post-install `vex` must attest exactly the patches, and finally
//! `remove <purl>` for every patch — in apply order and, from the same
//! post-scan state, in reverse — which must leave the project
//! byte-identical to its pre-scan state.
//!
//! `SOCKET_PATCH_CARGO_E2E_LOCK_VERSION` / `_TOOLCHAIN` (see
//! `cargo_e2e_matrix`) re-encode the baseline lock, so a v1 lock's full-id
//! dependency edges and `[metadata]` checksums meet every shape too.
//!
//! Skips (with a println) when `cargo` is missing or crates.io is
//! unreachable (a failure instead under `SOCKET_PATCH_CARGO_E2E_REQUIRED=1`).

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
    /// A shape hosted mode must REFUSE: the rewriter warning code every
    /// patch is skipped with. The scan must leave every file untouched.
    refused: Option<&'static str>,
}

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_socket-patch"))
}

fn run_socket(cwd: &Path, args: &[&str], cargo_home: &Path) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args(args).current_dir(cwd);
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("SOCKET_") {
            cmd.env_remove(&k);
        }
    }
    cmd.env("SOCKET_NO_CONFIG", "1");
    cmd.env("CARGO_HOME", cargo_home);
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
        assert_eq!(env["redirect"]["redirected"], 0, "{}: {env}", shape.tag);
        let codes: Vec<&str> = env["redirect"]["warnings"]
            .as_array()
            .unwrap()
            .iter()
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
        let fetch = cargo(&proj, &["fetch", "--locked"], &home);
        assert!(
            fetch.status.success(),
            "{}: the untouched project still fetches --locked:\n{}",
            shape.tag,
            stderr(&fetch)
        );
        return Some(());
    }
    assert_eq!(
        env["redirect"]["redirected"],
        shape.patches.len(),
        "{}: every patch redirected: {env}",
        shape.tag
    );
    assert_eq!(
        env["redirect"]["warnings"],
        serde_json::json!([]),
        "{}: {env}",
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

    // Rollback: removing every purl restores the pre-scan project exactly —
    // in apply order AND in reverse (a v1 lock's shared dependent blocks
    // once made the first-applied purl unremovable before its sibling).
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
            let (code, stdout, err) = run_socket(
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
            );
            assert_eq!(
                code, 0,
                "{} (removal order {n}): remove {purl}\nstdout:\n{stdout}\nstderr:\n{err}",
                shape.tag
            );
        }
        let after = snapshot(&proj);
        for (rel, bytes) in &before {
            assert_eq!(
                after
                    .get(rel)
                    .map(|b| String::from_utf8_lossy(b).into_owned()),
                Some(String::from_utf8_lossy(bytes).into_owned()),
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
        refused: None,
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
        refused: None,
    };
    let _ = run_shape(shape).await;
}

/// Bug H, exactly: a config without a final newline, and one ending in a
/// blank line, both come back byte-for-byte (the appended block's removal
/// once normalized the trailing newline run).
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
            refused: None,
        };
        if run_shape(shape).await.is_none() {
            return;
        }
    }
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
        refused: None,
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
        refused: None,
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
        refused: Some("redirect_cargo_transitive_dependents"),
    };
    let _ = run_shape(shape).await;
}
