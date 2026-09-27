//! The v5 hosted unwind, pinned against the shared redirect goldens: each
//! case's `expected/` tree (what `scan --mode hosted` writes) restored to
//! the upstream registry entry must give back the `input/` bytes — with the
//! upstream values served by a mock registry that knows only what `input/`
//! pins, exactly as the public registry would answer.
//!
//! A case is exercised when its rewrite is invertible without a ledger (the
//! list below names the ones whose original spelling is not derivable, and
//! why); every other case must round-trip byte for byte.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serial_test::serial;
use socket_patch_core::patch::redirect::upstream::{
    restore_upstream, HostedPin, PinStatus, RestoreOptions,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/redirect")
}

fn walk(dir: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if !dir.is_dir() {
        return out;
    }
    for entry in walkdir::WalkDir::new(dir).into_iter().filter_map(Result::ok) {
        if entry.file_type().is_file() {
            let rel = entry
                .path()
                .strip_prefix(dir)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            out.insert(rel, fs::read_to_string(entry.path()).unwrap());
        }
    }
    out
}

/// Tokens of `pattern` that `input` holds and `expected` does not: the
/// upstream values the hosted rewrite replaced.
fn vanished(input: &BTreeMap<String, String>, expected: &BTreeMap<String, String>, re: &str) -> Vec<String> {
    let re = regex::Regex::new(re).unwrap();
    let all = |files: &BTreeMap<String, String>| -> BTreeSet<String> {
        files
            .values()
            .flat_map(|t| re.captures_iter(t).map(|c| c[1].to_string()).collect::<Vec<_>>())
            .collect()
    };
    let after = all(expected);
    let mut out: Vec<String> = all(input).into_iter().filter(|t| !after.contains(t)).collect();
    out.sort();
    out
}

struct Case {
    dir: PathBuf,
    input: BTreeMap<String, String>,
    expected: BTreeMap<String, String>,
    overrides: Vec<serde_json::Value>,
}

fn load(flavor: &str) -> Vec<Case> {
    let root = fixtures().join(flavor);
    let mut dirs: Vec<PathBuf> = fs::read_dir(&root)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.join("input").is_dir() && p.join("expected").is_dir())
        .collect();
    dirs.sort();
    dirs.into_iter()
        .map(|dir| {
            let input = walk(&dir.join("input"));
            // `expected/` holds only the files the rewrite changed.
            let mut expected = input.clone();
            expected.extend(walk(&dir.join("expected")));
            let overrides = serde_json::from_str(
                &fs::read_to_string(dir.join("overrides.json")).unwrap(),
            )
            .unwrap();
            Case {
                dir,
                input,
                expected,
                overrides,
            }
        })
        // A rewrite happened, from a pristine tree (re-redirect cases start
        // hosted: there is no upstream `input/` to come back to).
        .filter(|c| {
            c.input != c.expected && !c.input.values().any(|t| t.contains("patch.socket.dev"))
        })
        .collect()
}

async fn run_case(case: &Case) -> (BTreeMap<String, String>, Vec<(String, PinStatus)>) {
    let tmp = tempfile::tempdir().unwrap();
    for (rel, text) in &case.expected {
        let p = tmp.path().join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, text).unwrap();
    }
    let discovery = socket_patch_core::vex::discover_patched_refs(tmp.path()).await;
    let pins = HostedPin::all(&discovery);
    let outcome = restore_upstream(tmp.path(), &pins, &RestoreOptions::default()).await;
    assert!(outcome.flush_error.is_none(), "{:?}", outcome.flush_error);
    let statuses = outcome
        .pins
        .iter()
        .map(|p| (p.purl.clone(), p.status.clone()))
        .collect();
    (walk(tmp.path()), statuses)
}

fn assert_round_trip(case: &Case, after: &BTreeMap<String, String>, statuses: &[(String, PinStatus)]) {
    assert!(!statuses.is_empty(), "{}: discovery found no hosted pin", case.dir.display());
    for (purl, status) in statuses {
        assert_eq!(*status, PinStatus::Restored, "{}: {purl}", case.dir.display());
    }
    for (rel, want) in &case.input {
        assert_eq!(
            after.get(rel),
            Some(want),
            "{}: {rel} did not round-trip",
            case.dir.display()
        );
    }
    let extra: Vec<&String> = after.keys().filter(|k| !case.input.contains_key(*k)).collect();
    assert!(extra.is_empty(), "{}: left behind {extra:?}", case.dir.display());
}

/// Sets env vars for the guard's lifetime (tests using it are `#[serial]`).
struct EnvGuard(Vec<(String, Option<String>)>);

impl EnvGuard {
    fn set(vars: &[(&str, String)]) -> Self {
        let saved = vars
            .iter()
            .map(|(k, _)| (k.to_string(), std::env::var(k).ok()))
            .collect();
        for (k, v) in vars {
            std::env::set_var(k, v);
        }
        EnvGuard(saved)
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (k, v) in self.0.drain(..) {
            match v {
                Some(v) => std::env::set_var(&k, v),
                None => std::env::remove_var(&k),
            }
        }
    }
}

/// Serve an npm version document for every single-override npm case.
async fn npm_mock(case: &Case) -> MockServer {
    let server = MockServer::start().await;
    let integrity = vanished(&case.input, &case.expected, r"(sha512-[A-Za-z0-9+/=]+)");
    let shasum = vanished(&case.input, &case.expected, r"#([0-9a-f]{40})\b");
    let tarballs = vanished(
        &case.input,
        &case.expected,
        r##"(https://registry\.[a-z]+\.(?:org|com)/[^"#\s]+\.tgz)"##,
    );
    for o in &case.overrides {
        let name = match o["namespace"].as_str() {
            Some(ns) if !ns.is_empty() => format!("{ns}/{}", o["name"].as_str().unwrap()),
            _ => o["name"].as_str().unwrap().to_string(),
        };
        let version = o["version"].as_str().unwrap();
        let leaf = name.rsplit('/').next().unwrap();
        let tarball = tarballs
            .iter()
            .find(|t| t.ends_with(&format!("/{leaf}-{version}.tgz")))
            .cloned()
            .unwrap_or_else(|| format!("https://registry.npmjs.org/{name}/-/{leaf}-{version}.tgz"));
        let mut dist = serde_json::json!({ "tarball": tarball });
        if let [only] = integrity.as_slice() {
            dist["integrity"] = only.clone().into();
        }
        if let [only] = shasum.as_slice() {
            dist["shasum"] = only.clone().into();
        }
        Mock::given(method("GET"))
            .and(path(format!("/{}/{version}", name.replace('/', "%2f"))))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "name": name, "version": version, "dist": dist })),
            )
            .mount(&server)
            .await;
    }
    server
}

async fn npm_flavor(flavor: &str, not_invertible: &[&str]) {
    let mut ran = 0;
    for case in load(flavor) {
        let name = case.dir.file_name().unwrap().to_string_lossy().into_owned();
        if not_invertible.contains(&name.as_str()) {
            continue;
        }
        let server = npm_mock(&case).await;
        let _env = EnvGuard::set(&[("SOCKET_NPM_REGISTRY", server.uri())]);
        let (after, statuses) = run_case(&case).await;
        assert_round_trip(&case, &after, &statuses);
        ran += 1;
    }
    assert!(ran > 0, "{flavor}: no case ran");
}

#[tokio::test]
#[serial]
async fn package_lock_goldens_round_trip() {
    npm_flavor("npm/package-lock-v3", &[]).await;
}

#[tokio::test]
#[serial]
async fn yarn_classic_goldens_round_trip() {
    npm_flavor("npm/yarn-classic", &[]).await;
}

#[tokio::test]
#[serial]
async fn pnpm_goldens_round_trip() {
    // nested-rush-lock: a nested (Rush) lock is outside root-only discovery.
    npm_flavor("npm/pnpm", &["nested-rush-lock"]).await;
}

#[tokio::test]
#[serial]
async fn bun_goldens_round_trip() {
    // custom-registry: the entry's registry slot is not recorded; the
    // restore writes the default registry (""). scoped-package: its artifact
    // leaf names another package, so discovery (rightly) claims no pin.
    npm_flavor("npm/bun", &["custom-registry", "scoped-package"]).await;
}

/// `(name, version, checksum)` of every checksummed entry of a Cargo.lock.
fn cargo_checksums(lock: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for block in lock.split("[[package]]").skip(1) {
        let field = |k: &str| {
            block.lines().find_map(|l| {
                l.strip_prefix(&format!("{k} = \""))
                    .and_then(|r| r.strip_suffix('"'))
                    .map(str::to_string)
            })
        };
        if let (Some(n), Some(v), Some(c)) = (field("name"), field("version"), field("checksum")) {
            out.push((n, v, c));
        }
    }
    out
}

#[tokio::test]
#[serial]
async fn cargo_goldens_round_trip() {
    let mut ran = 0;
    for case in load("cargo/cargo") {
        let server = MockServer::start().await;
        let Some(lock) = case.input.get("Cargo.lock") else {
            continue;
        };
        let mut by_crate: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (n, v, c) in cargo_checksums(lock) {
            by_crate
                .entry(n.clone())
                .or_default()
                .push(serde_json::json!({ "name": n, "vers": v, "cksum": c }).to_string());
        }
        for (name, rows) in by_crate {
            let lower = name.to_ascii_lowercase();
            let index_path = match lower.len() {
                1 => format!("/1/{lower}"),
                2 => format!("/2/{lower}"),
                3 => format!("/3/{}/{lower}", &lower[..1]),
                _ => format!("/{}/{}/{lower}", &lower[..2], &lower[2..4]),
            };
            Mock::given(method("GET"))
                .and(path(index_path))
                .respond_with(ResponseTemplate::new(200).set_body_string(rows.join("\n")))
                .mount(&server)
                .await;
        }
        let _env = EnvGuard::set(&[("SOCKET_CRATES_INDEX", server.uri())]);
        let (after, statuses) = run_case(&case).await;
        assert_round_trip(&case, &after, &statuses);
        ran += 1;
    }
    assert!(ran > 0);
}

#[tokio::test]
#[serial]
async fn golang_goldens_round_trip() {
    let mut ran = 0;
    for case in load("golang/gomod") {
        let server = MockServer::start().await;
        let sum = case.input.get("go.sum").cloned().unwrap_or_default();
        let mut by_module: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for line in sum.lines() {
            let mut parts = line.split_whitespace();
            let (Some(m), Some(v)) = (parts.next(), parts.next()) else {
                continue;
            };
            let v = v.trim_end_matches("/go.mod");
            by_module
                .entry(format!("{m}@{v}"))
                .or_default()
                .push(line.to_string());
        }
        for (id, lines) in by_module {
            Mock::given(method("GET"))
                .and(path(format!("/lookup/{id}")))
                .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                    "12345\n{}\n\ngo.sum database tree\n",
                    lines.join("\n")
                )))
                .mount(&server)
                .await;
        }
        let _env = EnvGuard::set(&[("SOCKET_GOSUMDB_URL", server.uri())]);
        let (after, statuses) = run_case(&case).await;
        assert_round_trip(&case, &after, &statuses);
        ran += 1;
    }
    assert!(ran > 0);
}
