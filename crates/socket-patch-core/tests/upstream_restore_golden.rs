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
    run_case_with(case, None, &RestoreOptions::default()).await
}

/// [`run_case`] with explicit pins (instead of discovery's) and options.
async fn run_case_with(
    case: &Case,
    pins: Option<Vec<HostedPin>>,
    opts: &RestoreOptions,
) -> (BTreeMap<String, String>, Vec<(String, PinStatus)>) {
    let tmp = tempfile::tempdir().unwrap();
    for (rel, text) in &case.expected {
        let p = tmp.path().join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, text).unwrap();
    }
    let pins = match pins {
        Some(p) => p,
        None => {
            let discovery = socket_patch_core::vex::discover_patched_refs(tmp.path()).await;
            HostedPin::all(&discovery)
        }
    };
    let outcome = restore_upstream(tmp.path(), &pins, opts).await;
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

// ── rubygems ────────────────────────────────────────────────────────────────

/// A case built by running the hosted rewriter over `input`, for the edge
/// shapes the shared goldens do not cover.
fn synthetic(label: &str, input: &[(&str, &str)], overrides: serde_json::Value) -> Case {
    let input: BTreeMap<String, String> = input
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let deps: Vec<socket_patch_core::patch::redirect::DepOverride> =
        serde_json::from_value(overrides.clone()).unwrap();
    let rewrite = socket_patch_core::patch::redirect::rewrite_registry_redirect(&input, &deps);
    assert!(
        !rewrite.files.is_empty(),
        "{label}: the rewrite changed nothing: {:?}",
        rewrite.warnings
    );
    let mut expected = input.clone();
    expected.extend(rewrite.files);
    Case {
        dir: PathBuf::from(format!("synthetic/{label}")),
        input,
        expected,
        overrides: overrides.as_array().unwrap().clone(),
    }
}

impl Case {
    fn clone_with(&self, label: &str) -> Case {
        Case {
            dir: self.dir.with_file_name(label),
            input: self.input.clone(),
            expected: self.expected.clone(),
            overrides: self.overrides.clone(),
        }
    }

    /// Apply `edit` to the named file of both trees.
    fn edit_both(&mut self, rel: &str, edit: impl Fn(&str) -> String) {
        for files in [&mut self.input, &mut self.expected] {
            let next = edit(&files[rel]);
            files.insert(rel.to_string(), next);
        }
    }
}

/// Assert the (single) pin was refused naming `want` and the checkout
/// remedy for `lock`, with nothing written.
fn assert_refused(
    case: &Case,
    after: &BTreeMap<String, String>,
    statuses: &[(String, PinStatus)],
    lock: &str,
    want: &str,
) {
    match &statuses[0].1 {
        PinStatus::Refused(why) => {
            assert!(why.contains(want), "{}: {why}", case.dir.display());
            assert!(why.contains(&format!("checkout -- {lock}")), "{why}");
        }
        other => panic!("{}: expected a refusal, got {other:?}", case.dir.display()),
    }
    assert_eq!(after, &case.expected, "{}: a refused pin must change nothing", case.dir.display());
}

fn offline() -> RestoreOptions {
    RestoreOptions {
        offline: true,
        ..RestoreOptions::default()
    }
}

const GEM_UUID: &str = "77777777-7777-7777-7777-777777777777";
const GEM_INDEX: &str = "https://patch.socket.dev/patch-registry/gem/11111111-1111-1111-1111-111111111111/77777777-7777-7777-7777-777777777777/";

fn gem_override(name: &str, version: &str) -> serde_json::Value {
    serde_json::json!([{
        "ecosystem": "gem",
        "name": name,
        "version": version,
        "token": "11111111-1111-1111-1111-111111111111",
        "patchUuid": GEM_UUID,
        "artifactUrl": format!("{GEM_INDEX}gems/{name}-{version}.gem"),
        "registryOverride": {
            "kind": "rubygems-compact-index",
            "indexUrl": GEM_INDEX,
            "identifiers": {"name": name, "version": version, "gemChecksumSha256": "de".repeat(32)}
        },
        "integrity": {"sha256": "de".repeat(32)}
    }])
}

/// Serve a compact-index `info/<name>` for every sha256-pinned gem of the
/// input locks.
async fn gem_mock(case: &Case) -> MockServer {
    let server = MockServer::start().await;
    let re = regex::Regex::new(r"(?m)^  ([A-Za-z0-9._-]+) \(([^)]+)\) sha256=([0-9a-f]{64})\r?$")
        .unwrap();
    let mut by_gem: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for rel in ["Gemfile.lock", "gems.locked"] {
        let Some(text) = case.input.get(rel) else {
            continue;
        };
        for c in re.captures_iter(text) {
            by_gem
                .entry(c[1].to_string())
                .or_default()
                .push(format!("{} dep:>= 0|checksum:{},ruby:>= 2.7", &c[2], &c[3]));
        }
    }
    for (name, lines) in by_gem {
        Mock::given(method("GET"))
            .and(path(format!("/info/{name}")))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(format!("---\n{}\n", lines.join("\n"))),
            )
            .mount(&server)
            .await;
    }
    server
}

async fn gem_run(case: &Case) -> (BTreeMap<String, String>, Vec<(String, PinStatus)>) {
    let server = gem_mock(case).await;
    let _env = EnvGuard::set(&[("SOCKET_RUBYGEMS_URL", server.uri())]);
    run_case(case).await
}

#[tokio::test]
#[serial]
async fn gem_goldens_round_trip() {
    let mut ran = 0;
    for case in load("gem/bundler") {
        let (after, statuses) = gem_run(&case).await;
        assert_round_trip(&case, &after, &statuses);
        ran += 1;
    }
    assert!(ran > 0);
}

const GEM_LOCK: &str = "GEM\n  remote: https://rubygems.org/\n  specs:\n    puma (6.0.0)\n      nio4r (~> 2.0)\n    rails (7.0.0)\n      rack (>= 2)\n    zeitwerk (2.6.0)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  puma\n  rails (= 7.0.0)\n\nCHECKSUMS\n  puma (6.0.0) sha256=1111111111111111111111111111111111111111111111111111111111111111\n  rails (7.0.0) sha256=2222222222222222222222222222222222222222222222222222222222222222\n  zeitwerk (2.6.0) sha256=3333333333333333333333333333333333333333333333333333333333333333\n\nBUNDLED WITH\n   2.6.2\n";

/// [`GEM_LOCK`] with `zeitwerk` a dependency of puma only (transitive).
fn transitive_lock() -> String {
    GEM_LOCK.replace(
        "      nio4r (~> 2.0)\n",
        "      nio4r (~> 2.0)\n      zeitwerk (~> 2.6)\n",
    )
}

#[tokio::test]
#[serial]
async fn gem_edge_shapes_round_trip() {
    let gemfile = "source \"https://rubygems.org\"\n\ngem \"puma\"\n\ngroup :test do\n  gem \"rails\", \"7.0.0\", require: false\nend\n";
    let crlf_gemfile = "source \"https://rubygems.org\"\r\n\r\ngem \"rails\", \"7.0.0\"\r\ngem \"puma\"\r\n";
    let two_sources_gemfile = "source \"https://rubygems.org\"\n\ngem \"rails\", \"7.0.0\"\nsource \"https://gems.example.com\" do\n  gem \"private-gem\"\nend\n";
    let two_sources_lock = "GEM\n  remote: https://gems.example.com/\n  specs:\n    private-gem (1.0.0)\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.0)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  private-gem!\n  rails (= 7.0.0)\n\nCHECKSUMS\n  private-gem (1.0.0) sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n  rails (7.0.0) sha256=2222222222222222222222222222222222222222222222222222222222222222\n\nBUNDLED WITH\n   2.6.2\n";
    // Provably transitive: the rewriter appended after a trailing blank
    // line, which its in-place rewrite would have swallowed.
    let transitive_gemfile = "source \"https://rubygems.org\"\n\ngem \"puma\"\n\n";
    let transitive = transitive_lock().replace("  rails (= 7.0.0)\n", "");
    let cases = [
        synthetic(
            "group-with-options",
            &[("Gemfile", gemfile), ("Gemfile.lock", GEM_LOCK)],
            gem_override("rails", "7.0.0"),
        ),
        synthetic(
            "gems-rb",
            &[("gems.rb", gemfile), ("gems.locked", GEM_LOCK)],
            gem_override("rails", "7.0.0"),
        ),
        synthetic(
            "crlf",
            &[
                ("Gemfile", crlf_gemfile),
                ("Gemfile.lock", &GEM_LOCK.replace('\n', "\r\n")),
            ],
            gem_override("rails", "7.0.0"),
        ),
        synthetic(
            "multiple-gem-sections",
            &[("Gemfile", two_sources_gemfile), ("Gemfile.lock", two_sources_lock)],
            gem_override("rails", "7.0.0"),
        ),
        synthetic(
            "transitive-appended",
            &[("Gemfile", transitive_gemfile), ("Gemfile.lock", &transitive)],
            gem_override("zeitwerk", "2.6.0"),
        ),
    ];
    for case in &cases {
        let (after, statuses) = gem_run(case).await;
        assert_round_trip(case, &after, &statuses);
    }
}

#[tokio::test]
#[serial]
async fn gem_pre_checksums_states() {
    let gemfile = "source \"https://rubygems.org\"\n\ngem \"rails\", \"~> 7.0\"\ngem \"puma\"\n";
    let checksums = GEM_LOCK
        .split("\nCHECKSUMS\n")
        .nth(1)
        .unwrap()
        .split("\n\n")
        .next()
        .unwrap();
    let lock = GEM_LOCK
        .replace("  rails (= 7.0.0)\n", "  rails (~> 7.0)\n")
        .replace(&format!("\nCHECKSUMS\n{checksums}\n"), "")
        .replace("2.6.2", "2.5.22");
    assert!(!lock.contains("CHECKSUMS"));
    // Mixed: the rewriter edits only the Gemfile, so discovery finds no pin;
    // hand the restore one. The untouched lock keeps the original constraint.
    let mut mixed = synthetic(
        "mixed",
        &[("Gemfile", gemfile), ("Gemfile.lock", &lock)],
        gem_override("rails", "7.0.0"),
    );
    assert_eq!(mixed.expected["Gemfile.lock"], lock);
    let pin = HostedPin {
        purl: "pkg:gem/rails@7.0.0".into(),
        uuid: GEM_UUID.into(),
        files: vec!["Gemfile".into()],
    };
    let (after, statuses) = run_case_with(&mixed, Some(vec![pin]), &offline()).await;
    assert_round_trip(&mixed, &after, &statuses);

    // Bundler 2.2–2.5 then converges the pair itself (a Socket GEM section,
    // a `!` pin, no CHECKSUMS): restorable offline. Not derivable: `~> 7.0`
    // comes back as the exact pin the lock records.
    let restored_lock = lock.replace("  rails (~> 7.0)\n", "  rails (= 7.0.0)\n");
    let restored_gemfile = gemfile.replace("\"~> 7.0\"", "\"7.0.0\"");
    let converged = lock
        .replace("    rails (7.0.0)\n      rack (>= 2)\n", "")
        .replace(
            "GEM\n  remote: https://rubygems.org/",
            &format!(
                "GEM\n  remote: {GEM_INDEX}\n  specs:\n    rails (7.0.0)\n      rack (>= 2)\n\n\
                 GEM\n  remote: https://rubygems.org/"
            ),
        )
        .replace("  rails (~> 7.0)\n", "  rails (= 7.0.0)!\n");
    mixed.expected.insert("Gemfile.lock".into(), converged);
    let (after, statuses) = run_case_with(&mixed, None, &offline()).await;
    assert_eq!(statuses, vec![("pkg:gem/rails@7.0.0".to_string(), PinStatus::Restored)]);
    assert_eq!(after["Gemfile.lock"], restored_lock);
    assert_eq!(after["Gemfile"], restored_gemfile);

    // Bundler ≤ 2.1 merged section: only the Socket remote line goes.
    let merged = lock
        .replace(
            "GEM\n  remote: https://rubygems.org/\n",
            &format!("GEM\n  remote: https://rubygems.org/\n  remote: {GEM_INDEX}\n"),
        )
        .replace("  rails (~> 7.0)\n", "  rails (= 7.0.0)!\n");
    mixed.expected.insert("Gemfile.lock".into(), merged);
    let (after, statuses) = run_case_with(&mixed, None, &offline()).await;
    assert_eq!(statuses, vec![("pkg:gem/rails@7.0.0".to_string(), PinStatus::Restored)]);
    assert_eq!(after["Gemfile.lock"], restored_lock);
    assert_eq!(after["Gemfile"], restored_gemfile);
}

#[tokio::test]
#[serial]
async fn gem_transitive_without_proof_stays_declared() {
    // The rewriter's append for a transitive gem is indistinguishable from a
    // direct last-line declaration, so it is kept as a direct exact pin.
    let gemfile = "source \"https://rubygems.org\"\n\ngem \"puma\"\n";
    let lock = transitive_lock().replace("  rails (= 7.0.0)\n", "");
    let case = synthetic(
        "transitive-ambiguous",
        &[("Gemfile", gemfile), ("Gemfile.lock", &lock)],
        gem_override("zeitwerk", "2.6.0"),
    );
    let (after, statuses) = gem_run(&case).await;
    assert_eq!(statuses[0].1, PinStatus::Restored);
    assert_eq!(after["Gemfile"], format!("{gemfile}gem \"zeitwerk\", \"2.6.0\"\n"));
    assert_eq!(
        after["Gemfile.lock"],
        lock.replace("  puma\n", "  puma\n  zeitwerk (= 2.6.0)\n")
    );
}

#[tokio::test]
#[serial]
async fn gem_refusals_leave_everything_hosted() {
    let gemfile = "source \"https://rubygems.org\"\n\ngem \"rails\", \"7.0.0\"\ngem \"puma\"\n";
    let case = synthetic(
        "refusals",
        &[("Gemfile", gemfile), ("Gemfile.lock", GEM_LOCK)],
        gem_override("rails", "7.0.0"),
    );
    // Offline: the CHECKSUMS sha256 needs the registry.
    let (after, statuses) = run_case_with(&case, None, &offline()).await;
    assert_refused(&case, &after, &statuses, "Gemfile.lock", "offline");
    // The registry does not know the gem.
    {
        let server = MockServer::start().await;
        let _env = EnvGuard::set(&[("SOCKET_RUBYGEMS_URL", server.uri())]);
        let (after, statuses) = run_case(&case).await;
        assert_refused(&case, &after, &statuses, "Gemfile.lock", "404");
    }
    // The upstream section is another registry's.
    let mut foreign = case.clone_with("foreign-upstream");
    foreign.edit_both("Gemfile.lock", |t| {
        t.replace("remote: https://rubygems.org/", "remote: https://gems.example.com/")
    });
    let (after, statuses) = gem_run(&foreign).await;
    assert_refused(&foreign, &after, &statuses, "Gemfile.lock", "not rubygems.org");
    // Two upstream sections, neither singled out.
    let mut ambiguous = case.clone_with("ambiguous-upstream");
    ambiguous.edit_both("Gemfile.lock", |t| {
        t.replace(
            "PLATFORMS",
            "GEM\n  remote: https://gems.example.com/\n  specs:\n    other (1.0.0)\n\nPLATFORMS",
        )
    });
    ambiguous.edit_both("Gemfile", |t| t.replace("source \"https://rubygems.org\"\n", ""));
    ambiguous.edit_both("Gemfile.lock", |t| t.replace("remote: https://rubygems.org/", "remote: https://mirror.example.com/"));
    let (after, statuses) = gem_run(&ambiguous).await;
    assert_refused(&ambiguous, &after, &statuses, "Gemfile.lock", "upstream GEM sections");
    // The Gemfile block was hand-edited.
    let mut edited = case.clone_with("edited-block");
    edited.expected.insert(
        "Gemfile".into(),
        edited.expected["Gemfile"].replace("  gem \"rails\", \"7.0.0\"", "  gem \"rails\", \"~> 7.0\""),
    );
    let (after, statuses) = gem_run(&edited).await;
    assert_refused(&edited, &after, &statuses, "Gemfile.lock", "shape other than the source block");
}

// ── composer ────────────────────────────────────────────────────────────────

/// Serve packagist `p2` metadata for every entry of the input lock, in
/// composer/2.0 minified form behind a decoy version (so the expansion —
/// inherited keys, `__unset` — is exercised). `tweak` edits each served
/// version's diff.
async fn composer_mock(case: &Case, tweak: impl Fn(&mut serde_json::Value)) -> MockServer {
    let server = MockServer::start().await;
    let lock: serde_json::Value = serde_json::from_str(&case.input["composer.lock"]).unwrap();
    let mut by_file: BTreeMap<String, (String, Vec<serde_json::Value>)> = BTreeMap::new();
    for section in ["packages", "packages-dev"] {
        for entry in lock[section].as_array().cloned().unwrap_or_default() {
            let name = entry["name"].as_str().unwrap().to_ascii_lowercase();
            let version = entry["version"].as_str().unwrap();
            let dev = version.starts_with("dev-") || version.ends_with("-dev");
            let file = format!("{name}{}", if dev { "~dev" } else { "" });
            let mut diff = serde_json::json!({
                "version": version,
                "dist": entry["dist"],
                "source": entry.get("source").cloned().unwrap_or_else(|| "__unset".into()),
            });
            tweak(&mut diff);
            let (_, versions) = by_file.entry(file).or_insert_with(|| {
                (
                    name.clone(),
                    vec![serde_json::json!({
                        "name": name,
                        "version": "99.0.0",
                        "type": "library",
                        "source": {"type": "git", "url": "https://decoy.example/x.git", "reference": "decoy"},
                        "dist": {"type": "zip", "url": "https://decoy.example/x.zip", "reference": "decoy", "shasum": "decoy"}
                    })],
                )
            });
            versions.push(diff);
        }
    }
    for (file, (name, versions)) in by_file {
        Mock::given(method("GET"))
            .and(path(format!("/p2/{file}.json")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "packages": { name: versions },
                "minified": "composer/2.0"
            })))
            .mount(&server)
            .await;
    }
    server
}

async fn composer_run(
    case: &Case,
    tweak: impl Fn(&mut serde_json::Value),
) -> (BTreeMap<String, String>, Vec<(String, PinStatus)>) {
    let server = composer_mock(case, tweak).await;
    let _env = EnvGuard::set(&[("SOCKET_PACKAGIST_URL", server.uri())]);
    run_case(case).await
}

#[tokio::test]
#[serial]
async fn composer_goldens_round_trip() {
    // Every composer golden with a rewrite is invertible.
    let mut ran = 0;
    for case in load("composer/composer-lock") {
        let (after, statuses) = composer_run(&case, |_| {}).await;
        assert_round_trip(&case, &after, &statuses);
        ran += 1;
    }
    assert!(ran >= 5, "{ran}");
}

fn composer_override(name: &str, version: &str) -> serde_json::Value {
    let (ns, leaf) = name.split_once('/').unwrap();
    serde_json::json!([{
        "ecosystem": "composer",
        "name": leaf,
        "namespace": ns,
        "version": version,
        "token": "11111111-1111-1111-1111-111111111111",
        "patchUuid": "44444444-4444-4444-4444-444444444444",
        "artifactUrl": format!(
            "https://patch.socket.dev/patch/composer/{name}/{version}/11111111-1111-1111-1111-111111111111/44444444-4444-4444-4444-444444444444/{leaf}.zip"
        ),
        "integrity": {"sha1": "abcdef0123456789abcdef0123456789abcdef01"}
    }])
}

const COMPOSER_LOCK: &str = r#"{
    "_readme": [
        "This file locks the dependencies of your project to a known state"
    ],
    "content-hash": "abc123",
    "packages": [
        {
            "name": "psr/log",
            "version": "1.1.4",
            "source": {
                "type": "git",
                "url": "https://github.com/php-fig/log.git",
                "reference": "d49695b909c3b7628b6289db5479a1c204601f11"
            },
            "dist": {
                "type": "zip",
                "url": "https://api.github.com/repos/php-fig/log/zipball/d49695b909c3b7628b6289db5479a1c204601f11",
                "reference": "d49695b909c3b7628b6289db5479a1c204601f11",
                "shasum": ""
            },
            "type": "library",
            "notification-url": "https://packagist.org/downloads/"
        }
    ],
    "packages-dev": [
        {
            "name": "acme/tool",
            "version": "dev-main",
            "source": {
                "type": "git",
                "url": "https://github.com/acme/tool.git",
                "reference": "0123456789abcdef0123456789abcdef01234567"
            },
            "dist": {
                "type": "zip",
                "url": "https://api.github.com/repos/acme/tool/zipball/0123456789abcdef0123456789abcdef01234567",
                "reference": "0123456789abcdef0123456789abcdef01234567",
                "shasum": ""
            },
            "type": "library",
            "notification-url": "https://packagist.org/downloads/"
        }
    ]
}
"#;

#[tokio::test]
#[serial]
async fn composer_edge_shapes_round_trip() {
    // Older composer escaped every slash; the rewriter matches names as
    // written, so only the URL values are escaped here.
    let escaped = regex::Regex::new(r#""(url|notification-url)": "([^"]*)""#)
        .unwrap()
        .replace_all(COMPOSER_LOCK, |c: &regex::Captures| {
            format!("\"{}\": \"{}\"", &c[1], c[2].replace('/', "\\/"))
        })
        .into_owned();
    let crlf = COMPOSER_LOCK.replace('\n', "\r\n");
    let cases = [
        synthetic(
            "dev-version-packages-dev",
            &[("composer.lock", COMPOSER_LOCK)],
            composer_override("acme/tool", "dev-main"),
        ),
        synthetic(
            "prod-entry",
            &[("composer.lock", COMPOSER_LOCK)],
            composer_override("psr/log", "1.1.4"),
        ),
        synthetic(
            "escaped-slashes",
            &[("composer.lock", &escaped)],
            composer_override("acme/tool", "dev-main"),
        ),
        synthetic("crlf", &[("composer.lock", &crlf)], composer_override("psr/log", "1.1.4")),
    ];
    for case in &cases {
        let (after, statuses) = composer_run(case, |_| {}).await;
        assert_round_trip(case, &after, &statuses);
    }
}

#[tokio::test]
#[serial]
async fn composer_refusals_leave_everything_hosted() {
    let case = synthetic(
        "refusals",
        &[("composer.lock", COMPOSER_LOCK)],
        composer_override("psr/log", "1.1.4"),
    );
    // Packagist now serves another commit for the version.
    let (after, statuses) =
        composer_run(&case, |d| d["dist"]["reference"] = "feedface".into()).await;
    assert_refused(&case, &after, &statuses, "composer.lock", "packagist now serves");
    // Packagist does not list the version.
    let (after, statuses) = composer_run(&case, |d| d["version"] = "0.0.1".into()).await;
    assert_refused(&case, &after, &statuses, "composer.lock", "does not list version 1.1.4");
    // Offline.
    let (after, statuses) = run_case_with(&case, None, &offline()).await;
    assert_refused(&case, &after, &statuses, "composer.lock", "offline");
    // Locked from another repository.
    let mut foreign = case.clone_with("foreign");
    foreign.edit_both("composer.lock", |t| {
        t.replacen("https://packagist.org/downloads/", "https://repo.example.com/downloads/", 1)
    });
    let (after, statuses) = composer_run(&foreign, |_| {}).await;
    assert_refused(&foreign, &after, &statuses, "composer.lock", "not packagist");
    // No notification-url, and composer.json names custom repositories.
    let mut custom = case.clone_with("custom-repos");
    custom.edit_both("composer.lock", |t| {
        t.replacen(
            ",\n            \"notification-url\": \"https://packagist.org/downloads/\"",
            "",
            1,
        )
    });
    for files in [&mut custom.input, &mut custom.expected] {
        files.insert(
            "composer.json".into(),
            r#"{"repositories": [{"type": "composer", "url": "https://repo.example.com"}]}"#.into(),
        );
    }
    let (after, statuses) = composer_run(&custom, |_| {}).await;
    assert_refused(&custom, &after, &statuses, "composer.lock", "custom repositories");
}
