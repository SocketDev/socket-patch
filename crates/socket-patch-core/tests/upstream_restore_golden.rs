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
use socket_patch_core::patch::redirect::{
    rewrite_registry_redirect_with_pipenv_version, DepOverride,
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
    for entry in walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(Result::ok)
    {
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
fn vanished(
    input: &BTreeMap<String, String>,
    expected: &BTreeMap<String, String>,
    re: &str,
) -> Vec<String> {
    let re = regex::Regex::new(re).unwrap();
    let all = |files: &BTreeMap<String, String>| -> BTreeSet<String> {
        files
            .values()
            .flat_map(|t| {
                re.captures_iter(t)
                    .map(|c| c[1].to_string())
                    .collect::<Vec<_>>()
            })
            .collect()
    };
    let after = all(expected);
    let mut out: Vec<String> = all(input)
        .into_iter()
        .filter(|t| !after.contains(t))
        .collect();
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
            let overrides =
                serde_json::from_str(&fs::read_to_string(dir.join("overrides.json")).unwrap())
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

fn assert_round_trip(
    case: &Case,
    after: &BTreeMap<String, String>,
    statuses: &[(String, PinStatus)],
) {
    assert!(
        !statuses.is_empty(),
        "{}: discovery found no hosted pin",
        case.dir.display()
    );
    for (purl, status) in statuses {
        assert_eq!(
            *status,
            PinStatus::Restored,
            "{}: {purl}",
            case.dir.display()
        );
    }
    for (rel, want) in &case.input {
        assert_eq!(
            after.get(rel),
            Some(want),
            "{}: {rel} did not round-trip",
            case.dir.display()
        );
    }
    let extra: Vec<&String> = after
        .keys()
        .filter(|k| !case.input.contains_key(*k))
        .collect();
    assert!(
        extra.is_empty(),
        "{}: left behind {extra:?}",
        case.dir.display()
    );
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
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({ "name": name, "version": version, "dist": dist }),
            ))
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

/// #324: the hosted unwind of a CRLF, tab-indented or BOM-prefixed
/// package-lock.json gives back the lock's original bytes (npm keeps those
/// layouts on its own rewrites and installs from a BOM lock).
#[tokio::test]
#[serial]
async fn package_lock_layouts_round_trip() {
    let basic = load("npm/package-lock-v3")
        .into_iter()
        .find(|c| c.dir.ends_with("basic"))
        .expect("npm/package-lock-v3/basic golden");
    let lf = basic.input["package-lock.json"].clone();
    let shapes = [
        ("crlf", lf.replace('\n', "\r\n")),
        ("tabs", lf.replace("  ", "\t")),
        ("bom", format!("\u{feff}{lf}")),
        (
            "bom+crlf+tabs",
            format!("\u{feff}{}", lf.replace("  ", "\t").replace('\n', "\r\n")),
        ),
    ];
    for (shape, pristine) in shapes {
        let case = synthetic(
            &format!("npm-lock-{shape}"),
            &[("package-lock.json", &pristine)],
            serde_json::Value::Array(basic.overrides.clone()),
        );
        let server = npm_mock(&case).await;
        let _env = EnvGuard::set(&[("SOCKET_NPM_REGISTRY", server.uri())]);
        let (after, statuses) = run_case(&case).await;
        assert_round_trip(&case, &after, &statuses);
    }
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
    assert_eq!(
        after,
        &case.expected,
        "{}: a refused pin must change nothing",
        case.dir.display()
    );
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
    let crlf_gemfile =
        "source \"https://rubygems.org\"\r\n\r\ngem \"rails\", \"7.0.0\"\r\ngem \"puma\"\r\n";
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
            &[
                ("Gemfile", two_sources_gemfile),
                ("Gemfile.lock", two_sources_lock),
            ],
            gem_override("rails", "7.0.0"),
        ),
        synthetic(
            "transitive-appended",
            &[
                ("Gemfile", transitive_gemfile),
                ("Gemfile.lock", &transitive),
            ],
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
    assert_eq!(
        statuses,
        vec![("pkg:gem/rails@7.0.0".to_string(), PinStatus::Restored)]
    );
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
    assert_eq!(
        statuses,
        vec![("pkg:gem/rails@7.0.0".to_string(), PinStatus::Restored)]
    );
    assert_eq!(after["Gemfile.lock"], restored_lock);
    assert_eq!(after["Gemfile"], restored_gemfile);
}

#[tokio::test]
#[serial]
async fn gem_transitive_append_round_trips_unless_unprovable() {
    // #457: on a Gemfile ending in a declaration line, the rewriter's own
    // append for a transitive gem is undone byte for byte: no new `gem`
    // line, no `(= version)` DEPENDENCIES pin freezing the version.
    let gemfile = "source \"https://rubygems.org\"\n\ngem \"puma\"\n";
    let lock = transitive_lock().replace("  rails (= 7.0.0)\n", "");
    let case = synthetic(
        "transitive-appended",
        &[("Gemfile", gemfile), ("Gemfile.lock", &lock)],
        gem_override("zeitwerk", "2.6.0"),
    );
    let (after, statuses) = gem_run(&case).await;
    assert_round_trip(&case, &after, &statuses);

    // An append with no blank line before it (what releases before #457
    // wrote) is indistinguishable from a direct last-line declaration, so
    // it is kept as a direct exact pin.
    let mut case = case.clone_with("transitive-ambiguous");
    let legacy = case.expected["Gemfile"].replace("\n\nsource", "\nsource");
    assert_ne!(legacy, case.expected["Gemfile"]);
    case.expected.insert("Gemfile".into(), legacy);
    let (after, statuses) = gem_run(&case).await;
    assert_eq!(statuses[0].1, PinStatus::Restored);
    assert_eq!(
        after["Gemfile"],
        format!("{gemfile}gem \"zeitwerk\", \"2.6.0\"\n")
    );
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
        t.replace(
            "remote: https://rubygems.org/",
            "remote: https://gems.example.com/",
        )
    });
    let (after, statuses) = gem_run(&foreign).await;
    assert_refused(
        &foreign,
        &after,
        &statuses,
        "Gemfile.lock",
        "not rubygems.org",
    );
    // Two upstream sections, neither singled out.
    let mut ambiguous = case.clone_with("ambiguous-upstream");
    ambiguous.edit_both("Gemfile.lock", |t| {
        t.replace(
            "PLATFORMS",
            "GEM\n  remote: https://gems.example.com/\n  specs:\n    other (1.0.0)\n\nPLATFORMS",
        )
    });
    ambiguous.edit_both("Gemfile", |t| {
        t.replace("source \"https://rubygems.org\"\n", "")
    });
    ambiguous.edit_both("Gemfile.lock", |t| {
        t.replace(
            "remote: https://rubygems.org/",
            "remote: https://mirror.example.com/",
        )
    });
    let (after, statuses) = gem_run(&ambiguous).await;
    assert_refused(
        &ambiguous,
        &after,
        &statuses,
        "Gemfile.lock",
        "upstream GEM sections",
    );
    // The Gemfile block was hand-edited.
    let mut edited = case.clone_with("edited-block");
    edited.expected.insert(
        "Gemfile".into(),
        edited.expected["Gemfile"]
            .replace("  gem \"rails\", \"7.0.0\"", "  gem \"rails\", \"~> 7.0\""),
    );
    let (after, statuses) = gem_run(&edited).await;
    assert_refused(
        &edited,
        &after,
        &statuses,
        "Gemfile.lock",
        "shape other than the source block",
    );
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
    // Restore registry fields byte for byte. A hosted rewrite removes local
    // mirror settings and the source block's original position, neither of
    // which Packagist can reconstruct without a ledger. Those cases record
    // the canonical upstream result in `restored/`.
    let mut ran = 0;
    for mut case in load("composer/composer-lock") {
        let (after, statuses) = composer_run(&case, |_| {}).await;
        case.input.extend(walk(&case.dir.join("restored")));
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
        synthetic(
            "crlf",
            &[("composer.lock", &crlf)],
            composer_override("psr/log", "1.1.4"),
        ),
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
    assert_refused(
        &case,
        &after,
        &statuses,
        "composer.lock",
        "packagist now serves",
    );
    // Packagist does not list the version.
    let (after, statuses) = composer_run(&case, |d| d["version"] = "0.0.1".into()).await;
    assert_refused(
        &case,
        &after,
        &statuses,
        "composer.lock",
        "does not list version 1.1.4",
    );
    // Offline.
    let (after, statuses) = run_case_with(&case, None, &offline()).await;
    assert_refused(&case, &after, &statuses, "composer.lock", "offline");
    // Locked from another repository.
    let mut foreign = case.clone_with("foreign");
    foreign.edit_both("composer.lock", |t| {
        t.replacen(
            "https://packagist.org/downloads/",
            "https://repo.example.com/downloads/",
            1,
        )
    });
    let (after, statuses) = composer_run(&foreign, |_| {}).await;
    assert_refused(
        &foreign,
        &after,
        &statuses,
        "composer.lock",
        "not packagist",
    );
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
    assert_refused(
        &custom,
        &after,
        &statuses,
        "composer.lock",
        "custom repositories",
    );
}

// ── PyPI ─────────────────────────────────────────────────────────────────────
//
// The shared goldens hold one requirements and one uv case; the other
// formats round-trip their native fixtures (`tests/fixtures/poetry`,
// `pdm-native`, `pipenv`) and synthetic locks through the REAL hosted
// rewriter, with a mock PyPI JSON API serving the release files the input
// pins.

const PYPI_UUID: &str = "33333333-3333-3333-3333-333333333333";
const URLLIB3_WHEEL: &str = "urllib3-1.26.18-py2.py3-none-any.whl";
const URLLIB3_WHEEL_SHA: &str = "34b97092d7e0a3a8cf7cd10e386f401b3737364026c45e622aa02903dffe0f07";
const URLLIB3_SDIST: &str = "urllib3-1.26.18.tar.gz";
const URLLIB3_SDIST_SHA: &str = "f8ecc1bba5667413457c529ab955bf8c67b45db799d159066261719e328580a0";

fn pypi_dep(name: &str, version: &str, leaf: &str, uuid: &str) -> DepOverride {
    serde_json::from_value(serde_json::json!({
        "ecosystem": "pypi", "name": name, "version": version,
        "token": "11111111-1111-1111-1111-111111111111",
        "patchUuid": uuid,
        "artifactUrl": format!(
            "https://patch.socket.dev/patch/pypi/{name}/{version}/11111111-1111-1111-1111-111111111111/{uuid}/{leaf}"
        ),
        "integrity": { "sha256": "d".repeat(64) }
    }))
    .unwrap()
}

fn urllib3_dep() -> DepOverride {
    pypi_dep("urllib3", "1.26.18", URLLIB3_WHEEL, PYPI_UUID)
}

/// The mock PyPI URL of a release file.
/// PyPI's blake2b-bucketed file URLs, with real urllib3 1.26.18's buckets: the
/// sdist sorts before the wheel by URL, the reverse of filename order.
fn pypi_file_url(filename: &str) -> String {
    let bucket = if filename.ends_with(".tar.gz") {
        "0c/39"
    } else {
        "b0/53"
    };
    format!("https://files.pythonhosted.org/packages/{bucket}/{filename}")
}

/// One PyPI JSON API release: name, version, `(filename, sha256, size,
/// upload_time_iso_8601)` per file.
type Release<'a> = (&'a str, &'a str, Vec<(&'a str, &'a str, u64, &'a str)>);

fn urllib3_release() -> Release<'static> {
    (
        "urllib3",
        "1.26.18",
        vec![
            (
                URLLIB3_WHEEL,
                URLLIB3_WHEEL_SHA,
                143835,
                "2023-10-17T17:46:21.184066Z",
            ),
            (
                URLLIB3_SDIST,
                URLLIB3_SDIST_SHA,
                305687,
                "2023-10-17T17:46:24.000000Z",
            ),
        ],
    )
}

/// Serve `GET /pypi/<name>/<version>/json` for every release, with
/// `SOCKET_PYPI_JSON_API` pointed at it for the guard's lifetime.
async fn pypi_mock(releases: &[Release<'_>]) -> (MockServer, EnvGuard) {
    let server = MockServer::start().await;
    for (name, version, files) in releases {
        let urls: Vec<serde_json::Value> = files
            .iter()
            .map(|(filename, sha, size, uploaded)| {
                serde_json::json!({
                    "filename": filename,
                    "url": pypi_file_url(filename),
                    "digests": { "sha256": sha },
                    "size": size,
                    "upload_time_iso_8601": uploaded,
                })
            })
            .collect();
        Mock::given(method("GET"))
            .and(path(format!("/pypi/{name}/{version}/json")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "urls": urls })),
            )
            .mount(&server)
            .await;
    }
    let env = EnvGuard::set(&[("SOCKET_PYPI_JSON_API", format!("{}/pypi", server.uri()))]);
    (server, env)
}

fn tree(files: &[(&str, String)]) -> BTreeMap<String, String> {
    files
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

/// `input` as the real hosted rewriter leaves it.
fn hosted(
    input: &BTreeMap<String, String>,
    deps: &[DepOverride],
    pipenv: Option<u32>,
) -> BTreeMap<String, String> {
    let result =
        rewrite_registry_redirect_with_pipenv_version(input, deps, &BTreeMap::new(), pipenv, false);
    let mut out = input.clone();
    out.extend(result.files);
    out
}

/// Discover and restore `files` in a scratch project.
async fn restore_tree(
    files: &BTreeMap<String, String>,
    opts: &RestoreOptions,
) -> (BTreeMap<String, String>, Vec<(String, PinStatus)>) {
    let tmp = tempfile::tempdir().unwrap();
    for (rel, text) in files {
        let p = tmp.path().join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, text).unwrap();
    }
    let discovery = socket_patch_core::vex::discover_patched_refs(tmp.path()).await;
    let pins = HostedPin::all(&discovery);
    let outcome = restore_upstream(tmp.path(), &pins, opts).await;
    assert!(outcome.flush_error.is_none(), "{:?}", outcome.flush_error);
    let statuses = outcome
        .pins
        .iter()
        .map(|p| (p.purl.clone(), p.status.clone()))
        .collect();
    (walk(tmp.path()), statuses)
}

/// Hosted-rewrite `input`, restore it, and require the input bytes back.
async fn assert_pypi_round_trip(
    label: &str,
    input: &BTreeMap<String, String>,
    deps: &[DepOverride],
    pipenv: Option<u32>,
) {
    let rewritten = hosted(input, deps, pipenv);
    assert_ne!(
        &rewritten, input,
        "{label}: the hosted rewrite changed nothing"
    );
    let (after, statuses) = restore_tree(&rewritten, &RestoreOptions::default()).await;
    assert!(
        !statuses.is_empty(),
        "{label}: discovery found no hosted pin"
    );
    for (purl, status) in &statuses {
        assert_eq!(*status, PinStatus::Restored, "{label}: {purl}");
    }
    for (rel, want) in input {
        assert_eq!(
            after.get(rel),
            Some(want),
            "{label}: {rel} did not round-trip"
        );
    }
    let extra: Vec<&String> = after.keys().filter(|k| !input.contains_key(*k)).collect();
    assert!(extra.is_empty(), "{label}: left behind {extra:?}");
}

/// Hosted-rewrite `input` and restore it, expecting every pin refused:
/// the joined refusals, the hosted tree and the tree after the restore.
async fn pypi_refusal(
    input: &BTreeMap<String, String>,
    deps: &[DepOverride],
    opts: &RestoreOptions,
) -> (String, BTreeMap<String, String>, BTreeMap<String, String>) {
    let rewritten = hosted(input, deps, None);
    assert_ne!(&rewritten, input, "the hosted rewrite changed nothing");
    let (after, statuses) = restore_tree(&rewritten, opts).await;
    let refusals: Vec<String> = statuses
        .iter()
        .filter_map(|(_, s)| match s {
            PinStatus::Refused(why) => Some(why.clone()),
            PinStatus::Restored => None,
        })
        .collect();
    assert!(
        !refusals.is_empty() && refusals.len() == statuses.len(),
        "{statuses:?}"
    );
    (refusals.join("\n"), rewritten, after)
}

fn fixture(rel: &str) -> String {
    fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(rel),
    )
    .unwrap()
}

#[tokio::test]
#[serial]
async fn requirements_golden_restores_modulo_name_casing() {
    // NOT byte-invertible: the hosted line spells the name as the grant does
    // (`Requests`); the original spelling (`requests`) is not recorded.
    let mut ran = 0;
    for case in load("pypi/requirements") {
        let (after, statuses) = run_case(&case).await;
        assert!(!statuses.is_empty());
        for (purl, status) in &statuses {
            assert_eq!(
                *status,
                PinStatus::Restored,
                "{}: {purl}",
                case.dir.display()
            );
        }
        assert_eq!(
            after["requirements.txt"].to_ascii_lowercase(),
            case.input["requirements.txt"].to_ascii_lowercase()
        );
        ran += 1;
    }
    assert!(ran > 0);
}

#[tokio::test]
#[serial]
async fn uv_golden_without_a_registry_sibling_is_refused() {
    // NOT invertible: the lock holds no other registry package, so which
    // artifact fields this uv release records (`size`, `upload-time`) and
    // how it lays out `wheels` is not derivable.
    let (_server, _env) = pypi_mock(&[(
        "click",
        "8.1.7",
        vec![(
            "click-8.1.7-py3-none-any.whl",
            URLLIB3_WHEEL_SHA,
            1,
            "2023-08-17T17:29:10Z",
        )],
    )])
    .await;
    let mut ran = 0;
    for case in load("pypi/uv") {
        let (after, statuses) = run_case(&case).await;
        assert!(!statuses.is_empty());
        for (purl, status) in &statuses {
            assert!(
                matches!(status, PinStatus::Refused(why)
                    if why.contains("sibling") && why.contains("git checkout -- uv.lock")),
                "{}: {purl} {status:?}",
                case.dir.display()
            );
        }
        assert_eq!(
            after, case.expected,
            "a refused pin must leave the files untouched"
        );
        ran += 1;
    }
    assert!(ran > 0);
}

#[tokio::test]
#[serial]
async fn poetry_every_lock_generation_round_trips() {
    let (_server, _env) = pypi_mock(&[urllib3_release()]).await;
    let files = format!(
        "urllib3 = [\n    {{file = \"{URLLIB3_WHEEL}\", hash = \"sha256:{URLLIB3_WHEEL_SHA}\"}},\n    {{file = \"{URLLIB3_SDIST}\", hash = \"sha256:{URLLIB3_SDIST_SHA}\"}},\n]"
    );
    for version in [
        "1.0.10", "1.1.15", "1.2.2", "1.3.2", "1.4.2", "1.5.1", "1.6.1", "1.7.1", "1.8.5", "2.0.1",
        "2.1.4", "2.2.1", "2.3.4", "2.4.3",
    ] {
        // The 1.0/1.1 fixtures were locked without hashes (`urllib3 = []`);
        // a real lock lists every release file.
        let lock =
            fixture(&format!("poetry/{version}/poetry.lock")).replace("urllib3 = []", &files);
        for eol in ["\n", "\r\n"] {
            let input = tree(&[("poetry.lock", lock.replace('\n', eol))]);
            let label = format!("poetry {version} {eol:?}");
            assert_pypi_round_trip(&label, &input, &[urllib3_dep()], None).await;
        }
    }
}

/// The backtest's `direct` and `crlf` shapes (`scripts/backtest-poetry.py`):
/// every native lock exactly as its Poetry wrote it — the 1.0/1.1 ones with
/// the empty `urllib3 = []` today's PyPI leaves them — LF and CRLF, through
/// the real hosted rewriter and back.
#[tokio::test]
#[serial]
async fn poetry_native_lock_generations_round_trip_byte_exactly() {
    let (_server, _env) = pypi_mock(&[urllib3_release()]).await;
    for version in [
        "1.0.10", "1.1.15", "1.2.2", "1.3.2", "1.4.2", "1.5.1", "1.6.1", "1.7.1", "1.8.5", "2.0.1",
        "2.1.4", "2.2.1", "2.3.4", "2.4.3",
    ] {
        let lock = fixture(&format!("poetry/{version}/poetry.lock")).replace("\r\n", "\n");
        for eol in ["\n", "\r\n"] {
            let input = tree(&[("poetry.lock", lock.replace('\n', eol))]);
            let label = format!("poetry {version} native {eol:?}");
            assert_pypi_round_trip(&label, &input, &[urllib3_dep()], None).await;
        }
    }
}

#[tokio::test]
#[serial]
async fn poetry_multi_package_lock_restores_only_the_pin() {
    let (_server, _env) = pypi_mock(&[urllib3_release()]).await;
    let lock = fixture("poetry/2.4.3/poetry.lock").replace(
        "\n[metadata]",
        "\n[[package]]\nname = \"idna\"\nversion = \"3.4\"\ndescription = \"x\"\noptional = false\npython-versions = \">=3.5\"\ngroups = [\"main\"]\nfiles = [\n    {file = \"idna-3.4-py3-none-any.whl\", hash = \"sha256:aaaa\"},\n]\n\n[metadata]",
    );
    let input = tree(&[("poetry.lock", lock)]);
    assert_pypi_round_trip("poetry siblings", &input, &[urllib3_dep()], None).await;
}

#[tokio::test]
#[serial]
async fn pdm_every_supported_format_round_trips() {
    let (_server, _env) = pypi_mock(&[urllib3_release()]).await;
    let mut ran = 0;
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pdm-native");
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("lock") {
            continue;
        }
        let lock = fs::read_to_string(&path).unwrap();
        for eol in ["\n", "\r\n"] {
            let input = tree(&[("pdm.lock", lock.replace('\n', eol))]);
            // Formats the hosted rewriter refuses (PDM 1.15, 2.0–2.7) have
            // nothing to restore.
            if hosted(&input, &[urllib3_dep()], None) == input {
                continue;
            }
            let label = format!("{} {eol:?}", path.display());
            assert_pypi_round_trip(&label, &input, &[urllib3_dep()], None).await;
            ran += 1;
        }
    }
    assert!(ran >= 10, "{ran}");
}

#[tokio::test]
#[serial]
async fn pdm_static_urls_round_trip() {
    let (_server, _env) = pypi_mock(&[urllib3_release()]).await;
    let lock = fixture("pdm-native/2.29.2.lock")
        .replace(
            "strategy = [\"inherit_metadata\"]",
            "strategy = [\"inherit_metadata\", \"static_urls\"]",
        )
        .replace(
            &format!("{{file = \"{URLLIB3_WHEEL}\""),
            &format!("{{url = \"{}\"", pypi_file_url(URLLIB3_WHEEL)),
        )
        .replace(
            &format!("{{file = \"{URLLIB3_SDIST}\""),
            &format!("{{url = \"{}\"", pypi_file_url(URLLIB3_SDIST)),
        );
    // PDM writes a static_urls entry's files in URL order (sdist first here).
    let wheel_line = format!(
        "    {{url = \"{}\", hash = \"sha256:{URLLIB3_WHEEL_SHA}\"}},\n",
        pypi_file_url(URLLIB3_WHEEL)
    );
    assert!(lock.contains(&wheel_line), "{lock}");
    let lock =
        lock.replacen(&wheel_line, "", 1)
            .replacen("\n]\n", &format!("\n{wheel_line}]\n"), 1);
    assert!(
        lock.find(URLLIB3_SDIST).unwrap() < lock.find(URLLIB3_WHEEL).unwrap(),
        "{lock}"
    );
    let input = tree(&[("pdm.lock", lock)]);
    assert_pypi_round_trip("pdm static_urls", &input, &[urllib3_dep()], None).await;
}

#[tokio::test]
#[serial]
async fn pdm_narrowed_lock_with_platform_wheels_is_refused() {
    let wheel = "urllib3-1.26.18-cp311-cp311-manylinux_2_17_x86_64.whl";
    let mut release = urllib3_release();
    release
        .2
        .push((wheel, URLLIB3_WHEEL_SHA, 1, "2023-10-17T17:46:21Z"));
    let (_server, _env) = pypi_mock(&[release]).await;
    let input = tree(&[("pdm.lock", fixture("pdm-native/2.29.2.lock"))]);
    let (why, rewritten, after) =
        pypi_refusal(&input, &[urllib3_dep()], &RestoreOptions::default()).await;
    assert!(
        why.contains("not derivable") && why.contains("cross_platform"),
        "{why}"
    );
    assert!(why.contains("git checkout -- pdm.lock"), "{why}");
    assert_eq!(after, rewritten);
    // A cross-platform lock records every file, whatever its tags.
    let input = tree(&[("pdm.lock", fixture("pdm-native/2.11.2.lock"))]);
    let rewritten = hosted(&input, &[urllib3_dep()], None);
    let (after, statuses) = restore_tree(&rewritten, &RestoreOptions::default()).await;
    assert_eq!(statuses[0].1, PinStatus::Restored);
    assert!(after["pdm.lock"].contains(wheel));
}

/// serde_json's 2-space pretty output re-indented to Pipenv's 4 spaces.
fn reindent4(text: &str) -> String {
    text.lines()
        .map(|l| {
            let n = l.len() - l.trim_start().len();
            format!("{}{}", " ".repeat(n * 2), l.trim_start())
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[tokio::test]
#[serial]
async fn pipfile_lock_fixture_and_every_category_round_trip() {
    let (_server, _env) = pypi_mock(&[urllib3_release()]).await;
    let dir = "pipenv/2026.8.0";
    let input = tree(&[
        ("Pipfile.lock", fixture(&format!("{dir}/Pipfile.lock"))),
        ("Pipfile", fixture(&format!("{dir}/Pipfile"))),
    ]);
    assert_pypi_round_trip("pipenv fixture", &input, &[urllib3_dep()], None).await;

    // Several categories (a custom one too), extras, markers, a registry
    // sibling; LF and CRLF.
    let hashes = serde_json::json!([
        format!("sha256:{URLLIB3_WHEEL_SHA}"),
        format!("sha256:{URLLIB3_SDIST_SHA}")
    ]);
    let lock = serde_json::json!({
        "_meta": { "hash": { "sha256": "x" }, "pipfile-spec": 6, "requires": {},
                   "sources": [{ "name": "pypi", "url": "https://pypi.org/simple", "verify_ssl": true }] },
        "default": {
            "idna": { "hashes": ["sha256:aaaa"], "index": "pypi", "version": "==3.4" },
            "urllib3": { "extras": ["socks"], "hashes": hashes, "index": "pypi",
                         "markers": "python_version >= '3'", "version": "==1.26.18" }
        },
        "develop": { "urllib3": { "hashes": hashes, "index": "pypi", "version": "==1.26.18" } },
        "tests": { "urllib3": { "hashes": hashes, "index": "pypi", "version": "==1.26.18" } }
    });
    let text = reindent4(&serde_json::to_string_pretty(&lock).unwrap()) + "\n";
    for eol in ["\n", "\r\n"] {
        let input = tree(&[
            ("Pipfile.lock", text.replace('\n', eol)),
            ("Pipfile", "[packages]\nurllib3 = \"*\"\n".into()),
        ]);
        let label = format!("pipenv categories {eol:?}");
        assert_pypi_round_trip(&label, &input, &[urllib3_dep()], None).await;
    }
    // Pipenv 7.x–2017 writes `path` (and, before 2018, no `index`).
    let old = text
        .replace(",\n            \"index\": \"pypi\"", "")
        .replace("\"index\": \"pypi\",\n            ", "");
    assert!(!old.contains("\"index\""), "{old}");
    let input = tree(&[("Pipfile.lock", old), ("Pipfile", "[packages]\n".into())]);
    assert_pypi_round_trip("pipenv 2017", &input, &[urllib3_dep()], Some(11)).await;
}

/// Real `pipenv lock` output for the backtest's `extras` and
/// `marker-excluded` shapes (`scripts/backtest-pipenv.py`), under
/// `tests/fixtures/pipenv-shapes/<release>/<shape>/`. Whether Pipenv
/// records `index` differs by release for the SAME Pipfile — 2018.11.26
/// writes it on both, 2022.12.19 only on the `extras` entry (the
/// marker-excluded one is written without resolving, and its transitive
/// `pysocks` gets none), 2026.8.0 on neither (an inline-table Pipfile entry
/// gets only an explicit `index`) — so the hosted entry keeps Pipenv's
/// `index` and the restore carries it back instead of guessing it. LF and
/// CRLF (the backtest's `crlf` shape) both round-trip byte for byte.
#[tokio::test]
#[serial]
async fn pipfile_lock_real_pipenv_shapes_round_trip_their_index() {
    let (_server, _env) = pypi_mock(&[urllib3_release()]).await;
    let cases = [
        ("2018.11.26", "extras", Some(2018), Some("pypi")),
        ("2018.11.26", "marker-excluded", Some(2018), Some("pypi")),
        ("2022.12.19", "extras", Some(2022), Some("pypi")),
        ("2022.12.19", "marker-excluded", Some(2022), None),
        ("2026.8.0", "extras", Some(2026), None),
        ("2026.8.0", "marker-excluded", Some(2026), None),
    ];
    for (release, shape, major, index) in cases {
        let dir = format!("pipenv-shapes/{release}/{shape}");
        let lock = fixture(&format!("{dir}/Pipfile.lock"));
        let pipfile = fixture(&format!("{dir}/Pipfile"));
        let pristine: serde_json::Value = serde_json::from_str(&lock).unwrap();
        assert_eq!(
            pristine["default"]["urllib3"]
                .get("index")
                .and_then(|v| v.as_str()),
            index,
            "{dir}: fixture drifted from what Pipenv writes"
        );
        for eol in ["\n", "\r\n"] {
            let input = tree(&[
                ("Pipfile.lock", lock.replace('\n', eol)),
                ("Pipfile", pipfile.replace('\n', eol)),
            ]);
            let label = format!("pipenv {release} {shape} {eol:?}");
            // The hosted entry keeps Pipenv's `index` (present or absent)
            // and every other registry-independent key.
            let hosted_lock = hosted(&input, &[urllib3_dep()], major)["Pipfile.lock"].clone();
            let entry: serde_json::Value = serde_json::from_str(&hosted_lock).unwrap();
            let entry = &entry["default"]["urllib3"];
            assert!(
                entry.get("file").is_some() && entry.get("version").is_none(),
                "{label}: {entry}"
            );
            for key in ["index", "markers", "extras"] {
                assert_eq!(
                    entry.get(key),
                    pristine["default"]["urllib3"].get(key),
                    "{label}: {key}"
                );
            }
            assert_pypi_round_trip(&label, &input, &[urllib3_dep()], major).await;
        }
    }
}

/// `pipenv lock` 2023+ over a hosted marker-excluded entry (the backtest's
/// `rollbackAfterRelockRetires` hybrid, measured on 2026.8.0) keeps our
/// `file` reference and writes `version` and the registry `hashes` back
/// around it — no `index`, as for the original entry. `rollback` must turn
/// it back into the pristine registry entry, not add an `index` Pipenv
/// never wrote.
#[tokio::test]
#[serial]
async fn pipfile_lock_marker_excluded_relock_hybrid_restores_the_original() {
    let (_server, _env) = pypi_mock(&[urllib3_release()]).await;
    let dir = "pipenv-shapes/2026.8.0/marker-excluded";
    let lock = fixture(&format!("{dir}/Pipfile.lock"));
    let input = tree(&[
        ("Pipfile.lock", lock.clone()),
        ("Pipfile", fixture(&format!("{dir}/Pipfile"))),
    ]);
    let rewritten = hosted(&input, &[urllib3_dep()], Some(2026));
    let mut relocked: serde_json::Value = serde_json::from_str(&rewritten["Pipfile.lock"]).unwrap();
    let pristine: serde_json::Value = serde_json::from_str(&lock).unwrap();
    let entry = relocked["default"]["urllib3"].as_object_mut().unwrap();
    assert!(
        entry.contains_key("file") && !entry.contains_key("index"),
        "{entry:?}"
    );
    entry.insert(
        "hashes".into(),
        pristine["default"]["urllib3"]["hashes"].clone(),
    );
    entry.insert("version".into(), serde_json::json!("==1.26.18"));
    relocked.sort_all_objects();
    let hybrid = reindent4(&serde_json::to_string_pretty(&relocked).unwrap()) + "\n";
    let mut tree_in = rewritten.clone();
    tree_in.insert("Pipfile.lock".into(), hybrid);
    let (after, statuses) = restore_tree(&tree_in, &RestoreOptions::default()).await;
    assert!(!statuses.is_empty(), "the hybrid is still a hosted pin");
    for (purl, status) in &statuses {
        assert_eq!(*status, PinStatus::Restored, "{purl}");
    }
    assert_eq!(
        after["Pipfile.lock"], lock,
        "the hybrid restores the pristine bytes"
    );
}

#[tokio::test]
#[serial]
async fn pipfile_lock_refusals() {
    let dir = "pipenv/2026.8.0";
    let pipfile = fixture(&format!("{dir}/Pipfile"));
    let lock = fixture(&format!("{dir}/Pipfile.lock"));
    {
        let (_server, _env) = pypi_mock(&[urllib3_release()]).await;
        // Offline: the hashes need PyPI.
        let input = tree(&[("Pipfile.lock", lock.clone()), ("Pipfile", pipfile.clone())]);
        let offline = RestoreOptions {
            offline: true,
            ..Default::default()
        };
        let (why, rewritten, after) = pypi_refusal(&input, &[urllib3_dep()], &offline).await;
        assert!(
            why.contains("offline") && why.contains("git checkout -- Pipfile.lock"),
            "{why}"
        );
        assert_eq!(after, rewritten);
        // A mirror as the only source.
        let mirror = lock.replace("https://pypi.org/simple", "https://mirror.example/simple");
        let input = tree(&[("Pipfile.lock", mirror), ("Pipfile", pipfile.clone())]);
        let (why, _, _) = pypi_refusal(&input, &[urllib3_dep()], &RestoreOptions::default()).await;
        assert!(why.contains("is PyPI"), "{why}");
        // The Pipfile routes the package to another index.
        let routed = pipfile.replace(
            "urllib3 = \"==1.26.18\"",
            "urllib3 = { version = \"==1.26.18\", index = \"private\" }",
        );
        let input = tree(&[("Pipfile.lock", lock.clone()), ("Pipfile", routed)]);
        let (why, _, _) = pypi_refusal(&input, &[urllib3_dep()], &RestoreOptions::default()).await;
        assert!(why.contains("not PyPI"), "{why}");
    }
    // PyPI does not know the release.
    let (_server, _env) = pypi_mock(&[]).await;
    let input = tree(&[("Pipfile.lock", lock), ("Pipfile", pipfile)]);
    let (why, _, _) = pypi_refusal(&input, &[urllib3_dep()], &RestoreOptions::default()).await;
    assert!(why.contains("404"), "{why}");
}

#[tokio::test]
#[serial]
async fn requirements_round_trips_in_both_hash_modes() {
    let (_server, _env) = pypi_mock(&[urllib3_release()]).await;
    // pip-compile --generate-hashes: continuation lines, `# via` comments.
    let compiled = format!(
        "#\n# pip-compile --generate-hashes\n#\nidna==3.4 \\\n    --hash=sha256:aaaa \\\n    --hash=sha256:bbbb\n    # via foo\nurllib3[socks]==1.26.18 ; python_version >= \"3\" \\\n    --hash=sha256:{URLLIB3_WHEEL_SHA} \\\n    --hash=sha256:{URLLIB3_SDIST_SHA}\n    # via -r requirements.in\n"
    );
    // Single-line hashes, a BOM, indentation, an inline comment, an option.
    let single = format!(
        "\u{feff}idna==3.4 --hash=sha256:aaaa\n  urllib3==1.26.18 --no-binary :none: --hash=sha256:{URLLIB3_WHEEL_SHA} --hash=sha256:{URLLIB3_SDIST_SHA} # keep\n"
    );
    let plain =
        "-i https://pypi.org/simple\nflask==2.0.1\nurllib3[socks]==1.26.18 ; sys_platform == \"linux\" # pinned\n"
            .to_string();
    for (label, text) in [("compiled", compiled), ("single", single), ("plain", plain)] {
        for eol in ["\n", "\r\n"] {
            let input = tree(&[("requirements.txt", text.replace('\n', eol))]);
            let label = format!("requirements {label} {eol:?}");
            assert_pypi_round_trip(&label, &input, &[urllib3_dep()], None).await;
        }
    }
}

#[tokio::test]
#[serial]
async fn requirements_hash_mode_ambiguity_is_refused() {
    let (_server, _env) = pypi_mock(&[urllib3_release()]).await;
    let input = tree(&[("requirements.txt", "urllib3==1.26.18\n".into())]);
    let (why, _, _) = pypi_refusal(&input, &[urllib3_dep()], &RestoreOptions::default()).await;
    assert!(
        why.contains("hash-checking mode") && why.contains("not derivable"),
        "{why}"
    );
    let input = tree(&[(
        "requirements.txt",
        "idna==3.4 --hash=sha256:aaaa\nsix==1.16.0\nurllib3==1.26.18\n".into(),
    )]);
    let (why, _, _) = pypi_refusal(&input, &[urllib3_dep()], &RestoreOptions::default()).await;
    assert!(why.contains("mixes hashed and unhashed"), "{why}");
    // `--require-hashes` alone settles it.
    let input = tree(&[(
        "requirements.txt",
        format!("--require-hashes\nurllib3==1.26.18 --hash=sha256:{URLLIB3_WHEEL_SHA} --hash=sha256:{URLLIB3_SDIST_SHA}\n"),
    )]);
    assert_pypi_round_trip("require-hashes", &input, &[urllib3_dep()], None).await;
    // Offline needs no lookup without hashes…
    let offline = RestoreOptions {
        offline: true,
        ..Default::default()
    };
    let input = tree(&[(
        "requirements.txt",
        "flask==2.0.1\nurllib3==1.26.18\n".into(),
    )]);
    let rewritten = hosted(&input, &[urllib3_dep()], None);
    let (after, statuses) = restore_tree(&rewritten, &offline).await;
    assert_eq!(statuses[0].1, PinStatus::Restored);
    assert_eq!(after["requirements.txt"], input["requirements.txt"]);
    // …and is refused in hash mode.
    let input = tree(&[(
        "requirements.txt",
        format!(
            "idna==3.4 --hash=sha256:aaaa\nurllib3==1.26.18 --hash=sha256:{URLLIB3_WHEEL_SHA}\n"
        ),
    )]);
    let (why, _, _) = pypi_refusal(&input, &[urllib3_dep()], &offline).await;
    assert!(why.contains("offline"), "{why}");
}

#[tokio::test]
#[serial]
async fn a_refused_pin_leaves_the_other_pins_restored() {
    // PyPI knows urllib3 only: idna's hashes cannot be re-derived.
    let (_server, _env) = pypi_mock(&[urllib3_release()]).await;
    let idna = pypi_dep(
        "idna",
        "3.4",
        "idna-3.4-py3-none-any.whl",
        "44444444-4444-4444-4444-444444444444",
    );
    let input = tree(&[(
        "requirements.txt",
        format!(
            "six==1.16.0 --hash=sha256:aaaa\nidna==3.4 --hash=sha256:bbbb\nurllib3==1.26.18 --hash=sha256:{URLLIB3_WHEEL_SHA} --hash=sha256:{URLLIB3_SDIST_SHA}\n"
        ),
    )]);
    let rewritten = hosted(&input, &[urllib3_dep(), idna], None);
    let (after, statuses) = restore_tree(&rewritten, &RestoreOptions::default()).await;
    let status = |purl: &str| &statuses.iter().find(|(p, _)| p == purl).unwrap().1;
    assert_eq!(*status("pkg:pypi/urllib3@1.26.18"), PinStatus::Restored);
    assert!(matches!(status("pkg:pypi/idna@3.4"), PinStatus::Refused(why) if why.contains("404")));
    let lines: Vec<&str> = after["requirements.txt"].lines().collect();
    assert_eq!(lines[0], "six==1.16.0 --hash=sha256:aaaa");
    assert!(
        lines[1].starts_with("idna @ https://patch.socket.dev/"),
        "{lines:?}"
    );
    assert_eq!(lines[2], input["requirements.txt"].lines().nth(2).unwrap());
}

#[tokio::test]
#[serial]
async fn hatch_round_trips_with_the_direct_reference_permission() {
    let (_server, _env) = pypi_mock(&[]).await;
    let cases = [
        // The permission tables did not exist.
        "[project]\nname = \"x\"\ndependencies = [\"Urllib3[socks]==1.26.18 ; python_version >= '3'\", \"idna\"]\n\n[build-system]\nrequires = [\"hatchling\"]\nbuild-backend = \"hatchling.build\"\n",
        // `[tool.hatch]` existed; extras and environments too.
        "[project]\nname = \"x\"\ndependencies = [\n    \"urllib3==1.26.18\",\n]\n\n[project.optional-dependencies]\nsocks = [\"urllib3[socks]==1.26.18\"]\n\n[tool.hatch.envs.default]\ndependencies = [\"urllib3==1.26.18\"]\n",
        // Environment-only: no permission is written.
        "[project]\nname = \"x\"\ndependencies = []\n\n[tool.hatch.envs.test]\nextra-dependencies = [\"urllib3==1.26.18\"] # pinned\n",
    ];
    for text in cases {
        for eol in ["\n", "\r\n"] {
            let input = tree(&[("pyproject.toml", text.replace('\n', eol))]);
            let label = format!("hatch {text:?} {eol:?}");
            assert_pypi_round_trip(&label, &input, &[urllib3_dep()], None).await;
        }
    }
    // hatch.toml environments and its `[metadata]` permission.
    let input = tree(&[
        ("pyproject.toml", "[project]\nname = \"x\"\ndependencies = [\"urllib3==1.26.18\"]\n".into()),
        ("hatch.toml", "[metadata]\nallow-direct-references = true\n\n[envs.default]\ndependencies = [\"urllib3==1.26.18\"]\n".into()),
    ]);
    let rewritten = hosted(&input, &[urllib3_dep()], None);
    assert!(rewritten["hatch.toml"].contains("allow-direct-references = true"));
    let (after, statuses) = restore_tree(&rewritten, &RestoreOptions::default()).await;
    assert_eq!(statuses[0].1, PinStatus::Restored, "{statuses:?}");
    assert_eq!(after["pyproject.toml"], input["pyproject.toml"]);
    // The permission governs nothing once no direct reference is left.
    assert!(!after["hatch.toml"].contains("allow-direct-references"));
    assert!(after["hatch.toml"].contains("dependencies = [\"urllib3==1.26.18\"]"));
}

// ── uv ───────────────────────────────────────────────────────────────────────

/// A uv.lock (revision 2 artifact shape) holding a registry `idna`, the
/// virtual root `proj` and `urllib3`; `root_deps` / `requires_dist` are the
/// root's `dependencies` and `requires-dist` entries.
fn uv_lock(root_deps: &str, requires_dist: &str, tail: &str) -> String {
    format!(
        "version = 1\nrevision = 2\nrequires-python = \">=3.8\"\n\n\
[[package]]\nname = \"idna\"\nversion = \"3.4\"\nsource = {{ registry = \"https://pypi.org/simple\" }}\n\
sdist = {{ url = \"https://files.pythonhosted.org/packages/aa/idna-3.4.tar.gz\", hash = \"sha256:{a}\", size = 183077, upload-time = \"2022-09-14T19:41:00.123Z\" }}\n\
wheels = [\n    {{ url = \"https://files.pythonhosted.org/packages/bb/idna-3.4-py3-none-any.whl\", hash = \"sha256:{b}\", size = 61538, upload-time = \"2022-09-14T19:40:59.1Z\" }},\n]\n\n\
[[package]]\nname = \"proj\"\nversion = \"0.1.0\"\nsource = {{ virtual = \".\" }}\ndependencies = [\n{root_deps}]\n\n\
[package.metadata]\nrequires-dist = [\n{requires_dist}]\n\n\
[[package]]\nname = \"urllib3\"\nversion = \"1.26.18\"\nsource = {{ registry = \"https://pypi.org/simple\" }}\n\
sdist = {{ url = \"{sdist_url}\", hash = \"sha256:{URLLIB3_SDIST_SHA}\", size = 305687, upload-time = \"2023-10-17T17:46:24Z\" }}\n\
wheels = [\n    {{ url = \"{wheel_url}\", hash = \"sha256:{URLLIB3_WHEEL_SHA}\", size = 143835, upload-time = \"2023-10-17T17:46:21.184Z\" }},\n]\n\n\
[package.optional-dependencies]\nsocks = [\n    {{ name = \"pysocks\" }},\n]\n{tail}",
        a = "a".repeat(64),
        b = "b".repeat(64),
        sdist_url = pypi_file_url(URLLIB3_SDIST),
        wheel_url = pypi_file_url(URLLIB3_WHEEL),
    )
}

#[tokio::test]
#[serial]
async fn uv_project_locks_round_trip() {
    let (_server, _env) = pypi_mock(&[urllib3_release()]).await;
    // A direct dependency (extras, a multi-clause specifier whose spelling
    // the idna entry shows), LF and CRLF.
    let lock = uv_lock(
        "    { name = \"idna\" },\n    { name = \"urllib3\", extra = [\"socks\"] },\n",
        "    { name = \"idna\", specifier = \">=3, <4\" },\n    { name = \"urllib3\", extras = [\"socks\"], specifier = \">=1.26, <2\" },\n",
        "",
    );
    let pyproject = "[project]\nname = \"proj\"\nversion = \"0.1.0\"\ndependencies = [\"idna>=3,<4\", \"urllib3[socks] >= 1.26, < 2\"]\n";
    for eol in ["\n", "\r\n"] {
        let input = tree(&[
            ("uv.lock", lock.replace('\n', eol)),
            ("pyproject.toml", pyproject.replace('\n', eol)),
        ]);
        assert_pypi_round_trip(
            &format!("uv direct {eol:?}"),
            &input,
            &[urllib3_dep()],
            None,
        )
        .await;
    }
    // A transitive dependency: the override the rewrite pins in the
    // pyproject and the lock's `[manifest]` both go again.
    let lock = uv_lock(
        "    { name = \"idna\" },\n",
        "    { name = \"idna\", specifier = \">=3\" },\n",
        "",
    );
    let pyproject = "[project]\nname = \"proj\"\nversion = \"0.1.0\"\ndependencies = [\"idna>=3\"]\n\n[tool.uv]\ndev-dependencies = []\n";
    let input = tree(&[("uv.lock", lock), ("pyproject.toml", pyproject.into())]);
    let rewritten = hosted(&input, &[urllib3_dep()], None);
    assert!(rewritten["pyproject.toml"].contains("override-dependencies"));
    assert!(rewritten["uv.lock"].contains("[manifest]"));
    assert_pypi_round_trip("uv transitive", &input, &[urllib3_dep()], None).await;
    // A lock-only checkout, with a dependent's source-qualified reference.
    let lock = uv_lock(
        "    { name = \"idna\" },\n    { name = \"urllib3\", source = { registry = \"https://pypi.org/simple\" } },\n",
        "    { name = \"idna\", specifier = \">=3\" },\n",
        "",
    );
    let input = tree(&[("uv.lock", lock)]);
    assert_pypi_round_trip("uv lock-only", &input, &[urllib3_dep()], None).await;
}

#[tokio::test]
#[serial]
async fn uv_script_lock_round_trips() {
    let (_server, _env) = pypi_mock(&[urllib3_release()]).await;
    let script = "#!/usr/bin/env python3\n# /// script\n# dependencies = [\"idna>=3\", \"urllib3==1.26.18\"]\n# ///\nprint('hi')\n";
    let lock = uv_lock("", "", "\n[manifest]\nrequirements = [\n    { name = \"idna\", specifier = \">=3\" },\n    { name = \"urllib3\", specifier = \"==1.26.18\" },\n]\n")
        .replace(
            "[[package]]\nname = \"proj\"\nversion = \"0.1.0\"\nsource = { virtual = \".\" }\ndependencies = [\n]\n\n[package.metadata]\nrequires-dist = [\n]\n\n",
            "",
        );
    assert!(!lock.contains("proj"), "{lock}");
    let input = tree(&[("tool.py", script.into()), ("tool.py.lock", lock)]);
    assert_pypi_round_trip("uv script", &input, &[urllib3_dep()], None).await;
}

#[tokio::test]
#[serial]
async fn pylock_round_trips() {
    let (_server, _env) = pypi_mock(&[urllib3_release()]).await;
    let lock = format!(
        "lock-version = \"1.0\"\ncreated-by = \"uv\"\nrequires-python = \">=3.8\"\n\n\
[[packages]]\nname = \"idna\"\nversion = \"3.4\"\nindex = \"https://pypi.org/simple\"\n\
sdist = {{ url = \"https://files.pythonhosted.org/packages/aa/idna-3.4.tar.gz\", upload-time = 2022-09-14T19:41:00.123Z, size = 183077, hashes = {{ sha256 = \"{a}\" }} }}\n\
wheels = [{{ url = \"https://files.pythonhosted.org/packages/bb/idna-3.4-py3-none-any.whl\", upload-time = 2022-09-14T19:40:59.1Z, size = 61538, hashes = {{ sha256 = \"{b}\" }} }}]\n\n\
[[packages]]\nname = \"urllib3\"\nversion = \"1.26.18\"\nindex = \"https://pypi.org/simple\"\n\
sdist = {{ url = \"{sdist_url}\", upload-time = 2023-10-17T17:46:24Z, size = 305687, hashes = {{ sha256 = \"{URLLIB3_SDIST_SHA}\" }} }}\n\
wheels = [{{ url = \"{wheel_url}\", upload-time = 2023-10-17T17:46:21.184Z, size = 143835, hashes = {{ sha256 = \"{URLLIB3_WHEEL_SHA}\" }} }}]\n",
        a = "a".repeat(64),
        b = "b".repeat(64),
        sdist_url = pypi_file_url(URLLIB3_SDIST),
        wheel_url = pypi_file_url(URLLIB3_WHEEL),
    );
    let input = tree(&[("pylock.toml", lock)]);
    assert_pypi_round_trip("pylock", &input, &[urllib3_dep()], None).await;
}

#[tokio::test]
#[serial]
async fn uv_refusals() {
    let direct = uv_lock(
        "    { name = \"idna\" },\n    { name = \"urllib3\" },\n",
        "    { name = \"idna\", specifier = \">=3\" },\n    { name = \"urllib3\", specifier = \">=1.26, <2\" },\n",
        "",
    );
    let pyproject = "[project]\nname = \"proj\"\nversion = \"0.1.0\"\ndependencies = [\"idna>=3\", \"urllib3>=1.26,<2\"]\n";
    {
        let (_server, _env) = pypi_mock(&[urllib3_release()]).await;
        // No other entry shows how this uv joins specifier clauses.
        let input = tree(&[
            ("uv.lock", direct.clone()),
            ("pyproject.toml", pyproject.into()),
        ]);
        let (why, rewritten, after) =
            pypi_refusal(&input, &[urllib3_dep()], &RestoreOptions::default()).await;
        assert!(why.contains("multi-clause"), "{why}");
        assert!(why.contains("git checkout -- uv.lock"), "{why}");
        assert_eq!(after, rewritten, "a refused pin leaves every file hosted");
        // Another registry than PyPI.
        let mirror = direct.replace("https://pypi.org/simple", "https://mirror.example/simple");
        let input = tree(&[("uv.lock", mirror)]);
        let (why, _, _) = pypi_refusal(&input, &[urllib3_dep()], &RestoreOptions::default()).await;
        assert!(why.contains("not PyPI"), "{why}");
        // Several registries.
        let mixed = direct.replace(
            "[[package]]\nname = \"proj\"",
            "[[package]]\nname = \"six\"\nversion = \"1.16.0\"\nsource = { registry = \"https://mirror.example/simple\" }\n\n[[package]]\nname = \"proj\"",
        );
        let input = tree(&[("uv.lock", mixed)]);
        let (why, _, _) = pypi_refusal(&input, &[urllib3_dep()], &RestoreOptions::default()).await;
        assert!(why.contains("several registries"), "{why}");
        // `exclude-newer` filters files by upload time.
        let newer = direct.replace(
            "requires-python = \">=3.8\"\n",
            "requires-python = \">=3.8\"\n\n[options]\nexclude-newer = \"2024-01-01T00:00:00Z\"\n",
        );
        let input = tree(&[("uv.lock", newer)]);
        let (why, _, _) = pypi_refusal(&input, &[urllib3_dep()], &RestoreOptions::default()).await;
        assert!(why.contains("exclude-newer"), "{why}");
        // Offline.
        let input = tree(&[("uv.lock", direct.clone())]);
        let offline = RestoreOptions {
            offline: true,
            ..Default::default()
        };
        let (why, _, _) = pypi_refusal(&input, &[urllib3_dep()], &offline).await;
        assert!(why.contains("offline"), "{why}");
    }
    // A release with interpreter-specific wheels.
    let mut release = urllib3_release();
    release.2.push((
        "urllib3-1.26.18-cp311-cp311-win_amd64.whl",
        URLLIB3_WHEEL_SHA,
        1,
        "2023-10-17T17:46:21Z",
    ));
    let (_server, _env) = pypi_mock(&[release]).await;
    let input = tree(&[("uv.lock", direct)]);
    let (why, _, _) = pypi_refusal(&input, &[urllib3_dep()], &RestoreOptions::default()).await;
    assert!(why.contains("interpreter-specific wheels"), "{why}");
}

/// Serve each override's npm version document with the slot-[2] integrity
/// its `input/` vlt-lock.json node records.
async fn vlt_mock(case: &Case) -> MockServer {
    let server = MockServer::start().await;
    let lock: serde_json::Value = case
        .input
        .get("vlt-lock.json")
        .and_then(|t| serde_json::from_str(t).ok())
        .unwrap_or_default();
    let empty = serde_json::Map::new();
    let nodes = lock["nodes"].as_object().unwrap_or(&empty);
    for o in &case.overrides {
        let name = match o["namespace"].as_str() {
            Some(ns) if !ns.is_empty() => format!("{ns}/{}", o["name"].as_str().unwrap()),
            _ => o["name"].as_str().unwrap().to_string(),
        };
        let version = o["version"].as_str().unwrap();
        let integrity = nodes.iter().find_map(|(id, tuple)| {
            (tuple[1].as_str() == Some(name.as_str()) && id.contains(&format!("@{version}")))
                .then(|| tuple[2].as_str().map(str::to_string))
                .flatten()
        });
        let leaf = name.rsplit('/').next().unwrap();
        let mut dist = serde_json::json!({
            "tarball": format!("https://registry.npmjs.org/{name}/-/{leaf}-{version}.tgz"),
        });
        if let Some(integrity) = integrity {
            dist["integrity"] = integrity.into();
        }
        Mock::given(method("GET"))
            .and(path(format!("/{}/{version}", name.replace('/', "%2f"))))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({ "name": name, "version": version, "dist": dist }),
            ))
            .mount(&server)
            .await;
    }
    server
}

#[tokio::test]
#[serial]
async fn vlt_goldens_round_trip() {
    // sibling-package-lock-vlt-installed, sibling-refused-in-vlt: vlt-lock.json
    // refused a package whose package-lock.json entry the rewrite still
    // pinned; with vlt-lock.json upstream that pin is not live wiring, so
    // discovery (rightly) reports no pin to restore there.
    let not_invertible = [
        "sibling-package-lock-vlt-installed",
        "sibling-refused-in-vlt",
    ];
    let mut ran = 0;
    for case in load("npm/vlt") {
        let name = case.dir.file_name().unwrap().to_string_lossy().into_owned();
        if not_invertible.contains(&name.as_str()) {
            continue;
        }
        let server = vlt_mock(&case).await;
        let _env = EnvGuard::set(&[("SOCKET_NPM_REGISTRY", server.uri())]);
        let (after, statuses) = run_case(&case).await;
        assert_round_trip(&case, &after, &statuses);
        ran += 1;
    }
    assert!(ran > 0);
}

#[tokio::test]
#[serial]
async fn maven_goldens_round_trip() {
    // mvn-config-merge: `.mvn/maven.config` existed, so whether the appended
    // resolver lines were the user's is not derivable; they stay (warned).
    // no-suffix-fallback: a same-GAV repository is tied to no artifact, so
    // discovery reports no pin to restore.
    let not_invertible = ["mvn-config-merge", "no-suffix-fallback"];
    let mut ran = 0;
    for case in load("maven/pom") {
        let name = case.dir.file_name().unwrap().to_string_lossy().into_owned();
        if not_invertible.contains(&name.as_str()) {
            continue;
        }
        let (after, statuses) = run_case(&case).await;
        assert_round_trip(&case, &after, &statuses);
        ran += 1;
    }
    assert!(ran > 0);
}

#[tokio::test]
#[serial]
async fn maven_config_merge_keeps_the_resolver_lines() {
    let case = load("maven/pom")
        .into_iter()
        .find(|c| c.dir.ends_with("mvn-config-merge"))
        .unwrap();
    let (after, statuses) = run_case(&case).await;
    assert!(
        matches!(statuses[..], [(_, PinStatus::Restored)]),
        "{statuses:?}"
    );
    for rel in ["pom.xml", ".mvn/checksums/checksums.sha256"] {
        assert_eq!(after.get(rel), case.input.get(rel), "{rel}");
    }
    assert_eq!(
        after.get(".mvn/maven.config"),
        case.expected.get(".mvn/maven.config")
    );
}

/// Serve nuget.org's registration leaf and catalog entry for every package
/// the `input/` lock pins, with the contentHash it records.
async fn nuget_mock(case: &Case) -> MockServer {
    let server = MockServer::start().await;
    let lock: serde_json::Value =
        serde_json::from_str(case.input.get("packages.lock.json").unwrap()).unwrap();
    for fw in lock["dependencies"].as_object().unwrap().values() {
        for (id, entry) in fw.as_object().unwrap() {
            let (id, version) = (id.to_lowercase(), entry["resolved"].as_str().unwrap());
            let catalog = format!("{}/catalog0/data/{id}.{version}.json", server.uri());
            Mock::given(method("GET"))
                .and(path(format!(
                    "/v3/registration5-gz-semver2/{id}/{version}.json"
                )))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(serde_json::json!({ "catalogEntry": catalog })),
                )
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("/catalog0/data/{id}.{version}.json")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": id,
                    "version": version,
                    "packageHash": entry["contentHash"],
                    "packageHashAlgorithm": "SHA512",
                })))
                .mount(&server)
                .await;
        }
    }
    server
}

/// The NuGet cases that do not round-trip byte for byte, and why.
const NUGET_NOT_INVERTIBLE: [&str; 3] = [
    // The rewriter seeded a nuget.org source into a source-less config,
    // which reads exactly like a user's own nuget.org source (`basic`); it
    // stays.
    "empty-sources",
    "empty-sources-selfclosing",
    // Two feeds serve every package once the Socket mapping is gone, so the
    // original contentHash's feed is ambiguous: refused.
    "no-preexisting-mapping",
];

#[tokio::test]
#[serial]
async fn nuget_goldens_round_trip() {
    let mut ran = 0;
    for case in load("nuget/packages-lock") {
        let name = case.dir.file_name().unwrap().to_string_lossy().into_owned();
        if NUGET_NOT_INVERTIBLE.contains(&name.as_str()) {
            continue;
        }
        let server = nuget_mock(&case).await;
        let _env = EnvGuard::set(&[("SOCKET_NUGET_URL", server.uri())]);
        let (after, statuses) = run_case(&case).await;
        assert_round_trip(&case, &after, &statuses);
        ran += 1;
    }
    assert!(ran > 0);
}

#[tokio::test]
#[serial]
async fn nuget_non_invertible_goldens_restore_or_refuse_as_documented() {
    for name in NUGET_NOT_INVERTIBLE {
        let case = load("nuget/packages-lock")
            .into_iter()
            .find(|c| c.dir.ends_with(name))
            .unwrap();
        let server = nuget_mock(&case).await;
        let _env = EnvGuard::set(&[("SOCKET_NUGET_URL", server.uri())]);
        let (after, statuses) = run_case(&case).await;
        let [(_, status)] = &statuses[..] else {
            panic!("{name}: {statuses:?}");
        };
        if name == "no-preexisting-mapping" {
            let PinStatus::Refused(why) = status else {
                panic!("{name}: {status:?}");
            };
            assert!(
                why.contains("corp-feed") && why.contains("git checkout"),
                "{why}"
            );
            assert_eq!(after, case.expected, "{name}: a refusal changes nothing");
        } else {
            assert_eq!(*status, PinStatus::Restored, "{name}");
            assert_eq!(
                after.get("packages.lock.json"),
                case.input.get("packages.lock.json")
            );
            let config = &after["nuget.config"];
            assert!(!config.contains("socket-patch") && !config.contains("packageSourceMapping"));
        }
    }
}
